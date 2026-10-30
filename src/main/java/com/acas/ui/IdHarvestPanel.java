package com.acas.ui;

import burp.api.montoya.MontoyaApi;
import com.acas.harvest.ResourceRegistry;
import com.acas.store.ActorStore;
import com.acas.engine.ObjectManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * ID Harvest Panel — Placeholder for future implementation.
 * This tab will be used for intelligent extraction and harvesting of IDs,
 * tokens, and resource identifiers across all actor sessions.
 */
public class IdHarvestPanel extends JPanel {

    private final MontoyaApi api;
    private final ActorStore store;
    private final ObjectManager objectManager;
    private final ResourceRegistry resourceRegistry;

    private final JLabel totalIdsValue = new JLabel("0");
    private final JLabel patternCountValue = new JLabel("0");
    private final JLabel crossActorValue = new JLabel("0");
    private final JLabel lastHarvestValue = new JLabel("never");
    private final DefaultTableModel actorModel = new DefaultTableModel(new Object[]{"Actor", "IDs"}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final DefaultTableModel patternModel = new DefaultTableModel(new Object[]{"Pattern", "Actors", "Cross-Actor"}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final JTextArea knownIdsArea = new JTextArea();
    private final JTable actorTable = new JTable(actorModel);
    private final JTable patternTable = new JTable(patternModel);
    private JScrollPane knownIdsScroll;
    private final JComboBox<String> patternCombo = new JComboBox<>();
    private final JComboBox<String> actorCombo = new JComboBox<>();
    private final JComboBox<String> knownIdCombo = new JComboBox<>();
    private final JTextField manualIdField = new JTextField();
    private final JTextField manualCandidateField = new JTextField();
    private String selectedActorFilter = null;
    private String selectedPatternFilter = null;
    private boolean suppressSelectionEvents = false;

    public IdHarvestPanel(MontoyaApi api, ActorStore store, ObjectManager objectManager, ResourceRegistry resourceRegistry) {
        this.api = api;
        this.store = store;
        this.objectManager = objectManager;
        this.resourceRegistry = resourceRegistry;
        
        setLayout(new BorderLayout());

        add(buildHeader(), BorderLayout.NORTH);
        add(buildMainContent(), BorderLayout.CENTER);

        new Timer(1500, e -> refreshData()).start();
        refreshData();
    }

    private JComponent buildHeader() {
        JPanel header = new JPanel(new BorderLayout(8, 8));
        header.setBorder(new EmptyBorder(12, 12, 8, 12));

        JLabel title = new JLabel("ID Harvest");
        title.setFont(new Font("SansSerif", Font.BOLD, 18));
        title.setForeground(new Color(239, 99, 52));
        header.add(title, BorderLayout.WEST);

        JTextArea desc = new JTextArea("Live registry of IDs, tokens, and object identifiers discovered during hunts.");
        desc.setEditable(false);
        desc.setOpaque(false);
        desc.setLineWrap(true);
        desc.setWrapStyleWord(true);
        desc.setFont(new Font("SansSerif", Font.PLAIN, 12));
        desc.setForeground(new Color(180, 180, 180));
        header.add(desc, BorderLayout.SOUTH);

        return header;
    }

    private JComponent buildMainContent() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(new EmptyBorder(0, 12, 12, 12));

        JPanel summary = new JPanel(new GridLayout(1, 4, 8, 0));
        summary.add(card("Total IDs", totalIdsValue));
        summary.add(card("Patterns", patternCountValue));
        summary.add(card("Cross-Actor", crossActorValue));
        summary.add(card("Last Harvest", lastHarvestValue));
        root.add(summary, BorderLayout.NORTH);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildActorTable(), buildPatternAndIdsPanel());
        split.setResizeWeight(0.35);
        split.setDividerLocation(320);
        split.setBorder(null);
        root.add(split, BorderLayout.CENTER);

        root.add(buildManualSection(), BorderLayout.SOUTH);

        return root;
    }

    private JPanel card(String label, JLabel valueLabel) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(70, 70, 70)),
            new EmptyBorder(8, 10, 8, 10)));
        JLabel name = new JLabel(label);
        name.setForeground(new Color(200, 200, 200));
        name.setFont(new Font("SansSerif", Font.PLAIN, 12));
        valueLabel.setFont(new Font("SansSerif", Font.BOLD, 18));
        valueLabel.setForeground(new Color(239, 99, 52));
        card.add(name, BorderLayout.NORTH);
        card.add(valueLabel, BorderLayout.CENTER);
        return card;
    }

    private JComponent buildActorTable() {
        actorTable.setFillsViewportHeight(true);
        actorTable.setRowHeight(22);
        actorTable.setShowGrid(false);
        actorTable.setFont(new Font("SansSerif", Font.PLAIN, 12));
        actorTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        actorTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            onActorSelected();
        });
        JScrollPane scroll = new JScrollPane(actorTable);
        scroll.setBorder(BorderFactory.createTitledBorder("IDs by Actor"));
        return scroll;
    }

    private JComponent buildPatternAndIdsPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));

        patternTable.setFillsViewportHeight(true);
        patternTable.setRowHeight(22);
        patternTable.setShowGrid(false);
        patternTable.setFont(new Font("SansSerif", Font.PLAIN, 12));
        patternTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        patternTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            onPatternSelected();
        });
        JScrollPane patternScroll = new JScrollPane(patternTable);
        patternScroll.setBorder(BorderFactory.createTitledBorder("Harvested Patterns"));

        knownIdsArea.setEditable(false);
        knownIdsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        knownIdsArea.setLineWrap(true);
        knownIdsArea.setWrapStyleWord(true);
        knownIdsScroll = new JScrollPane(knownIdsArea);
        knownIdsScroll.setBorder(BorderFactory.createTitledBorder("Known IDs"));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, patternScroll, knownIdsScroll);
        split.setResizeWeight(0.55);
        split.setDividerLocation(220);
        split.setBorder(null);
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    private JComponent buildManualSection() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder("Manual ID / Candidate Mode"));

        JPanel idForm = new JPanel(new GridLayout(2, 4, 8, 6));
        idForm.add(new JLabel("Pattern"));
        idForm.add(new JLabel("Actor"));
        idForm.add(new JLabel("Known IDs"));
        idForm.add(new JLabel("Manual ID"));

        idForm.add(patternCombo);
        idForm.add(actorCombo);
        idForm.add(knownIdCombo);
        idForm.add(manualIdField);

        JButton addSelected = new JButton("Add Selected ID");
        addSelected.addActionListener(e -> addManualId((String) knownIdCombo.getSelectedItem()));
        JButton addManual = new JButton("Add Manual ID");
        addManual.addActionListener(e -> addManualId(manualIdField.getText()));

        JPanel idActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        idActions.add(addSelected);
        idActions.add(addManual);

        idForm.add(idActions);

        JPanel candidateForm = new JPanel(new GridLayout(2, 2, 8, 6));
        candidateForm.setBorder(BorderFactory.createTitledBorder("Manual Candidate Keywords"));
        candidateForm.add(new JLabel("Candidate Value"));
        candidateForm.add(new JLabel("Uses selected Pattern + Actor above"));
        candidateForm.add(manualCandidateField);
        candidateForm.add(new JLabel("Examples: admin_card, confidential, admin_export, private.jpg"));

        JButton addCandidate = new JButton("Add Candidate");
        addCandidate.addActionListener(e -> addManualValue(manualCandidateField.getText(), "manual_candidate", "manual candidate"));

        JPanel candidateActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        candidateActions.add(addCandidate);

        panel.add(idForm);
        panel.add(Box.createVerticalStrut(8));
        panel.add(candidateForm);
        panel.add(candidateActions);

        patternCombo.addActionListener(e -> refreshKnownIdsDropdown());
        actorCombo.addActionListener(e -> refreshKnownIdsDropdown());
        manualIdField.setToolTipText("Example: 12345 or abc-uuid value for {id} path placeholder");
        manualCandidateField.setToolTipText("Example: admin_card, confidential, admin_export, private.jpg");
        return panel;
    }

    private void onActorSelected() {
        if (suppressSelectionEvents) return;
        int row = actorTable.getSelectedRow();
        if (row < 0) {
            selectedActorFilter = null;
        } else {
            Object val = actorModel.getValueAt(row, 0);
            selectedActorFilter = val != null ? String.valueOf(val) : null;
            if (selectedActorFilter != null) {
                actorCombo.setSelectedItem(selectedActorFilter);
            }
        }
        refreshKnownIdsFromSelection();
    }

    private void onPatternSelected() {
        if (suppressSelectionEvents) return;
        int row = patternTable.getSelectedRow();
        if (row < 0) {
            selectedPatternFilter = null;
        } else {
            Object val = patternModel.getValueAt(row, 0);
            selectedPatternFilter = val != null ? String.valueOf(val) : null;
            if (selectedPatternFilter != null) {
                patternCombo.setSelectedItem(selectedPatternFilter);
            }
        }
        refreshKnownIdsFromSelection();
    }

    private void addManualId(String rawValue) {
        addManualValue(rawValue, "manual_id", "ID");
    }

    private void addManualValue(String rawValue, String fieldName, String label) {
        if (resourceRegistry == null) {
            return;
        }
        String value = rawValue == null ? "" : rawValue.trim();
        if (value.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Provide a value first.", "ACAS ID Harvest", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String pattern = (String) patternCombo.getSelectedItem();
        String actor = (String) actorCombo.getSelectedItem();
        if (pattern == null || pattern.isBlank()) pattern = "MANUAL";
        if (actor == null || actor.isBlank()) actor = "Manual";

        resourceRegistry.addManualId(value, pattern, actor, fieldName);
        if ("manual_candidate".equals(fieldName)) {
            manualCandidateField.setText("");
        } else {
            manualIdField.setText("");
        }
        refreshData();
        JOptionPane.showMessageDialog(this,
            label + " added to harvest for pattern:\n" + pattern + "\nActor: " + actor,
            "ACAS ID Harvest",
            JOptionPane.INFORMATION_MESSAGE);
    }

    private void refreshKnownIdsDropdown() {
        if (resourceRegistry == null) return;
        String pattern = (String) patternCombo.getSelectedItem();
        String actor = (String) actorCombo.getSelectedItem();

        knownIdCombo.removeAllItems();
        if (pattern == null || actor == null) return;

        List<String> ids = resourceRegistry.getIdsByPatternAndActor(pattern, actor);
        for (String id : ids) {
            knownIdCombo.addItem(id);
        }
    }

    private void refreshKnownIdsFromSelection() {
        if (resourceRegistry == null) return;

        List<String> ids = resolveFilteredIds();
        if (ids.isEmpty()) {
            setKnownIdsTextPreserveScroll("No IDs match current selection.\n\nTip: click a row in IDs by Actor and/or Harvested Patterns.");
            return;
        }

        String actorLabel = selectedActorFilter != null ? selectedActorFilter : "All Actors";
        String patternLabel = selectedPatternFilter != null ? selectedPatternFilter : "All Patterns";
        setKnownIdsTextPreserveScroll("Filter: Actor=" + actorLabel + " | Pattern=" + patternLabel + "\n\n" + String.join("\n", ids));
    }

    private void setKnownIdsTextPreserveScroll(String text) {
        if (text == null) text = "";
        String current = knownIdsArea.getText();
        if (text.equals(current)) {
            return;
        }

        Point viewPos = null;
        if (knownIdsScroll != null) {
            viewPos = knownIdsScroll.getViewport().getViewPosition();
        }

        knownIdsArea.setText(text);

        if (knownIdsScroll != null && viewPos != null) {
            final Point restorePos = viewPos;
            SwingUtilities.invokeLater(() -> knownIdsScroll.getViewport().setViewPosition(restorePos));
        }
    }

    private List<String> resolveFilteredIds() {
        if (selectedActorFilter == null && selectedPatternFilter == null) {
            return resourceRegistry.getAllKnownIds();
        }

        Set<String> out = new LinkedHashSet<>();

        if (selectedActorFilter != null && selectedPatternFilter != null) {
            out.addAll(resourceRegistry.getIdsByPatternAndActor(selectedPatternFilter, selectedActorFilter));
            return new ArrayList<>(out);
        }

        if (selectedPatternFilter != null) {
            for (String actor : resourceRegistry.getActorsForPattern(selectedPatternFilter)) {
                out.addAll(resourceRegistry.getIdsByPatternAndActor(selectedPatternFilter, actor));
            }
            return new ArrayList<>(out);
        }

        // Actor-only filter.
        return resourceRegistry.getAllIdsByActor(selectedActorFilter).stream()
            .map(com.acas.harvest.HarvestedId::getValue)
            .filter(v -> v != null && !v.isBlank())
            .distinct()
            .collect(Collectors.toList());
    }

    private void refreshDropdowns() {
        if (resourceRegistry == null) return;

        String selectedPattern = (String) patternCombo.getSelectedItem();
        String selectedActor = (String) actorCombo.getSelectedItem();

        patternCombo.removeAllItems();
        actorCombo.removeAllItems();

        List<String> patterns = new ArrayList<>(resourceRegistry.getAllPatterns());
        Collections.sort(patterns);
        if (patterns.isEmpty()) {
            patternCombo.addItem("MANUAL");
        } else {
            for (String p : patterns) {
                patternCombo.addItem(p);
            }
        }

        List<String> actors = new ArrayList<>(resourceRegistry.getAllActors());
        Collections.sort(actors);
        if (actors.isEmpty()) {
            actorCombo.addItem("Manual");
        } else {
            for (String a : actors) {
                actorCombo.addItem(a);
            }
        }

        if (selectedPattern != null) patternCombo.setSelectedItem(selectedPattern);
        if (selectedActor != null) actorCombo.setSelectedItem(selectedActor);
        if (patternCombo.getSelectedItem() == null && patternCombo.getItemCount() > 0) {
            patternCombo.setSelectedIndex(0);
        }
        if (actorCombo.getSelectedItem() == null && actorCombo.getItemCount() > 0) {
            actorCombo.setSelectedIndex(0);
        }

        refreshKnownIdsDropdown();
    }

    private void refreshData() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshData);
            return;
        }

        if (resourceRegistry == null) {
            totalIdsValue.setText("0");
            patternCountValue.setText("0");
            crossActorValue.setText("0");
            lastHarvestValue.setText("unavailable");
            actorModel.setRowCount(0);
            patternModel.setRowCount(0);
            knownIdsArea.setText("Resource registry not available.");
            return;
        }

        totalIdsValue.setText(String.valueOf(resourceRegistry.getTotalHarvestedCount()));
        patternCountValue.setText(String.valueOf(resourceRegistry.getPatternCount()));
        crossActorValue.setText(String.valueOf(resourceRegistry.getCrossActorPatternCount()));
        lastHarvestValue.setText(formatInstant(resourceRegistry.getLastHarvestAt()));

        suppressSelectionEvents = true;
        actorModel.setRowCount(0);
        for (Map.Entry<String, Integer> entry : resourceRegistry.getSummaryByActor().entrySet()) {
            actorModel.addRow(new Object[]{entry.getKey(), entry.getValue()});
        }

        patternModel.setRowCount(0);
        for (String pattern : resourceRegistry.getAllPatterns()) {
            List<String> actors = List.copyOf(resourceRegistry.getActorsForPattern(pattern));
            patternModel.addRow(new Object[]{pattern, actors.size(), resourceRegistry.getCrossActorPatternCount(pattern)});
        }

        restoreSelections();
        suppressSelectionEvents = false;

        refreshDropdowns();

        List<String> knownIds = resourceRegistry.getAllKnownIds();
        if (knownIds.isEmpty()) {
            setKnownIdsTextPreserveScroll("No harvested IDs yet. Run hunts against endpoints that expose user IDs, tokens, or object references.");
        } else {
            refreshKnownIdsFromSelection();
        }
    }

    private void restoreSelections() {
        if (selectedActorFilter != null) {
            for (int i = 0; i < actorModel.getRowCount(); i++) {
                Object actor = actorModel.getValueAt(i, 0);
                if (selectedActorFilter.equals(actor)) {
                    actorTable.getSelectionModel().setSelectionInterval(i, i);
                    break;
                }
            }
        }

        if (selectedPatternFilter != null) {
            for (int i = 0; i < patternModel.getRowCount(); i++) {
                Object pattern = patternModel.getValueAt(i, 0);
                if (selectedPatternFilter.equals(pattern)) {
                    patternTable.getSelectionModel().setSelectionInterval(i, i);
                    break;
                }
            }
        }
    }

    private String formatInstant(Instant instant) {
        if (instant == null) {
            return "never";
        }
        return instant.atZone(ZoneId.systemDefault()).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }
}
