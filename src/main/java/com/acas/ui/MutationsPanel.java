package com.acas.ui;

import com.acas.engine.CustomMutationDefinition;
import com.acas.engine.MutationDefinition;
import com.acas.engine.MutationRegistry;
import com.acas.store.PayloadStore;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class MutationsPanel extends JPanel {
    private final MutationRegistry registry;
    private final PayloadStore payloadStore;
    private final DefaultTableModel tableModel;
    private final JTable mutationsTable;
    private final JEditorPane detailsPane;
    private final ListSelectionModel selectionModel;
    private final JPanel payloadEditorPanel;
    private final JTextArea payloadsTextArea;
    private final JButton loadBtn;
    private final JButton dedupBtn;
    private final JButton clearBtn;
    private final JButton addBtn;
    private final JButton saveBtn;
    private JSplitPane rightSplit;
    private String currentMutationCode;

    public MutationsPanel(MutationRegistry registry, PayloadStore payloadStore) {
        this.registry = registry;
        this.payloadStore = payloadStore;
        this.currentMutationCode = null;
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel titleLabel = new JLabel("Mutation Catalog");
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 16));
        add(titleLabel, BorderLayout.NORTH);

        // Left-side list, similar to scanner issue catalogs
        String[] cols = {"Sl. No.", "Name", "Typical severity", "Type index", "Enabled"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return c == 4; }
            @Override public Class<?> getColumnClass(int c) { return c == 4 ? Boolean.class : String.class; }
        };
        mutationsTable = new JTable(tableModel);
        mutationsTable.setRowHeight(24);
        mutationsTable.setShowGrid(false);
        mutationsTable.setFont(new Font("SansSerif", Font.PLAIN, 11));
        mutationsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        selectionModel = mutationsTable.getSelectionModel();

        // Column widths
        mutationsTable.getColumnModel().getColumn(0).setPreferredWidth(70);
        mutationsTable.getColumnModel().getColumn(0).setMaxWidth(90);
        mutationsTable.getColumnModel().getColumn(1).setPreferredWidth(260);
        mutationsTable.getColumnModel().getColumn(2).setPreferredWidth(120);
        mutationsTable.getColumnModel().getColumn(2).setMaxWidth(140);
        mutationsTable.getColumnModel().getColumn(3).setPreferredWidth(120);
        mutationsTable.getColumnModel().getColumn(3).setMaxWidth(140);
        mutationsTable.getColumnModel().getColumn(4).setPreferredWidth(70);
        mutationsTable.getColumnModel().getColumn(4).setMaxWidth(80);

        selectionModel.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateDetailsForSelected();
            }
        });

        // Double-click opens focused details dialog
        mutationsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = mutationsTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        showMutationDetails(row);
                    }
                }
            }
        });

        // Checkbox edits immediately persist
        tableModel.addTableModelListener(e -> {
            if (e.getColumn() == 4) {
                int row = e.getFirstRow();
                Boolean enabled = (Boolean) tableModel.getValueAt(row, 4);
                String mutationName = (String) tableModel.getValueAt(row, 1);
                updateMutationStatus(mutationName, enabled);
                updateDetailsForSelected();
            }
        });

        detailsPane = new JEditorPane();
        detailsPane.setContentType("text/html");
        detailsPane.setEditable(false);
        detailsPane.setFont(new Font("SansSerif", Font.PLAIN, 12));
        detailsPane.setText(emptyDetailsHtml());

        // Build payload editor panel (Burp Intruder-like interface)
        payloadsTextArea = new JTextArea();
        payloadsTextArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        payloadsTextArea.setLineWrap(false);
        payloadsTextArea.setWrapStyleWord(false);
        
        payloadEditorPanel = new JPanel(new BorderLayout(10, 10));
        payloadEditorPanel.setBorder(BorderFactory.createTitledBorder("Payload Editor"));
        
        // Left button panel
        JPanel payloadButtonsPanel = new JPanel(new GridLayout(0, 1, 5, 5));
        payloadButtonsPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        loadBtn = new JButton("Load ...");
        configureCompactButton(loadBtn);
        loadBtn.addActionListener(e -> loadPayloadsFromFile());
        payloadButtonsPanel.add(loadBtn);

        dedupBtn = new JButton("Deduplicate");
        configureCompactButton(dedupBtn);
        dedupBtn.addActionListener(e -> deduplicatePayloads());
        payloadButtonsPanel.add(dedupBtn);

        clearBtn = new JButton("Clear");
        configureCompactButton(clearBtn);
        clearBtn.addActionListener(e -> clearAllPayloads());
        payloadButtonsPanel.add(clearBtn);

        addBtn = new JButton("Add");
        configureCompactButton(addBtn);
        addBtn.addActionListener(e -> addNewPayload());
        payloadButtonsPanel.add(addBtn);

        saveBtn = new JButton("Save");
        configureCompactButton(saveBtn);
        saveBtn.addActionListener(e -> savePayloadsForMutation());
        payloadButtonsPanel.add(saveBtn);
        
        JScrollPane payloadsScroll = new JScrollPane(payloadsTextArea);
        payloadEditorPanel.add(payloadButtonsPanel, BorderLayout.WEST);
        payloadEditorPanel.add(payloadsScroll, BorderLayout.CENTER);
        // KEEP ALWAYS VISIBLE - JSplitPane doesn't handle visibility changes well
        payloadEditorPanel.setVisible(true);
        setPayloadEditorEnabled(false);

        // Right side: split details and payload editor
        JScrollPane detailsScroll = new JScrollPane(detailsPane);
        this.rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, detailsScroll, payloadEditorPanel);
        this.rightSplit.setDividerLocation(300);
        this.rightSplit.setResizeWeight(0.5);
        this.rightSplit.setBorder(null);

        JScrollPane leftScroll = new JScrollPane(mutationsTable);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftScroll, this.rightSplit);
        split.setDividerLocation(620);
        split.setResizeWeight(0.42);
        split.setBorder(null);
        add(split, BorderLayout.CENTER);

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 5));
        JButton enableBtn = new JButton("Enable");
        enableBtn.addActionListener(e -> setSelectedEnabled(true));
        toolbar.add(enableBtn);

        JButton disableBtn = new JButton("Disable");
        disableBtn.addActionListener(e -> setSelectedEnabled(false));
        toolbar.add(disableBtn);

        toolbar.add(new JSeparator(JSeparator.VERTICAL));

        JButton enableAllBtn = new JButton("Enable All");
        enableAllBtn.setFont(new Font("SansSerif", Font.PLAIN, 10));
        enableAllBtn.addActionListener(e -> enableAll());
        toolbar.add(enableAllBtn);

        JButton disableAllBtn = new JButton("Disable All");
        disableAllBtn.setFont(new Font("SansSerif", Font.PLAIN, 10));
        disableAllBtn.addActionListener(e -> disableAll());
        toolbar.add(disableAllBtn);

        JButton enableOnlyBtn = new JButton("Enable Only This");
        enableOnlyBtn.setFont(new Font("SansSerif", Font.PLAIN, 10));
        enableOnlyBtn.addActionListener(e -> enableOnlySelected());
        toolbar.add(enableOnlyBtn);

        JComboBox<String> groupCombo = new JComboBox<>(new String[]{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K"});
        groupCombo.setFont(new Font("SansSerif", Font.PLAIN, 10));
        groupCombo.setPreferredSize(new Dimension(55, 22));
        toolbar.add(groupCombo);

        JButton enableGroupBtn = new JButton("Enable Group");
        enableGroupBtn.setFont(new Font("SansSerif", Font.PLAIN, 10));
        enableGroupBtn.addActionListener(e -> {
            String selectedGroup = (String) groupCombo.getSelectedItem();
            if (selectedGroup != null) {
                enableOnlyGroup(selectedGroup);
            }
        });
        toolbar.add(enableGroupBtn);

        toolbar.add(new JSeparator(JSeparator.VERTICAL));

        JButton addCustomBtn = new JButton("Build Custom Mutation");
        addCustomBtn.setFont(new Font("SansSerif", Font.PLAIN, 11));
        addCustomBtn.addActionListener(e -> openAddCustomDialog());
        toolbar.add(addCustomBtn);

        JButton refreshBtn = new JButton("Refresh");
        refreshBtn.setFont(new Font("SansSerif", Font.PLAIN, 11));
        refreshBtn.addActionListener(e -> refresh());
        toolbar.add(refreshBtn);

        add(toolbar, BorderLayout.SOUTH);

        refresh();
    }

    public void refresh() {
        tableModel.setRowCount(0);
        List<MutationDefinition> mutations = registry.getAll();
        for (int i = 0; i < mutations.size(); i++) {
            MutationDefinition m = mutations.get(i);
            tableModel.addRow(new Object[]{
                String.valueOf(i + 1),
                m.name,
                severityForCategory(m.category),
                buildTypeIndex(m),
                m.isEnabled()
            });
        }

        if (tableModel.getRowCount() > 0) {
            mutationsTable.setRowSelectionInterval(0, 0);
            updateDetailsForSelected();
        } else {
            detailsPane.setText(emptyDetailsHtml());
        }
    }

    private void showMutationDetails(int row) {
        String mutationName = (String) tableModel.getValueAt(row, 1);
        List<MutationDefinition> mutations = registry.getAll();
        for (MutationDefinition m : mutations) {
            if (m.name.equals(mutationName)) {
                MutationDetailsDialog dialog = new MutationDetailsDialog(
                    SwingUtilities.getWindowAncestor(this), m);
                dialog.setVisible(true);
                return;
            }
        }
    }

    private void updateMutationStatus(String mutationName, boolean enabled) {
        List<MutationDefinition> mutations = registry.getAll();
        for (MutationDefinition m : mutations) {
            if (m.name.equals(mutationName)) {
                m.setEnabled(enabled);
                registry.saveToPersistence();
                break;
            }
        }
    }

    private void setSelectedEnabled(boolean enabled) {
        int row = mutationsTable.getSelectedRow();
        if (row < 0) return;
        tableModel.setValueAt(enabled, row, 4);
    }

    private void enableAll() {
        for (int row = 0; row < tableModel.getRowCount(); row++) {
            tableModel.setValueAt(true, row, 4);
        }
    }

    private void disableAll() {
        for (int row = 0; row < tableModel.getRowCount(); row++) {
            tableModel.setValueAt(false, row, 4);
        }
    }

    private void enableOnlySelected() {
        int selectedRow = mutationsTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a mutation first.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        for (int row = 0; row < tableModel.getRowCount(); row++) {
            boolean enable = (row == selectedRow);
            tableModel.setValueAt(enable, row, 4);
        }
    }

    private void enableOnlyGroup(String groupLetter) {
        if (groupLetter == null || groupLetter.isBlank()) {
            return;
        }
        String normalized = groupLetter.trim().toUpperCase();
        for (int row = 0; row < tableModel.getRowCount(); row++) {
            String mutationName = String.valueOf(tableModel.getValueAt(row, 1));
            boolean enable = belongsToGroup(mutationName, normalized);
            tableModel.setValueAt(enable, row, 4);
        }
    }

    private boolean belongsToGroup(String mutationName, String groupLetter) {
        if (mutationName == null || mutationName.isBlank() || groupLetter == null || groupLetter.isBlank()) {
            return false;
        }
        String token = mutationName.trim().split("[\\s:]")[0].toUpperCase();
        return token.startsWith(groupLetter);
    }

    private void updateDetailsForSelected() {
        int row = mutationsTable.getSelectedRow();
        if (row < 0) {
            detailsPane.setText(emptyDetailsHtml());
            payloadsTextArea.setText("(Select a mutation to view payloads)");
            return;
        }

        String mutationName = String.valueOf(tableModel.getValueAt(row, 1));
        MutationDefinition selected = null;
        for (MutationDefinition m : registry.getAll()) {
            if (m.name.equals(mutationName)) {
                selected = m;
                break;
            }
        }

        if (selected == null) {
            detailsPane.setText(emptyDetailsHtml());
            payloadsTextArea.setText("(Select a mutation to view payloads)");
            return;
        }

        String serialNo = String.valueOf(tableModel.getValueAt(row, 0));

        String html = "<html><body style='font-family: sans-serif; padding: 12px;'>"
            + "<h2 style='margin-top:0;'>" + escape(selected.name) + "</h2>"
            + "<h3>Description</h3>"
            + "<p>" + escape(selected.description) + "</p>"
            + "<h3>Classification</h3>"
            + "<ul>"
            + "<li><b>Sl. No.:</b> " + escape(serialNo) + "</li>"
            + "<li><b>Category:</b> " + escape(selected.category.toString()) + "</li>"
            + "<li><b>Typical severity:</b> " + escape(severityForCategory(selected.category)) + "</li>"
            + "<li><b>Type index:</b> " + escape(buildTypeIndex(selected)) + "</li>"
            + "<li><b>Status:</b> " + (selected.isEnabled() ? "Enabled" : "Disabled") + "</li>"
            + "<li><b>Source:</b> " + (selected.isCustom ? "Custom" : "Built-in") + "</li>"
            + "</ul>"
            + "<h3>Remediation Guidance</h3>"
            + "<p>Keep this mutation enabled for broad coverage unless it causes noise on your specific target. "
            + "For stateful/destructive flows, use a safe test environment and run with explicit approval only.</p>"
            + "</body></html>";

        detailsPane.setText(html);
        detailsPane.setCaretPosition(0);
        
        // Extract mutation code (e.g., "A1" from "A1: something")
        String mutationCode = null;
        if (selected.name != null && !selected.name.isEmpty()) {
            String[] parts = selected.name.split("[\\s:]");
            if (parts.length > 0) {
                mutationCode = parts[0].toUpperCase();
            }
        }
        
        // Load payloads for this mutation
        loadPayloadsForMutation(mutationCode);
    }

    private String severityForCategory(MutationDefinition.Category category) {
        switch (category) {
            case A:
            case B:
            case E:
            case K:
                return "High";
            case C:
            case D:
            case F:
            case G:
            case H:
            case I:
            case J:
                return "Medium";
            default:
                return "Information";
        }
    }

    private String buildTypeIndex(MutationDefinition mutation) {
        String name = mutation.name != null ? mutation.name : "";
        String code = name.split(" ")[0].toUpperCase();
        if (code.matches("[A-Z]\\d+")) {
            String catHex = String.format("%02X", mutation.category.ordinal() + 1);
            String numHex = String.format("%04X", Integer.parseInt(code.substring(1)));
            return "0xAC" + catHex + numHex;
        }
        return "0xAC" + String.format("%06X", Math.abs(name.hashCode()) & 0x00FFFFFF);
    }

    private String emptyDetailsHtml() {
        return "<html><body style='font-family: sans-serif; padding: 12px;'>"
            + "<h2 style='margin-top:0;'>Mutation Details</h2>"
            + "<p>Select a mutation from the left list to view details.</p>"
            + "</body></html>";
    }

    private String escape(String value) {
        if (value == null) return "";
        return value
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
    }

    private void openAddCustomDialog() {
        Window parent = SwingUtilities.getWindowAncestor(this);
        CustomMutationDialog dialog = new CustomMutationDialog(parent);
        dialog.setVisible(true);
        CustomMutationDefinition created = dialog.getResult();
        if (created != null) {
            registry.addCustom(created);
        }
        refresh();
    }

    // ===== Payload Editor Methods =====
    
    private void loadPayloadsForMutation(String mutationCode) {
        currentMutationCode = mutationCode;
        
        if (payloadStore == null || mutationCode == null || mutationCode.isEmpty()) {
            payloadsTextArea.setText("(No payloads configured for this mutation)");
            setPayloadEditorEnabled(false);
            return;
        }
        
        // Get all groups for this mutation
        List<PayloadStore.PayloadGroup> groups = payloadStore.getGroupsForMutation(mutationCode);
        if (groups.isEmpty()) {
            payloadsTextArea.setText("(No payloads configured for this mutation)");
            setPayloadEditorEnabled(false);
            return;
        }

        setPayloadEditorEnabled(true);
        
        // Combine all payloads for this mutation code
        StringBuilder sb = new StringBuilder();
        for (PayloadStore.PayloadGroup group : groups) {
            List<String> payloads = payloadStore.getPayloads(group.getKey());
            for (String payload : payloads) {
                sb.append(payload).append("\n");
            }
        }
        
        if (sb.length() == 0) {
            payloadsTextArea.setText("(No payloads configured for this mutation)");
        } else {
            payloadsTextArea.setText(sb.toString());
            payloadsTextArea.setCaretPosition(0);
        }
    }

    private void savePayloadsForMutation() {
        if (payloadStore == null || currentMutationCode == null || currentMutationCode.isEmpty()) {
            return;
        }
        
        String text = payloadsTextArea.getText();
        List<String> payloads = new ArrayList<>();
        for (String line : text.split("\\r?\\n")) {
            line = line.trim();
            if (line.startsWith("(") && line.endsWith(")")) {
                continue;
            }
            if (!line.isEmpty()) {
                payloads.add(line);
            }
        }
        
        // Get all groups for this mutation and set payloads to each
        List<PayloadStore.PayloadGroup> groups = payloadStore.getGroupsForMutation(currentMutationCode);
        if (!groups.isEmpty()) {
            // Set all payloads to the first group (main payload group for this code)
            PayloadStore.PayloadGroup mainGroup = groups.get(0);
            payloadStore.setPayloads(mainGroup.getKey(), payloads);
        }
    }

    private void loadPayloadsFromFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Load Payloads from File");
        int result = fileChooser.showOpenDialog(this);
        
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                File file = fileChooser.getSelectedFile();
                List<String> lines = Files.readAllLines(file.toPath());
                StringBuilder sb = new StringBuilder();
                for (String line : lines) {
                    sb.append(line).append("\n");
                }
                String current = payloadsTextArea.getText().trim();
                if (current.isEmpty()) {
                    payloadsTextArea.setText(sb.toString());
                } else {
                    payloadsTextArea.setText(current + "\n" + sb.toString());
                }
                savePayloadsForMutation();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Failed to load file: " + ex.getMessage(),
                    "Load Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void clearAllPayloads() {
        int option = JOptionPane.showConfirmDialog(this, 
            "Clear all payloads for this mutation?", "Confirm Clear", 
            JOptionPane.YES_NO_OPTION);
        if (option == JOptionPane.YES_OPTION) {
            payloadsTextArea.setText("");
            savePayloadsForMutation();
        }
    }

    private void deduplicatePayloads() {
        String text = payloadsTextArea.getText();
        Set<String> unique = new LinkedHashSet<>();
        for (String line : text.split("\\r?\\n")) {
            line = line.trim();
            if (!line.isEmpty()) {
                unique.add(line);
            }
        }
        
        StringBuilder sb = new StringBuilder();
        for (String payload : unique) {
            sb.append(payload).append("\n");
        }
        payloadsTextArea.setText(sb.toString());
        savePayloadsForMutation();
    }

    private void addNewPayload() {
        String input = JOptionPane.showInputDialog(this, 
            "Enter new payload:", "Add Payload", JOptionPane.PLAIN_MESSAGE);
        if (input != null && !input.trim().isEmpty()) {
            String current = payloadsTextArea.getText().trim();
            if (current.isEmpty()) {
                payloadsTextArea.setText(input);
            } else {
                payloadsTextArea.setText(current + "\n" + input);
            }
            savePayloadsForMutation();
        }
    }

    private void configureCompactButton(JButton button) {
        button.setFont(new Font("SansSerif", Font.PLAIN, 10));
        button.setMargin(new Insets(2, 6, 2, 6));
        button.setPreferredSize(new Dimension(96, 22));
    }

    private void setPayloadEditorEnabled(boolean enabled) {
        payloadsTextArea.setEditable(enabled);
        loadBtn.setEnabled(enabled);
        dedupBtn.setEnabled(enabled);
        clearBtn.setEnabled(enabled);
        addBtn.setEnabled(enabled);
        saveBtn.setEnabled(enabled);
    }
}
