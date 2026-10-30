package com.acas.ui;

import burp.api.montoya.MontoyaApi;
import com.acas.engine.SyncMatrixEngine;
import com.acas.engine.ProbeEngine;
import com.acas.engine.ClassifierEngine;
import com.acas.model.ActorProfile;
import com.acas.model.CapturedEndpoint;
import com.acas.store.ActorStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;
import java.util.stream.Collectors;

public class SyncMatrixDialog extends JFrame {

    private final MontoyaApi api;
    private final ActorStore store;
    private final ProbeEngine probeEngine;
    private final ClassifierEngine classifier;
    private final SyncMatrixEngine syncEngine;
    
    private final JComboBox<String> actorCombo;
    private final JRadioButton fillGapsBtn;
    private final JRadioButton forceRefreshBtn;
    private final JRadioButton fixStaleBtn;
    
    private final JRadioButton allEndpointsBtn;
    private final JRadioButton selectedOnlyBtn;
    
    private final JEditorPane previewPane;
    private final JButton startBtn;
    private final JProgressBar progressBar;
    
    private final List<String> selectedEndpointIds;
    private boolean isSyncing = false;

    public SyncMatrixDialog(Window parent, MontoyaApi api, ActorStore store, ProbeEngine probeEngine, ClassifierEngine classifier, List<String> selectedEndpointIds) {
        super("🔄 Sync Matrix Configuration");
        this.api = api;
        this.store = store;
        this.probeEngine = probeEngine;
        this.classifier = classifier;
        this.syncEngine = new SyncMatrixEngine();
        this.selectedEndpointIds = selectedEndpointIds;

        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout());
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(new EmptyBorder(15, 15, 15, 15));

        // 1. Actor Selector
        JPanel actorPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        actorPanel.add(new JLabel("Actor to sync:"));
        actorCombo = new JComboBox<>();
        actorCombo.addItem("All Actors");
        for (ActorProfile actor : store.getAllActors()) {
            actorCombo.addItem(actor.getName());
        }
        actorPanel.add(actorCombo);
        mainPanel.add(actorPanel);

        // 2. Mode Selector
        JPanel modePanel = new JPanel();
        modePanel.setBorder(BorderFactory.createTitledBorder("Sync Mode"));
        modePanel.setLayout(new BoxLayout(modePanel, BoxLayout.Y_AXIS));
        
        fillGapsBtn = new JRadioButton("Fill Gaps (Only run missing probes)", true);
        forceRefreshBtn = new JRadioButton("Force Refresh (Re-run everything)");
        fixStaleBtn = new JRadioButton("Fix Stale Only (Re-run 401/errors only)");
        
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(fillGapsBtn);
        modeGroup.add(forceRefreshBtn);
        modeGroup.add(fixStaleBtn);
        
        modePanel.add(fillGapsBtn);
        modePanel.add(forceRefreshBtn);
        modePanel.add(fixStaleBtn);
        mainPanel.add(modePanel);
        mainPanel.add(Box.createVerticalStrut(10));

        // 3. Scope Selector
        JPanel scopePanel = new JPanel();
        scopePanel.setBorder(BorderFactory.createTitledBorder("Apply To"));
        scopePanel.setLayout(new BoxLayout(scopePanel, BoxLayout.Y_AXIS));
        
        allEndpointsBtn = new JRadioButton("All endpoints in history", true);
        selectedOnlyBtn = new JRadioButton("Selected endpoints only (" + selectedEndpointIds.size() + ")");
        selectedOnlyBtn.setEnabled(!selectedEndpointIds.isEmpty());
        if (selectedEndpointIds.isEmpty()) allEndpointsBtn.setSelected(true);

        ButtonGroup scopeGroup = new ButtonGroup();
        scopeGroup.add(allEndpointsBtn);
        scopeGroup.add(selectedOnlyBtn);
        
        scopePanel.add(allEndpointsBtn);
        scopePanel.add(selectedOnlyBtn);
        mainPanel.add(scopePanel);
        mainPanel.add(Box.createVerticalStrut(10));

        // 4. Preview Area
        JPanel previewPanel = new JPanel(new BorderLayout());
        previewPanel.setBorder(BorderFactory.createTitledBorder("Preview"));
        previewPane = new JEditorPane();
        previewPane.setContentType("text/html");
        previewPane.setEditable(false);
        previewPane.setFont(new Font("SansSerif", Font.PLAIN, 12));
        previewPane.setText("<html><body style='font-family: sans-serif; color: #d4d4d4;'>Calculating...</body></html>");
        previewPanel.add(new JScrollPane(previewPane), BorderLayout.CENTER);
        mainPanel.add(previewPanel);
        mainPanel.add(Box.createVerticalStrut(15));

        // 5. Controls
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        mainPanel.add(progressBar);
        mainPanel.add(Box.createVerticalStrut(10));

        JPanel footerPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        startBtn = new JButton("Start Sync");
        startBtn.setBackground(new Color(34, 197, 94));
        startBtn.setForeground(Color.WHITE);
        startBtn.setFont(new Font("SansSerif", Font.BOLD, 12));
        
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());
        
        footerPanel.add(cancelBtn);
        footerPanel.add(startBtn);

        // Listeners
        actorCombo.addActionListener(e -> updatePreview());
        fillGapsBtn.addActionListener(e -> updatePreview());
        forceRefreshBtn.addActionListener(e -> updatePreview());
        fixStaleBtn.addActionListener(e -> updatePreview());
        allEndpointsBtn.addActionListener(e -> updatePreview());
        selectedOnlyBtn.addActionListener(e -> updatePreview());
        
        startBtn.addActionListener(e -> {
            if (isSyncing) stopSync();
            else runSync();
        });

        add(mainPanel, BorderLayout.CENTER);
        add(footerPanel, BorderLayout.SOUTH);
        
        updatePreview();
        setSize(450, 500);
        setLocationRelativeTo(parent);
    }

    private void updatePreview() {
        SyncMatrixEngine.SyncMode mode = getSelectedMode();
        boolean onlySelected = selectedOnlyBtn.isSelected();
        List<ActorProfile> actors = getTargetActors();
        
        SyncMatrixEngine.SyncPreview preview = syncEngine.calculatePreview(
            store.getCapturedEndpoints(), actors, mode, onlySelected, selectedEndpointIds
        );
        
        String html = "<html><body style='font-family: sans-serif; color: #d4d4d4; padding: 10px;'>" +
            "<div style='font-size: 12pt; margin-bottom: 8px;'><b>Preview</b></div>" +
            "<div>Gaps: <b>" + preview.missingCount + "</b></div>" +
            "<div>Stale: <b>" + preview.staleCount + "</b></div>" +
            "<div>Complete: <b>" + preview.completeCount + "</b></div>" +
            "<br><div style='color: #22c55e; font-weight: bold;'>Will probe: " + preview.willProbeCount + " endpoints</div>" +
            "<br><div style='color: #9ca3af;'>Use this dialog to control how many endpoints are re-synced before starting.</div>" +
            "</body></html>";
        previewPane.setText(html);
        startBtn.setEnabled(preview.willProbeCount > 0);
    }

    private SyncMatrixEngine.SyncMode getSelectedMode() {
        if (fillGapsBtn.isSelected()) return SyncMatrixEngine.SyncMode.FILL_GAPS;
        if (fixStaleBtn.isSelected()) return SyncMatrixEngine.SyncMode.FIX_STALE;
        return SyncMatrixEngine.SyncMode.FORCE_REFRESH;
    }

    private List<ActorProfile> getTargetActors() {
        String selectedName = (String) actorCombo.getSelectedItem();
        if ("All Actors".equals(selectedName)) {
            return store.getAllActors();
        }
        return store.getAllActors().stream()
            .filter(a -> a.getName().equals(selectedName))
            .collect(Collectors.toList());
    }

    private void runSync() {
        isSyncing = true;
        startBtn.setText("Stop Sync");
        startBtn.setBackground(Color.RED);
        progressBar.setVisible(true);
        disableOptions(false);

        List<SyncMatrixEngine.SyncTask> queue = syncEngine.buildQueue(
            store.getCapturedEndpoints(), getTargetActors(), getSelectedMode(), selectedOnlyBtn.isSelected(), selectedEndpointIds
        );

        progressBar.setMaximum(queue.size());
        progressBar.setValue(0);

        java.util.concurrent.atomic.AtomicInteger completed = new java.util.concurrent.atomic.AtomicInteger(0);
        
        for (SyncMatrixEngine.SyncTask task : queue) {
            if (!isSyncing) break;
            
            probeEngine.runTargetedProbe(task.endpoint, task.actor, () -> {
                int count = completed.incrementAndGet();
                SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(count);
                    progressBar.setString("Processing " + count + "/" + queue.size());
                    
                    // Re-classify this endpoint based on new data
                    classifier.promote(task.endpoint, store.getAllActors());
                    
                    if (count >= queue.size()) {
                        finishSync();
                    }
                });
            });
        }
    }

    private void stopSync() {
        isSyncing = false;
        finishSync();
    }

    private void finishSync() {
        isSyncing = false;
        startBtn.setText("Start Sync");
        startBtn.setBackground(new Color(34, 197, 94));
        progressBar.setVisible(false);
        disableOptions(true);
        updatePreview();
        api.logging().logToOutput("ACAS: Sync Matrix Complete.");
    }

    private void disableOptions(boolean enabled) {
        actorCombo.setEnabled(enabled);
        fillGapsBtn.setEnabled(enabled);
        forceRefreshBtn.setEnabled(enabled);
        fixStaleBtn.setEnabled(enabled);
        allEndpointsBtn.setEnabled(enabled);
        selectedOnlyBtn.setEnabled(enabled && !selectedEndpointIds.isEmpty());
    }
}
