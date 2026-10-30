package com.acas.ui;

import burp.api.montoya.MontoyaApi;
import com.acas.engine.ObjectManager;
import com.acas.engine.ReplayEngine;
import com.acas.engine.SeverityClassifier;
import com.acas.harvest.ResourceRegistry;
import com.acas.notification.NotificationService;
import com.acas.store.ActorStore;
import com.acas.store.PayloadStore;

import javax.swing.*;
import java.awt.*;

public class AcasPanel extends JPanel {

    private final ActorsPanel actorsPanel;
    private final HistoryPanel historyPanel;
    private final HuntHubPanel huntHubPanel;
    private final ResultMatrixPanel matrixPanel;
    private final SettingsPanel settingsPanel;
    private final JTabbedPane tabs;

    // Finding badge state
    private final SeverityClassifier severityClassifier;
    private final com.acas.engine.HuntManager huntManager;
    private final com.acas.engine.MutationEngine mutationEngine;

    public AcasPanel(MontoyaApi api, ActorStore store, ObjectManager objectManager, ReplayEngine replayEngine, com.acas.engine.MutationEngine mutationEngine, com.acas.engine.MutationRegistry mutationRegistry, PayloadStore payloadStore, ResourceRegistry resourceRegistry, com.acas.engine.ProbeEngine probeEngine, com.acas.engine.ClassifierEngine classifier, NotificationService notifier) {
        com.acas.engine.ComparisonEngine comparisonEngine = new com.acas.engine.ComparisonEngine(objectManager);
        com.acas.engine.SeverityClassifier sevClassifier = new com.acas.engine.SeverityClassifier(api);
        this.severityClassifier = sevClassifier;
        this.mutationEngine = mutationEngine;
        probeEngine.setSeverityClassifier(sevClassifier);
        this.huntManager = new com.acas.engine.HuntManager(api, store, mutationEngine, replayEngine, comparisonEngine, sevClassifier, objectManager, resourceRegistry);
        
        // Phase 15: Critical Alerts
        sevClassifier.addListener(finding -> {
            if ("CRITICAL".equals(finding.getSeverity())) {
                api.logging().raiseCriticalEvent("ACAS: CRITICAL finding discovered at " + finding.getUrl());
            }
        });

        this.historyPanel = new HistoryPanel(api, store, this.huntManager, probeEngine, sevClassifier, notifier);
        this.huntHubPanel = new HuntHubPanel(api, this.huntManager, sevClassifier, store, mutationRegistry);
        this.matrixPanel = new ResultMatrixPanel(api, store, sevClassifier, notifier, resourceRegistry, this.huntManager);

        this.actorsPanel = new ActorsPanel(api, store, this.huntManager, notifier);
        this.settingsPanel = new SettingsPanel(store, this.huntManager, mutationRegistry, sevClassifier, notifier);

        setLayout(new BorderLayout(0, 0));

        tabs = new JTabbedPane(JTabbedPane.TOP);
        
        // Tab order: Actors | Captured History | Result Matrix | Settings
        tabs.addTab("  Actors  ", actorsPanel);
        tabs.addTab("  Captured History  ", historyPanel);
        tabs.addTab("  Result Matrix  ", matrixPanel);
        tabs.addTab("  Settings  ", settingsPanel);

        tabs.setFont(new Font("SansSerif", Font.BOLD, 12));
        add(tabs, BorderLayout.CENTER);

        // Back-fill the Result Matrix from already-probed endpoints whenever the
        // tab is opened, so results captured earlier always show up.
        final com.acas.engine.ProbeEngine probeEngineRef = probeEngine;
        tabs.addChangeListener(e -> {
            if (tabs.getSelectedComponent() == matrixPanel) {
                new Thread(() -> {
                    probeEngineRef.backfillResults();
                    SwingUtilities.invokeLater(matrixPanel::refresh);
                }, "ACAS-Matrix-Backfill").start();
            }
        });
        // One-time back-fill shortly after load (covers persisted endpoints).
        Timer backfillOnce = new Timer(2500, e -> new Thread(() -> {
            probeEngineRef.backfillResults();
            SwingUtilities.invokeLater(matrixPanel::refresh);
        }, "ACAS-Matrix-Backfill-Init").start());
        backfillOnce.setRepeats(false);
        backfillOnce.start();

        // ========== Finding Count Badge on Result Matrix Tab ==========
        new Timer(2000, e -> updateResultMatrixBadge()).start();
    }

    /**
     * Updates the Result Matrix tab title with a finding count badge.
     * Red badge if any Critical/High findings, amber if Medium/Low only.
     */
    private void updateResultMatrixBadge() {
        int totalFindings = severityClassifier.getAllFindings().size();
        int matrixTabIndex = tabs.indexOfComponent(matrixPanel);
        if (matrixTabIndex < 0) return;

        if (totalFindings > 0) {
            tabs.setTitleAt(matrixTabIndex, "  Result Matrix (" + totalFindings + ")  ");
            
            // Color the tab title based on severity
            if (severityClassifier.hasHighSeverityFindings()) {
                tabs.setForegroundAt(matrixTabIndex, new Color(239, 68, 68)); // Red
            } else if (severityClassifier.hasMediumSeverityOnly()) {
                tabs.setForegroundAt(matrixTabIndex, new Color(245, 158, 11)); // Amber
            } else {
                tabs.setForegroundAt(matrixTabIndex, null); // Default
            }
        } else {
            tabs.setTitleAt(matrixTabIndex, "  Result Matrix  ");
            tabs.setForegroundAt(matrixTabIndex, null);
        }
    }

    /** Called after an actor is deleted: drop its findings so the Result Matrix stays in sync. */
    public void onActorDeleted(String actorName) {
        if (actorName == null) return;
        severityClassifier.removeFindingsByActor(actorName);
        if (matrixPanel != null) matrixPanel.refresh();
    }

    public ActorsPanel getActorsPanel() { return actorsPanel; }
    public HuntHubPanel getHuntHubPanel() { return huntHubPanel; }
    public ResultMatrixPanel getMatrixPanel() { return matrixPanel; }
    public HistoryPanel getHistoryPanel() { return historyPanel; }
    public com.acas.engine.HuntManager getHuntManager() { return huntManager; }
    public com.acas.engine.MutationEngine getMutationEngine() { return mutationEngine; }

    public void switchToHuntHub() {
        // Hunt Hub tab was removed — swap + anonymous now run automatically on
        // capture and are viewed inline in Captured History. This is kept as a
        // safe no-op (redirects to Captured History) so existing callers compile.
        if (tabs.indexOfComponent(historyPanel) >= 0) {
            tabs.setSelectedComponent(historyPanel);
        }
    }

    public void switchToResultMatrix() {
        tabs.setSelectedComponent(matrixPanel);
    }

    public void switchToTab(Component panel) {
        tabs.setSelectedComponent(panel);
    }
}

