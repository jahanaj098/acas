package com.acas.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.acas.engine.HuntManager;
import com.acas.engine.SeverityClassifier;
import com.acas.model.AcasFinding;
import com.acas.model.CapturedEndpoint;
import com.acas.store.ActorStore;
import com.acas.util.HttpUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.net.URI;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class HuntHubPanel extends JPanel {
    private final MontoyaApi api;
    private final HuntManager huntManager;
    private final SeverityClassifier classifier;
    private final ActorStore store;
    private final com.acas.engine.MutationRegistry mutationRegistry;

    private final JLabel criticalLabel = new JLabel("0");
    private final JLabel highLabel = new JLabel("0");
    private final JLabel mediumLabel = new JLabel("0");
    private final JLabel lowLabel = new JLabel("0");
    private final JPanel harvestAlertPanel = new JPanel(new BorderLayout(8, 0));
    private final JLabel harvestAlertLabel = new JLabel();
    private final JButton queueAffectedBtn = new JButton("Queue Affected");

    // Session-expiry banner — shown when a session expires mid-hunt
    private final JPanel sessionExpiredPanel = new JPanel(new BorderLayout(8, 0));
    private final JLabel sessionExpiredLabel = new JLabel();
    private final JButton sessionResumeBtn = new JButton("Session Updated → Resume");

    private final DefaultTableModel queueModel = new DefaultTableModel(new Object[]{"State", "Method", "URL", "Priority"}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final JTable queueTable = new JTable(queueModel);
    private final List<CapturedEndpoint> queueRows = new ArrayList<>();

    private final DefaultTableModel contentsModel = new DefaultTableModel(new Object[]{"Time", "Host", "Method", "URL", "Status", "Length", "Mutation", "Actor"}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final JTable contentsTable = new JTable(contentsModel);

    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JTextPane advisoryPane = new JTextPane();

    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel progressLabel = new JLabel("Status: IDLE");
    private JButton startBtn;
    private JButton pauseBtn;

    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final Map<String, List<HuntManager.MutationEvent>> eventsByEndpoint = new HashMap<>();
    private final List<HuntManager.MutationEvent> visibleEvents = new ArrayList<>();
    private String selectedEndpointKey = null;
    private String selectedContentKey = null;
    private String lastQueueSignature = "";
    private String lastLogLine = "";
    private final Deque<String> recentLogLines = new ArrayDeque<>();
    private static final int MAX_RECENT_LOGS = 2000;
    private String lastAdvisoryHtml = "";

    public HuntHubPanel(MontoyaApi api, HuntManager huntManager, SeverityClassifier classifier, ActorStore store, com.acas.engine.MutationRegistry mutationRegistry) {
        this.api = api;
        this.huntManager = huntManager;
        this.classifier = classifier;
        this.store = store;
        this.mutationRegistry = mutationRegistry;
        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor();

        setLayout(new BorderLayout(8, 8));
        setBorder(new EmptyBorder(10, 12, 10, 12));

        add(buildNorthPanel(), BorderLayout.NORTH);
        add(buildMainPanel(), BorderLayout.CENTER);
        add(buildControlBar(), BorderLayout.SOUTH);

        queueTable.setRowHeight(24);
        queueTable.setShowGrid(false);
        queueTable.setIntercellSpacing(new Dimension(0, 1));
        queueTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        queueTable.setFont(new Font("SansSerif", Font.PLAIN, 12));
        queueTable.getColumnModel().getColumn(0).setPreferredWidth(60);
        queueTable.getColumnModel().getColumn(0).setMaxWidth(70);
        queueTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        queueTable.getColumnModel().getColumn(1).setMaxWidth(90);
        queueTable.getColumnModel().getColumn(2).setPreferredWidth(300);
        queueTable.getColumnModel().getColumn(3).setPreferredWidth(70);
        queueTable.getColumnModel().getColumn(3).setMaxWidth(80);

        queueTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onQueueSelectionChanged();
            }
        });
        queueTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showQueueContextMenu(e);
                }
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showQueueContextMenu(e);
                }
            }
        });

        contentsTable.setRowHeight(24);
        contentsTable.setShowGrid(false);
        contentsTable.setIntercellSpacing(new Dimension(0, 1));
        contentsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        contentsTable.setFont(new Font("SansSerif", Font.PLAIN, 12));
        contentsTable.getColumnModel().getColumn(0).setPreferredWidth(70);
        contentsTable.getColumnModel().getColumn(1).setPreferredWidth(160);
        contentsTable.getColumnModel().getColumn(2).setPreferredWidth(65);
        contentsTable.getColumnModel().getColumn(2).setMaxWidth(70);
        contentsTable.getColumnModel().getColumn(3).setPreferredWidth(220);
        contentsTable.getColumnModel().getColumn(4).setPreferredWidth(70);
        contentsTable.getColumnModel().getColumn(4).setMaxWidth(80);
        contentsTable.getColumnModel().getColumn(5).setPreferredWidth(70);
        contentsTable.getColumnModel().getColumn(5).setMaxWidth(80);
        contentsTable.getColumnModel().getColumn(6).setPreferredWidth(170);
        contentsTable.getColumnModel().getColumn(7).setPreferredWidth(90);
        configureContentsSorting();

        contentsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onContentSelectionChanged();
            }
        });
        contentsTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showContentsContextMenu(e);
                }
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showContentsContextMenu(e);
                }
            }
        });

        advisoryPane.setContentType("text/html");
        advisoryPane.setEditable(false);
        advisoryPane.setFont(new Font("SansSerif", Font.PLAIN, 12));
        advisoryPane.setText("<html><body style='font-family: sans-serif;'>Select a queue item to view advisory.</body></html>");

        configureHarvestAlertPanel();

        new Timer(500, e -> updateStatus()).start();
    }

    private JComponent buildNorthPanel() {
        JPanel north = new JPanel(new BorderLayout(4, 4));
        north.add(buildSeverityBar(), BorderLayout.NORTH);

        JPanel alerts = new JPanel();
        alerts.setLayout(new BoxLayout(alerts, BoxLayout.Y_AXIS));
        alerts.add(harvestAlertPanel);
        alerts.add(Box.createVerticalStrut(4));
        alerts.add(sessionExpiredPanel);
        north.add(alerts, BorderLayout.SOUTH);
        return north;
    }

    private void configureHarvestAlertPanel() {
        harvestAlertPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 95, 10)),
            new EmptyBorder(6, 8, 6, 8)
        ));
        harvestAlertPanel.setBackground(new Color(47, 39, 19));
        harvestAlertLabel.setForeground(new Color(255, 219, 128));
        harvestAlertLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
        harvestAlertPanel.add(harvestAlertLabel, BorderLayout.CENTER);
        queueAffectedBtn.setFont(new Font("SansSerif", Font.PLAIN, 11));
        queueAffectedBtn.addActionListener(e -> queueHarvestAffectedEndpoints());
        harvestAlertPanel.add(queueAffectedBtn, BorderLayout.EAST);
        harvestAlertPanel.setVisible(false);

        // Session-expiry banner (red)
        sessionExpiredPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(180, 30, 30)),
            new EmptyBorder(6, 8, 6, 8)
        ));
        sessionExpiredPanel.setBackground(new Color(60, 15, 15));
        sessionExpiredLabel.setForeground(new Color(255, 120, 120));
        sessionExpiredLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
        sessionExpiredPanel.add(sessionExpiredLabel, BorderLayout.CENTER);
        sessionResumeBtn.setFont(new Font("SansSerif", Font.BOLD, 11));
        sessionResumeBtn.setBackground(new Color(180, 30, 30));
        sessionResumeBtn.setForeground(Color.WHITE);
        sessionResumeBtn.addActionListener(e -> onSessionResumeClicked());
        sessionExpiredPanel.add(sessionResumeBtn, BorderLayout.EAST);
        sessionExpiredPanel.setVisible(false);
    }

    // ── Session Expiry Banner Helpers ─────────────────────────────────────────

    /** Called from the hunt thread (via invokeLater) when a session expires. */
    private void showSessionExpiredBanner(String actorName) {
        sessionExpiredLabel.setText(
            "\u26a0\ufe0f  SESSION EXPIRED \u2014 Actor \u201c" + actorName + "\u201d  \u2014  " +
            "Right-click the actor in the Actors tab \u2192 Update Session, then click the button \u2192"
        );
        sessionExpiredPanel.setVisible(true);
        pauseBtn.setText("Resume");
        revalidate();
        repaint();
        addLog("\u23f8\ufe0f Hunt paused \u2014 session expired for actor \u2018" + actorName +
               "\u2019. Update the session cookie/token in Actors tab, then click \u2018Session Updated \u2192 Resume\u2019.");
    }

    /** Hides the banner once the hunt completes or the user resumes. */
    private void hideSessionExpiredBanner() {
        sessionExpiredPanel.setVisible(false);
        revalidate();
        repaint();
    }

    /**
     * Called when the user clicks "Session Updated → Resume" OR when the right-click
     * context menu auto-resumes after updating a session.
     * Public so AcasContextMenu (different package) can call it via getHuntHubPanel().
     */
    public void onSessionResumeClicked() {
        hideSessionExpiredBanner();
        huntManager.resumeAfterSessionRefresh();
        pauseBtn.setText("Pause");
        addLog("\u25b6\ufe0f Session refreshed \u2014 resuming hunt from paused position.");
    }

    private void queueHarvestAffectedEndpoints() {

        HuntManager.QueueEnqueueResult result = huntManager.enqueueHarvestAffectedEndpoints();
        addLog("Harvest-impact queue action: added=" + result.addedCount + ", duplicates=" + result.duplicateCount);
        rebuildQueue();
        if (result.addedCount <= 0 && result.duplicateCount <= 0) {
            JOptionPane.showMessageDialog(this,
                "No affected endpoints were available to queue.",
                "ACAS Hunt Hub",
                JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private JComponent buildSeverityBar() {
        JPanel panel = new JPanel(new GridLayout(1, 4, 8, 0));
        panel.add(statCard("Critical", criticalLabel));
        panel.add(statCard("High", highLabel));
        panel.add(statCard("Medium", mediumLabel));
        panel.add(statCard("Low", lowLabel));
        return panel;
    }

    private JPanel statCard(String title, JLabel valueLabel) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(80, 80, 80)),
            new EmptyBorder(6, 8, 6, 8)
        ));
        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        valueLabel.setFont(new Font("SansSerif", Font.BOLD, 16));
        card.add(titleLabel, BorderLayout.WEST);
        card.add(valueLabel, BorderLayout.EAST);
        return card;
    }

    private JComponent buildMainPanel() {
        JPanel left = new JPanel(new BorderLayout());
        left.setBorder(BorderFactory.createTitledBorder("Queue"));
        left.add(new JScrollPane(queueTable), BorderLayout.CENTER);

        JPanel right = new JPanel(new BorderLayout(6, 6));

        JPanel top = new JPanel(new BorderLayout());
        top.setBorder(BorderFactory.createTitledBorder("Contents"));
        top.add(new JScrollPane(contentsTable), BorderLayout.CENTER);

        JSplitPane reqRes = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
            requestEditor.uiComponent(), responseEditor.uiComponent());
        reqRes.setDividerLocation(430);
        reqRes.setBorder(null);

        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, reqRes);
        rightSplit.setDividerLocation(240);
        rightSplit.setResizeWeight(0.45);
        rightSplit.setBorder(null);

        right.add(rightSplit, BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right);
        split.setDividerLocation(380);
        split.setResizeWeight(0.3);
        split.setBorder(null);
        return split;
    }

    private JComponent buildControlBar() {
        JPanel panel = new JPanel(new BorderLayout(8, 6));

        progressBar.setStringPainted(true);
        progressBar.setMinimum(0);
        progressBar.setMaximum(1);

        panel.add(progressLabel, BorderLayout.NORTH);
        panel.add(progressBar, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        startBtn = new JButton("Start");
        pauseBtn = new JButton("Pause");
        JButton stopBtn = new JButton("Stop");

        startBtn.addActionListener(e -> {
            // Get the SELECTED endpoint (not all queued ones)
            com.acas.model.CapturedEndpoint selectedEndpoint = getSelectedQueueEndpoint();
            
            if (selectedEndpoint == null) {
                addLog("⚠️ Start ignored: No endpoint selected in queue. Click on an endpoint first.");
                JOptionPane.showMessageDialog(this, "Please select an endpoint in the queue before clicking Start.", "ACAS Hunt Hub", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            
            if (huntManager.getCurrentState() == HuntManager.State.RUNNING || huntManager.getCurrentState() == HuntManager.State.PAUSED) {
                addLog("⚠️ Start ignored: Hunt is already running or paused.");
                JOptionPane.showMessageDialog(this, "Hunt is already running.", "ACAS Hunt Hub", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            
            addLog("🎯 Starting hunt for selected endpoint: " + selectedEndpoint.getMethod() + " " + selectedEndpoint.getNormalizedPath());
            
            // Hunt ONLY the selected endpoint (wrapped in a single-item list)
            java.util.List<com.acas.model.CapturedEndpoint> singleEndpoint = java.util.Collections.singletonList(selectedEndpoint);
            huntManager.startHunt(
                singleEndpoint,
                this::addLog,
                this::addMutationEvent,
                progress -> { },
                () -> {
                    SwingUtilities.invokeLater(() -> hideSessionExpiredBanner());
                    addLog("\u2705 Hunt cycle ended for this endpoint. Select another endpoint and click Start to continue.");
                },
                // onSessionExpired callback — fires on the hunt thread, delegate to EDT
                expiredActorName -> SwingUtilities.invokeLater(() -> showSessionExpiredBanner(expiredActorName))
            );
        });

        pauseBtn.addActionListener(e -> {
            if (huntManager.getCurrentState() == HuntManager.State.PAUSED) {
                // If paused due to session expiry, use the session-aware resume path
                if (huntManager.getHealthMonitor().hasPendingRefresh()) {
                    onSessionResumeClicked();
                } else {
                    huntManager.resume();
                    pauseBtn.setText("Pause");
                }
            } else {
                huntManager.pause();
                pauseBtn.setText("Resume");
            }
        });

        stopBtn.addActionListener(e -> huntManager.stop());

        buttons.add(startBtn);
        buttons.add(pauseBtn);
        buttons.add(stopBtn);
        JButton rateLimitBtn = new JButton("Rate Limiting");
        rateLimitBtn.addActionListener(e -> {
            RateLimitConfigDialog dialog = new RateLimitConfigDialog(
                SwingUtilities.getWindowAncestor(this)
            );
            dialog.setVisible(true);
            
            // After dialog closes, apply config to HuntManager
            huntManager.setRateLimitConfig(
                dialog.getRequestsPerSec(),
                dialog.getRequestsPerMin(),
                dialog.getMaxConcurrent(),
                dialog.getIntervalMinutes(),
                dialog.isRateLimitEnabled()
            );
        });
        buttons.add(rateLimitBtn);
        panel.add(buttons, BorderLayout.SOUTH);

        return panel;
    }

    public void addLog(String msg) {
        String text = msg != null ? msg : "";
        String stamped = timeFormatter.format(Instant.now()) + "  " + text;
        lastLogLine = stamped;
        synchronized (recentLogLines) {
            recentLogLines.addLast(stamped);
            while (recentLogLines.size() > MAX_RECENT_LOGS) {
                recentLogLines.removeFirst();
            }
        }
        SwingUtilities.invokeLater(this::renderAdvisoryForSelectedEndpoint);
    }

    public void addMutationEvent(HuntManager.MutationEvent event) {
        if (event == null) return;
        SwingUtilities.invokeLater(() -> {
            String key = endpointKey(event.endpointMethod, event.endpointPath, event.endpointOwnerActorId);
            eventsByEndpoint.computeIfAbsent(key, k -> new ArrayList<>()).add(event);

            if (key.equals(selectedEndpointKey)) {
                appendEventToContents(event);
                renderAdvisoryForSelectedEndpoint();
            }
        });
    }

    public void updateStatus() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::updateStatus);
            return;
        }

        huntManager.refreshRuntimeState(this::addLog);

        List<AcasFinding> findings = classifier.getAllFindings();
        criticalLabel.setText(String.valueOf(findings.stream().filter(f -> "CRITICAL".equals(f.getSeverity())).count()));
        highLabel.setText(String.valueOf(findings.stream().filter(f -> "HIGH".equals(f.getSeverity())).count()));
        mediumLabel.setText(String.valueOf(findings.stream().filter(f -> "MEDIUM".equals(f.getSeverity())).count()));
        lowLabel.setText(String.valueOf(findings.stream().filter(f -> "LOW".equals(f.getSeverity())).count()));

        HuntManager.State state = huntManager.getCurrentState();

        int[] liveMutation = computeLiveMutationProgress();
        if ((state == HuntManager.State.RUNNING || state == HuntManager.State.PAUSED) && liveMutation[1] > 0) {
            int completed = Math.min(liveMutation[0], liveMutation[1]);
            progressBar.setMaximum(Math.max(1, liveMutation[1]));
            progressBar.setValue(Math.max(0, completed));
            progressBar.setString(completed + " / " + liveMutation[1] + " mutations");
            progressLabel.setText("Status: " + state + " | Mutation Progress: " + completed + "/" + liveMutation[1]);
        } else {
            int total = Math.max(1, huntManager.getTotalTasks());
            int progress = Math.min(total, huntManager.getProgress());
            progressBar.setMaximum(total);
            progressBar.setValue(progress);
            progressBar.setString(progress + " / " + total + " endpoints");
            progressLabel.setText("Status: " + state);
        }

        if (startBtn != null) {
            startBtn.setEnabled(state != HuntManager.State.RUNNING && state != HuntManager.State.PAUSED);
        }
        if (pauseBtn != null) {
            pauseBtn.setText(state == HuntManager.State.PAUSED ? "Resume" : "Pause");
            pauseBtn.setEnabled(state == HuntManager.State.RUNNING || state == HuntManager.State.PAUSED);
        }

        int harvestAffected = huntManager.getHarvestRehuntRecommendedCount();
        if (harvestAffected > 0) {
            harvestAlertLabel.setText("New harvested IDs detected for " + harvestAffected + " endpoint(s). Re-hunt recommended.");
            harvestAlertPanel.setVisible(true);
        } else {
            harvestAlertPanel.setVisible(false);
        }

        rebuildQueue();
    }

    private int[] computeLiveMutationProgress() {
        // Show progress for selected queue endpoint only.
        CapturedEndpoint selected = getSelectedQueueEndpoint();
        if (selected != null) {
            int total = Math.max(0, selected.getHuntProbesTotal());
            int completedFromEndpoint = Math.max(0, selected.getHuntProbesCompleted());

            int completedFromEvents = 0;
            if (selectedEndpointKey != null) {
                List<HuntManager.MutationEvent> events = eventsByEndpoint.get(selectedEndpointKey);
                completedFromEvents = events != null ? events.size() : 0;
            }

            // Event stream is the most reliable live source for executed mutations.
            int completed = Math.max(completedFromEndpoint, completedFromEvents);
            if (total <= 0) {
                total = completed;
            }
            completed = Math.min(completed, total);
            return new int[]{completed, total};
        }

        return new int[]{0, 0};
    }

    private void configureContentsSorting() {
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(contentsModel);

        sorter.setComparator(0, (a, b) -> {
            try {
                LocalTime t1 = LocalTime.parse(String.valueOf(a), DateTimeFormatter.ofPattern("HH:mm:ss"));
                LocalTime t2 = LocalTime.parse(String.valueOf(b), DateTimeFormatter.ofPattern("HH:mm:ss"));
                return t1.compareTo(t2);
            } catch (Exception e) {
                return String.valueOf(a).compareTo(String.valueOf(b));
            }
        });
        sorter.setComparator(2, (a, b) -> String.valueOf(a).compareTo(String.valueOf(b))); // Method
        sorter.setComparator(4, (a, b) -> Integer.compare(parseIntSafe(a), parseIntSafe(b))); // Status
        sorter.setComparator(5, (a, b) -> Integer.compare(parseIntSafe(a), parseIntSafe(b))); // Length
        sorter.setComparator(7, (a, b) -> String.valueOf(a).compareToIgnoreCase(String.valueOf(b))); // Actor

        contentsTable.setRowSorter(sorter);
        contentsTable.getTableHeader().setToolTipText("Click column headers to sort (Time, Method, Status, Length, Actor).");
    }

    private int parseIntSafe(Object value) {
        try {
            return Integer.parseInt(String.valueOf(value));
        } catch (Exception ignored) {
            return 0;
        }
    }

    private void rebuildQueue() {
        String selectedKeyBefore = getQueueSelectionKeyFromTable();
        if (selectedKeyBefore == null) {
            selectedKeyBefore = selectedEndpointKey;
        }

        List<CapturedEndpoint> merged = huntManager.getHuntQueue();

        String signature = buildQueueSignature(merged);
        if (signature.equals(lastQueueSignature)) {
            return;
        }
        lastQueueSignature = signature;

        queueRows.clear();
        queueRows.addAll(merged);

        queueModel.setRowCount(0);
        for (CapturedEndpoint ep : queueRows) {
            queueModel.addRow(new Object[]{
                statusSymbol(ep.getHuntStatus()),
                ep.getMethod(),
                ep.getNormalizedPath(),
                ep.getPriorityScore()
            });
        }

        if (selectedKeyBefore != null) {
            int idx = indexOfEndpointKey(selectedKeyBefore);
            if (idx >= 0) {
                if (queueTable.getSelectedRow() != idx) {
                    queueTable.setRowSelectionInterval(idx, idx);
                }
                return;
            }
        }

        if (queueModel.getRowCount() > 0 && queueTable.getSelectedRow() < 0) {
            queueTable.setRowSelectionInterval(0, 0);
        }
    }

    private void onQueueSelectionChanged() {
        int viewRow = queueTable.getSelectedRow();
        if (viewRow < 0) {
            selectedEndpointKey = null;
            selectedContentKey = null;
            contentsModel.setRowCount(0);
            visibleEvents.clear();
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
            setAdvisoryHtml("<html><body style='font-family: sans-serif;'>Select a queue item to view advisory.</body></html>");
            return;
        }

        int modelRow = queueTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= queueRows.size()) return;

        CapturedEndpoint ep = queueRows.get(modelRow);
        String newKey = endpointKey(ep.getMethod(), ep.getNormalizedPath(), ep.getActorId());
        if (Objects.equals(newKey, selectedEndpointKey)) {
            return;
        }
        selectedEndpointKey = newKey;
        selectedContentKey = null;

        refreshContentsForSelectedEndpoint();
        renderAdvisoryForSelectedEndpoint();
    }

    private void showQueueContextMenu(java.awt.event.MouseEvent e) {
        int row = queueTable.rowAtPoint(e.getPoint());
        if (row >= 0 && !queueTable.isRowSelected(row)) {
            queueTable.setRowSelectionInterval(row, row);
        }

        JPopupMenu menu = new JPopupMenu();
        JMenuItem removeOne = new JMenuItem("Delete This Request From Queue");
        JMenuItem clearAll = new JMenuItem("Clear All Queue Requests");

        removeOne.setEnabled(queueTable.getSelectedRow() >= 0);
        clearAll.setEnabled(queueModel.getRowCount() > 0);

        removeOne.addActionListener(al -> removeSelectedQueueItem());
        clearAll.addActionListener(al -> clearAllQueueItems());

        menu.add(removeOne);
        menu.add(clearAll);
        menu.show(queueTable, e.getX(), e.getY());
    }

    private void removeSelectedQueueItem() {
        if (huntManager.getCurrentState() == HuntManager.State.RUNNING || huntManager.getCurrentState() == HuntManager.State.PAUSED) {
            JOptionPane.showMessageDialog(this,
                "Cannot remove queue items while hunt is running. Stop hunt first.",
                "ACAS Hunt Hub",
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        CapturedEndpoint selected = getSelectedQueueEndpoint();
        if (selected == null) return;

        boolean removed = huntManager.removeFromQueue(selected);
        if (removed) {
            addLog("Removed from queue: " + selected.getMethod() + " " + selected.getNormalizedPath());
            rebuildQueue();
        }
    }

    private void clearAllQueueItems() {
        if (huntManager.getCurrentState() == HuntManager.State.RUNNING || huntManager.getCurrentState() == HuntManager.State.PAUSED) {
            JOptionPane.showMessageDialog(this,
                "Cannot clear queue while hunt is running. Stop hunt first.",
                "ACAS Hunt Hub",
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        int total = queueModel.getRowCount();
        if (total == 0) return;

        int choice = JOptionPane.showConfirmDialog(
            this,
            "Clear all " + total + " request(s) from Hunt Hub queue?",
            "ACAS Hunt Hub",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.WARNING_MESSAGE
        );
        if (choice != JOptionPane.OK_OPTION) return;

        int removed = huntManager.clearQueue();
        addLog("Cleared queue: " + removed + " request(s) removed.");
        rebuildQueue();
    }

    private void refreshContentsForSelectedEndpoint() {
        String previousContentKey = selectedContentKey;
        contentsModel.setRowCount(0);
        visibleEvents.clear();

        if (selectedEndpointKey == null) return;

        List<HuntManager.MutationEvent> events = eventsByEndpoint.getOrDefault(selectedEndpointKey, new ArrayList<>());
        for (HuntManager.MutationEvent event : events) {
            appendEventToContents(event);
        }

        if (contentsModel.getRowCount() == 0) {
            selectedContentKey = null;
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
            return;
        }

        int restoreIndex = previousContentKey != null ? indexOfVisibleEvent(previousContentKey) : -1;
        int target = restoreIndex >= 0 ? restoreIndex : contentsModel.getRowCount() - 1;
        contentsTable.setRowSelectionInterval(target, target);
    }

    private int indexOfVisibleEvent(String eventKey) {
        for (int i = 0; i < visibleEvents.size(); i++) {
            if (eventKey.equals(eventKey(visibleEvents.get(i)))) {
                return i;
            }
        }
        return -1;
    }

    private void appendEventToContents(HuntManager.MutationEvent event) {
        visibleEvents.add(event);
        contentsModel.addRow(new Object[]{
            timeFormatter.format(Instant.ofEpochMilli(event.timestamp)),
            extractHost(event),
            event.endpointMethod,
            event.endpointPath,
            event.statusCode,
            event.responseLength,
            event.mutationType + " - " + event.mutationDescription,
            event.actorName
        });
    }

    private void onContentSelectionChanged() {
        int viewRow = contentsTable.getSelectedRow();
        if (viewRow < 0) {
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
            return;
        }

        int modelRow = contentsTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= visibleEvents.size()) return;

        HuntManager.MutationEvent event = visibleEvents.get(modelRow);
        String eventKey = eventKey(event);
        if (Objects.equals(eventKey, selectedContentKey)) {
            return;
        }
        selectedContentKey = eventKey;

        CapturedEndpoint selectedEp = getSelectedQueueEndpoint();
        String fallbackUrl = selectedEp != null ? selectedEp.getOriginalUrl() : null;

        if (event.requestBytes != null) {
            HttpRequest req = HttpRequest.httpRequest(ByteArray.byteArray(event.requestBytes));
            req = HttpUtils.ensureRequestService(req, fallbackUrl);
            requestEditor.setRequest(req);
        } else {
            requestEditor.setRequest(null);
        }

        if (event.responseBytes != null) {
            responseEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(event.responseBytes)));
        } else {
            responseEditor.setResponse(null);
        }

        renderAdvisoryForSelectedEndpoint();
    }

    private void showContentsContextMenu(java.awt.event.MouseEvent e) {
        int row = contentsTable.rowAtPoint(e.getPoint());
        if (row >= 0 && !contentsTable.isRowSelected(row)) {
            contentsTable.setRowSelectionInterval(row, row);
        }

        JPopupMenu menu = new JPopupMenu();
        JMenuItem repeater = new JMenuItem("Send Selected Mutation to Repeater");
        JMenuItem intruder = new JMenuItem("Send Selected Mutation to Intruder");

        repeater.setEnabled(contentsTable.getSelectedRow() >= 0);
        intruder.setEnabled(contentsTable.getSelectedRow() >= 0);

        repeater.addActionListener(al -> sendSelectedMutationToRepeater());
        intruder.addActionListener(al -> sendSelectedMutationToIntruder());

        menu.add(repeater);
        menu.add(intruder);
        menu.show(contentsTable, e.getX(), e.getY());
    }

    private void sendSelectedMutationToRepeater() {
        int viewRow = contentsTable.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = contentsTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= visibleEvents.size()) return;

        HuntManager.MutationEvent event = visibleEvents.get(modelRow);
        if (event.requestBytes == null) return;

        CapturedEndpoint selectedEp = getSelectedQueueEndpoint();
        String fallbackUrl = selectedEp != null ? selectedEp.getOriginalUrl() : null;
        HttpRequest req = HttpRequest.httpRequest(ByteArray.byteArray(event.requestBytes));
        req = HttpUtils.ensureRequestService(req, fallbackUrl);
        String title = HttpUtils.buildRepeaterTabName("ACAS HuntHub", req, fallbackUrl, event.mutationType);
        api.repeater().sendToRepeater(req, title);
    }

    private void sendSelectedMutationToIntruder() {
        int viewRow = contentsTable.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = contentsTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= visibleEvents.size()) return;

        HuntManager.MutationEvent event = visibleEvents.get(modelRow);
        if (event.requestBytes == null) return;

        CapturedEndpoint selectedEp = getSelectedQueueEndpoint();
        String fallbackUrl = selectedEp != null ? selectedEp.getOriginalUrl() : null;
        HttpRequest req = HttpRequest.httpRequest(ByteArray.byteArray(event.requestBytes));
        req = HttpUtils.ensureRequestService(req, fallbackUrl);
        api.intruder().sendToIntruder(req);
    }

    private void renderAdvisoryForSelectedEndpoint() {
        if (selectedEndpointKey == null) return;

        CapturedEndpoint ep = getSelectedQueueEndpoint();
        if (ep == null) return;

        List<HuntManager.MutationEvent> events = eventsByEndpoint.getOrDefault(selectedEndpointKey, new ArrayList<>());
        HuntManager.MutationEvent selectedEvent = null;
        int selectedRow = contentsTable.getSelectedRow();
        if (selectedRow >= 0) {
            int modelRow = contentsTable.convertRowIndexToModel(selectedRow);
            if (modelRow >= 0 && modelRow < visibleEvents.size()) {
                selectedEvent = visibleEvents.get(modelRow);
            }
        }

        StringBuilder html = new StringBuilder();
        html.append("<html><body style='font-family: sans-serif; padding: 8px;'>");
        html.append("<h3 style='margin-top: 0;'>Advisory</h3>");
        html.append("<p><b>Endpoint:</b> ").append(escape(ep.getMethod())).append(" ").append(escape(ep.getNormalizedPath())).append("</p>");
        html.append("<p><b>Status:</b> ").append(escape(String.valueOf(ep.getHuntStatus()))).append(" | <b>Priority:</b> ").append(ep.getPriorityScore()).append("</p>");
        html.append("<p><b>Mutations Executed:</b> ").append(events.size()).append("</p>");

        if (!events.isEmpty()) {
            html.append("<p><b>Mutation Set:</b> ");
            int shown = 0;
            for (HuntManager.MutationEvent e : events) {
                if (shown >= 6) break;
                if (shown > 0) html.append(", ");
                html.append(escape(e.mutationType));
                shown++;
            }
            if (events.size() > 6) {
                html.append(" ... (+").append(events.size() - 6).append(" more)");
            }
            html.append("</p>");
        }

        if (selectedEvent != null) {
            html.append("<hr>");
            html.append("<p><b>Selected Mutation:</b> ").append(escape(selectedEvent.mutationType)).append("</p>");
            html.append("<p><b>Description:</b> ").append(escape(selectedEvent.mutationDescription)).append("</p>");
            html.append("<p><b>Actor:</b> ").append(escape(selectedEvent.actorName)).append("</p>");
            html.append("<p><b>Response:</b> ").append(selectedEvent.statusCode).append(" / ").append(selectedEvent.responseLength).append(" bytes</p>");
            html.append("<p><b>Verdict:</b> ").append(escape(selectedEvent.verdict)).append("</p>");
        }

        if (lastLogLine != null && !lastLogLine.isEmpty()) {
            html.append("<hr>");
            html.append("<p><b>Latest Runner Log:</b><br>").append(escape(lastLogLine)).append("</p>");
        }

        html.append("<hr>");
        html.append("<p><b>Full Runner Logs:</b></p>");
        html.append("<pre style='background:#1f2937; color:#d1d5db; padding:8px; border:1px solid #374151; max-height:300px; overflow:auto;'>");
        synchronized (recentLogLines) {
            for (String line : recentLogLines) {
                html.append(escape(line)).append("\n");
            }
        }
        html.append("</pre>");

        html.append("</body></html>");
        setAdvisoryHtml(html.toString());
    }

    private void setAdvisoryHtml(String html) {
        if (html == null) html = "";
        if (html.equals(lastAdvisoryHtml)) {
            return;
        }
        lastAdvisoryHtml = html;
        advisoryPane.setText(html);
    }

    private CapturedEndpoint getSelectedQueueEndpoint() {
        int viewRow = queueTable.getSelectedRow();
        if (viewRow < 0) return null;
        int modelRow = queueTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= queueRows.size()) return null;
        return queueRows.get(modelRow);
    }

    private int indexOfEndpointKey(String key) {
        for (int i = 0; i < queueRows.size(); i++) {
            CapturedEndpoint ep = queueRows.get(i);
            String epKey = endpointKey(ep.getMethod(), ep.getNormalizedPath(), ep.getActorId());
            if (epKey.equals(key)) return i;
        }
        return -1;
    }

    private String endpointKey(String method, String path, String actorId) {
        return (method != null ? method : "-") + "|" + (path != null ? path : "-") + "|" + (actorId != null ? actorId : "-");
    }

    private String getQueueSelectionKeyFromTable() {
        int viewRow = queueTable.getSelectedRow();
        if (viewRow < 0) return null;
        int modelRow = queueTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= queueRows.size()) return null;
        CapturedEndpoint ep = queueRows.get(modelRow);
        return endpointKey(ep.getMethod(), ep.getNormalizedPath(), ep.getActorId());
    }

    private String buildQueueSignature(List<CapturedEndpoint> merged) {
        StringBuilder sb = new StringBuilder();
        for (CapturedEndpoint ep : merged) {
            sb.append(endpointKey(ep.getMethod(), ep.getNormalizedPath(), ep.getActorId()))
                .append('#').append(ep.getHuntStatus())
                .append('#').append(ep.getPriorityScore())
                .append(';');
        }
        return sb.toString();
    }

    private String eventKey(HuntManager.MutationEvent event) {
        return event.timestamp + "|" + event.mutationType + "|" + event.mutationDescription + "|" + event.statusCode + "|" + event.responseLength;
    }

    private String statusSymbol(CapturedEndpoint.HuntStatus status) {
        if (status == null) return "⬜";
        switch (status) {
            case NEVER: return "⬜";
            case QUEUED: return "⏺";
            case RUNNING: return "⏳";
            case CLEAN: return "✅";
            case FINDING_CRITICAL:
            case FINDING_HIGH:
            case FINDING_MEDIUM:
            case FINDING_LOW:
                return "⚠";
            case ERROR: return "⛔";
            case STALE: return "♻";
            default: return "⬜";
        }
    }

    private String extractHost(HuntManager.MutationEvent event) {
        CapturedEndpoint ep = getSelectedQueueEndpoint();
        if (ep != null && ep.getOriginalUrl() != null) {
            try {
                URI uri = URI.create(ep.getOriginalUrl());
                if (uri.getHost() != null) return uri.getHost();
            } catch (Exception ignored) {
            }
        }
        return "-";
    }

    private String escape(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;");
    }
}
