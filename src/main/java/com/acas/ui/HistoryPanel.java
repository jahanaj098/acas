package com.acas.ui;

import com.acas.model.CapturedEndpoint;
import com.acas.store.ActorStore;
import com.acas.engine.HuntManager;
import com.acas.engine.SeverityClassifier;
import com.acas.util.HttpUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class HistoryPanel extends JPanel {
    private Timer refreshTimer;
    @Override public void addNotify(){super.addNotify();if(refreshTimer!=null)refreshTimer.start();}
    @Override public void removeNotify(){if(refreshTimer!=null)refreshTimer.stop();super.removeNotify();}
    private final java.util.concurrent.atomic.AtomicBoolean refreshPending=new java.util.concurrent.atomic.AtomicBoolean();
    private final burp.api.montoya.MontoyaApi api;
    private final ActorStore store;
    private final HuntManager huntManager;
    private final com.acas.engine.ProbeEngine probeEngine;
    private final SeverityClassifier severityClassifier;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final TableRowSorter<DefaultTableModel> sorter;

    // Dynamic per-test viewer: one tab per probe (Baseline, Anonymous, Swap → each actor).
    // Editors are pooled and reused as the probe count grows.
    private final JTabbedPane modeTabs = new JTabbedPane();
    private final List<burp.api.montoya.ui.editor.HttpRequestEditor> requestEditorPool = new ArrayList<>();
    private final List<burp.api.montoya.ui.editor.HttpResponseEditor> responseEditorPool = new ArrayList<>();
    private String lastViewerStateKey = "";

    // Hunt toolbar components
    private final JButton huntBtn;

    // Filter state
    private final JComboBox<String> actorFilter = new JComboBox<>(new String[]{"All Actors"});
    private final JCheckBox onlyHitsFilter = new JCheckBox("Only show hits (BROKEN / BYPASS / SUSPICIOUS)");
    private final JCheckBox groupByActorFilter = new JCheckBox("Group by actor", true);

    // Grouped-row model: rowEndpoints[i] == null marks an actor group header;
    // rowGroupKeys[i] holds that header's actor id (null for request rows).
    private final List<CapturedEndpoint> rowEndpoints = new ArrayList<>();
    private final List<String> rowGroupKeys = new ArrayList<>();
    private final java.util.Set<String> collapsedActors = new java.util.HashSet<>();

    // Column indices
    private static final int COL_NUM = 0;
    private static final int COL_ACTOR = 1;
    private static final int COL_METHOD = 2;
    private static final int COL_URL = 3;
    private static final int COL_LABEL = 4;
    private static final int COL_BASELINE = 5;
    private static final int COL_ANON = 6;
    private static final int COL_SWAP = 7;
    private static final int COL_PRIORITY = 8;

    public HistoryPanel(burp.api.montoya.MontoyaApi api, ActorStore store, HuntManager huntManager, 
                         com.acas.engine.ProbeEngine probeEngine, SeverityClassifier severityClassifier,
                         com.acas.notification.NotificationService notifier) {
        this.api = api;
        this.store = store;
        this.huntManager = huntManager;
        this.probeEngine = probeEngine;
        this.severityClassifier = severityClassifier;

        setLayout(new BorderLayout());
        
        // ========== TABLE SETUP ==========
        String[] cols = {"#", "Actor", "Method", "URL", "Label", "Baseline", "Anon", "Swap", "Priority"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        table = new NativeHistoryTable(tableModel) {
            @Override
            public Component prepareRenderer(javax.swing.table.TableCellRenderer renderer, int row, int col) {
                Component c = super.prepareRenderer(renderer, row, col);
                int modelRow = convertRowIndexToModel(row);
                boolean header = modelRow >= 0 && modelRow < rowEndpoints.size() && rowEndpoints.get(modelRow) == null;
                if (header && !isRowSelected(row)) {

                    c.setFont(c.getFont().deriveFont(java.awt.Font.BOLD));
                }
                return c;
            }
        };

        // MULTI-SELECT: Standard Ctrl+Click, Shift+Click, Ctrl+A
        ((NativeHistoryTable) table).setActorColors(row -> {
            if (row < 0 || row >= rowEndpoints.size()) return null;
            CapturedEndpoint endpoint = rowEndpoints.get(row);
            String actorId = endpoint != null ? endpoint.getActorId() : rowGroupKeys.get(row);
            com.acas.model.ActorProfile actor = store.getActor(actorId);
            return actor == null ? null : ActorsPanel.safeColor(actor.getColor(), null);
        });
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);


        // Sorter kept only for row-index conversion; column sorting is disabled so
        // actor grouping is never scrambled.
        sorter = new TableRowSorter<>(tableModel);
        for (int i = 0; i < 9; i++) sorter.setSortable(i, false);
        table.setRowSorter(sorter);

        // Column widths
        table.getColumnModel().getColumn(COL_NUM).setPreferredWidth(35);
        table.getColumnModel().getColumn(COL_NUM).setMaxWidth(45);
        table.getColumnModel().getColumn(COL_ACTOR).setPreferredWidth(80);
        table.getColumnModel().getColumn(COL_METHOD).setPreferredWidth(55);
        table.getColumnModel().getColumn(COL_METHOD).setMaxWidth(70);
        table.getColumnModel().getColumn(COL_URL).setPreferredWidth(320);
        table.getColumnModel().getColumn(COL_LABEL).setPreferredWidth(160);
        table.getColumnModel().getColumn(COL_BASELINE).setPreferredWidth(55);
        table.getColumnModel().getColumn(COL_BASELINE).setMaxWidth(65);
        table.getColumnModel().getColumn(COL_ANON).setPreferredWidth(140);
        table.getColumnModel().getColumn(COL_SWAP).setPreferredWidth(210);
        table.getColumnModel().getColumn(COL_PRIORITY).setPreferredWidth(50);
        table.getColumnModel().getColumn(COL_PRIORITY).setMaxWidth(60);

        // Custom renderers

        AcasTheme.styleTabs(modeTabs);
        table.getColumnModel().getColumn(COL_ACTOR).setCellRenderer(new ActorColorRenderer());



        // Selection listener — update editors + hunt button text
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateEditors();
                updateHuntButtonText();
            }
        });

        // Click an actor group header to collapse/expand it; right-click = context menu.
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int viewRow = table.rowAtPoint(e.getPoint());
                if (viewRow < 0) return;
                int modelRow = table.convertRowIndexToModel(viewRow);
                if (modelRow >= 0 && modelRow < rowGroupKeys.size() && rowGroupKeys.get(modelRow) != null) {
                    String key = rowGroupKeys.get(modelRow);
                    if (collapsedActors.contains(key)) collapsedActors.remove(key);
                    else collapsedActors.add(key);
                    refresh();
                }
            }
            @Override
            public void mousePressed(MouseEvent e) { if (e.isPopupTrigger()) showContextMenu(e); }
            @Override
            public void mouseReleased(MouseEvent e) { if (e.isPopupTrigger()) showContextMenu(e); }
        });

        // ========== DYNAMIC PER-TEST VIEWER ==========
        // Tabs are (re)built per selected endpoint in updateEditors(): one tab per
        // probe — Baseline, Anonymous, then Swap → each actor — each showing the
        // live request AND response that auto-ran on capture.
        JPanel testerRoot = new JPanel(new BorderLayout());
        testerRoot.add(modeTabs, BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), testerRoot);
        splitPane.setDividerLocation(300);

        // ========== HEADER: filters ==========
        JPanel headerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        headerPanel.add(new JLabel("Actor:"));
        actorFilter.setFont(AcasTheme.UI_PLAIN);
        actorFilter.addActionListener(e -> refresh());
        headerPanel.add(actorFilter);

        groupByActorFilter.setToolTipText("Group captured requests under each actor instead of one mixed list.");
        groupByActorFilter.addActionListener(e -> refresh());
        headerPanel.add(groupByActorFilter);

        onlyHitsFilter.setToolTipText("Show only endpoints where a swap or anonymous test got in (Label is BROKEN / BYPASS / SUSPICIOUS).");
        onlyHitsFilter.addActionListener(e -> applyFilter());
        headerPanel.add(onlyHitsFilter);

        JButton deleteSelectedBtn = new JButton("Delete Selected");
        AcasTheme.styleButton(deleteSelectedBtn);
        deleteSelectedBtn.setToolTipText("Delete selected captured requests (Del)");
        deleteSelectedBtn.addActionListener(e -> deleteSelectedRequests());
        headerPanel.add(deleteSelectedBtn);

        JButton clearAllBtn = new JButton("Clear All");
        AcasTheme.styleButton(clearAllBtn);
        clearAllBtn.addActionListener(e -> clearAllRequests());
        headerPanel.add(clearAllBtn);

        JButton exportHermes = new JButton("🚀 Send to Hermes (Discord)");
        exportHermes.setFont(AcasTheme.UI_BOLD);
        exportHermes.setBackground(new Color(88, 101, 242));
        exportHermes.setForeground(Color.WHITE);
        exportHermes.setToolTipText("Export captured requests to Hermes over Discord webhook.");
        exportHermes.addActionListener(e -> new HermesExportDialog(this, api, store, severityClassifier, notifier, true).setVisible(true));
        headerPanel.add(exportHermes);

        JButton exportOptions = new JButton("More Export Options…");
        AcasTheme.styleButton(exportOptions);
        exportOptions.setToolTipText("Choose destination, local file export, encryption, or retry test.");
        exportOptions.addActionListener(e -> new HermesExportDialog(this, api, store, severityClassifier, notifier).setVisible(true));
        headerPanel.add(exportOptions);

        add(headerPanel, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);

        // ========== HUNT BUTTON BAR ==========
        JPanel controls = new JPanel(new BorderLayout());
        JPanel huntBar = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        huntBtn = new JButton("↻  Re-run Swap + Anonymous");
        AcasTheme.stylePrimaryButton(huntBtn, new Color(239, 99, 52));
        huntBtn.setToolTipText("Swap + anonymous run automatically on capture. Use this to re-test the selected request(s) after updating a session.");
        huntBtn.addActionListener(e -> triggerHunt());
        huntBar.add(huntBtn);
        controls.add(huntBar, BorderLayout.CENTER);
        add(controls, BorderLayout.SOUTH);

        // ========== KEYBOARD SHORTCUTS ==========
        setupShortcuts();

        // ========== DATA BINDING ==========
        store.addChangeListener(this::refresh);
        
        // Auto-refresh timer to pick up new captures / probe results
        refreshTimer=new Timer(1000,e->refresh());

        refresh();
    }

    // ======================== RESULT FILTER ========================

    private void applyFilter() {
        // Filtering is applied while (re)building grouped rows.
        refresh();
    }

    private boolean passesHitFilter(CapturedEndpoint ep) {
        if (!onlyHitsFilter.isSelected()) return true;
        String label = ep.getClassificationLabel() != null ? ep.getClassificationLabel().toUpperCase() : "";
        return label.contains("BROKEN") || label.contains("BYPASS") || label.contains("SUSPICIOUS");
    }

    private Object[] buildRequestRow(CapturedEndpoint ep, int displayNum) {
        Object[] row = new Object[9];
        row[COL_NUM] = displayNum;
        com.acas.model.ActorProfile actor = store.getActor(ep.getActorId());
        row[COL_ACTOR] = actor != null ? actor : "[Unknown]";
        row[COL_METHOD] = ep.getMethod();
        row[COL_URL] = ep.getNormalizedPath();
        row[COL_LABEL] = "PRIVATE_SECURE".equals(ep.getClassificationLabel())
            ? "No bypass confirmed" : ep.getClassificationLabel();
        if(ep.getAutomaticProbeNote()!=null)row[COL_LABEL]="Replay skipped: "+ep.getAutomaticProbeNote();
        List<CapturedEndpoint.ProbeResult> probes = ep.getProbes();
        row[COL_BASELINE] = getProbeStatus(probes, 0);
        row[COL_ANON] = getProbeStatus(probes, 1);
        row[COL_SWAP] = getProbeStatus(probes, 2);
        row[COL_PRIORITY] = ep.getPriorityScore();
        return row;
    }

    // ======================== RE-RUN BUTTON ========================

    private void updateHuntButtonText() {
        int count = table.getSelectedRowCount();
        if (count > 1) {
            huntBtn.setText("↻ Re-run Swap + Anonymous (" + count + ")");
        } else {
            huntBtn.setText("↻ Re-run Swap + Anonymous");
        }
    }

    // ======================== TABLE DATA ========================

    private void refresh() {
        if(!refreshPending.compareAndSet(false,true))return;
        SwingUtilities.invokeLater(()->{
            refreshPending.set(false);
            refreshNow();
        });
    }
    private void refreshNow() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refresh);
            return;
        }
        
        // Preserve selection
        int[] selectedViewRows = table.getSelectedRows();
        Set<Integer> selectedModelRows = new HashSet<>();
        for (int vr : selectedViewRows) {
            if (vr >= 0) selectedModelRows.add(table.convertRowIndexToModel(vr));
        }

        // Update actor filter dropdown items
        String selectedActor = (String) actorFilter.getSelectedItem();
        List<com.acas.model.ActorProfile> allActors = store.getAllActors();
        java.util.List<String> actorNames = new ArrayList<>();
        actorNames.add("All Actors");
        for (com.acas.model.ActorProfile a : allActors) {
            actorNames.add(a.getName());
        }
        boolean itemsChanged = actorFilter.getItemCount() != actorNames.size();
        if (!itemsChanged) {
            for (int i = 0; i < actorNames.size(); i++) {
                if (!actorNames.get(i).equals(actorFilter.getItemAt(i))) { itemsChanged = true; break; }
            }
        }
        if (itemsChanged) {
            java.awt.event.ActionListener[] listeners = actorFilter.getActionListeners();
            for (java.awt.event.ActionListener l : listeners) actorFilter.removeActionListener(l);
            actorFilter.removeAllItems();
            for (String name : actorNames) actorFilter.addItem(name);
            if (selectedActor != null && actorNames.contains(selectedActor)) {
                actorFilter.setSelectedItem(selectedActor);
            } else {
                actorFilter.setSelectedIndex(0);
            }
            for (java.awt.event.ActionListener l : listeners) actorFilter.addActionListener(l);
            selectedActor = (String) actorFilter.getSelectedItem();
        }

        List<CapturedEndpoint> all = store.getCapturedEndpoints();
        List<CapturedEndpoint> endpoints = new ArrayList<>();
        for (CapturedEndpoint ep : all) {
            if (!passesHitFilter(ep)) continue;
            if (selectedActor != null && !selectedActor.equals("All Actors")) {
                com.acas.model.ActorProfile epActor = store.getActor(ep.getActorId());
                String epActorName = epActor != null ? epActor.getName() : "Unknown";
                if (!selectedActor.equalsIgnoreCase(epActorName)) continue;
            }
            endpoints.add(ep);
        }

        if (!groupByActorFilter.isSelected()) {
            int n = 1;
            for (CapturedEndpoint ep : endpoints) {
                tableModel.addRow(buildRequestRow(ep, n++));
                rowEndpoints.add(ep);
                rowGroupKeys.add(null);
            }
        } else {
            // Group endpoints by owning actor, preserving first-seen actor order.
            java.util.LinkedHashMap<String, List<CapturedEndpoint>> groups = new java.util.LinkedHashMap<>();
            for (CapturedEndpoint ep : endpoints) {
                String key = ep.getActorId() != null ? ep.getActorId() : "__unknown__";
                groups.computeIfAbsent(key, k -> new ArrayList<>()).add(ep);
            }
            for (java.util.Map.Entry<String, List<CapturedEndpoint>> entry : groups.entrySet()) {
                String actorId = entry.getKey();
                List<CapturedEndpoint> group = entry.getValue();
                com.acas.model.ActorProfile actor = store.getActor(actorId);
                String actorName = actor != null ? actor.getName() : "Unknown / Anonymous";
                boolean collapsed = collapsedActors.contains(actorId);

                Object[] header = new Object[9];
                header[COL_NUM] = collapsed ? "▶" : "▼";
                header[COL_ACTOR] = actorName;
                header[COL_METHOD] = "";
                header[COL_URL] = group.size() + " request" + (group.size() == 1 ? "" : "s");
                header[COL_LABEL] = "";
                header[COL_BASELINE] = "";
                header[COL_ANON] = "";
                header[COL_SWAP] = "";
                tableModel.addRow(header);
                rowEndpoints.add(null);
                rowGroupKeys.add(actorId);

                if (!collapsed) {
                    int n = 1;
                    for (CapturedEndpoint ep : group) {
                        tableModel.addRow(buildRequestRow(ep, n++));
                        rowEndpoints.add(ep);
                        rowGroupKeys.add(null);
                    }
                }
            }
        }

        // Restore selection
        for (int modelRow : selectedModelRows) {
            if (modelRow < tableModel.getRowCount()) {
                int viewRow = table.convertRowIndexToView(modelRow);
                if (viewRow >= 0) {
                    table.addRowSelectionInterval(viewRow, viewRow);
                }
            }
        }

        updateHuntButtonText();
    }

    private void updateEditors() {
        int row = table.getSelectedRow();
        if (row < 0) return;
        int modelRow = table.convertRowIndexToModel(row);
        if (modelRow < 0 || modelRow >= rowEndpoints.size()) return;
        CapturedEndpoint ep = rowEndpoints.get(modelRow);
        if (ep == null) return; // group header row
        burp.api.montoya.http.message.requests.HttpRequest orig = ep.getOriginalRequest();
        if (orig == null) return;

        List<CapturedEndpoint.ProbeResult> probes = ep.getProbes();

        // If swap or anonymous probes are pending/missing, trigger them automatically on selection
        boolean hasAnon = probes.stream().anyMatch(p -> "anonymous".equalsIgnoreCase(p.actorName));
        long swapCount = probes.stream().filter(p -> !p.isBaseline && !"anonymous".equalsIgnoreCase(p.actorName)).count();
        long otherActors = store.getAllActors().stream().filter(a -> !a.getId().equals(ep.getActorId())).count();
        if ((!hasAnon || (otherActors > 0 && swapCount == 0)) && ep.getOriginalRequest() != null) {
            probeEngine.rerunProbes(ep, () -> SwingUtilities.invokeLater(() -> {
                lastViewerStateKey = "";
                refresh();
                updateEditors();
            }));
        }

        // Avoid rebuilding (and losing the active tab) when nothing changed —
        // the 1s refresh timer calls refresh()/updateEditors() repeatedly.
        String stateKey = buildViewerStateKey(ep, probes);
        if (stateKey.equals(lastViewerStateKey)) return;
        lastViewerStateKey = stateKey;

        int selectedTab = modeTabs.getSelectedIndex();
        modeTabs.removeAll();

        for (int i = 0; i < probes.size(); i++) {
            CapturedEndpoint.ProbeResult pr = probes.get(i);
            burp.api.montoya.ui.editor.HttpRequestEditor reqEd = requestEditorAt(i);
            burp.api.montoya.ui.editor.HttpResponseEditor resEd = responseEditorAt(i);

            if (pr.request != null) {
                reqEd.setRequest(burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                    orig.httpService(), burp.api.montoya.core.ByteArray.byteArray(pr.request)));
            } else {
                reqEd.setRequest(generateDefaultRequest(orig, i, ep.getActorId()));
            }
            resEd.setResponse(pr.response != null
                ? burp.api.montoya.http.message.responses.HttpResponse.httpResponse(burp.api.montoya.core.ByteArray.byteArray(pr.response))
                : null);

            JSplitPane hSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqEd.uiComponent(), resEd.uiComponent());
            hSplit.setDividerLocation(450);

            final int probeIndex = i;
            JPopupMenu viewerMenu = new JPopupMenu();
            JMenuItem sendRepeater = new JMenuItem("Send This Variant to Repeater");
            JMenuItem sendIntruder = new JMenuItem("Send This Variant to Intruder");
            sendRepeater.addActionListener(e -> sendProbeToRepeater(ep, probeIndex));
            sendIntruder.addActionListener(e -> sendProbeToIntruder(ep, probeIndex));
            viewerMenu.add(sendRepeater);
            viewerMenu.add(sendIntruder);
            if (reqEd.uiComponent() instanceof JComponent) {
                ((JComponent) reqEd.uiComponent()).setComponentPopupMenu(viewerMenu);
            }

            modeTabs.addTab(tabTitleFor(pr, i), hSplit);
        }

        if (selectedTab >= 0 && selectedTab < modeTabs.getTabCount()) {
            modeTabs.setSelectedIndex(selectedTab);
        }
    }

    private burp.api.montoya.ui.editor.HttpRequestEditor requestEditorAt(int i) {
        while (requestEditorPool.size() <= i) requestEditorPool.add(api.userInterface().createHttpRequestEditor());
        return requestEditorPool.get(i);
    }

    private burp.api.montoya.ui.editor.HttpResponseEditor responseEditorAt(int i) {
        while (responseEditorPool.size() <= i) responseEditorPool.add(api.userInterface().createHttpResponseEditor());
        return responseEditorPool.get(i);
    }

    private String tabTitleFor(CapturedEndpoint.ProbeResult pr, int i) {
        String name = pr.actorName != null ? pr.actorName : ("Probe " + i);
        if (pr.isBaseline) return "Baseline (" + name + ")";
        if ("anonymous".equalsIgnoreCase(name)) return "Anonymous";
        return "Swap → " + name;
    }

    private String buildViewerStateKey(CapturedEndpoint ep, List<CapturedEndpoint.ProbeResult> probes) {
        StringBuilder sb = new StringBuilder();
        sb.append(ep.getId() != null ? ep.getId() : ep.getNormalizedPath());
        sb.append('#').append(probes.size());
        for (CapturedEndpoint.ProbeResult pr : probes) {
            sb.append('|').append(pr.actorName).append(':').append(pr.statusCode).append(':').append(pr.responseLength);
            sb.append('/').append(java.util.Arrays.hashCode(pr.response != null ? pr.response : new byte[0]));
        }
        return sb.toString();
    }

    private burp.api.montoya.http.message.requests.HttpRequest generateDefaultRequest(burp.api.montoya.http.message.requests.HttpRequest orig, int type, String ownerId) {
        if (type == 0) return probeEngine.buildBaselineRequest(orig, ownerId);
        if (type == 1) return probeEngine.buildAnonymousRequest(orig);
        return probeEngine.buildSwapRequest(orig, ownerId);
    }

    // ======================== HUNT TRIGGERING ========================

    private void triggerHunt() {
        int[] selectedRows = table.getSelectedRows();
        if (selectedRows.length == 0) {
            JOptionPane.showMessageDialog(this, "Select captured request(s) to re-run swap + anonymous.");
            return;
        }

        List<CapturedEndpoint> selected = new ArrayList<>();
        for (int viewRow : selectedRows) {
            CapturedEndpoint ep = getEndpointAtViewRow(viewRow); // null for header rows
            if (ep != null) selected.add(ep);
        }
        if (selected.isEmpty()) return;

        for (CapturedEndpoint ep : selected) {
            reHuntEndpoint(ep);
        }
    }

    private void reHuntEndpoint(CapturedEndpoint ep) {
        if (ep == null) return;
        probeEngine.rerunProbes(ep, () -> SwingUtilities.invokeLater(() -> {
            lastViewerStateKey = "";
            refresh();
            updateEditors();
        }));
    }

    // ======================== CONTEXT MENUS ========================

    private void showContextMenu(MouseEvent e) {
        int row = table.rowAtPoint(e.getPoint());
        if (row < 0) {
            JPopupMenu popup = new JPopupMenu();
            JMenuItem clearAllItem = new JMenuItem("Clear All Requests");
            clearAllItem.addActionListener(al -> clearAllRequests());
            popup.add(clearAllItem);
            popup.show(table, e.getX(), e.getY());
            return;
        }
        
        // Only select if not already part of multi-select
        if (!table.isRowSelected(row)) {
            table.setRowSelectionInterval(row, row);
        }

        JPopupMenu popup = new JPopupMenu();
        
        int selectedCount = table.getSelectedRowCount();
        
        if (selectedCount > 1) {
            JMenuItem huntMulti = new JMenuItem("↻ Re-run Swap + Anonymous (" + selectedCount + ") — Ctrl+H");
            huntMulti.setFont(new Font("SansSerif", Font.BOLD, 12));
            huntMulti.addActionListener(al -> triggerHunt());
            popup.add(huntMulti);
            popup.addSeparator();
        }

        // Single-row actions
        JMenuItem reHuntItem = new JMenuItem("↻ Re-run Swap + Anonymous");
        JMenuItem reHuntFreshItem = new JMenuItem("↻ Re-run with Fresh Session");
        JMenuItem viewFindingsItem = new JMenuItem("📋 View Hunt Findings");
        JMenuItem resourceItem = new JMenuItem("Confirm Resource Ownership / Operation Safety...");
        JMenuItem examineItem = new JMenuItem("Examine Detail");
        JMenuItem repeaterItem = new JMenuItem("Send to Repeater (Ctrl+R)");
        JMenuItem intruderItem = new JMenuItem("Send to Intruder (Ctrl+I)");
        JMenuItem deleteItem = new JMenuItem("Delete Item");
        JMenuItem clearAllItem = new JMenuItem("Clear All Requests");

        popup.add(reHuntItem);
        popup.add(reHuntFreshItem);
        popup.add(viewFindingsItem);
        popup.add(resourceItem);
        popup.addSeparator();
        popup.add(examineItem);
        popup.add(repeaterItem);
        popup.add(intruderItem);
        popup.addSeparator();
        popup.add(deleteItem);
        popup.add(clearAllItem);

        // Actions
        reHuntItem.addActionListener(al -> {
            CapturedEndpoint ep = getEndpointAtViewRow(row);
            if (ep != null) reHuntEndpoint(ep);
        });

        reHuntFreshItem.addActionListener(al -> {
            CapturedEndpoint ep = getEndpointAtViewRow(row);
            if (ep != null) {
                JOptionPane.showMessageDialog(this, 
                    "Please update the actor's session in the Actors tab first,\nthen re-hunt this endpoint.",
                    "ACAS — Fresh Session", JOptionPane.INFORMATION_MESSAGE);
                reHuntEndpoint(ep);
            }
        });

        viewFindingsItem.addActionListener(al -> {
            Container p = getParent();
            while (p != null && !(p instanceof AcasPanel)) p = p.getParent();
            if (p instanceof AcasPanel) {
                ((AcasPanel) p).switchToResultMatrix();
            }
        });

        resourceItem.addActionListener(al -> {
            CapturedEndpoint ep = getEndpointAtViewRow(row);
            if (ep == null) return;
            EndpointResourceDialog dialog = new EndpointResourceDialog(
                SwingUtilities.getWindowAncestor(this), store, ep);
            dialog.setVisible(true);
            if (dialog.saved()) refresh();
        });

        repeaterItem.addActionListener(al -> sendSelectedToRepeater());
        intruderItem.addActionListener(al -> sendSelectedToIntruder());
        
        deleteItem.addActionListener(al -> {
            CapturedEndpoint ep = getEndpointAtViewRow(row);
            if (ep != null) {
                store.removeEndpoint(ep);
                refresh();
            }
        });

        clearAllItem.addActionListener(al -> clearAllRequests());

        popup.show(table, e.getX(), e.getY());
    }

    // ======================== KEYBOARD SHORTCUTS ========================

    private void setupShortcuts() {
        InputMap im = table.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        ActionMap am = table.getActionMap();
        
        im.put(KeyStroke.getKeyStroke("control R"), "sendToRepeater");
        am.put("sendToRepeater", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { sendSelectedToRepeater(); }
        });

        im.put(KeyStroke.getKeyStroke("control I"), "sendToIntruder");
        am.put("sendToIntruder", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { sendSelectedToIntruder(); }
        });

        // Ctrl+H — Send to Hunt Queue
        im.put(KeyStroke.getKeyStroke("control H"), "huntSelected");
        am.put("huntSelected", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { triggerHunt(); }
        });

        // Delete / Backspace — Delete selected items
        im.put(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_DELETE, 0), "deleteSelected");
        am.put("deleteSelected", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { deleteSelectedRequests(); }
        });
    }

    private void deleteSelectedRequests() {
        int[] rows = table.getSelectedRows();
        if (rows.length == 0) {
            JOptionPane.showMessageDialog(this, "Select one or more requests to delete.", "Delete Requests", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int confirm = JOptionPane.showConfirmDialog(
            this,
            "Delete " + rows.length + " selected request(s)?",
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        );
        if (confirm != JOptionPane.YES_OPTION) return;

        List<CapturedEndpoint> toRemove = new ArrayList<>();
        for (int r : rows) {
            CapturedEndpoint ep = getEndpointAtViewRow(r);
            if (ep != null) toRemove.add(ep);
        }
        for (CapturedEndpoint ep : toRemove) {
            store.removeEndpoint(ep);
        }
        refresh();
    }

    // ======================== ACTIONS ========================

    private void sendSelectedToRepeater() {
        int row = table.getSelectedRow();
        if (row >= 0) {
            CapturedEndpoint ep = getEndpointAtViewRow(row);
            if (ep != null && ep.getOriginalRequest() != null) {
                burp.api.montoya.http.message.requests.HttpRequest req =
                    HttpUtils.ensureRequestService(ep.getOriginalRequest(), ep.getOriginalUrl());
                String title = HttpUtils.buildRepeaterTabName("ACAS History", req, ep.getOriginalUrl(), null);
                api.repeater().sendToRepeater(req, title);
            }
        }
    }

    private void sendSelectedToIntruder() {
        int row = table.getSelectedRow();
        if (row >= 0) {
            CapturedEndpoint ep = getEndpointAtViewRow(row);
            if (ep != null && ep.getOriginalRequest() != null) {
                api.intruder().sendToIntruder(HttpUtils.ensureRequestService(ep.getOriginalRequest(), ep.getOriginalUrl()));
            }
        }
    }

    private void sendProbeToRepeater(CapturedEndpoint ep, int index) {
        if (ep == null || ep.getOriginalRequest() == null) return;
        List<CapturedEndpoint.ProbeResult> probes = ep.getProbes();
        burp.api.montoya.http.message.requests.HttpRequest req;
        String modeName;

        if (index >= 0 && index < probes.size() && probes.get(index) != null && probes.get(index).request != null) {
            CapturedEndpoint.ProbeResult pr = probes.get(index);
            req = burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                ep.getOriginalRequest().httpService(),
                burp.api.montoya.core.ByteArray.byteArray(pr.request)
            );
            modeName = pr.actorName != null ? pr.actorName : ("Probe " + index);
        } else {
            req = generateDefaultRequest(ep.getOriginalRequest(), index, ep.getActorId());
            modeName = "Probe " + index;
        }

        req = HttpUtils.ensureRequestService(req, ep.getOriginalUrl());
        String title = HttpUtils.buildRepeaterTabName("ACAS", req, ep.getOriginalUrl(), modeName);
        api.repeater().sendToRepeater(req, title);
    }

    private void sendProbeToIntruder(CapturedEndpoint ep, int index) {
        if (ep == null || ep.getOriginalRequest() == null) return;
        List<CapturedEndpoint.ProbeResult> probes = ep.getProbes();
        burp.api.montoya.http.message.requests.HttpRequest req;

        if (index >= 0 && index < probes.size() && probes.get(index) != null && probes.get(index).request != null) {
            CapturedEndpoint.ProbeResult pr = probes.get(index);
            req = burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                ep.getOriginalRequest().httpService(),
                burp.api.montoya.core.ByteArray.byteArray(pr.request)
            );
        } else {
            req = generateDefaultRequest(ep.getOriginalRequest(), index, ep.getActorId());
        }

        req = HttpUtils.ensureRequestService(req, ep.getOriginalUrl());
        api.intruder().sendToIntruder(req);
    }

    private CapturedEndpoint getEndpointAtViewRow(int viewRow) {
        if (viewRow < 0) return null;
        int modelRow = table.convertRowIndexToModel(viewRow);
        return (modelRow >= 0 && modelRow < rowEndpoints.size()) ? rowEndpoints.get(modelRow) : null;
    }

    private void clearAllRequests() {
        int total = store.getCapturedEndpoints().size();
        if (total == 0) {
            JOptionPane.showMessageDialog(this, "No captured requests to clear.", "ACAS — Captured History", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int choice = JOptionPane.showConfirmDialog(
            this,
            "Clear all " + total + " captured request(s) from this tab?",
            "ACAS — Clear Captured Requests",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.WARNING_MESSAGE
        );
        if (choice != JOptionPane.OK_OPTION) return;

        if (huntManager.getCurrentState() == HuntManager.State.RUNNING || huntManager.getCurrentState() == HuntManager.State.PAUSED) {
            JOptionPane.showMessageDialog(this,
                "Hunt is active. Stop hunt before clearing all captured requests.",
                "ACAS — Hunt Running",
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        int removedFromQueue = huntManager.clearQueue();
        store.clearCapturedEndpoints();
        refresh();
        JOptionPane.showMessageDialog(this,
            "Cleared all captured requests." + (removedFromQueue > 0 ? " Removed " + removedFromQueue + " queued item(s) from Hunt Hub." : ""),
            "ACAS — Cleared",
            JOptionPane.INFORMATION_MESSAGE);
    }

    // ======================== HELPERS ========================

    static String getProbeStatus(List<CapturedEndpoint.ProbeResult> probes, int type) {
        java.util.Map<String,CapturedEndpoint.ProbeResult> latest=new java.util.LinkedHashMap<>();
        int unresolved=0;
        for(var probe:probes) {
            String key=probe.identityType==null || probe.identityType==CapturedEndpoint.ProbeIdentity.UNRESOLVED?"unresolved:"+(unresolved++):probe.identityType+":"+probe.actorId;
            latest.put(key,probe);
        }
        List<CapturedEndpoint.ProbeResult> matches = latest.values().stream().filter(p -> {
            if (type == 0) return p.isBaseline;
            boolean anonymous = p.identityType==CapturedEndpoint.ProbeIdentity.ANONYMOUS;
            return !p.isBaseline && (type == 1 ? anonymous : !anonymous);
        }).toList();
        if (matches.isEmpty()) return "Pending";
        return matches.stream().map(p -> {
            String status = p.statusCode <= 0 || p.response == null ? "No response" : Integer.toString(p.statusCode);
            if (p.response != null && p.statusCode > 0 && type != 0) {
                status += switch (p.verdict == null ? "" : p.verdict) {
                    case "BROKEN" -> " (bypass evidence)";
                    case "ACCESSIBLE" -> " (no bypass confirmed)";
                    case "BLOCKED" -> " (blocked)";
                    default -> " (review)";
                };
            }
            return matches.size() > 1 ? p.actorName + ": " + status : status;
        }).collect(java.util.stream.Collectors.joining("; "));
    }

    // Actor names follow the native text colour; only the identity swatch is coloured.
    private static class ActorColorRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setIcon(null);
            setToolTipText(value == null ? null : value.toString());
            if (value instanceof com.acas.model.ActorProfile actor) {
                setText(actor.getName());
                setToolTipText(actor.getName());
                setIconTextGap(6);
                Color color = ActorsPanel.safeColor(actor.getColor(), table.getForeground());
                setIcon(new Icon() {
                    public int getIconWidth() { return 12; }
                    public int getIconHeight() { return 12; }
                    public void paintIcon(Component c, Graphics g, int x, int y) {
                        Graphics2D graphics = (Graphics2D) g.create();
                        try {
                            graphics.setColor(color);
                            graphics.fillRoundRect(x + 1, y + 1, 10, 10, 3, 3);
                            graphics.setColor(table.getForeground());
                            graphics.drawRoundRect(x + 1, y + 1, 10, 10, 3, 3);
                        } finally {
                            graphics.dispose();
                        }
                    }
                });
            }
            return this;
        }
    }
}
