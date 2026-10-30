package com.acas.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.acas.model.CapturedEndpoint;
import com.acas.model.ActorProfile;
import com.acas.store.ActorStore;
import com.acas.engine.ProbeEngine;
import com.acas.engine.ClassifierEngine;
import com.acas.notification.NotificationService;
import com.acas.util.ReportGenerator;
import com.acas.util.HttpUtils;
import java.awt.datatransfer.StringSelection;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class ProbeClassificationPanel extends JPanel {
    private final MontoyaApi api;
    private final ActorStore store;
    private final ProbeEngine probeEngine;
    private final ClassifierEngine classifier;
    private final NotificationService notifier;
    
    private final JTable findingsTable;
    private final DefaultTableModel findingsModel;
    
    private final JButton syncBtn;
    private final JProgressBar progressBar;
    
    // Right Side Detail Components
    private final JTable summaryTable;
    private final DefaultTableModel summaryModel;
    private final JTabbedPane probeTabs;
    private final List<ProbeTabComponents> probeTabList = new ArrayList<>();

    private static class ProbeTabComponents {
        HttpRequestEditor requestEditor;
        HttpResponseEditor responseEditor;
        JPanel panel;
    }

    public ProbeClassificationPanel(MontoyaApi api, ActorStore store, ProbeEngine probeEngine, ClassifierEngine classifier, NotificationService notifier) {
        this.api = api;
        this.store = store;
        this.probeEngine = probeEngine;
        this.classifier = classifier;
        this.notifier = notifier;
        setLayout(new BorderLayout());

        // --- LEFT SIDE: Discovery List ---
        // Hidden cols 4,5 for lookup
        String[] leftCols = {"Name", "Method", "Priority", "Classification", "HiddenMethod", "HiddenPath"};
        findingsModel = new DefaultTableModel(leftCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        findingsTable = new JTable(findingsModel);
        findingsTable.setRowHeight(22);
        findingsTable.setShowGrid(false);
        findingsTable.setIntercellSpacing(new Dimension(0, 0));
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        findingsTable.setFont(new Font("SansSerif", Font.PLAIN, 12));
        
        // Sorting & Filtering
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(findingsModel);
        findingsTable.setRowSorter(sorter);
        
        // Custom Burp Native Renderer
        BurpNativeRenderer renderer = new BurpNativeRenderer();
        findingsTable.getColumnModel().getColumn(2).setCellRenderer(renderer);
        findingsTable.getColumnModel().getColumn(3).setCellRenderer(renderer);
        
        // Column Widths
        findingsTable.getColumnModel().getColumn(0).setPreferredWidth(260);
        findingsTable.getColumnModel().getColumn(1).setMaxWidth(60);
        findingsTable.getColumnModel().getColumn(2).setMaxWidth(60);
        findingsTable.getColumnModel().getColumn(3).setPreferredWidth(120);

        findingsTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    inspectSelectedFinding();
                }
            }
        });
        
        // Hide logic columns
        findingsTable.removeColumn(findingsTable.getColumnModel().getColumn(5)); // HiddenPath
        findingsTable.removeColumn(findingsTable.getColumnModel().getColumn(4)); // HiddenMethod

        JScrollPane leftScroll = new JScrollPane(findingsTable);
        leftScroll.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, Color.DARK_GRAY));

        // --- RIGHT SIDE: Investigation Console ---
        JPanel rightPanel = new JPanel(new BorderLayout());
        
        // Top: Summary Matrix
        String[] summaryCols = {"Actor", "Status", "Length", "Similarity", "Leaked Fields", "Verdict"};
        summaryModel = new DefaultTableModel(summaryCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        summaryTable = new JTable(summaryModel);
        summaryTable.setRowHeight(24);
        summaryTable.setFont(new Font("Monospaced", Font.PLAIN, 12));
        summaryTable.setShowGrid(false);
        
        JPanel summaryHeader = new JPanel(new BorderLayout());
        summaryHeader.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, Color.DARK_GRAY), "Probe Matrix Summary"));
        summaryHeader.add(new JScrollPane(summaryTable), BorderLayout.CENTER);
        summaryHeader.setPreferredSize(new Dimension(0, 120));

        // Bottom: Probe Tabs (Repeater-like)
        probeTabs = new JTabbedPane();
        probeTabs.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, summaryHeader, probeTabs);
        rightSplit.setDividerSize(2);
        rightSplit.setDividerLocation(130);
        rightSplit.setBorder(null);

        rightPanel.add(rightSplit, BorderLayout.CENTER);

        // --- MAIN LAYOUT: Split Pane ---
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftScroll, rightPanel);
        mainSplit.setDividerLocation(450);
        mainSplit.setDividerSize(3);
        mainSplit.setBorder(null);

        add(mainSplit, BorderLayout.CENTER);

        // --- EVENTS ---
        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) updateDetail();
        });

        // Search Bar (Optional Header)
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        toolbar.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        JTextField searchField = new JTextField(25);
        searchField.putClientProperty("JTextField.placeholderText", "Filter findings...");
        toolbar.add(new JLabel(" 🔍 "));
        toolbar.add(searchField);
        toolbar.add(Box.createHorizontalStrut(10));

        JButton clearBtn = new JButton("🗑️ CLEAR ALL");
        clearBtn.setFont(new Font("SansSerif", Font.PLAIN, 11));
        clearBtn.addActionListener(e -> {
            int choice = JOptionPane.showConfirmDialog(this, 
                "Are you sure you want to clear ALL captured findings?\nThis action cannot be undone.",
                "ACAS - Reset Discovery", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice == JOptionPane.YES_OPTION) {
                store.clearCapturedEndpoints();
                api.logging().logToOutput("ACAS: Probe Classification results cleared.");
            }
        });
        toolbar.add(clearBtn);
        toolbar.add(Box.createHorizontalStrut(10));

        syncBtn = new JButton("🔄 SYNC MATRIX");
        syncBtn.setBackground(new Color(34, 197, 94));
        syncBtn.setForeground(Color.WHITE);
        syncBtn.setFont(new Font("SansSerif", Font.BOLD, 11));
        syncBtn.addActionListener(e -> runGlobalSync());
        toolbar.add(syncBtn);

        progressBar = new JProgressBar(0, 100);
        progressBar.setVisible(false);
        progressBar.setPreferredSize(new Dimension(150, 20));
        toolbar.add(Box.createHorizontalGlue());
        toolbar.add(progressBar);

        add(toolbar, BorderLayout.NORTH);

        // Context Menu
        setupContextMenus();

        store.addChangeListener(this::refresh);
        refresh();
    }

    public void refresh() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refresh);
            return;
        }

        int selectedRow = findingsTable.getSelectedRow();
        findingsModel.setRowCount(0);
        List<CapturedEndpoint> endpoints = store.getCapturedEndpoints();

        // Sort by Priority Score descending by default
        endpoints.sort((e1, e2) -> Integer.compare(e2.getPriorityScore(), e1.getPriorityScore()));

        for (CapturedEndpoint ep : endpoints) {
            findingsModel.addRow(new Object[]{
                ep.getNormalizedPath(),
                ep.getMethod(),
                ep.getPriorityScore(),
                ep.getClassificationLabel(),
                ep.getMethod(),
                ep.getNormalizedPath()
            });
        }

        if (selectedRow != -1 && selectedRow < findingsTable.getRowCount()) {
            findingsTable.setRowSelectionInterval(selectedRow, selectedRow);
        }
    }

    private void runGlobalSync() {
        List<String> selectedIds = new ArrayList<>();
        int[] selectedRows = findingsTable.getSelectedRows();
        for (int row : selectedRows) {
            CapturedEndpoint ep = getEndpointAtRow(row);
            if (ep != null) selectedIds.add(ep.getId());
        }

        Window parent = SwingUtilities.getWindowAncestor(this);
        SyncMatrixDialog dialog = new SyncMatrixDialog(parent, api, store, probeEngine, classifier, selectedIds);
        dialog.setVisible(true);
    }

    private CapturedEndpoint getEndpointAtRow(int viewRow) {
        if (viewRow == -1) return null;
        int modelRow = findingsTable.convertRowIndexToModel(viewRow);
        String method = (String) findingsModel.getValueAt(modelRow, 4);
        String path = (String) findingsModel.getValueAt(modelRow, 5);

        return store.getCapturedEndpoints().stream()
            .filter(e -> e.getMethod().equals(method) && e.getNormalizedPath().equals(path))
            .findFirst().orElse(null);
    }

    private void updateDetail() {
        int row = findingsTable.getSelectedRow();
        if (row == -1) {
            summaryModel.setRowCount(0);
            probeTabs.removeAll();
            probeTabList.clear();
            return;
        }

        int modelRow = findingsTable.convertRowIndexToModel(row);
        String method = (String) findingsModel.getValueAt(modelRow, 4);
        String path = (String) findingsModel.getValueAt(modelRow, 5);

        CapturedEndpoint ep = store.getCapturedEndpoints().stream()
            .filter(e -> e.getMethod().equals(method) && e.getNormalizedPath().equals(path))
            .findFirst().orElse(null);

        if (ep == null) return;

        // 1. Update Summary Table
        summaryModel.setRowCount(0);
        List<CapturedEndpoint.ProbeResult> sortedResults = getSortedResults(ep);
        CapturedEndpoint.ProbeResult p1 = sortedResults.size() > 0 ? sortedResults.get(0) : null;
        for (CapturedEndpoint.ProbeResult pr : sortedResults) {
            String simStr = "---";
            if (p1 != null && pr.response != null && p1.response != null) {
                double sim = com.acas.util.HttpUtils.calculateSimilarity(p1.responseLength, pr.responseLength);
                simStr = String.format("%.1f%%", sim * 100);
            }
            summaryModel.addRow(new Object[]{pr.actorName, pr.statusCode, pr.responseLength, simStr, pr.verdict != null ? pr.verdict : "BLOCKED"});
        }

        // 2. Update Detail Tabs
        probeTabs.removeAll();
        probeTabList.clear();
        for (CapturedEndpoint.ProbeResult pr : sortedResults) {
            ProbeTabComponents components = new ProbeTabComponents();
            components.requestEditor = api.userInterface().createHttpRequestEditor();
            components.responseEditor = api.userInterface().createHttpResponseEditor();

            if (pr.request != null) {
                burp.api.montoya.http.message.requests.HttpRequest req =
                    burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                        burp.api.montoya.core.ByteArray.byteArray(pr.request));
                req = HttpUtils.ensureRequestService(req, ep.getOriginalUrl());
                components.requestEditor.setRequest(req);
            }
            if (pr.response != null) {
                components.responseEditor.setResponse(burp.api.montoya.http.message.responses.HttpResponse.httpResponse(burp.api.montoya.core.ByteArray.byteArray(pr.response)));
            }

            JSplitPane hSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, components.requestEditor.uiComponent(), components.responseEditor.uiComponent());
            hSplit.setDividerLocation(400);
            hSplit.setBorder(null);

            components.panel = new JPanel(new BorderLayout());
            components.panel.add(hSplit, BorderLayout.CENTER);

            probeTabs.addTab(pr.actorName, components.panel);
            probeTabList.add(components);
        }

        probeTabs.setComponentPopupMenu(buildProbeTabsPopup());
    }

    private JPopupMenu buildProbeTabsPopup() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem repeater = new JMenuItem("Send Selected Probe Tab to Repeater");
        JMenuItem intruder = new JMenuItem("Send Selected Probe Tab to Intruder");
        repeater.addActionListener(e -> sendSelectedProbeTabToRepeater());
        intruder.addActionListener(e -> sendSelectedProbeTabToIntruder());
        menu.add(repeater);
        menu.add(intruder);
        return menu;
    }

    private void sendSelectedProbeTabToRepeater() {
        CapturedEndpoint ep = getSelectedEndpoint();
        int tab = probeTabs.getSelectedIndex();
        if (ep == null || tab < 0) {
            return;
        }
        List<CapturedEndpoint.ProbeResult> sorted = getSortedResults(ep);
        if (tab >= sorted.size()) {
            return;
        }
        CapturedEndpoint.ProbeResult pr = sorted.get(tab);
        if (pr.request == null) {
            return;
        }
        burp.api.montoya.http.message.requests.HttpRequest req =
            burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                burp.api.montoya.core.ByteArray.byteArray(pr.request));
        req = HttpUtils.ensureRequestService(req, ep.getOriginalUrl());
        String title = HttpUtils.buildRepeaterTabName("ACAS ProbeTab", req, ep.getOriginalUrl(), safeText(pr.actorName, "actor"));
        api.repeater().sendToRepeater(req, title);
    }

    private void sendSelectedProbeTabToIntruder() {
        CapturedEndpoint ep = getSelectedEndpoint();
        int tab = probeTabs.getSelectedIndex();
        if (ep == null || tab < 0) {
            return;
        }
        List<CapturedEndpoint.ProbeResult> sorted = getSortedResults(ep);
        if (tab >= sorted.size()) {
            return;
        }
        CapturedEndpoint.ProbeResult pr = sorted.get(tab);
        if (pr.request == null) {
            return;
        }
        burp.api.montoya.http.message.requests.HttpRequest req =
            burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                burp.api.montoya.core.ByteArray.byteArray(pr.request));
        req = HttpUtils.ensureRequestService(req, ep.getOriginalUrl());
        api.intruder().sendToIntruder(req);
    }

    private String safeText(String value, String fallback) {
        return (value == null || value.trim().isEmpty()) ? fallback : value;
    }

    private void setupContextMenus() {
        JPopupMenu popup = new JPopupMenu();
        JMenuItem huntItem = new JMenuItem("Send to Hunt Queue");
        JMenuItem repeatItem = new JMenuItem("Send to Repeater");
        
        popup.addSeparator();
        JMenuItem copyReportItem = new JMenuItem("Copy as Bug Report (Markdown)");
        JMenuItem discordItem = new JMenuItem("Send to Discord");
        JMenuItem telegramItem = new JMenuItem("Send to Telegram");
        
        popup.add(huntItem);
        popup.add(repeatItem);
        popup.addSeparator();
        popup.add(copyReportItem);
        popup.add(discordItem);
        popup.add(telegramItem);

        findingsTable.setComponentPopupMenu(popup);

        copyReportItem.addActionListener(e -> {
            CapturedEndpoint ep = getSelectedEndpoint();
            if (ep != null) {
                String report = ReportGenerator.generateMarkdown(ep, store.getAllActors());
                StringSelection selection = new StringSelection(report);
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
                api.logging().logToOutput("ACAS: Bug report copied to clipboard.");
            }
        });

        discordItem.addActionListener(e -> {
            CapturedEndpoint ep = getSelectedEndpoint();
            if (ep != null) {
                notifier.sendFinding(ep.getMethod(), ep.getOriginalUrl(), ep.getClassificationLabel(), getLeakedFields(ep));
            }
        });

        telegramItem.addActionListener(e -> {
            CapturedEndpoint ep = getSelectedEndpoint();
            if (ep != null) {
                notifier.sendFinding(ep.getMethod(), ep.getOriginalUrl(), ep.getClassificationLabel(), getLeakedFields(ep));
            }
        });

        repeatItem.addActionListener(e -> {
            int row = findingsTable.getSelectedRow();
            if (row != -1) {
                int modelRow = findingsTable.convertRowIndexToModel(row);
                String method = (String) findingsModel.getValueAt(modelRow, 4);
                String path = (String) findingsModel.getValueAt(modelRow, 5);
                CapturedEndpoint ep = store.getCapturedEndpoints().stream()
                    .filter(ex -> ex.getMethod().equals(method) && ex.getNormalizedPath().equals(path))
                    .findFirst().orElse(null);
                if (ep != null) {
                    burp.api.montoya.http.message.requests.HttpRequest req =
                        HttpUtils.ensureRequestService(ep.getOriginalRequest(), ep.getOriginalUrl());
                    String title = HttpUtils.buildRepeaterTabName("ACAS Probe", req, ep.getOriginalUrl(), null);
                    api.repeater().sendToRepeater(req, title);
                }
            }
        });

        huntItem.addActionListener(e -> {
            int row = findingsTable.getSelectedRow();
            if (row != -1) {
                int modelRow = findingsTable.convertRowIndexToModel(row);
                String method = (String) findingsModel.getValueAt(modelRow, 4);
                String path = (String) findingsModel.getValueAt(modelRow, 5);
                Optional<CapturedEndpoint> op = store.getCapturedEndpoints().stream()
                    .filter(ex -> ex.getMethod().equals(method) && ex.getNormalizedPath().equals(path))
                    .findFirst();
                
                op.ifPresent(ep -> {
                    Container parent = getParent();
                    while (parent != null && !(parent instanceof AcasPanel)) parent = parent.getParent();
                    if (parent instanceof AcasPanel) {
                        AcasPanel acas = (AcasPanel) parent;
                        acas.switchToHuntHub();
                        // Trigger actual hunt logic if needed, or just highlight
                    }
                });
            }
        });
    }

    // --- RENDERERS ---
    private static class BurpNativeRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            JLabel c = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            c.setFont(c.getFont().deriveFont(Font.PLAIN, 12));
            String strValue = String.valueOf(value);
            
            // Priority coloring
            if (column == 2) {
                int score = (int) value;
                if (score >= 80) c.setForeground(new Color(239, 68, 68));
                else if (score >= 60) c.setForeground(new Color(245, 158, 11));
                else c.setForeground(new Color(99, 102, 241));
            } 
            // Classification coloring
            else if (column == 3) {
                if (strValue.contains("BROKEN") || strValue.contains("BYPASS")) c.setForeground(new Color(239, 68, 68));
                else if (strValue.contains("SUSPICIOUS")) c.setForeground(new Color(245, 158, 11));
                else c.setForeground(new Color(34, 197, 94));
            } else {
                c.setForeground(Color.LIGHT_GRAY);
            }
            
            if (isSelected) {
                c.setForeground(Color.WHITE);
            }
            return c;
        }
    }

    private CapturedEndpoint getSelectedEndpoint() {
        int row = findingsTable.getSelectedRow();
        return getEndpointAtRow(row);
    }

    private void inspectSelectedFinding() {
        CapturedEndpoint ep = getSelectedEndpoint();
        if (ep == null) return;
        
        Window parent = SwingUtilities.getWindowAncestor(this);
        FindingDetailDialog dialog = new FindingDetailDialog(parent, api, store, notifier, ep);
        dialog.setVisible(true);
    }

    private String getLeakedFields(CapturedEndpoint ep) {
        for (CapturedEndpoint.ProbeResult pr : ep.getProbes()) {
            if ("BROKEN".equals(pr.verdict)) return pr.leakedFields;
        }
        return "None";
    }

    private List<CapturedEndpoint.ProbeResult> getSortedResults(CapturedEndpoint ep) {
        String ownerName = store.getActorById(ep.getActorId())
                .map(ActorProfile::getName)
                .orElse("Owner");
        
        List<CapturedEndpoint.ProbeResult> sorted = new ArrayList<>(ep.getProbes());
        sorted.sort((p1, p2) -> {
            // 1. Owner first
            if (p1.actorName.equals(ownerName)) return -1;
            if (p2.actorName.equals(ownerName)) return 1;
            
            // 2. Anonymous second
            boolean p1Anon = p1.actorName.equalsIgnoreCase("Anonymous") || p1.actorName.equalsIgnoreCase("anon");
            boolean p2Anon = p2.actorName.equalsIgnoreCase("Anonymous") || p2.actorName.equalsIgnoreCase("anon");
            if (p1Anon) return -1;
            if (p2Anon) return 1;
            
            // 3. Alphabetical others
            return p1.actorName.compareToIgnoreCase(p2.actorName);
        });
        return sorted;
    }
}
