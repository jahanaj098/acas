package com.acas.ui;

import com.acas.engine.SeverityClassifier;
import com.acas.engine.HuntManager;
import com.acas.harvest.ResourceRegistry;
import com.acas.model.AcasFinding;
import com.acas.model.ActorProfile;
import com.acas.model.HuntConfig;
import com.acas.store.ActorStore;
import com.acas.notification.NotificationService;
import com.acas.util.CurlGenerator;
import com.acas.util.ReportExporter;
import com.acas.util.ReportGenerator;
import com.acas.util.HttpUtils;
import com.acas.util.DiffUtils;
import com.google.gson.GsonBuilder;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableCellEditor;
import java.io.File;
import java.io.FileWriter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URI;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.stream.Collectors;

/**
 * Burp Suite Dashboard-style live audit results panel.
 * Mirrors the flat issue list from Burp's "Live audit from all proxy" view.
 */
public class ResultMatrixPanel extends JPanel {
    private final ActorStore store;
    private final SeverityClassifier classifier;
    private final MontoyaApi api;
    private final NotificationService notifier;
    private final ResourceRegistry resourceRegistry;
    private final HuntManager huntManager;

    // --- Table ---
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final TableRowSorter<DefaultTableModel> sorter;
    private final DefaultTableModel reviewModel;
    private final JTable reviewTable;
    private final JTabbedPane mainTabs;

    // --- Filter State ---
    private final Set<String> activeSeverityFilters = new HashSet<>();
    private final Set<String> activeConfidenceFilters = new HashSet<>();
    private String searchText = "";

    // --- Detail Pane (bottom) ---
    private final JTabbedPane detailTabs;
    private final JTextPane advisoryPane;
    private final HttpRequestEditor baseRequestEditor;
    private final HttpResponseEditor baseResponseEditor;
    private final HttpRequestEditor anonymousRequestEditor;
    private final HttpResponseEditor anonymousResponseEditor;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JTextPane diffPane;
    private final JTextPane pathPane;
    private final JTabbedPane reviewDetailTabs;
    private final JTextPane reviewAdvisoryPane;
    private final HttpRequestEditor reviewBaseRequestEditor;
    private final HttpResponseEditor reviewBaseResponseEditor;
    private final HttpRequestEditor reviewAnonymousRequestEditor;
    private final HttpResponseEditor reviewAnonymousResponseEditor;
    private final HttpRequestEditor reviewRequestEditor;
    private final HttpResponseEditor reviewResponseEditor;
    private final JTextPane reviewDiffPane;
    private final JTextPane reviewPathPane;
    private final JPanel reviewSummaryBar;
    private final JLabel reviewScorePill;
    private final JLabel reviewVerdictLabel;
    private final JLabel reviewMutationLabel;
    private final JLabel reviewOwnerSimilarityLabel;
    private final JLabel reviewAnonSimilarityLabel;
    private final JLabel reviewInvalidSimilarityLabel;
    private final JLabel reviewProbeLengthLabel;
    private final JLabel reviewOwnerLengthLabel;
    private final JLabel reviewBaselineAgeLabel;
    private final JLabel reviewReasonLabel;

    // --- Columns (matching Burp Dashboard) ---
    private static final String[] COLUMNS = {"Time", "Source", "Issue type", "Path", "Severity", "Confidence", "Comment"};
    private static final int COL_TIME = 0;
    private static final int COL_SOURCE = 1;
    private static final int COL_ISSUE = 2;
    private static final int COL_PATH = 3;
    private static final int COL_SEVERITY = 4;
    private static final int COL_CONFIDENCE = 5;
    private static final int COL_COMMENT = 6;

    // Backing data list (ordered newest first)
    private final List<AcasFinding> displayFindings = new ArrayList<>();
    private final List<AcasFinding> displayReviewFindings = new ArrayList<>();

    // Confirmed-table row model: explicit mapping so grouped header rows and
    // finding rows can be mixed. rowFindings[i] == null marks a group header;
    // rowGroupKeys[i] holds that header's group key (null for finding rows).
    private final List<AcasFinding> rowFindings = new ArrayList<>();
    private final List<String> rowGroupKeys = new ArrayList<>();
    private final java.util.Set<String> collapsedGroups = new java.util.HashSet<>();
    private boolean groupByEndpoint = true;

    // Per-finding comments (keyed by finding ID)
    private final Map<String, String> findingComments = new HashMap<>();

    // Refresh/detail-state guards to avoid scroll reset while user reads content.
    private String lastConfirmedSignature = "";
    private String lastReviewSignature = "";
    private String lastDetailFingerprint = "";
    private String lastReviewDetailFingerprint = "";

    public ResultMatrixPanel(MontoyaApi api,
            ActorStore store,
            SeverityClassifier classifier,
            NotificationService notifier,
            ResourceRegistry resourceRegistry,
            HuntManager huntManager) {
        this.api = api;
        this.store = store;
        this.classifier = classifier;
        this.notifier = notifier;
        this.resourceRegistry = resourceRegistry;
        this.huntManager = huntManager;

        setLayout(new BorderLayout(0, 0));

        // ========== FILTER TOOLBAR ==========
        add(buildFilterToolbar(), BorderLayout.NORTH);

        // ========== TABLE ==========
        tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                // Only the Comment column of a real finding row is editable (not group headers)
                return col == COL_COMMENT && row < rowFindings.size() && rowFindings.get(row) != null;
            }
        };

        table = new NativeHistoryTable(tableModel) {
            @Override
            public boolean getScrollableTracksViewportWidth() {
                return getParent() == null || getParent().getWidth() >= getMinimumSize().width;
            }

            @Override
            public Component prepareRenderer(TableCellRenderer renderer, int row, int col) {
                Component c = super.prepareRenderer(renderer, row, col);
                int modelRow = convertRowIndexToModel(row);
                boolean header = modelRow >= 0 && modelRow < rowFindings.size() && rowFindings.get(modelRow) == null;
                if (header && !isRowSelected(row)) {



                    c.setFont(c.getFont().deriveFont(Font.BOLD));
                }
                return c;
            }
        };
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        ((NativeHistoryTable) table).setActorColors(row ->
            row >= 0 && row < rowFindings.size() ? findingActorColor(rowFindings.get(row)) : null);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);


        // Sorter kept for row-index conversion, but column sorting is disabled so
        // endpoint grouping/ordering is never scrambled by a header click.
        sorter = new TableRowSorter<>(tableModel);
        for (int i = 0; i < COLUMNS.length; i++) sorter.setSortable(i, false);
        table.setRowSorter(sorter);

        // Column widths — match Burp layout
        table.getColumnModel().getColumn(COL_TIME).setPreferredWidth(155);
        table.getColumnModel().getColumn(COL_TIME).setMaxWidth(170);
        table.getColumnModel().getColumn(COL_SOURCE).setPreferredWidth(100);
        table.getColumnModel().getColumn(COL_SOURCE).setMaxWidth(130);
        table.getColumnModel().getColumn(COL_ISSUE).setPreferredWidth(290);
        table.getColumnModel().getColumn(COL_PATH).setPreferredWidth(480);
        table.getColumnModel().getColumn(COL_SEVERITY).setPreferredWidth(90);
        table.getColumnModel().getColumn(COL_SEVERITY).setMaxWidth(110);
        table.getColumnModel().getColumn(COL_CONFIDENCE).setPreferredWidth(90);
        table.getColumnModel().getColumn(COL_CONFIDENCE).setMaxWidth(110);
        table.getColumnModel().getColumn(COL_COMMENT).setPreferredWidth(120);
        table.getColumnModel().getColumn(COL_COMMENT).setMaxWidth(260);
        // Keep the evidence columns readable; small windows scroll horizontally.
        int[] minimumWidths = {145, 120, 210, 260, 90, 95, 100};
        for (int i = 0; i < minimumWidths.length; i++) {
            table.getColumnModel().getColumn(i).setMinWidth(minimumWidths[i]);
        }

        // Listen for comment edits
        tableModel.addTableModelListener(e -> {
            if (e.getColumn() == COL_COMMENT) {
                int modelRow = e.getFirstRow();
                if (modelRow >= 0 && modelRow < rowFindings.size()) {
                    AcasFinding f = rowFindings.get(modelRow);
                    if (f != null) {
                        Object val = tableModel.getValueAt(modelRow, COL_COMMENT);
                        findingComments.put(f.getId(), val != null ? val.toString() : "");
                    }
                }
            }
        });

        // Selection
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) updateDetailPane();
        });

        // Click a group header to collapse/expand it; double-click a finding for detail.
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                int viewRow = table.rowAtPoint(e.getPoint());
                if (viewRow < 0) return;
                int modelRow = table.convertRowIndexToModel(viewRow);
                boolean header = modelRow >= 0 && modelRow < rowGroupKeys.size() && rowGroupKeys.get(modelRow) != null;
                if (header) {
                    String key = rowGroupKeys.get(modelRow);
                    if (collapsedGroups.contains(key)) collapsedGroups.remove(key);
                    else collapsedGroups.add(key);
                    rebuildConfirmedTable();
                    return;
                }
                if (e.getClickCount() == 2) {
                    showFindingDetail();
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createEmptyBorder());

        reviewModel = new DefaultTableModel(
            new String[]{"Time", "Endpoint / Pattern", "Actor", "Mutation", "Score", "Status Code", "FP Reason", "Diff Preview", "Actions"},
            0
        ) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return col == 8;
            }
        };
        reviewTable = new NativeHistoryTable(reviewModel);
        ((NativeHistoryTable) reviewTable).setActorColors(row -> findingActorColor(rowToReviewFinding(row)));
        reviewTable.setRowHeight(26);
        reviewTable.setShowGrid(false);
        reviewTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        reviewTable.getColumnModel().getColumn(0).setPreferredWidth(140);
        reviewTable.getColumnModel().getColumn(1).setPreferredWidth(260);
        reviewTable.getColumnModel().getColumn(2).setPreferredWidth(110);
        reviewTable.getColumnModel().getColumn(3).setPreferredWidth(90);
        reviewTable.getColumnModel().getColumn(4).setPreferredWidth(60);
        reviewTable.getColumnModel().getColumn(5).setPreferredWidth(80);
        reviewTable.getColumnModel().getColumn(6).setPreferredWidth(260);
        reviewTable.getColumnModel().getColumn(7).setPreferredWidth(320);
        reviewTable.getColumnModel().getColumn(8).setPreferredWidth(340);
        reviewTable.getColumnModel().getColumn(7).setCellRenderer(new ReviewPreviewCellRenderer());
        reviewTable.getColumnModel().getColumn(8).setCellRenderer(new ReviewActionCellRenderer());
        reviewTable.getColumnModel().getColumn(8).setCellEditor(new ReviewActionCellEditor());

        reviewTable.setRowHeight(26);
        reviewTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateReviewDetailPane();
            }
        });
        reviewTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    AcasFinding f = getSelectedReviewFinding();
                    if (f != null) {
                        showFindingDetail(f);
                    }
                }
            }
        });

        // ========== DETAIL PANE (Bottom) ==========
        detailTabs = new JTabbedPane(JTabbedPane.TOP);

        // Advisory tab
        advisoryPane = new JTextPane();
        advisoryPane.setContentType("text/html");
        advisoryPane.setEditable(false);
        advisoryPane.setFont(new Font("SansSerif", Font.PLAIN, 12));
        JScrollPane advisoryScroll = new JScrollPane(advisoryPane);
        detailTabs.addTab("Advisory", advisoryScroll);

        // Baseline tab (request | response)
        baseRequestEditor = api.userInterface().createHttpRequestEditor();
        baseResponseEditor = api.userInterface().createHttpResponseEditor();
        detailTabs.addTab("Baseline", buildRequestResponseSplit(baseRequestEditor, baseResponseEditor));

        // Anonymous tab (request | response)
        anonymousRequestEditor = api.userInterface().createHttpRequestEditor();
        anonymousResponseEditor = api.userInterface().createHttpResponseEditor();
        detailTabs.addTab("Anonymous", buildRequestResponseSplit(anonymousRequestEditor, anonymousResponseEditor));

        // Mutated tab (request | response)
        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor();
        detailTabs.addTab("Mutated", buildRequestResponseSplit(requestEditor, responseEditor));
        
        // Visual Diff tab
        diffPane = new JTextPane();
        diffPane.setContentType("text/html");
        diffPane.setEditable(false);
        JScrollPane diffScroll = new JScrollPane(diffPane);
        detailTabs.addTab("Visual Diff", diffScroll);

        // Path to Issue tab
        pathPane = new JTextPane();
        pathPane.setContentType("text/html");
        pathPane.setEditable(false);
        pathPane.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane pathScroll = new JScrollPane(pathPane);
        detailTabs.addTab("Path to Issue", pathScroll);

        // ========== REVIEW DETAIL PANE (Bottom) ==========
        reviewDetailTabs = new JTabbedPane(JTabbedPane.TOP);

        reviewAdvisoryPane = new JTextPane();
        reviewAdvisoryPane.setContentType("text/html");
        reviewAdvisoryPane.setEditable(false);
        reviewAdvisoryPane.setFont(new Font("SansSerif", Font.PLAIN, 12));
        JScrollPane reviewAdvisoryScroll = new JScrollPane(reviewAdvisoryPane);
        reviewDetailTabs.addTab("Advisory", reviewAdvisoryScroll);

        reviewBaseRequestEditor = api.userInterface().createHttpRequestEditor();
        reviewBaseResponseEditor = api.userInterface().createHttpResponseEditor();
        reviewDetailTabs.addTab("Baseline", buildRequestResponseSplit(reviewBaseRequestEditor, reviewBaseResponseEditor));

        reviewAnonymousRequestEditor = api.userInterface().createHttpRequestEditor();
        reviewAnonymousResponseEditor = api.userInterface().createHttpResponseEditor();
        reviewDetailTabs.addTab("Anonymous", buildRequestResponseSplit(reviewAnonymousRequestEditor, reviewAnonymousResponseEditor));

        reviewRequestEditor = api.userInterface().createHttpRequestEditor();
        reviewResponseEditor = api.userInterface().createHttpResponseEditor();
        reviewDetailTabs.addTab("Mutated", buildRequestResponseSplit(reviewRequestEditor, reviewResponseEditor));

        reviewDiffPane = new JTextPane();
        reviewDiffPane.setContentType("text/html");
        reviewDiffPane.setEditable(false);
        JScrollPane reviewDiffScroll = new JScrollPane(reviewDiffPane);
        reviewDetailTabs.addTab("Visual Diff", reviewDiffScroll);

        reviewPathPane = new JTextPane();
        reviewPathPane.setContentType("text/html");
        reviewPathPane.setEditable(false);
        reviewPathPane.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane reviewPathScroll = new JScrollPane(reviewPathPane);
        reviewDetailTabs.addTab("Path to Issue", reviewPathScroll);

        reviewScorePill = new JLabel();
        reviewVerdictLabel = new JLabel();
        reviewMutationLabel = new JLabel();
        reviewOwnerSimilarityLabel = new JLabel();
        reviewAnonSimilarityLabel = new JLabel();
        reviewInvalidSimilarityLabel = new JLabel();
        reviewProbeLengthLabel = new JLabel();
        reviewOwnerLengthLabel = new JLabel();
        reviewBaselineAgeLabel = new JLabel();
        reviewReasonLabel = new JLabel();
        reviewSummaryBar = buildReviewSummaryBar();
        registerReviewShortcuts();

        // ========== SPLIT PANE ==========
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailTabs);
        splitPane.setDividerLocation(320);
        splitPane.setDividerSize(4);
        splitPane.setBorder(null);

        JPanel confirmedPanel = new JPanel(new BorderLayout());
        confirmedPanel.add(splitPane, BorderLayout.CENTER);

        JPanel reviewPanel = buildReviewQueuePanel();

        mainTabs = new JTabbedPane();
        AcasTheme.styleTabs(mainTabs);
        mainTabs.addTab("Confirmed Findings", confirmedPanel);
        mainTabs.addTab("Review Queue (0)", reviewPanel);
        add(mainTabs, BorderLayout.CENTER);

        // ========== STATUS BAR ==========
        add(buildStatusBar(), BorderLayout.SOUTH);

        // ========== CONTEXT MENU ==========
        setupContextMenu();

        // ========== LIVE UPDATES ==========
        // Register listener for immediate updates when new findings arrive
        classifier.addListener(finding -> refresh());

        // Also periodic refresh as fallback
        new javax.swing.Timer(2000, e -> refresh()).start();

        // Initialize all filters as active
        activeSeverityFilters.add("HIGH");
        activeSeverityFilters.add("MEDIUM");
        activeSeverityFilters.add("LOW");
        activeSeverityFilters.add("CRITICAL");
        activeSeverityFilters.add("INFO");
        activeConfidenceFilters.add("Certain");
        activeConfidenceFilters.add("Firm");
        activeConfidenceFilters.add("Tentative");

        refresh();
    }

    // ======================== FILTER TOOLBAR ========================

    private JPanel buildFilterToolbar() {
        JPanel toolbar = new JPanel();
        toolbar.setLayout(new BoxLayout(toolbar, BoxLayout.X_AXIS));
        toolbar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(60, 60, 60)),
            new EmptyBorder(8, 10, 8, 10)));

        // Filter icon
        JLabel filterIcon = new JLabel("▼ Filter");
        filterIcon.setFont(new Font("SansSerif", Font.BOLD, 12));

        toolbar.add(filterIcon);
        toolbar.add(Box.createHorizontalStrut(12));

        // Severity buttons — match Burp order: High, Medium, Low, Info
        toolbar.add(createFilterToggle("Critical", "CRITICAL", new Color(153, 27, 27), activeSeverityFilters));
        toolbar.add(Box.createHorizontalStrut(4));
        toolbar.add(createFilterToggle("High", "HIGH", new Color(185, 28, 28), activeSeverityFilters));
        toolbar.add(Box.createHorizontalStrut(4));
        toolbar.add(createFilterToggle("Medium", "MEDIUM", new Color(217, 119, 6), activeSeverityFilters));
        toolbar.add(Box.createHorizontalStrut(4));
        toolbar.add(createFilterToggle("Low", "LOW", new Color(30, 64, 175), activeSeverityFilters));
        toolbar.add(Box.createHorizontalStrut(4));
        toolbar.add(createFilterToggle("Info", "INFO", new Color(100, 100, 100), activeSeverityFilters));
        toolbar.add(Box.createHorizontalStrut(16));

        // Confidence buttons — match Burp: Certain, Firm, Tentative
        toolbar.add(createFilterToggle("Certain", "Certain", new Color(34, 197, 94), activeConfidenceFilters));
        toolbar.add(Box.createHorizontalStrut(4));
        toolbar.add(createFilterToggle("Firm", "Firm", new Color(168, 162, 158), activeConfidenceFilters));
        toolbar.add(Box.createHorizontalStrut(4));
        toolbar.add(createFilterToggle("Tentative", "Tentative", new Color(120, 113, 108), activeConfidenceFilters));
        toolbar.add(Box.createHorizontalStrut(12));

        JButton exportReportBtn = new JButton("Export Report");
        styleToolbarActionButton(exportReportBtn);
        exportReportBtn.addActionListener(e -> exportConfirmedFindingsReport());
        toolbar.add(exportReportBtn);
        toolbar.add(Box.createHorizontalStrut(10));

        JToggleButton groupToggle = new JToggleButton("Group by endpoint", groupByEndpoint);
        groupToggle.setFont(new Font("SansSerif", Font.PLAIN, 12));
        groupToggle.setFocusPainted(false);
        groupToggle.addActionListener(e -> {
            groupByEndpoint = groupToggle.isSelected();
            rebuildConfirmedTable();
        });
        toolbar.add(groupToggle);
        toolbar.add(Box.createHorizontalStrut(4));

        JButton collapseAllBtn = new JButton("⊟");
        collapseAllBtn.setToolTipText("Collapse all endpoint groups");
        styleToolbarActionButton(collapseAllBtn);
        collapseAllBtn.addActionListener(e -> {
            for (AcasFinding f : displayFindings) if (passesFilters(f)) collapsedGroups.add(groupKey(f));
            rebuildConfirmedTable();
        });
        toolbar.add(collapseAllBtn);
        toolbar.add(Box.createHorizontalStrut(2));

        JButton expandAllBtn = new JButton("⊞");
        expandAllBtn.setToolTipText("Expand all endpoint groups");
        styleToolbarActionButton(expandAllBtn);
        expandAllBtn.addActionListener(e -> {
            collapsedGroups.clear();
            rebuildConfirmedTable();
        });
        toolbar.add(expandAllBtn);

        toolbar.add(Box.createHorizontalGlue());

        // Search field
        JTextField searchField = new JTextField(22);
        searchField.putClientProperty("JTextField.placeholderText", "Search...");
        searchField.setMaximumSize(new Dimension(280, 30));
        searchField.setPreferredSize(new Dimension(260, 28));
        searchField.setFont(new Font("SansSerif", Font.PLAIN, 12));
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { onSearch(searchField); }
            @Override public void removeUpdate(DocumentEvent e) { onSearch(searchField); }
            @Override public void changedUpdate(DocumentEvent e) { onSearch(searchField); }
        });
        JLabel searchIcon = new JLabel(" 🔍 ");
        searchIcon.setFont(new Font("SansSerif", Font.PLAIN, 12));
        toolbar.add(searchIcon);
        toolbar.add(searchField);

        return toolbar;
    }

    private void styleToolbarActionButton(JButton button) {
        AcasTheme.styleButton(button);
    }

    private JToggleButton createFilterToggle(String label, String filterKey, Color color, Set<String> filterSet) {
        // Native toggle button so it matches Burp's own theme (light or dark).
        JToggleButton btn = new JToggleButton(label, true);
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.addActionListener(e -> {
            if (btn.isSelected()) filterSet.add(filterKey);
            else filterSet.remove(filterKey);
            applyFilters();
        });
        return btn;
    }

    private void onSearch(JTextField field) {
        searchText = field.getText().trim().toLowerCase();
        applyFilters();
    }

    private void applyFilters() {
        // Filtering is applied while building grouped rows (headers must stay with
        // their children), so a filter change just rebuilds the table.
        rebuildConfirmedTable();
    }

    private boolean passesFilters(AcasFinding f) {
        if (f == null) return false;
        String severity = f.getSeverity() != null ? capitalizeFirst(f.getSeverity()) : "Low";
        String confidence = deriveConfidence(f);

        boolean sevMatch = activeSeverityFilters.isEmpty() || activeSeverityFilters.contains(severity.toUpperCase());
        boolean confMatch = activeConfidenceFilters.isEmpty() || activeConfidenceFilters.stream()
                .anyMatch(cf -> confidence.toLowerCase().contains(cf.toLowerCase()));

        boolean textMatch = true;
        if (!searchText.isEmpty()) {
            String hay = (f.getSource() + " " + buildIssueType(f) + " " + buildFullUrl(f) + " "
                    + severity + " " + confidence + " " + f.getReplayerActorName()).toLowerCase();
            textMatch = hay.contains(searchText);
        }
        return sevMatch && confMatch && textMatch;
    }

    // ======================== GROUPED TABLE BUILD ========================

    private void rebuildConfirmedTable() {
        String selectedId = currentSelectedFindingId();

        tableModel.setRowCount(0);
        rowFindings.clear();
        rowGroupKeys.clear();

        List<AcasFinding> filtered = new ArrayList<>();
        for (AcasFinding f : displayFindings) {
            if (passesFilters(f)) filtered.add(f);
        }

        if (!groupByEndpoint) {
            for (int i = filtered.size() - 1; i >= 0; i--) addFindingRow(filtered.get(i));
        } else {
            Map<String, List<AcasFinding>> groups = new HashMap<>();
            for (AcasFinding f : filtered) {
                groups.computeIfAbsent(groupKey(f), k -> new ArrayList<>()).add(f);
            }
            List<String> keys = new ArrayList<>(groups.keySet());
            keys.sort((a, b) -> {
                int sa = worstSevRank(groups.get(a));
                int sb = worstSevRank(groups.get(b));
                if (sa != sb) return Integer.compare(sb, sa);
                return latestTs(groups.get(b)).compareTo(latestTs(groups.get(a)));
            });
            for (String key : keys) {
                List<AcasFinding> grp = groups.get(key);
                grp.sort((x, y) -> Integer.compare(sevRank(y.getSeverity()), sevRank(x.getSeverity())));
                boolean collapsed = collapsedGroups.contains(key);
                addGroupHeaderRow(key, grp, collapsed);
                if (!collapsed) {
                    for (AcasFinding f : grp) addFindingRow(f);
                }
            }
        }

        restoreSelectionById(selectedId);
    }

    private void addFindingRow(AcasFinding f) {
        tableModel.addRow(new Object[]{
                f.getTimestamp(),
                f.getSource() != null ? f.getSource() : "Unknown",
                buildIssueType(f),
                buildFullUrl(f),
                f.getSeverity() != null ? capitalizeFirst(f.getSeverity()) : "Low",
                deriveConfidence(f),
                findingComments.getOrDefault(f.getId(), "")
        });
        rowFindings.add(f);
        rowGroupKeys.add(null);
    }

    private void addGroupHeaderRow(String key, List<AcasFinding> grp, boolean collapsed) {
        // key format: "METHOD\u0001pattern"
        String method = key;
        String pattern = "";
        int sep = key.indexOf('\u0001');
        if (sep >= 0) {
            method = key.substring(0, sep);
            pattern = key.substring(sep + 1);
        }
        int hi = 0, med = 0, low = 0, info = 0;
        for (AcasFinding f : grp) {
            switch (sevRank(f.getSeverity())) {
                case 4: case 3: hi++; break;
                case 2: med++; break;
                case 1: low++; break;
                default: info++; break;
            }
        }
        StringBuilder summary = new StringBuilder();
        if (hi > 0) summary.append(hi).append(" high  ");
        if (med > 0) summary.append(med).append(" med  ");
        if (low > 0) summary.append(low).append(" low  ");
        if (info > 0) summary.append(info).append(" info");
        String worst = worstSevLabel(grp);

        tableModel.addRow(new Object[]{
                (collapsed ? "▶  " : "▼  ") + method + "  " + pattern,
                grp.size() + " result" + (grp.size() == 1 ? "" : "s"),
                summary.toString().trim(),
                "",
                worst,
                "",
                ""
        });
        rowFindings.add(null);
        rowGroupKeys.add(key);
    }

    private String groupKey(AcasFinding f) {
        String method = f.getMethod() != null ? f.getMethod() : "?";
        String pattern = f.getEndpointPattern() != null && !f.getEndpointPattern().isEmpty()
                ? f.getEndpointPattern() : buildFullUrl(f);
        return method + "\u0001" + pattern;
    }

    private int sevRank(String sev) {
        if (sev == null) return 0;
        switch (sev.toUpperCase()) {
            case "CRITICAL": return 4;
            case "HIGH": return 3;
            case "MEDIUM": return 2;
            case "LOW": return 1;
            default: return 0;
        }
    }

    private int worstSevRank(List<AcasFinding> grp) {
        int worst = 0;
        for (AcasFinding f : grp) worst = Math.max(worst, sevRank(f.getSeverity()));
        return worst;
    }

    private String worstSevLabel(List<AcasFinding> grp) {
        switch (worstSevRank(grp)) {
            case 4: return "Critical";
            case 3: return "High";
            case 2: return "Medium";
            case 1: return "Low";
            default: return "Info";
        }
    }

    private String latestTs(List<AcasFinding> grp) {
        String latest = "";
        for (AcasFinding f : grp) {
            String ts = f.getTimestamp() != null ? f.getTimestamp() : "";
            if (ts.compareTo(latest) > 0) latest = ts;
        }
        return latest;
    }

    private String currentSelectedFindingId() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return null;
        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow >= 0 && modelRow < rowFindings.size() && rowFindings.get(modelRow) != null) {
            return rowFindings.get(modelRow).getId();
        }
        return null;
    }

    private void restoreSelectionById(String selectedId) {
        if (selectedId == null) return;
        for (int i = 0; i < rowFindings.size(); i++) {
            AcasFinding f = rowFindings.get(i);
            if (f != null && selectedId.equals(f.getId())) {
                int viewRow = table.convertRowIndexToView(i);
                if (viewRow >= 0) table.setRowSelectionInterval(viewRow, viewRow);
                return;
            }
        }
    }

    // ======================== STATUS BAR ========================

    private JPanel buildStatusBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        bar.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(60, 60, 60)));

        JLabel statusLabel = new JLabel("Live audit results");
        statusLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        statusLabel.setForeground(new Color(150, 150, 150));
        bar.add(statusLabel);

        JLabel reviewLabel = new JLabel("Review Queue: 0");
        reviewLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        reviewLabel.setForeground(new Color(212, 160, 23));
        bar.add(reviewLabel);

        // Timer to update count
        new javax.swing.Timer(1000, e -> {
            int total = classifier.getAllFindings().size();
            int showing = table.getRowCount();
            statusLabel.setText("Live audit results — " + showing + " of " + total + " rows");
            reviewLabel.setText("Review Queue: " + classifier.getReviewFindings().size());
        }).start();

        return bar;
    }

    private JPanel buildReviewQueuePanel() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        JButton markAllFpBtn = new JButton("Mark All as False Positive");
        JButton exportBtn = new JButton("Export for Manual Review");
        JButton reevaluateBtn = new JButton("Re-evaluate Selected");
        JButton suppressionBtn = new JButton("Suppression List");

        markAllFpBtn.addActionListener(e -> {
            int removed = classifier.suppressAllReviewFindings();
            refresh();
            JOptionPane.showMessageDialog(this, "Suppressed " + removed + " review findings.", "ACAS", JOptionPane.INFORMATION_MESSAGE);
        });

        reevaluateBtn.addActionListener(e -> reevaluateSelectedReviewFinding());
        exportBtn.addActionListener(e -> exportReviewQueue());
        suppressionBtn.addActionListener(e -> openSuppressionViewer());

        for (JButton b : new JButton[]{markAllFpBtn, reevaluateBtn, exportBtn, suppressionBtn}) AcasTheme.styleButton(b);

        toolbar.add(markAllFpBtn);
        toolbar.add(reevaluateBtn);
        toolbar.add(exportBtn);
        toolbar.add(suppressionBtn);
        toolbar.add(Box.createHorizontalStrut(12));
        JLabel tip = new JLabel("Tip: Y = Confirm  N = Dismiss  D = Detail  R = Re-evaluate");
        tip.setFont(new Font("SansSerif", Font.PLAIN, 11));
        tip.setForeground(new Color(140, 140, 140));
        toolbar.add(tip);

        panel.add(toolbar, BorderLayout.NORTH);

        JScrollPane reviewTableScroll = new JScrollPane(reviewTable);
        JPanel tableAndSummary = new JPanel(new BorderLayout(0, 0));
        tableAndSummary.add(reviewTableScroll, BorderLayout.CENTER);
        tableAndSummary.add(reviewSummaryBar, BorderLayout.SOUTH);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableAndSummary, reviewDetailTabs);
        split.setDividerLocation(260);
        split.setResizeWeight(0.45);
        split.setDividerSize(4);
        split.setBorder(null);

        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildReviewSummaryBar() {
        JPanel bar = new JPanel(new GridLayout(4, 1, 0, 0));
        bar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 1, 0, new Color(60, 60, 60)),
            new EmptyBorder(4, 8, 4, 8)));
        bar.setPreferredSize(new Dimension(0, 82));
        bar.setMinimumSize(new Dimension(0, 82));
        bar.setMaximumSize(new Dimension(Integer.MAX_VALUE, 82));
        // native background (follows Burp theme)

        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        row1.setOpaque(false);
        reviewScorePill.setOpaque(true);
        reviewScorePill.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
        reviewScorePill.setForeground(Color.WHITE);
        reviewScorePill.setFont(new Font("SansSerif", Font.BOLD, 12));
        reviewVerdictLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
        reviewMutationLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
        row1.add(reviewScorePill);
        row1.add(reviewVerdictLabel);
        row1.add(reviewMutationLabel);

        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 0));
        row2.setOpaque(false);
        reviewOwnerSimilarityLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        reviewAnonSimilarityLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        reviewInvalidSimilarityLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        row2.add(reviewOwnerSimilarityLabel);
        row2.add(reviewAnonSimilarityLabel);
        row2.add(reviewInvalidSimilarityLabel);

        JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 0));
        row3.setOpaque(false);
        reviewProbeLengthLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        reviewOwnerLengthLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        reviewBaselineAgeLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        row3.add(reviewProbeLengthLabel);
        row3.add(reviewOwnerLengthLabel);
        row3.add(reviewBaselineAgeLabel);

        JPanel row4 = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        row4.setOpaque(false);
        reviewReasonLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        row4.add(reviewReasonLabel);

        bar.add(row1);
        bar.add(row2);
        bar.add(row3);
        bar.add(row4);

        updateReviewSummaryBar(null);
        return bar;
    }

    private void registerReviewShortcuts() {
        InputMap inputMap = reviewTable.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        ActionMap actionMap = reviewTable.getActionMap();

        inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_Y, 0), "acas.review.confirm");
        inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "acas.review.confirm");
        inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_N, 0), "acas.review.dismiss");
        inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), "acas.review.dismiss");
        inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_D, 0), "acas.review.detail");
        inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_R, 0), "acas.review.reevaluate");

        actionMap.put("acas.review.confirm", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                markSelectedReviewAsReal();
            }
        });
        actionMap.put("acas.review.dismiss", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                markSelectedReviewAsFalsePositive();
            }
        });
        actionMap.put("acas.review.detail", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                AcasFinding selected = getSelectedReviewFinding();
                if (selected != null) showFindingDetail(selected);
            }
        });
        actionMap.put("acas.review.reevaluate", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                reevaluateSelectedReviewFinding();
                reviewTable.requestFocusInWindow();
            }
        });
    }

    private void markSelectedReviewAsReal() {
        applyReviewDecision(true);
    }

    private void markSelectedReviewAsFalsePositive() {
        applyReviewDecision(false);
    }

    private void applyReviewDecision(boolean markRealFinding) {
        int selectedRow = reviewTable.getSelectedRow();
        AcasFinding finding = getSelectedReviewFinding();
        if (selectedRow < 0 || finding == null) {
            return;
        }

        if (markRealFinding) {
            classifier.promoteReviewFinding(finding.getId());
        } else {
            classifier.suppressReviewFinding(finding.getId());
        }

        refresh();

        int nextRow = Math.min(selectedRow, reviewTable.getRowCount() - 1);
        if (nextRow >= 0) {
            reviewTable.setRowSelectionInterval(nextRow, nextRow);
            reviewTable.scrollRectToVisible(reviewTable.getCellRect(nextRow, 0, true));
        }
        reviewTable.requestFocusInWindow();
    }

    private void reevaluateSelectedReviewFinding() {
        AcasFinding finding = getSelectedReviewFinding();
        if (finding == null) {
            JOptionPane.showMessageDialog(this, "Select a review finding first.", "ACAS", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        if (huntManager == null) {
            return;
        }

        HuntManager.ReevaluateRoute route = huntManager.reevaluateReviewFinding(finding);
        refresh();
        if (route == HuntManager.ReevaluateRoute.CONFIRMED) {
            mainTabs.setSelectedIndex(0);
        }
    }

    private void exportReviewQueue() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Review Queue as JSON");
        chooser.setSelectedFile(new File("acas-review-queue.json"));
        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;

        File file = chooser.getSelectedFile();
        try (FileWriter writer = new FileWriter(file)) {
            String json = new GsonBuilder().setPrettyPrinting().create().toJson(classifier.getReviewFindings());
            writer.write(json);
            JOptionPane.showMessageDialog(this, "Exported review queue to " + file.getAbsolutePath(), "ACAS", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "ACAS", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportConfirmedFindingsReport() {
        List<AcasFinding> findings = new ArrayList<>(classifier.getAllFindings());
        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No confirmed findings available.", "ACAS", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export ACAS Hunt Report");
        chooser.setSelectedFile(new File("acas-hunt-report.md"));
        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = chooser.getSelectedFile();
        if (!file.getName().toLowerCase().endsWith(".md")) {
            file = new File(file.getParentFile(), file.getName() + ".md");
        }

        try {
            HuntConfig config = buildHuntConfig(findings);
            ReportExporter.exportMarkdown(findings, config, file);

            Object[] options = {"Open in Explorer", "Close"};
            int choice = JOptionPane.showOptionDialog(
                this,
                "Report saved: " + file.getAbsolutePath(),
                "ACAS",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.INFORMATION_MESSAGE,
                null,
                options,
                options[1]
            );

            if (choice == 0 && Desktop.isDesktopSupported()) {
                File parent = file.getParentFile();
                if (parent != null && parent.exists()) {
                    Desktop.getDesktop().open(parent);
                }
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Report export failed: " + ex.getMessage(), "ACAS", JOptionPane.ERROR_MESSAGE);
        }
    }

    private HuntConfig buildHuntConfig(List<AcasFinding> findings) {
        String targetHost = "-";
        String start = "-";
        String end = "-";

        AcasFinding firstWithUrl = findings.stream().filter(f -> f.getUrl() != null && !f.getUrl().isBlank()).findFirst().orElse(null);
        if (firstWithUrl != null) {
            try {
                URI uri = URI.create(firstWithUrl.getUrl());
                if (uri.getHost() != null && !uri.getHost().isBlank()) {
                    targetHost = uri.getHost();
                }
            } catch (Exception ignored) {
            }
        }

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        List<LocalDateTime> times = findings.stream()
            .map(AcasFinding::getTimestamp)
            .filter(t -> t != null && !t.isBlank())
            .map(t -> {
                try {
                    return LocalDateTime.parse(t, formatter);
                } catch (Exception ex) {
                    return null;
                }
            })
            .filter(t -> t != null)
            .sorted(Comparator.naturalOrder())
            .collect(Collectors.toList());

        if (!times.isEmpty()) {
            start = times.get(0).format(formatter);
            end = times.get(times.size() - 1).format(formatter);
        }

        return new HuntConfig(targetHost, start, end);
    }

    private void openSuppressionViewer() {
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this), "Suppression List", Dialog.ModalityType.MODELESS);
        dialog.setLayout(new BorderLayout(8, 8));

        DefaultListModel<String> model = new DefaultListModel<>();
        for (String key : classifier.getSuppressions()) model.addElement(key);
        JList<String> list = new JList<>(model);

        JButton removeBtn = new JButton("Remove Suppression");
        removeBtn.addActionListener(e -> {
            String selected = list.getSelectedValue();
            if (selected == null) return;
            if (classifier.removeSuppression(selected)) {
                model.removeElement(selected);
            }
        });

        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        bottom.add(removeBtn);

        dialog.add(new JScrollPane(list), BorderLayout.CENTER);
        dialog.add(bottom, BorderLayout.SOUTH);
        dialog.setSize(700, 360);
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }

    // ======================== CONTEXT MENU ========================

    private void setupContextMenu() {
        JPopupMenu popup = new JPopupMenu();

        JMenuItem inspectItem = new JMenuItem("Inspect Finding");
        JMenuItem repeaterItem = new JMenuItem("Send to Repeater");
        JMenuItem copyUrlItem = new JMenuItem("Copy URL");
        JMenuItem copyReportItem = new JMenuItem("Copy as Bug Report");
        JMenuItem discordItem = new JMenuItem("Send to Discord");
        JMenuItem telegramItem = new JMenuItem("Send to Telegram");

        popup.add(inspectItem);
        popup.add(repeaterItem);
        popup.addSeparator();
        popup.add(copyUrlItem);
        popup.add(copyReportItem);
        popup.addSeparator();
        popup.add(discordItem);
        popup.add(telegramItem);

        // Select the row under the cursor before showing the menu, so actions
        // (Send to Telegram/Discord, Copy, etc.) target the right finding and
        // never fire on a group-header row.
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            private void maybeShow(java.awt.event.MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int viewRow = table.rowAtPoint(e.getPoint());
                if (viewRow < 0) return;
                int modelRow = table.convertRowIndexToModel(viewRow);
                boolean header = modelRow >= 0 && modelRow < rowFindings.size() && rowFindings.get(modelRow) == null;
                if (header) return; // no row-actions on group headers
                table.setRowSelectionInterval(viewRow, viewRow);
                popup.show(table, e.getX(), e.getY());
            }
            @Override public void mousePressed(java.awt.event.MouseEvent e) { maybeShow(e); }
            @Override public void mouseReleased(java.awt.event.MouseEvent e) { maybeShow(e); }
        });

        inspectItem.addActionListener(e -> showFindingDetail());

        repeaterItem.addActionListener(e -> {
            AcasFinding f = getSelectedFinding();
            if (f != null && f.getMutatedRequest() != null) {
                burp.api.montoya.http.message.requests.HttpRequest req =
                    burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                        burp.api.montoya.core.ByteArray.byteArray(f.getMutatedRequest()));
                req = HttpUtils.ensureRequestService(req, f.getUrl());
                String title = HttpUtils.buildRepeaterTabName("ACAS Matrix", req, f.getUrl(), f.getEndpointPattern());
                api.repeater().sendToRepeater(req, title);
            }
        });

        copyUrlItem.addActionListener(e -> {
            AcasFinding f = getSelectedFinding();
            if (f != null) {
                java.awt.datatransfer.StringSelection sel = new java.awt.datatransfer.StringSelection(f.getUrl());
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, sel);
            }
        });

        copyReportItem.addActionListener(e -> {
            AcasFinding f = getSelectedFinding();
            if (f != null) {
                String report = formatFindingReport(f);
                java.awt.datatransfer.StringSelection sel = new java.awt.datatransfer.StringSelection(report);
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, sel);
            }
        });

        discordItem.addActionListener(e -> {
            AcasFinding finding = getSelectedFinding();
            if (finding != null) NotificationFeedback.send(this, discordItem,
                () -> notifier.sendDiscordReport(formatFindingReport(finding)));
        });
        telegramItem.addActionListener(e -> {
            AcasFinding finding = getSelectedFinding();
            if (finding != null) NotificationFeedback.send(this, telegramItem,
                () -> notifier.sendTelegramReport(formatFindingReport(finding)));
        });
    }
    // ======================== DATA REFRESH ========================

    private final java.util.concurrent.atomic.AtomicBoolean refreshQueued=new java.util.concurrent.atomic.AtomicBoolean();
    public void refresh() {
        if(!refreshQueued.compareAndSet(false,true))return;
        SwingUtilities.invokeLater(()->{refreshQueued.set(false);refreshNow();});
    }
    private void refreshNow() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refresh);
            return;
        }

        List<AcasFinding> allFindings = classifier.getAllFindings();
        List<AcasFinding> reviewFindings = classifier.getReviewFindings();

        String confirmedSignature = buildFindingsSignature(allFindings);
        String reviewSignature = buildFindingsSignature(reviewFindings);
        boolean confirmedChanged = !confirmedSignature.equals(lastConfirmedSignature);
        boolean reviewChanged = !reviewSignature.equals(lastReviewSignature);

        if (!confirmedChanged && !reviewChanged) {
            return;
        }

        lastConfirmedSignature = confirmedSignature;
        lastReviewSignature = reviewSignature;

        // Rebuild backing list (newest first) then (re)build the grouped table view.
        displayFindings.clear();
        displayFindings.addAll(allFindings);
        rebuildConfirmedTable();

        // Rebuild review table
        displayReviewFindings.clear();
        displayReviewFindings.addAll(reviewFindings);
        reviewModel.setRowCount(0);
        for (int i = displayReviewFindings.size() - 1; i >= 0; i--) {
            AcasFinding f = displayReviewFindings.get(i);
            String diffPreview = String.format(
                "Owner sim: %.0f%% | Anon sim: %.0f%% | Len: %d vs %d | Reason: %s",
                f.getSimilarityToOwner() * 100,
                f.getSimilarityToAnon() * 100,
                f.getMutatedLength(),
                f.getBaseLength(),
                f.getFpReason() != null ? f.getFpReason() : "-"
            );
            reviewModel.addRow(new Object[]{
                f.getTimestamp(),
                f.getEndpointPattern(),
                f.getReplayerActorName(),
                f.getMutationType(),
                f.getConfidenceScore(),
                f.getMutatedStatus(),
                f.getFpReason() != null ? f.getFpReason() : "",
                diffPreview,
                ""
            });
        }
        mainTabs.setTitleAt(1, "Review Queue (" + displayReviewFindings.size() + ")");
        updateReviewDetailPane();
    }

    private String buildFindingsSignature(List<AcasFinding> findings) {
        StringBuilder sb = new StringBuilder();
        for (AcasFinding f : findings) {
            if (f == null) continue;
            sb.append(f.getId()).append('|')
                .append(f.getTimestamp()).append('|')
                .append(f.getConfidenceScore()).append('|')
                .append(f.getMutatedStatus()).append('|')
                .append(f.getMutatedLength()).append(';');
        }
        return sb.toString();
    }

    // ======================== FULL URL BUILDER ========================

    /**
     * Build the full URL with protocol + domain + path for display in the Path column.
     * If the URL already contains a protocol/domain, use it as-is.
     * Otherwise, try to reconstruct from the finding data.
     */
    private String buildFullUrl(AcasFinding f) {
        String url = f.getUrl();
        if (url != null && !url.isEmpty()) {
            // Already a full URL (starts with http:// or https://)
            if (url.startsWith("http://") || url.startsWith("https://")) {
                return url;
            }
            // It's just a path — try to extract domain from endpoint or use as-is
            return url;
        }
        // Fallback to endpoint pattern
        return f.getEndpointPattern() != null ? f.getEndpointPattern() : "";
    }

    // ======================== ISSUE TYPE BUILDER ========================

    private Color findingActorColor(AcasFinding finding) {
        if (finding == null || finding.getReplayerActorName() == null
                || "Anonymous".equalsIgnoreCase(finding.getReplayerActorName())) return null;
        List<ActorProfile> matches = store.getAllActors().stream()
            .filter(actor -> finding.getReplayerActorName().equals(actor.getName()))
            .collect(Collectors.toList());
        return matches.size() == 1 ? ActorsPanel.safeColor(matches.get(0).getColor(), null) : null;
    }

    private String buildIssueType(AcasFinding f) {
        StringBuilder sb = new StringBuilder();

        // Label-based naming (like Burp issue names)
        String label = f.getLabel();
        if (label != null) {
            if (label.equals("NO_CONFIRMED_BYPASS")) sb.append("No confirmed access control issue");
            else if (label.equals("ACCESS_BLOCKED")) sb.append("Access blocked");
            else if (label.contains("ANON_BROKEN")) sb.append("Broken authentication (anonymous access)");
            else if (label.contains("HORIZ_BROKEN")) sb.append("Horizontal privilege escalation (IDOR)");
            else if (label.contains("PRIV_ESC")) sb.append("Vertical privilege escalation");
            else if (label.contains("IDOR_DATA_LEAK")) sb.append("Cross-actor data leak (IDOR)");
            else if (label.contains("DATA_LEAK")) sb.append("Sensitive data exposure");
            else if (label.contains("PARTIAL")) sb.append("Partial access control bypass");
            else if (label.contains("WRITE_BYPASS")) sb.append("Write operation authorization bypass");
            else if (label.contains("SUSPICIOUS_STATUS")) sb.append("Suspicious status code match");
            else if (label.contains("VULNERABLE")) sb.append("Broken access control");
            else sb.append("Access control issue");
        } else {
            // Fallback to mutation type
            String mt = f.getMutationType();
            if (mt != null) {
                if (mt.contains("IDOR") || mt.contains("ID_SWAP")) sb.append("Insecure direct object reference");
                else if (mt.contains("PARAM")) sb.append("Parameter tampering");
                else if (mt.contains("METHOD")) sb.append("HTTP method override");
                else if (mt.contains("HEADER")) sb.append("Security header bypass");
                else sb.append("Access control misconfiguration");
            } else {
                sb.append("Access control finding");
            }
        }

        return sb.toString();
    }

    private String deriveConfidence(AcasFinding f) {
        int score = f.getConfidenceScore();
        if (score > 0) {
            if (score > 80) return "Certain";
            if (score >= 60) return "Firm";
            if (score >= 30) return "Tentative";
            return "Tentative";
        }

        double sim = f.getSizeSimilarity();
        String severity = f.getSeverity();

        // High similarity + high severity = Certain
        if (sim >= 0.85 && ("CRITICAL".equals(severity) || "HIGH".equals(severity))) return "Certain";
        if (sim >= 0.70) return "Firm";
        if (sim >= 0.40) return "Tentative";

        // If replayed and successful, boost confidence
        if (f.isReplayed() && f.getMutatedStatus() >= 200 && f.getMutatedStatus() < 300) return "Firm";

        return "Tentative";
    }

    private String capitalizeFirst(String s) {
        if (s == null || s.isEmpty()) return s;
        return s.substring(0, 1).toUpperCase() + s.substring(1).toLowerCase();
    }

    // ======================== DETAIL PANE ========================

    private void updateDetailPane() {
        AcasFinding f = getSelectedFinding();
        String fp = detailFingerprint(f);
        if (fp.equals(lastDetailFingerprint)) {
            return;
        }
        lastDetailFingerprint = fp;
        lastDetailFingerprint = fp;
        applyDetailToPane(f, advisoryPane, pathPane,
            baseRequestEditor, baseResponseEditor,
            anonymousRequestEditor, anonymousResponseEditor,
            requestEditor, responseEditor, diffPane);
    }

    private void updateReviewDetailPane() {
        AcasFinding f = getSelectedReviewFinding();
        String fp = detailFingerprint(f);
        if (fp.equals(lastReviewDetailFingerprint)) {
            return;
        }
        lastReviewDetailFingerprint = fp;
        lastReviewDetailFingerprint = fp;
        updateReviewSummaryBar(f);
        applyDetailToPane(f, reviewAdvisoryPane, reviewPathPane,
            reviewBaseRequestEditor, reviewBaseResponseEditor,
            reviewAnonymousRequestEditor, reviewAnonymousResponseEditor,
            reviewRequestEditor, reviewResponseEditor, reviewDiffPane);
    }

    private String detailFingerprint(AcasFinding f) {
        if (f == null) return "<none>";
        return f.getId() + "|"
            + f.getTimestamp() + "|"
            + f.getConfidenceScore() + "|"
            + f.getBaseStatus() + "|"
            + f.getMutatedStatus() + "|"
            + f.getBaseLength() + "|"
            + f.getMutatedLength() + "|"
            + (f.getBaseRequest() != null ? f.getBaseRequest().length : 0) + "|"
            + (f.getBaseResponse() != null ? f.getBaseResponse().length : 0) + "|"
            + (f.getAnonymousRequest() != null ? f.getAnonymousRequest().length : 0) + "|"
            + (f.getAnonymousResponse() != null ? f.getAnonymousResponse().length : 0) + "|"
            + (f.getMutatedRequest() != null ? f.getMutatedRequest().length : 0) + "|"
            + (f.getMutatedResponse() != null ? f.getMutatedResponse().length : 0);
    }

    private JComponent buildRequestResponseSplit(HttpRequestEditor reqEditor, HttpResponseEditor respEditor) {
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqEditor.uiComponent(), respEditor.uiComponent());
        split.setDividerLocation(0.5);
        split.setResizeWeight(0.5);
        split.setBorder(null);
        return split;
    }

    private void updateReviewSummaryBar(AcasFinding finding) {
        if (finding == null) {
            reviewScorePill.setText("SCORE: --");
            reviewScorePill.setBackground(new Color(95, 95, 95));
            reviewVerdictLabel.setText("VERDICT: -");
            reviewMutationLabel.setText("MUTATION: -");
            reviewOwnerSimilarityLabel.setText("Owner sim: -");
            reviewAnonSimilarityLabel.setText("Anon sim: -");
            reviewInvalidSimilarityLabel.setText("Invalid ID sim: -");
            reviewProbeLengthLabel.setText("Probe len: -");
            reviewOwnerLengthLabel.setText("Owner len: -");
            reviewBaselineAgeLabel.setText("Baseline age: -");
            reviewReasonLabel.setText("Select a review finding to see triage summary");
            return;
        }

        int score = finding.getConfidenceScore();
        reviewScorePill.setText("SCORE: " + score);
        reviewScorePill.setBackground(colorForScore(score));

        String verdict = parseVerdictFromReason(finding.getFpReason(), score);
        reviewVerdictLabel.setText("VERDICT: " + verdict);
        reviewMutationLabel.setText("MUTATION: " + safeText(finding.getMutationType(), "-"));

        reviewOwnerSimilarityLabel.setText("Owner sim: " + percent(finding.getSimilarityToOwner()));
        reviewAnonSimilarityLabel.setText("Anon sim: " + percent(finding.getSimilarityToAnon()));
        reviewInvalidSimilarityLabel.setText("Invalid ID sim: " + percent(finding.getSimilarityToInvalid()));

        reviewProbeLengthLabel.setText("Probe len: " + finding.getMutatedLength());
        reviewOwnerLengthLabel.setText("Owner len: " + finding.getBaseLength());
        reviewBaselineAgeLabel.setText("Baseline age: " + formatBaselineAge(finding));

        reviewReasonLabel.setText("FP Reason: " + safeText(finding.getFpReason(), "-"));
    }

    private Color colorForScore(int score) {
        if (score < 30) return new Color(107, 114, 128);
        if (score <= 60) return new Color(217, 119, 6);
        if (score <= 80) return new Color(234, 88, 12);
        return new Color(185, 28, 28);
    }

    private String parseVerdictFromReason(String reason, int score) {
        if (reason == null || reason.isBlank()) {
            return score >= 60 ? "LIKELY_TRUE" : "NEEDS_REVIEW";
        }

        String text = reason.toLowerCase();
        if (text.contains("anonymous") || text.contains("invalid-id") || text.contains("blocked") || text.contains("error")) {
            return "LIKELY_FALSE";
        }
        if (text.contains("highly similar to owner")) {
            return "TRUE_POSITIVE";
        }
        if (text.contains("owner baseline") || text.contains("close to owner")) {
            return "LIKELY_TRUE";
        }
        if (text.contains("inconclusive") || text.contains("missing baseline")) {
            return "NEEDS_REVIEW";
        }

        return score >= 60 ? "LIKELY_TRUE" : "NEEDS_REVIEW";
    }

    private String percent(double value) {
        double normalized = Math.max(0.0, Math.min(1.0, value));
        return String.format("%.0f%%", normalized * 100.0);
    }

    private String formatBaselineAge(AcasFinding finding) {
        long ts = finding.getBaselineCapturedAtEpochMs();
        if (ts <= 0) {
            return "unknown";
        }
        long elapsedSec = Math.max(0, (System.currentTimeMillis() - ts) / 1000);
        long minutes = elapsedSec / 60;
        long seconds = elapsedSec % 60;
        return minutes + "m " + seconds + "s ago";
    }

    private String safeText(String value, String fallback) {
        return (value == null || value.isBlank()) ? fallback : value;
    }

    private void applyDetailToPane(AcasFinding f,
                                   JTextPane advisory,
                                   JTextPane path,
                                   HttpRequestEditor baseReqEditor,
                                   HttpResponseEditor baseRespEditor,
                                   HttpRequestEditor anonymousReqEditor,
                                   HttpResponseEditor anonymousRespEditor,
                                   HttpRequestEditor mutatedReqEditor,
                                   HttpResponseEditor mutatedRespEditor,
                                   JTextPane diffPane) {
        if (f == null) {
            advisory.setText("");
            path.setText("");
            baseReqEditor.setRequest(null);
            baseRespEditor.setResponse(null);
            anonymousReqEditor.setRequest(null);
            anonymousRespEditor.setResponse(null);
            mutatedReqEditor.setRequest(null);
            mutatedRespEditor.setResponse(null);
            diffPane.setText("");
            return;
        }

        advisory.setText(themeHtml(buildAdvisoryHtml(f)));
        advisory.setCaretPosition(0);

        if (f.getBaseRequest() != null) {
            burp.api.montoya.http.message.requests.HttpRequest req =
                burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                    burp.api.montoya.core.ByteArray.byteArray(f.getBaseRequest()));
            baseReqEditor.setRequest(HttpUtils.ensureRequestService(req, f.getUrl()));
        } else {
            baseReqEditor.setRequest(null);
        }

        if (f.getBaseResponse() != null) {
            baseRespEditor.setResponse(
                burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                    burp.api.montoya.core.ByteArray.byteArray(f.getBaseResponse())));
        } else {
            baseRespEditor.setResponse(null);
        }

        if (f.getAnonymousRequest() != null) {
            burp.api.montoya.http.message.requests.HttpRequest req =
                burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                    burp.api.montoya.core.ByteArray.byteArray(f.getAnonymousRequest()));
            anonymousReqEditor.setRequest(HttpUtils.ensureRequestService(req, f.getUrl()));
        } else {
            anonymousReqEditor.setRequest(null);
        }

        if (f.getAnonymousResponse() != null) {
            anonymousRespEditor.setResponse(
                burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                    burp.api.montoya.core.ByteArray.byteArray(f.getAnonymousResponse())));
        } else {
            anonymousRespEditor.setResponse(null);
        }

        if (f.getMutatedRequest() != null) {
            burp.api.montoya.http.message.requests.HttpRequest req =
                burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                    burp.api.montoya.core.ByteArray.byteArray(f.getMutatedRequest()));
            mutatedReqEditor.setRequest(HttpUtils.ensureRequestService(req, f.getUrl()));
        } else {
            mutatedReqEditor.setRequest(null);
        }

        if (f.getMutatedResponse() != null) {
            mutatedRespEditor.setResponse(
                burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                    burp.api.montoya.core.ByteArray.byteArray(f.getMutatedResponse())));
        } else {
            mutatedRespEditor.setResponse(null);
        }

        path.setText(themeHtml(buildPathToIssueHtml(f)));
        path.setCaretPosition(0);

        // Generate Visual Diff
        String baseStr = f.getBaseResponse() != null ? new String(f.getBaseResponse()) : "";
        String mutatedStr = f.getMutatedResponse() != null ? new String(f.getMutatedResponse()) : "";
        
        // Strip headers for diff if they exist (usually double newline splits headers from body)
        int baseHeaderEnd = baseStr.indexOf("\r\n\r\n");
        if (baseHeaderEnd > 0) baseStr = baseStr.substring(baseHeaderEnd + 4);
        int mutatedHeaderEnd = mutatedStr.indexOf("\r\n\r\n");
        if (mutatedHeaderEnd > 0) mutatedStr = mutatedStr.substring(mutatedHeaderEnd + 4);

        diffPane.setText(DiffUtils.generateHtmlDiff(baseStr, mutatedStr, isDarkTheme()));
        diffPane.setCaretPosition(0);
    }

    private String buildAdvisoryHtml(AcasFinding f) {
        String sevColor = getSeverityHtmlColor(f.getSeverity());
        String confidence = deriveConfidence(f);

        StringBuilder html = new StringBuilder();
        html.append("<html><body style='font-family: sans-serif; font-size: 10pt; color: #d4d4d4; padding: 12px;'>");

        // Issue header
        html.append("<h2 style='color: ").append(sevColor).append("; margin-bottom: 4px;'>")
                .append(buildIssueType(f)).append("</h2>");

        // Meta table
        html.append("<table style='font-size: 10pt; margin-bottom: 16px;'>");
        html.append("<tr><td style='color: #999; padding-right: 16px;'>Severity:</td><td style='color: ").append(sevColor).append("; font-weight: bold;'>").append(capitalizeFirst(f.getSeverity())).append("</td></tr>");
        html.append("<tr><td style='color: #999; padding-right: 16px;'>Confidence:</td><td>").append(confidence).append("</td></tr>");
        if (f.getConfidenceScore() > 0) {
            html.append("<tr><td style='color: #999; padding-right: 16px;'>Confidence Score:</td><td>").append(f.getConfidenceScore()).append("/100</td></tr>");
        }
        html.append("<tr><td style='color: #999; padding-right: 16px;'>URL:</td><td style='color: #93c5fd;'>").append(escapeHtml(buildFullUrl(f))).append("</td></tr>");
        html.append("<tr><td style='color: #999; padding-right: 16px;'>Method:</td><td>").append(f.getMethod()).append("</td></tr>");
        html.append("<tr><td style='color: #999; padding-right: 16px;'>Owner Actor:</td><td>").append(escapeHtml(f.getOwnerActorName())).append("</td></tr>");
        html.append("<tr><td style='color: #999; padding-right: 16px;'>Replayer Actor:</td><td>").append(escapeHtml(f.getReplayerActorName())).append("</td></tr>");
        html.append("<tr><td style='color: #999; padding-right: 16px;'>Timestamp:</td><td>").append(f.getTimestamp()).append("</td></tr>");
        html.append("</table>");

        // Issue detail
        html.append("<h3 style='color: #ef6334; margin-bottom: 4px;'>Issue Detail</h3>");
        html.append("<p>").append(getIssueDescription(f)).append("</p>");

        // Mutation info
        if (f.getMutationType() != null) {
            html.append("<h3 style='color: #ef6334; margin-bottom: 4px;'>Mutation Applied</h3>");
            html.append("<p><b>Type:</b> ").append(escapeHtml(f.getMutationType())).append("</p>");
            if (f.getMutationDescription() != null) {
                html.append("<p><b>Description:</b> ").append(escapeHtml(f.getMutationDescription())).append("</p>");
            }
            html.append("<p><b>Replay Actor:</b> ").append(escapeHtml(f.getReplayerActorName())).append("</p>");
            html.append("<p><b>Mutation Data:</b> request replayed with the above actor and request shape shown in the Request tabs.</p>");
        }

        // Response comparison
        html.append("<h3 style='color: #ef6334; margin-bottom: 4px;'>Response Comparison</h3>");
        html.append("<table style='font-size: 10pt; border-collapse: collapse;'>");
        html.append("<tr style='border-bottom: 1px solid #444;'><th style='text-align: left; padding: 4px 12px 4px 0; color: #999;'></th><th style='padding: 4px 12px; color: #999;'>Status</th><th style='padding: 4px 12px; color: #999;'>Length</th></tr>");
        html.append("<tr><td style='padding: 4px 12px 4px 0; color: #999;'>Original</td><td style='padding: 4px 12px; text-align: center;'>").append(f.getBaseStatus()).append("</td><td style='padding: 4px 12px; text-align: center;'>").append(f.getBaseLength()).append("</td></tr>");
        html.append("<tr><td style='padding: 4px 12px 4px 0; color: #999;'>Mutated</td><td style='padding: 4px 12px; text-align: center;'>").append(f.getMutatedStatus()).append("</td><td style='padding: 4px 12px; text-align: center;'>").append(f.getMutatedLength()).append("</td></tr>");
        html.append("</table>");
        html.append("<p style='margin-top: 6px;'>Size Similarity: <b>").append(String.format("%.1f%%", f.getSizeSimilarity() * 100)).append("</b></p>");

        // Full mutation payload preview
        if (f.getMutatedRequest() != null) {
            html.append("<h3 style='color: #ef6334; margin-bottom: 4px;'>Complete Mutation Data</h3>");
            html.append("<p><b>Actor:</b> ").append(escapeHtml(f.getReplayerActorName())).append("</p>");
            html.append("<p><b>Method:</b> ").append(escapeHtml(f.getMethod())).append("</p>");
            html.append("<p><b>Path:</b> ").append(escapeHtml(buildFullUrl(f))).append("</p>");
            html.append("<p><b>Mutation Type:</b> ").append(escapeHtml(f.getMutationType())).append("</p>");
            if (f.getMutationDescription() != null) {
                html.append("<p><b>Mutation Description:</b> ").append(escapeHtml(f.getMutationDescription())).append("</p>");
            }
            html.append("<p><b>Mutated Request:</b> use the <i>Mutated Request</i> tab to inspect the full raw request sent to the server.</p>");
        }

        // Analysis note
        if (f.getAnalysisNote() != null && !f.getAnalysisNote().isEmpty()) {
            html.append("<h3 style='color: #ef6334; margin-bottom: 4px;'>Analysis Note</h3>");
            html.append("<p style='background: #1a1a2e; padding: 8px; border-left: 3px solid #ef6334;'>").append(escapeHtml(f.getAnalysisNote())).append("</p>");
        }
        if (f.getFpReason() != null && !f.getFpReason().isEmpty()) {
            html.append("<h3 style='color: #ef6334; margin-bottom: 4px;'>FP Analysis</h3>");
            html.append("<p style='background: #1f2937; padding: 8px; border-left: 3px solid #9ca3af;'>").append(escapeHtml(f.getFpReason())).append("</p>");
        }

        html.append("</body></html>");
        return html.toString();
    }

    private String buildPathToIssueHtml(AcasFinding f) {
        StringBuilder html = new StringBuilder();
        html.append("<html><body style='font-family: monospace; font-size: 10pt; color: #d4d4d4; padding: 12px;'>");

        html.append("<h3 style='color: #ef6334;'>Path to Issue</h3>");

        // Full URL breakdown
        String url = buildFullUrl(f);
        html.append("<p><b>Full URL:</b> <span style='color: #93c5fd;'>").append(escapeHtml(url)).append("</span></p>");
        html.append("<p><b>Endpoint Pattern:</b> ").append(escapeHtml(f.getEndpointPattern())).append("</p>");
        html.append("<p><b>Method:</b> ").append(f.getMethod()).append("</p>");

        // Steps
        html.append("<h3 style='color: #ef6334; margin-top: 16px;'>Reproduction Steps</h3>");
        html.append("<ol style='color: #ccc;'>");
        html.append("<li>Authenticate as actor '<b>").append(escapeHtml(f.getReplayerActorName())).append("</b>'</li>");
        html.append("<li>Send ").append(f.getMethod()).append(" request to <span style='color: #93c5fd;'>").append(escapeHtml(url)).append("</span></li>");
        if (f.getMutationType() != null) {
            html.append("<li>Apply mutation category: <b>").append(escapeHtml(f.getMutationType())).append("</b></li>");
        }
        if (f.getMutationDescription() != null && !f.getMutationDescription().isEmpty()) {
            html.append("<li>Mutation detail: <b>").append(escapeHtml(f.getMutationDescription())).append("</b></li>");
        }
        html.append("<li>Observe response status ").append(f.getMutatedStatus()).append(" (expected denial, got access)</li>");
        html.append("<li>Compare with original response from '<b>").append(escapeHtml(f.getOwnerActorName())).append("</b>' (status ").append(f.getBaseStatus()).append(")</li>");
        html.append("</ol>");

        html.append("<h3 style='color: #ef6334; margin-top: 16px;'>Complete Mutation Data</h3>");
        html.append("<p><b>Replay Actor:</b> ").append(escapeHtml(f.getReplayerActorName())).append("</p>");
        html.append("<p><b>Owner Actor:</b> ").append(escapeHtml(f.getOwnerActorName())).append("</p>");
        html.append("<p><b>Mutation Type:</b> ").append(escapeHtml(f.getMutationType())).append("</p>");
        if (f.getMutationDescription() != null && !f.getMutationDescription().isEmpty()) {
            html.append("<p><b>Mutation Description:</b> ").append(escapeHtml(f.getMutationDescription())).append("</p>");
        }
        html.append("<p><b>Base Status:</b> ").append(f.getBaseStatus()).append(" | <b>Mutated Status:</b> ").append(f.getMutatedStatus()).append("</p>");
        html.append("<p><b>Base Length:</b> ").append(f.getBaseLength()).append(" | <b>Mutated Length:</b> ").append(f.getMutatedLength()).append("</p>");

        if (f.getMutatedRequest() != null) {
            html.append("<p><b>Replayed Request Preview:</b></p>");
            html.append("<pre style='white-space: pre-wrap; background: #111827; color: #d4d4d4; padding: 10px; border: 1px solid #374151; border-radius: 4px;'>");
            html.append(escapeHtml(bytesToText(f.getMutatedRequest())));
            html.append("</pre>");
        }

        html.append("</body></html>");
        return html.toString();
    }

    private String getIssueDescription(AcasFinding f) {
        String label = f.getLabel();
        if (label == null) return "An access control issue was identified at this endpoint.";

        if (label.contains("ANON_BROKEN"))
            return "The endpoint is accessible without any authentication. An unauthenticated user can access resources that belong to '<b>" + escapeHtml(f.getOwnerActorName()) + "</b>'. This indicates a missing authentication check.";
        if (label.contains("HORIZ_BROKEN"))
            return "A user at the same privilege level as the resource owner can access or modify the resource. Actor '<b>" + escapeHtml(f.getReplayerActorName()) + "</b>' was able to access data belonging to '<b>" + escapeHtml(f.getOwnerActorName()) + "</b>', indicating an Insecure Direct Object Reference (IDOR) vulnerability.";
        if (label.contains("PRIV_ESC"))
            return "A lower-privileged actor '<b>" + escapeHtml(f.getReplayerActorName()) + "</b>' was able to access administrative or higher-privilege functionality belonging to '<b>" + escapeHtml(f.getOwnerActorName()) + "</b>'. This constitutes a vertical privilege escalation.";
        if (label.contains("IDOR_DATA_LEAK"))
            return "Sensitive data belonging to another actor was detected in the response when replayed by '<b>" + escapeHtml(f.getReplayerActorName()) + "</b>'. This is a cross-actor data leak through an Insecure Direct Object Reference.";
        if (label.contains("DATA_LEAK"))
            return "Sensitive data fields were exposed in the response when replayed by actor '<b>" + escapeHtml(f.getReplayerActorName()) + "</b>'. Fields from the original owner's response were accessible to an unauthorized party.";
        if (label.contains("PARTIAL"))
            return "A partial access control bypass was detected. While full access was not granted, the response contained enough information to indicate insufficient authorization validation.";
        if (label.contains("WRITE_BYPASS"))
            return "A write operation (POST/PUT/PATCH/DELETE) was executed successfully by an unauthorized actor '<b>" + escapeHtml(f.getReplayerActorName()) + "</b>'. This may allow data modification without proper authorization.";
        if (label.contains("SUSPICIOUS_STATUS"))
            return "The mutated request returned the same status code as the original, but with low similarity. This may indicate a partial bypass or inconsistent access control enforcement.";

        return "An access control issue was identified. Actor '<b>" + escapeHtml(f.getReplayerActorName()) + "</b>' gained unauthorized access to resources belonging to '<b>" + escapeHtml(f.getOwnerActorName()) + "</b>'.";
    }

    private String bytesToText(byte[] data) {
        if (data == null || data.length == 0) {
            return "<no request captured>";
        }
        return new String(data, java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    // ======================== FINDING DETAIL DIALOG ========================

    private void showFindingDetail() {
        AcasFinding f = getSelectedFinding();
        if (f == null) return;
        showFindingDetail(f);
    }

    private void showFindingDetail(AcasFinding f) {
        if (f == null) return;

        Window parent = SwingUtilities.getWindowAncestor(this);
        FindingDetailDialog dialog = new FindingDetailDialog(parent, api, store, notifier, f);
        dialog.setVisible(true);
    }

    // ======================== HELPERS ========================

    private AcasFinding getSelectedFinding() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return null;
        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= rowFindings.size()) return null;
        return rowFindings.get(modelRow); // null for group-header rows
    }

    private AcasFinding getSelectedReviewFinding() {
        int row = reviewTable.getSelectedRow();
        if (row < 0) return null;
        int backingIdx = displayReviewFindings.size() - 1 - row;
        if (backingIdx < 0 || backingIdx >= displayReviewFindings.size()) return null;
        return displayReviewFindings.get(backingIdx);
    }

    private String formatFindingReport(AcasFinding f) {
        return ReportGenerator.generateMarkdown(f);
    }

    private String buildCurlForFinding(AcasFinding finding) {
        if (finding == null || finding.getMutatedRequest() == null) {
            return "";
        }

        String scheme = "https";
        String host = "";
        try {
            if (finding.getUrl() != null && !finding.getUrl().isBlank()) {
                URI uri = URI.create(finding.getUrl());
                if (uri.getScheme() != null && !uri.getScheme().isBlank()) {
                    scheme = uri.getScheme();
                }
                if (uri.getHost() != null && !uri.getHost().isBlank()) {
                    host = uri.getHost();
                }
            }
        } catch (Exception ignored) {
        }

        HttpRequest request = HttpRequest.httpRequest(ByteArray.byteArray(finding.getMutatedRequest()));
        return CurlGenerator.generateCurl(request, scheme, host);
    }

    private void copyCurlToClipboard(AcasFinding finding, JButton sourceButton) {
        String curl = buildCurlForFinding(finding);
        if (curl.isBlank()) {
            return;
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(curl), null);
        showTemporaryButtonTooltip(sourceButton, "PoC curl copied to clipboard ✓");
    }

    private void showTemporaryButtonTooltip(JButton button, String text) {
        String old = button.getToolTipText();
        button.setToolTipText(text);
        ToolTipManager.sharedInstance().setInitialDelay(0);
        MouseEvent phantom = new MouseEvent(button, MouseEvent.MOUSE_MOVED, System.currentTimeMillis(), 0, 1, 1, 0, false);
        ToolTipManager.sharedInstance().mouseMoved(phantom);
        Timer t = new Timer(2000, e -> {
            button.setToolTipText(old);
            ((Timer) e.getSource()).stop();
        });
        t.setRepeats(false);
        t.start();
    }

    private String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    /** True when Burp's current Look-and-Feel is a dark theme. */
    private boolean isDarkTheme() {
        Color bg = UIManager.getColor("Panel.background");
        if (bg == null) return true;
        double lum = 0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue();
        return lum < 128;
    }

    /** Adapts dark-authored advisory/path HTML so it stays readable under Burp's light theme. */
    private String themeHtml(String html) {
        if (html == null || isDarkTheme()) return html;
        return html
            .replace("#d4d4d4", "#1e1e1e")
            .replace("#ccc", "#333333")
            .replace("color: #999", "color: #555")
            .replace("background: #1a1a2e", "background: #eef0f6")
            .replace("background: #1f2937", "background: #eef1f5")
            .replace("background: #111827", "background: #f3f4f6")
            .replace("border: 1px solid #374151", "border: 1px solid #cbd5e1");
    }

    private String getSeverityHtmlColor(String severity) {
        if (severity == null) return "#6b7280";
        switch (severity.toUpperCase()) {
            case "CRITICAL": return "#dc2626";
            case "HIGH": return "#ef4444";
            case "MEDIUM": return "#f59e0b";
            case "LOW": return "#3b82f6";
            case "INFO": return "#6b7280";
            default: return "#6b7280";
        }
    }

    private static class ReviewPreviewCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            JLabel c = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            String txt = value != null ? value.toString() : "";
            c.setToolTipText(txt);

            return c;
        }
    }

    private class ReviewActionCellRenderer extends JPanel implements TableCellRenderer {
        private final JButton realBtn = new JButton("✅ Real Finding");
        private final JButton fpBtn = new JButton("❌ False Positive");
        private final JButton copyBtn = new JButton("Copy PoC curl");

        ReviewActionCellRenderer() {
            setLayout(new FlowLayout(FlowLayout.CENTER, 4, 0));
            realBtn.setFont(new Font("SansSerif", Font.PLAIN, 10));
            fpBtn.setFont(new Font("SansSerif", Font.PLAIN, 10));
            copyBtn.setFont(new Font("SansSerif", Font.PLAIN, 10));
            add(realBtn);
            add(fpBtn);
            add(copyBtn);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());
            return this;
        }
    }

    private class ReviewActionCellEditor extends AbstractCellEditor implements TableCellEditor {
        private final JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 4, 0));
        private final JButton realBtn = new JButton("✅ Real Finding");
        private final JButton fpBtn = new JButton("❌ False Positive");
        private final JButton copyBtn = new JButton("Copy PoC curl");
        private int editingRow = -1;

        ReviewActionCellEditor() {
            realBtn.setFont(new Font("SansSerif", Font.PLAIN, 10));
            fpBtn.setFont(new Font("SansSerif", Font.PLAIN, 10));
            copyBtn.setFont(new Font("SansSerif", Font.PLAIN, 10));
            panel.add(realBtn);
            panel.add(fpBtn);
            panel.add(copyBtn);

            realBtn.addActionListener(e -> {
                if (editingRow >= 0 && editingRow < reviewTable.getRowCount()) {
                    reviewTable.setRowSelectionInterval(editingRow, editingRow);
                    markSelectedReviewAsReal();
                }
                fireEditingStopped();
            });

            fpBtn.addActionListener(e -> {
                if (editingRow >= 0 && editingRow < reviewTable.getRowCount()) {
                    reviewTable.setRowSelectionInterval(editingRow, editingRow);
                    markSelectedReviewAsFalsePositive();
                }
                fireEditingStopped();
            });

            copyBtn.addActionListener(e -> {
                AcasFinding finding = rowToReviewFinding(editingRow);
                if (finding != null) {
                    copyCurlToClipboard(finding, copyBtn);
                }
                fireEditingStopped();
            });
        }

        @Override
        public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
            editingRow = row;
            return panel;
        }

        @Override
        public Object getCellEditorValue() {
            return "";
        }
    }

    private AcasFinding rowToReviewFinding(int row) {
        int backingIdx = displayReviewFindings.size() - 1 - row;
        if (backingIdx < 0 || backingIdx >= displayReviewFindings.size()) return null;
        return displayReviewFindings.get(backingIdx);
    }
}
