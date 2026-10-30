package com.acas.ui;

import burp.api.montoya.MontoyaApi;
import com.acas.model.CapturedEndpoint;
import com.acas.model.AcasFinding;
import com.acas.model.ActorProfile;
import com.acas.store.ActorStore;
import com.acas.notification.NotificationService;
import com.acas.util.CurlGenerator;
import com.acas.util.ReportGenerator;
import com.acas.util.ResponseDiffUtil;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.text.DefaultHighlighter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.Toolkit;
import java.net.URI;
import java.util.List;

public class FindingDetailDialog extends JDialog {

    private final MontoyaApi api;
    private final ActorStore store;
    private final NotificationService notifier;
    private AcasFinding currentFinding;

    public FindingDetailDialog(Window parent, MontoyaApi api, ActorStore store, NotificationService notifier, CapturedEndpoint endpoint) {
        super(parent, "🔬 Finding Inspection: " + endpoint.getNormalizedPath(), ModalityType.MODELESS);
        this.api = api;
        this.store = store;
        this.notifier = notifier;
        this.currentFinding = null;

        initUI(endpoint.getNormalizedPath(),
               endpoint.getPriorityScore(),
               endpoint.getClassificationLabel(),
               ReportGenerator.generateMarkdown(endpoint, store.getAllActors()));
    }

    public FindingDetailDialog(Window parent, MontoyaApi api, ActorStore store, NotificationService notifier, AcasFinding finding) {
        super(parent, "🔬 Sync Finding: " + finding.getUrl(), ModalityType.MODELESS);
        this.api = api;
        this.store = store;
        this.notifier = notifier;
        this.currentFinding = finding;

        initFindingUI(finding);
    }

    private void initFindingUI(AcasFinding finding) {
        setLayout(new BorderLayout());

        JPanel topToolbar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 6));
        JButton copyCurlBtn = new JButton("📋 Copy PoC curl");
        copyCurlBtn.addActionListener(e -> copyPocCurl(copyCurlBtn));
        topToolbar.add(copyCurlBtn);
        add(topToolbar, BorderLayout.NORTH);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Report", buildReportPanel(
            finding.getUrl(),
            mapSeverityToScore(finding.getSeverity()),
            finding.getLabel(),
            ReportGenerator.generateMarkdown(finding)));
        tabs.addTab("Response Diff", buildResponseDiffPanel(finding));

        add(tabs, BorderLayout.CENTER);
        add(buildFooter(ReportGenerator.generateMarkdown(finding)), BorderLayout.SOUTH);

        setSize(1000, 760);
        Window owner = getOwner();
        if (owner != null) setLocationRelativeTo(owner);
    }

    private void copyPocCurl(JButton sourceButton) {
        if (currentFinding == null || currentFinding.getMutatedRequest() == null) {
            return;
        }

        String scheme = "https";
        String host = "";
        try {
            if (currentFinding.getUrl() != null && !currentFinding.getUrl().isBlank()) {
                URI uri = URI.create(currentFinding.getUrl());
                if (uri.getScheme() != null && !uri.getScheme().isBlank()) {
                    scheme = uri.getScheme();
                }
                if (uri.getHost() != null && !uri.getHost().isBlank()) {
                    host = uri.getHost();
                }
            }
        } catch (Exception ignored) {
        }

        HttpRequest request = HttpRequest.httpRequest(ByteArray.byteArray(currentFinding.getMutatedRequest()));
        String curl = CurlGenerator.generateCurl(request, scheme, host);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(curl), null);

        String old = sourceButton.getToolTipText();
        sourceButton.setToolTipText("PoC curl copied to clipboard ✓");
        ToolTipManager.sharedInstance().setInitialDelay(0);
        java.awt.event.MouseEvent phantom = new java.awt.event.MouseEvent(sourceButton,
            java.awt.event.MouseEvent.MOUSE_MOVED,
            System.currentTimeMillis(), 0, 1, 1, 0, false);
        ToolTipManager.sharedInstance().mouseMoved(phantom);

        Timer t = new Timer(2000, e -> {
            sourceButton.setToolTipText(old);
            ((Timer) e.getSource()).stop();
        });
        t.setRepeats(false);
        t.start();
    }

    private void initUI(String path, int score, String label, String reportContent) {
        setLayout(new BorderLayout());
        add(buildReportPanel(path, score, label, reportContent), BorderLayout.CENTER);
        add(buildFooter(reportContent), BorderLayout.SOUTH);

        setSize(700, 750);
        Window owner = getOwner();
        if (owner != null) setLocationRelativeTo(owner);
    }

    private JComponent buildReportPanel(String path, int score, String label, String reportContent) {
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(new EmptyBorder(15, 15, 15, 15));

        // 1. Priority Section
        mainPanel.add(buildSectionHeader("📊 Priority Scoring (" + score + "/100)"));
        mainPanel.add(createHtmlViewer(getPriorityExplanation(score)));
        mainPanel.add(Box.createVerticalStrut(15));

        // 2. Classification Section
        mainPanel.add(buildSectionHeader("🛡️ Vulnerability Classification: " + label));
        mainPanel.add(createHtmlViewer(getClassificationExplanation(label)));
        mainPanel.add(Box.createVerticalStrut(15));

        // 3. Report Section
        mainPanel.add(buildSectionHeader("📋 Investigative Bug Report"));
        JTextArea reportArea = new JTextArea(15, 50);
        reportArea.setText(reportContent);
        reportArea.setLineWrap(true);
        reportArea.setWrapStyleWord(true);
        reportArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        reportArea.setEditable(false);
        
        JScrollPane scroll = new JScrollPane(reportArea);
        mainPanel.add(scroll);

        return mainPanel;
    }

    private JPanel buildFooter(String reportContent) {
        JPanel footer = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton discordBtn = new JButton("🚀 Discord");
        JButton telegramBtn = new JButton("✈️ Telegram");
        JButton copyBtn = new JButton("📋 Copy Report");
        JButton closeBtn = new JButton("Close");

        copyBtn.addActionListener(e -> {
            StringSelection selection = new StringSelection(reportContent);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
            showStatus(copyBtn, "Copied!", "📋 Copy Report");
        });

        discordBtn.addActionListener(e -> NotificationFeedback.send(this, discordBtn,
            () -> notifier.sendDiscordReport(reportContent)));
        telegramBtn.addActionListener(e -> NotificationFeedback.send(this, telegramBtn,
            () -> notifier.sendTelegramReport(reportContent)));
        closeBtn.addActionListener(e -> dispose());
        
        footer.add(discordBtn);
        footer.add(telegramBtn);
        footer.add(copyBtn);
        footer.add(closeBtn);
                return footer;
    }

            private JComponent buildResponseDiffPanel(AcasFinding finding) {
                JPanel panel = new JPanel(new BorderLayout(8, 8));
                panel.setBorder(new EmptyBorder(10, 10, 10, 10));

                JLabel title = new JLabel("Left: Probe Response | Right: Owner Baseline Response");
                title.setFont(new Font("SansSerif", Font.BOLD, 12));
                panel.add(title, BorderLayout.NORTH);

                JTextArea leftArea = new JTextArea();
                JTextArea rightArea = new JTextArea();
                leftArea.setEditable(false);
                rightArea.setEditable(false);
                leftArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
                rightArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

                String probeBody = extractBody(finding.getMutatedResponse());
                String ownerBody = extractBody(finding.getBaseResponse());

                ResponseDiffUtil.DiffResult diff = ResponseDiffUtil.diff(probeBody, ownerBody);
                leftArea.setText(joinLines(diff.leftLines));
                rightArea.setText(joinLines(diff.rightLines));

                highlightDiff(leftArea, diff.leftLines, true);
                highlightDiff(rightArea, diff.rightLines, false);

                JScrollPane leftScroll = new JScrollPane(leftArea);
                JScrollPane rightScroll = new JScrollPane(rightArea);
                leftScroll.setBorder(BorderFactory.createTitledBorder("Probe Response"));
                rightScroll.setBorder(BorderFactory.createTitledBorder("Owner Baseline"));

                JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftScroll, rightScroll);
                split.setDividerLocation(0.5);
                split.setResizeWeight(0.5);

                panel.add(split, BorderLayout.CENTER);
                return panel;
            }

            private void highlightDiff(JTextArea area, List<ResponseDiffUtil.DiffLine> lines, boolean isProbeSide) {
                Color green = new Color(21, 128, 61, 40);
                Color red = new Color(153, 27, 27, 40);
                Color yellow = new Color(217, 119, 6, 40);

                int offset = 0;
                for (ResponseDiffUtil.DiffLine line : lines) {
                    int len = line.text.length();
                    Color color = null;

                    if (line.type == ResponseDiffUtil.DiffType.CHANGED) {
                        color = yellow;
                    } else if (line.type == ResponseDiffUtil.DiffType.ADDED && isProbeSide) {
                        color = green;
                    } else if (line.type == ResponseDiffUtil.DiffType.REMOVED && !isProbeSide) {
                        color = red;
                    }

                    if (color != null && len > 0) {
                        try {
                            area.getHighlighter().addHighlight(offset, offset + len,
                                new DefaultHighlighter.DefaultHighlightPainter(color));
                        } catch (Exception ignored) {
                        }
                    }
                    offset += len + 1;
                }
            }

            private String joinLines(List<ResponseDiffUtil.DiffLine> lines) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < lines.size(); i++) {
                    sb.append(lines.get(i).text);
                    if (i < lines.size() - 1) sb.append('\n');
                }
                return sb.toString();
            }

            private String extractBody(byte[] rawResponse) {
                if (rawResponse == null || rawResponse.length == 0) return "";
                String text = new String(rawResponse, java.nio.charset.StandardCharsets.ISO_8859_1);
                int idx = text.indexOf("\r\n\r\n");
                if (idx >= 0) return text.substring(idx + 4);
                idx = text.indexOf("\n\n");
                if (idx >= 0) return text.substring(idx + 2);
                return text;
            }

    private void showStatus(JButton button, String statusText, String originalText) {
        button.setText(statusText);
        button.setEnabled(false);
        new Timer(2000, e -> {
            button.setText(originalText);
            button.setEnabled(true);
        }).start();
    }

    private JComponent createHtmlViewer(String html) {
        JTextPane pane = new JTextPane();
        pane.setContentType("text/html");
        pane.setText("<html><body style='font-family: sans-serif; font-size: 10pt; color: #CCCCCC;'>" + html + "</body></html>");
        pane.setEditable(false);
        pane.setOpaque(false);
        pane.setBorder(null);
        pane.setMaximumSize(new Dimension(800, 40));
        pane.setAlignmentX(Component.LEFT_ALIGNMENT);
        return pane;
    }

    private JLabel buildSectionHeader(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("SansSerif", Font.BOLD, 14));
        label.setForeground(new Color(239, 99, 52)); // Burp Orange
        label.setBorder(new EmptyBorder(0, 0, 5, 0));
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        return label;
    }

    private String getPriorityExplanation(int score) {
        if (score >= 80) return "<b style='color: #ef4444;'>Critical Target:</b> This endpoint contains sensitive PII, authentication tokens, or administrative fields. A bypass here is high-impact.";
        if (score >= 60) return "<b style='color: #f59e0b;'>Sensitive Target:</b> This endpoint contains user-specific data or state information.";
        if (score >= 30) return "<b style='color: #6366f1;'>Standard Target:</b> Basic informational endpoint.";
        return "<b>Low Impact:</b> The target appears to be informational or generic.";
    }

    private int mapSeverityToScore(String severity) {
        if ("CRITICAL".equalsIgnoreCase(severity)) return 95;
        if ("HIGH".equalsIgnoreCase(severity)) return 85;
        if ("MEDIUM".equalsIgnoreCase(severity)) return 55;
        return 20;
    }

    private String getClassificationExplanation(String label) {
        if (label == null) return "<b>Unknown Label:</b> Investigation required.";
        if (label.contains("ANON_BROKEN")) return "<b>Anonymous Bypass:</b> Endpoint accessible WITHOUT authentication.";
        if (label.contains("HORIZ_BROKEN")) return "<b>Horizontal IDOR:</b> Accessing another user's data at the same role level.";
        if (label.contains("PRIV_ESC")) return "<b>Vertical Privilege Escalation:</b> Low-privileged account accessing Admin data.";
        if (label.contains("DATA_LEAK")) return "<b>Data Leak:</b> Unauthorized fields discovered in response.";
        return "<b>General Finding:</b> Authentication check failed or was bypassed.";
    }

    private String formatAcasFindingReport(AcasFinding f) {
        return ReportGenerator.generateMarkdown(f);
    }
}
