package com.acas.ui;

import burp.api.montoya.MontoyaApi;
import com.acas.engine.HuntManager;
import com.acas.engine.MatchReplaceRule;
import com.acas.engine.MutationRegistry;
import com.acas.store.PayloadStore;

import javax.swing.*;
import javax.swing.event.ChangeListener;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

public class HuntOptionsPanel extends JPanel {

    private final MontoyaApi api;
    private final MutationRegistry registry;
    private final PayloadStore payloadStore;
    private final HuntManager huntManager;
    private final java.util.List<Runnable> matchReplaceReloaders = new java.util.ArrayList<>();

    public HuntOptionsPanel(MontoyaApi api, MutationRegistry registry, PayloadStore payloadStore, HuntManager huntManager) {
        this.api = api;
        this.registry = registry;
        this.payloadStore = payloadStore;
        this.huntManager = huntManager;

        setLayout(new BorderLayout());

        // Tabbed interface
        JTabbedPane tabs = new JTabbedPane();
        tabs.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        tabs.setBorder(null);

        // Tab 1: Mutations (with integrated payload editor)
        MutationsPanel mutationsPanel = new MutationsPanel(registry, payloadStore);
        tabs.addTab("Mutations", mutationsPanel);

        // Tab 2: Hunt Settings
        JPanel settingsPanel = buildSettingsPanel();
        tabs.addTab("Options", settingsPanel);

        // Tab 3: Match & Replace Rules (with Simple/Advanced modes)
        tabs.addTab("Match & Replace", buildMatchReplaceContainer());

        add(tabs, BorderLayout.CENTER);
    }

    private JPanel buildSettingsPanel() {
        JPanel root = new JPanel(new BorderLayout(10, 10));
        root.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));

        JPanel confidenceCard = new JPanel(new GridBagLayout());
        confidenceCard.setBorder(BorderFactory.createTitledBorder("Confidence Thresholds"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;

        JSlider discardSlider = new JSlider(0, 100, huntManager.getDiscardThreshold());
        JSlider reviewSlider = new JSlider(0, 100, huntManager.getReviewThreshold());
        JSlider autoConfirmSlider = new JSlider(0, 100, huntManager.getAutoConfirmThreshold());

        JLabel discardValue = new JLabel(String.valueOf(discardSlider.getValue()));
        JLabel reviewValue = new JLabel(String.valueOf(reviewSlider.getValue()));
        JLabel autoValue = new JLabel(String.valueOf(autoConfirmSlider.getValue()));

        addThresholdRow(confidenceCard, gbc, "Discard below:", discardSlider, discardValue,
            "(findings below this score are silently dropped)");
        addThresholdRow(confidenceCard, gbc, "Review Queue below:", reviewSlider, reviewValue,
            "(findings below this go to Review Queue)");
        addThresholdRow(confidenceCard, gbc, "Auto-confirm above:", autoConfirmSlider, autoValue,
            "(findings above this go straight to Confirmed with CERTAIN confidence)");

        ChangeListener syncListener = e -> {
            enforceThresholdOrder(discardSlider, reviewSlider, autoConfirmSlider);
            discardValue.setText(String.valueOf(discardSlider.getValue()));
            reviewValue.setText(String.valueOf(reviewSlider.getValue()));
            autoValue.setText(String.valueOf(autoConfirmSlider.getValue()));
            huntManager.setConfidenceThresholds(
                discardSlider.getValue(),
                reviewSlider.getValue(),
                autoConfirmSlider.getValue()
            );
        };

        discardSlider.addChangeListener(syncListener);
        reviewSlider.addChangeListener(syncListener);
        autoConfirmSlider.addChangeListener(syncListener);

        JPanel baselineCard = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 8));
        baselineCard.setBorder(BorderFactory.createTitledBorder("Baseline Cache"));
        JLabel ttlLabel = new JLabel("Baseline TTL (minutes):");
        JSpinner ttlSpinner = new JSpinner(new SpinnerNumberModel(huntManager.getBaselineTtlMinutes(), 1, 60, 1));
        ttlSpinner.addChangeListener(e -> {
            int ttl = ((Number) ttlSpinner.getValue()).intValue();
            huntManager.setBaselineTtlMinutes(ttl);
        });
        baselineCard.add(ttlLabel);
        baselineCard.add(ttlSpinner);

        content.add(confidenceCard);
        content.add(Box.createVerticalStrut(10));
        content.add(baselineCard);

        root.add(content, BorderLayout.NORTH);
        return root;
    }

    private void addThresholdRow(JPanel panel,
                                 GridBagConstraints gbc,
                                 String title,
                                 JSlider slider,
                                 JLabel valueLabel,
                                 String help) {
        JPanel row = new JPanel(new BorderLayout(8, 2));
        JLabel titleLabel = new JLabel(title);
        titleLabel.setPreferredSize(new Dimension(150, 20));
        row.add(titleLabel, BorderLayout.WEST);
        row.add(slider, BorderLayout.CENTER);
        valueLabel.setPreferredSize(new Dimension(36, 20));
        row.add(valueLabel, BorderLayout.EAST);

        JPanel wrap = new JPanel(new BorderLayout());
        wrap.add(row, BorderLayout.NORTH);
        JLabel helper = new JLabel(help);
        helper.setFont(new Font("SansSerif", Font.PLAIN, 11));
        helper.setForeground(new Color(130, 130, 130));
        wrap.add(helper, BorderLayout.SOUTH);

        panel.add(wrap, gbc);
        gbc.gridy++;
    }

    private void enforceThresholdOrder(JSlider discard, JSlider review, JSlider autoConfirm) {
        if (discard.getValue() >= review.getValue()) {
            review.setValue(Math.min(100, discard.getValue() + 10));
        }
        if (review.getValue() >= autoConfirm.getValue()) {
            autoConfirm.setValue(Math.min(100, review.getValue() + 10));
        }
    }

    private JPanel buildMatchReplaceContainer() {
        JPanel root = new JPanel(new BorderLayout());
        
        JTabbedPane modeTabs = new JTabbedPane();
        modeTabs.setBorder(null);
        modeTabs.addTab("Simple", buildMatchReplacePanel());
        modeTabs.addTab("Advanced", buildMatchReplaceAdvanced());
        
        root.add(modeTabs, BorderLayout.CENTER);
        return root;
    }

    private JPanel buildMatchReplacePanel() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JTextArea intro = new JTextArea("Enter text to find and text to replace it with. Click 'Replace' to add.");
        intro.setEditable(false);
        intro.setOpaque(false);
        intro.setLineWrap(true);
        intro.setWrapStyleWord(true);
        intro.setFont(new Font("SansSerif", Font.PLAIN, 12));
        root.add(intro, BorderLayout.NORTH);

        DefaultTableModel model = new DefaultTableModel(
            new Object[]{"Enabled", "Find", "Replace With"}, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Boolean.class : String.class;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0;
            }
        };
        JTable table = new JTable(model);
        table.setRowHeight(22);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane scroll = new JScrollPane(table);
        root.add(scroll, BorderLayout.CENTER);

        final boolean[] reloading = new boolean[]{false};
        Runnable reload = () -> {
            reloading[0] = true;
            model.setRowCount(0);
            java.util.List<MatchReplaceRule> currentRules = registry.getMatchReplaceRules();
            for (MatchReplaceRule r : currentRules) {
                model.addRow(new Object[]{
                    r.enabled,
                    r.pattern,
                    displayReplacement(r.replacement)
                });
            }
            reloading[0] = false;
        };
        matchReplaceReloaders.add(reload);
        reload.run();

        model.addTableModelListener(e -> {
            if (reloading[0]) {
                return;
            }
            if (e.getFirstRow() >= 0 && e.getColumn() == 0) {
                java.util.List<MatchReplaceRule> rules = registry.getMatchReplaceRules();
                if (e.getFirstRow() < rules.size()) {
                    rules.get(e.getFirstRow()).enabled = Boolean.TRUE.equals(model.getValueAt(e.getFirstRow(), 0));
                    registry.replaceMatchReplaceRules(rules);
                    reloadAllMatchReplaceTables();
                }
            }
        });

        JPanel form = new JPanel(new GridLayout(1, 2, 6, 6));
        JTextField findField = new JTextField();
        JTextField replaceField = new JTextField();

        form.add(findField);
        form.add(replaceField);

        JPanel labels = new JPanel(new GridLayout(1, 2, 6, 6));
        labels.add(new JLabel("Find:"));
        labels.add(new JLabel("Replace with:"));

        JPanel south = new JPanel(new BorderLayout(6, 6));
        south.add(labels, BorderLayout.NORTH);
        south.add(form, BorderLayout.CENTER);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton replaceBtn = new JButton("Replace");
        JButton removeBtn = new JButton("Remove Selected");

        replaceBtn.addActionListener(e -> {
            String find = findField.getText() != null ? findField.getText().trim() : "";
            if (find.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Find text is required.", "ACAS Find & Replace", JOptionPane.WARNING_MESSAGE);
                return;
            }
            java.util.List<MatchReplaceRule> rules = new java.util.ArrayList<>(registry.getMatchReplaceRules());
            MatchReplaceRule rule = new MatchReplaceRule(
                "Rule " + (rules.size() + 1),
                MatchReplaceRule.Target.BODY,
                MatchReplaceRule.MatchType.CONTAINS,
                MatchReplaceRule.Scope.ALL,
                true,
                find,
                replaceField.getText() != null ? replaceField.getText() : ""
            );
            rules.add(rule);
            registry.replaceMatchReplaceRules(rules);
            reloadAllMatchReplaceTables();
            findField.setText("");
            replaceField.setText("");
        });

        removeBtn.addActionListener(e -> {
            int row = table.getSelectedRow();
            java.util.List<MatchReplaceRule> rules = registry.getMatchReplaceRules();
            if (row < 0 || row >= rules.size()) {
                return;
            }
            rules.remove(row);
            registry.replaceMatchReplaceRules(rules);
            reloadAllMatchReplaceTables();
        });

        actions.add(replaceBtn);
        actions.add(removeBtn);
        south.add(actions, BorderLayout.SOUTH);
        root.add(south, BorderLayout.SOUTH);

        return root;
    }

    private JPanel buildMatchReplaceAdvanced() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JTextArea intro = new JTextArea("Advanced mode: Choose where, how, and what to replace.\n"
            + "Supports regex patterns and scoped replacements.");
        intro.setEditable(false);
        intro.setOpaque(false);
        intro.setLineWrap(true);
        intro.setWrapStyleWord(true);
        intro.setFont(new Font("SansSerif", Font.PLAIN, 12));
        root.add(intro, BorderLayout.NORTH);

        DefaultTableModel model = new DefaultTableModel(
            new Object[]{"Enabled", "Target", "Mode", "Match", "Replace"}, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Boolean.class : String.class;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0;
            }
        };
        JTable table = new JTable(model);
        table.setRowHeight(22);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane scroll = new JScrollPane(table);
        root.add(scroll, BorderLayout.CENTER);

        final boolean[] reloading = new boolean[]{false};
        Runnable reload = () -> {
            reloading[0] = true;
            model.setRowCount(0);
            java.util.List<MatchReplaceRule> currentRules = registry.getMatchReplaceRules();
            for (MatchReplaceRule r : currentRules) {
                model.addRow(new Object[]{
                    r.enabled,
                    friendlyTarget(r.target),
                    r.matchType == MatchReplaceRule.MatchType.REGEX ? "Regex" : "Text",
                    r.pattern,
                    displayReplacement(r.replacement)
                });
            }
            reloading[0] = false;
        };
        matchReplaceReloaders.add(reload);
        reload.run();

        model.addTableModelListener(e -> {
            if (reloading[0]) {
                return;
            }
            if (e.getFirstRow() >= 0 && e.getColumn() == 0) {
                java.util.List<MatchReplaceRule> rules = registry.getMatchReplaceRules();
                if (e.getFirstRow() < rules.size()) {
                    rules.get(e.getFirstRow()).enabled = Boolean.TRUE.equals(model.getValueAt(e.getFirstRow(), 0));
                    registry.replaceMatchReplaceRules(rules);
                    reloadAllMatchReplaceTables();
                }
            }
        });

        JPanel form = new JPanel(new GridLayout(2, 5, 6, 6));
        JComboBox<MatchReplaceRule.Target> targetBox = new JComboBox<>(new MatchReplaceRule.Target[]{
            MatchReplaceRule.Target.PATH,
            MatchReplaceRule.Target.QUERY_VALUE,
            MatchReplaceRule.Target.BODY,
            MatchReplaceRule.Target.HEADER_VALUE
        });
        JTextField patternField = new JTextField();
        JTextField replaceField = new JTextField();
        JCheckBox regexBox = new JCheckBox("Use regex", false);
        JCheckBox firstOnlyBox = new JCheckBox("Replace first only", false);
        JCheckBox enableFiltersBox = new JCheckBox("Enable request filters", false);
        JTextField includeUrlRegexField = new JTextField();
        JTextField excludeUrlRegexField = new JTextField();
        JTextField methodsField = new JTextField();

        form.add(targetBox);
        form.add(patternField);
        form.add(replaceField);
        form.add(regexBox);
        form.add(firstOnlyBox);

        JPanel labels = new JPanel(new GridLayout(1, 5, 6, 6));
        labels.add(new JLabel("Target"));
        labels.add(new JLabel("Match text"));
        labels.add(new JLabel("Replace with"));
        labels.add(new JLabel("Mode"));
        labels.add(new JLabel("Scope"));

        JPanel filterPanel = new JPanel(new GridLayout(3, 2, 6, 6));
        filterPanel.setBorder(BorderFactory.createTitledBorder("Interception Filters"));
        filterPanel.add(enableFiltersBox);
        filterPanel.add(new JLabel("Enable include/exclude URL and method filters"));
        filterPanel.add(new JLabel("Include URL regex:"));
        filterPanel.add(includeUrlRegexField);
        filterPanel.add(new JLabel("Exclude URL regex:"));
        filterPanel.add(excludeUrlRegexField);

        JPanel methodPanel = new JPanel(new BorderLayout(6, 0));
        methodPanel.add(new JLabel("Methods (comma-separated):"), BorderLayout.WEST);
        methodPanel.add(methodsField, BorderLayout.CENTER);

        JPanel south = new JPanel(new BorderLayout(6, 6));
        south.add(labels, BorderLayout.NORTH);
        south.add(form, BorderLayout.CENTER);
        south.add(filterPanel, BorderLayout.SOUTH);

        JPanel lower = new JPanel(new BorderLayout(6, 6));
        lower.add(south, BorderLayout.CENTER);
        lower.add(methodPanel, BorderLayout.SOUTH);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton addBtn = new JButton("Add Rule");
        JButton removeBtn = new JButton("Remove Selected");
        JButton previewBtn = new JButton("Preview Rule");

        addBtn.addActionListener(e -> {
            String pattern = patternField.getText() != null ? patternField.getText().trim() : "";
            if (pattern.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Match text is required.", "ACAS Advanced Mode", JOptionPane.WARNING_MESSAGE);
                return;
            }
            MatchReplaceRule.MatchType matchType = regexBox.isSelected()
                ? MatchReplaceRule.MatchType.REGEX
                : MatchReplaceRule.MatchType.CONTAINS;
            MatchReplaceRule.Scope scope = firstOnlyBox.isSelected()
                ? MatchReplaceRule.Scope.FIRST
                : MatchReplaceRule.Scope.ALL;

            java.util.List<MatchReplaceRule> rules = new java.util.ArrayList<>(registry.getMatchReplaceRules());
            MatchReplaceRule rule = new MatchReplaceRule(
                "Rule " + (rules.size() + 1),
                (MatchReplaceRule.Target) targetBox.getSelectedItem(),
                matchType,
                scope,
                true,
                pattern,
                replaceField.getText() != null ? replaceField.getText() : ""
            );
            rule.useRequestFilters = enableFiltersBox.isSelected();
            rule.includeUrlRegex = includeUrlRegexField.getText() != null ? includeUrlRegexField.getText().trim() : "";
            rule.excludeUrlRegex = excludeUrlRegexField.getText() != null ? excludeUrlRegexField.getText().trim() : "";
            rule.allowedMethodsCsv = methodsField.getText() != null ? methodsField.getText().trim() : "";
            rules.add(rule);
            registry.replaceMatchReplaceRules(rules);
            reloadAllMatchReplaceTables();
            patternField.setText("");
            replaceField.setText("");
            regexBox.setSelected(false);
            firstOnlyBox.setSelected(false);
            enableFiltersBox.setSelected(false);
            includeUrlRegexField.setText("");
            excludeUrlRegexField.setText("");
            methodsField.setText("");
        });

        removeBtn.addActionListener(e -> {
            int row = table.getSelectedRow();
            java.util.List<MatchReplaceRule> rules = registry.getMatchReplaceRules();
            if (row < 0 || row >= rules.size()) {
                return;
            }
            rules.remove(row);
            registry.replaceMatchReplaceRules(rules);
            reloadAllMatchReplaceTables();
        });

        previewBtn.addActionListener(e -> {
            String sample = JOptionPane.showInputDialog(this, "Enter sample text to preview:", "ACAS Advanced Preview", JOptionPane.PLAIN_MESSAGE);
            if (sample == null) return;

            MatchReplaceRule.MatchType matchType = regexBox.isSelected()
                ? MatchReplaceRule.MatchType.REGEX
                : MatchReplaceRule.MatchType.CONTAINS;
            MatchReplaceRule.Scope scope = firstOnlyBox.isSelected()
                ? MatchReplaceRule.Scope.FIRST
                : MatchReplaceRule.Scope.ALL;

            MatchReplaceRule preview = new MatchReplaceRule(
                "Preview",
                (MatchReplaceRule.Target) targetBox.getSelectedItem(),
                matchType,
                scope,
                true,
                patternField.getText(),
                replaceField.getText()
            );
            preview.useRequestFilters = enableFiltersBox.isSelected();
            preview.includeUrlRegex = includeUrlRegexField.getText() != null ? includeUrlRegexField.getText().trim() : "";
            preview.excludeUrlRegex = excludeUrlRegexField.getText() != null ? excludeUrlRegexField.getText().trim() : "";
            preview.allowedMethodsCsv = methodsField.getText() != null ? methodsField.getText().trim() : "";
            String out = previewApply(sample, preview);
            JTextArea area = new JTextArea("Before:\n" + sample + "\n\nAfter:\n" + out);
            area.setEditable(false);
            area.setFont(new Font("Monospaced", Font.PLAIN, 12));
            JOptionPane.showMessageDialog(this, new JScrollPane(area), "ACAS Advanced Preview", JOptionPane.INFORMATION_MESSAGE);
        });

        actions.add(previewBtn);
        actions.add(addBtn);
        actions.add(removeBtn);
        lower.add(actions, BorderLayout.NORTH);
        root.add(lower, BorderLayout.SOUTH);

        return root;
    }

    private void reloadAllMatchReplaceTables() {
        for (Runnable reloader : matchReplaceReloaders) {
            reloader.run();
        }
    }

    private String displayReplacement(String replacement) {
        if (replacement == null || replacement.isEmpty()) {
            return "(empty)";
        }
        return replacement;
    }

    private String friendlyTarget(MatchReplaceRule.Target target) {
        if (target == null) {
            return "Path";
        }
        switch (target) {
            case QUERY_KEY:
                return "Query Key";
            case QUERY_VALUE:
                return "Query Value";
            case HEADER_NAME:
                return "Header Name";
            case HEADER_VALUE:
                return "Header Value";
            case BODY:
                return "Body";
            case PATH:
            default:
                return "Path";
        }
    }

    private String previewApply(String source, MatchReplaceRule rule) {
        if (source == null || rule == null || rule.pattern == null || rule.pattern.trim().isEmpty()) {
            return source;
        }
        String replacement = rule.replacement != null ? rule.replacement : "";
        switch (rule.matchType) {
            case EXACT:
                if (rule.caseSensitive) {
                    return source.equals(rule.pattern) ? replacement : source;
                }
                return source.equalsIgnoreCase(rule.pattern) ? replacement : source;
            case REGEX:
                try {
                    int flags = rule.caseSensitive ? 0 : java.util.regex.Pattern.CASE_INSENSITIVE;
                    java.util.regex.Pattern p = java.util.regex.Pattern.compile(rule.pattern, flags);
                    java.util.regex.Matcher m = p.matcher(source);
                    return rule.scope == MatchReplaceRule.Scope.FIRST ? m.replaceFirst(replacement) : m.replaceAll(replacement);
                } catch (Exception ex) {
                    return source;
                }
            case CONTAINS:
            default:
                if (rule.caseSensitive) {
                    return rule.scope == MatchReplaceRule.Scope.FIRST
                        ? source.replaceFirst(java.util.regex.Pattern.quote(rule.pattern), java.util.regex.Matcher.quoteReplacement(replacement))
                        : source.replace(rule.pattern, replacement);
                }
                java.util.regex.Pattern p = java.util.regex.Pattern.compile(java.util.regex.Pattern.quote(rule.pattern), java.util.regex.Pattern.CASE_INSENSITIVE);
                java.util.regex.Matcher m = p.matcher(source);
                return rule.scope == MatchReplaceRule.Scope.FIRST
                    ? m.replaceFirst(java.util.regex.Matcher.quoteReplacement(replacement))
                    : m.replaceAll(java.util.regex.Matcher.quoteReplacement(replacement));
        }
    }
}

