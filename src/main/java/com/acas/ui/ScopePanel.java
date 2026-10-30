package com.acas.ui;

import com.acas.model.ScopeConfig;
import com.acas.store.ActorStore;
import com.acas.util.IdParameterDetector;
import burp.api.montoya.MontoyaApi;


import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class ScopePanel extends JPanel {


    private final MontoyaApi api;
    private final ActorStore store;

    private final JCheckBox useBurpScope = new JCheckBox("Use Burp Target Scope");
    private final JTextArea includeArea = new JTextArea(4, 30);
    private final JTextArea excludeArea = new JTextArea(4, 30);
    private final JCheckBox filterGet = new JCheckBox("GET", true);
    private final JCheckBox filterPost = new JCheckBox("POST", true);
    private final JCheckBox filterPut = new JCheckBox("PUT", false);
    private final JCheckBox filterDelete = new JCheckBox("DELETE", false);
    private final JCheckBox filterPatch = new JCheckBox("PATCH", false);
    private final JCheckBox filterIdParams = new JCheckBox("Only test requests with ID-type parameters (IDOR focus)");
    private final JTextArea customParamsArea = new JTextArea(2, 30);

    public ScopePanel(MontoyaApi api, ActorStore store) {
        this.api = api;
        this.store = store;
        includeArea.setFont(AcasTheme.MONO);
        excludeArea.setFont(AcasTheme.MONO);
        customParamsArea.setFont(AcasTheme.MONO);
        setLayout(new BorderLayout(0, 0));
        add(buildTopBar(), BorderLayout.NORTH);
        add(new JScrollPane(buildForm()), BorderLayout.CENTER);
        add(buildButtons(), BorderLayout.SOUTH);
        loadConfig();
    }

    private JComponent buildTopBar() {
        JPanel wrap = new JPanel();
        wrap.setLayout(new BoxLayout(wrap, BoxLayout.Y_AXIS));
        JPanel row = new JPanel(new BorderLayout());
        row.setBorder(new EmptyBorder(6, 14, 4, 14));
        row.add(AcasTheme.sectionTitle("Scope & Targeting"), BorderLayout.WEST);
        JLabel sub = new JLabel("Control which requests ACAS auto-tests ");
        sub.setFont(AcasTheme.UI_SMALL);
        sub.setForeground(AcasTheme.MUTED);
        row.add(sub, BorderLayout.EAST);
        wrap.add(row);
        wrap.add(AcasTheme.accentDivider());
        return wrap;
    }

    private JPanel buildForm() {
        JPanel form = new JPanel();
        form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
        form.setBorder(new EmptyBorder(12, 16, 12, 16));

        // Burp scope
        JPanel burpScopePanel = card("Burp Integration");
        burpScopePanel.add(useBurpScope);
        JLabel note = new JLabel("  When enabled, ACAS respects your Burp Target Scope settings.");
        note.setFont(new Font("SansSerif", Font.ITALIC, 11));
        burpScopePanel.add(note);
        form.add(burpScopePanel);
        form.add(Box.createVerticalStrut(10));

        // URL patterns
        JPanel urlPanel = card("URL Patterns (one per line, supports * wildcards)");
        urlPanel.add(new JLabel("Include:") {{ setFont(new Font("SansSerif", Font.BOLD, 11)); }});
        urlPanel.add(new JScrollPane(includeArea));
        urlPanel.add(Box.createVerticalStrut(6));
        urlPanel.add(new JLabel("Exclude:") {{ setFont(new Font("SansSerif", Font.BOLD, 11)); }});
        urlPanel.add(new JScrollPane(excludeArea));
        form.add(urlPanel);
        form.add(Box.createVerticalStrut(10));

        // Methods
        JPanel methodPanel = card("HTTP Methods to Test");
        JPanel methodRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        for (JCheckBox cb : new JCheckBox[]{filterGet, filterPost, filterPut, filterDelete, filterPatch}) {
            methodRow.add(cb);
        }
        methodPanel.add(methodRow);
        form.add(methodPanel);
        form.add(Box.createVerticalStrut(10));

        // IDOR params
        JPanel idorPanel = card("IDOR Parameter Filtering");
        idorPanel.add(filterIdParams);
        JLabel paramLabel = new JLabel("Additional ID parameter names (comma separated):");
        paramLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        paramLabel.setBorder(new EmptyBorder(6, 0, 2, 0));
        idorPanel.add(paramLabel);
        idorPanel.add(new JScrollPane(customParamsArea));
        form.add(idorPanel);

        return form;
    }

    private JPanel buildButtons() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        JButton save = new JButton("Save Scope");
        JButton reset = new JButton("Reset Defaults");
        AcasTheme.styleButton(save);
        AcasTheme.styleButton(reset);
        save.addActionListener(e -> saveConfig());
        reset.addActionListener(e -> resetDefaults());
        p.add(reset);
        p.add(save);
        return p;
    }

    private void saveConfig() {
        ScopeConfig cfg = new ScopeConfig();
        cfg.setUseBurpScope(useBurpScope.isSelected());
        cfg.setIncludePatterns(Arrays.stream(includeArea.getText().split("\n"))
            .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList()));
        cfg.setExcludePatterns(Arrays.stream(excludeArea.getText().split("\n"))
            .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList()));
        List<String> methods = new ArrayList<>();
        if (filterGet.isSelected()) methods.add("GET");
        if (filterPost.isSelected()) methods.add("POST");
        if (filterPut.isSelected()) methods.add("PUT");
        if (filterDelete.isSelected()) methods.add("DELETE");
        if (filterPatch.isSelected()) methods.add("PATCH");
        cfg.setMethods(methods);
        cfg.setFilterIdParameters(filterIdParams.isSelected());
        cfg.setCustomIdParams(Arrays.stream(customParamsArea.getText().split(","))
            .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList()));
        store.saveScopeConfig(cfg);
        JOptionPane.showMessageDialog(this, "Scope configuration saved.", "Saved", JOptionPane.INFORMATION_MESSAGE);
    }

    private void loadConfig() {
        ScopeConfig cfg = store.getScopeConfig();
        useBurpScope.setSelected(cfg.isUseBurpScope());
        includeArea.setText(String.join("\n", cfg.getIncludePatterns()));
        excludeArea.setText(String.join("\n", cfg.getExcludePatterns()));
        filterGet.setSelected(cfg.getMethods().contains("GET"));
        filterPost.setSelected(cfg.getMethods().contains("POST"));
        filterPut.setSelected(cfg.getMethods().contains("PUT"));
        filterDelete.setSelected(cfg.getMethods().contains("DELETE"));
        filterPatch.setSelected(cfg.getMethods().contains("PATCH"));
        filterIdParams.setSelected(cfg.isFilterIdParameters());
        customParamsArea.setText(String.join(", ", cfg.getCustomIdParams()));
    }

    private void resetDefaults() {
        store.saveScopeConfig(new ScopeConfig());
        loadConfig();
    }

    public boolean isInScope(burp.api.montoya.http.message.requests.HttpRequest request) {
        ScopeConfig cfg = store.getScopeConfig();
        if (cfg.isUseBurpScope()) {
            try { if (!api.scope().isInScope(request.url())) return false; } catch (Exception ignored) {}
        }
        String method = request.method();
        if (!cfg.getMethods().contains(method)) return false;
        if (cfg.isFilterIdParameters() && !IdParameterDetector.hasIdParameters(request)) return false;
        String url = request.url();
        for (String ex : cfg.getExcludePatterns()) {
            if (matchesPattern(url, ex)) return false;
        }
        if (!cfg.getIncludePatterns().isEmpty()) {
            return cfg.getIncludePatterns().stream().anyMatch(p -> matchesPattern(url, p));
        }
        return true;
    }

    private boolean matchesPattern(String url, String pattern) {
        String regex = pattern.replace(".", "\\.").replace("*", ".*");
        try { return url.matches(".*" + regex + ".*"); } catch (Exception e) { return false; }
    }

    private JPanel card(String title) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        javax.swing.border.TitledBorder tb = BorderFactory.createTitledBorder(title);
        tb.setTitleColor(AcasTheme.ACCENT);
        tb.setTitleFont(AcasTheme.UI_BOLD);
        p.setBorder(BorderFactory.createCompoundBorder(tb, new EmptyBorder(6, 8, 8, 8)));
        p.setAlignmentX(LEFT_ALIGNMENT);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, p.getPreferredSize().height + 200));
        return p;
    }
}
