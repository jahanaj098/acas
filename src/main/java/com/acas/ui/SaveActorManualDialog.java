package com.acas.ui;

import com.acas.model.ActorProfile;
import com.acas.util.IdParameterDetector;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class SaveActorManualDialog extends JDialog {

    private boolean confirmed = false;
    private ActorProfile result;
    private final String fullRequest;
    private final String identitySourceUrl;

    private final JTextField nameField = new JTextField(20);
    private final JComboBox<String> roleCombo = new JComboBox<>(ActorProfile.ROLE_OPTIONS);
    private final JTable headerTable;
    private final DefaultTableModel headerModel;

    private String selectedColor = "#0a84ff";

    public SaveActorManualDialog(Frame parent, List<String[]> detectedHeaders, String capturedUrl, String fullRequest, int originalStatus) {
        this(parent, detectedHeaders, capturedUrl, fullRequest, originalStatus, null);
    }

    public SaveActorManualDialog(Frame parent, List<String[]> detectedHeaders, String capturedUrl, String fullRequest, int originalStatus, String suggestedActorName) {
        super(parent, "ACAS - Save Actor Profile (Manual)", true);
        this.fullRequest = fullRequest;
        this.identitySourceUrl = capturedUrl;

        if (suggestedActorName != null && !suggestedActorName.trim().isEmpty()) {
            nameField.setText(suggestedActorName.trim());
            nameField.selectAll();
        }

        headerModel = new DefaultTableModel(new Object[]{"Use", "Header", "Value"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0 || column == 1 || column == 2;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0) return Boolean.class;
                return String.class;
            }
        };
        headerTable = new JTable(headerModel);

        preloadHeaders(detectedHeaders);
        buildUI(capturedUrl, originalStatus);
        pack();
        setMinimumSize(new Dimension(760, 520));
        setLocationRelativeTo(parent);
    }

    private void preloadHeaders(List<String[]> detectedHeaders) {
        for (String[] h : detectedHeaders) {
            if (h == null || h.length < 2) continue;
            String name = h[0] != null ? h[0].trim() : "";
            String value = h[1] != null ? h[1].trim() : "";
            if (name.isEmpty()) continue;

            boolean defaultUse = IdParameterDetector.isAuthHeader(name) && !IdParameterDetector.isSkippableHeader(name);
            headerModel.addRow(new Object[]{defaultUse, name, value});
        }
    }

    private void buildUI(String url, int status) {
        JPanel root = new JPanel(new BorderLayout());

        JPanel banner = new JPanel(new BorderLayout());
        banner.setBorder(new EmptyBorder(12, 16, 8, 16));
        JLabel title = new JLabel("  Save Actor Profile (Manual Header Selection)");
        title.setFont(new Font("SansSerif", Font.BOLD, 15));
        banner.add(title, BorderLayout.NORTH);

        JLabel sub = new JLabel("Pick exactly which Cookie/Auth headers should identify this actor.");
        sub.setFont(new Font("SansSerif", Font.PLAIN, 11));
        banner.add(sub, BorderLayout.CENTER);

        if (status != 200 && status != 0) {
            JLabel warning = new JLabel("Warning: source request returned " + status + ". 200 OK is recommended.");
            warning.setForeground(new Color(180, 83, 9));
            warning.setFont(new Font("SansSerif", Font.BOLD, 11));
            banner.add(warning, BorderLayout.SOUTH);
        }

        JPanel meta = new JPanel(new GridBagLayout());
        meta.setBorder(new EmptyBorder(8, 16, 8, 16));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0;
        gbc.gridy = 0;
        meta.add(new JLabel("Actor Name:"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        meta.add(nameField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.NONE;
        meta.add(new JLabel("Privilege:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        roleCombo.setSelectedItem("User");
        roleCombo.setToolTipText("<html>Low → high privilege. ACAS uses this to tell escalation apart:<br>"
            + "a <b>lower</b> actor reaching a <b>higher</b> actor's resource is a privilege-escalation IDOR.<br>"
            + "Set one actor to <b>Super Admin</b> to enable the admin reference baseline.</html>");
        meta.add(roleCombo, gbc);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.fill = GridBagConstraints.NONE;
        meta.add(new JLabel("Color:"), gbc);
        gbc.gridx = 1;
        meta.add(buildColorPicker(), gbc);

        gbc.gridx = 0;
        gbc.gridy = 3;
        meta.add(new JLabel("Captured From:"), gbc);
        gbc.gridx = 1;
        JLabel urlLabel = new JLabel(url.length() > 90 ? url.substring(0, 90) + "..." : url);
        urlLabel.setFont(new Font("Monospaced", Font.PLAIN, 11));
        meta.add(urlLabel, gbc);

        JScrollPane headerScroll = new JScrollPane(headerTable);
        headerTable.setRowHeight(22);
        headerTable.getColumnModel().getColumn(0).setMaxWidth(50);
        headerTable.getColumnModel().getColumn(1).setPreferredWidth(220);
        headerTable.getColumnModel().getColumn(2).setPreferredWidth(420);

        JPanel tablePanel = new JPanel(new BorderLayout(0, 6));
        tablePanel.setBorder(new EmptyBorder(4, 16, 6, 16));
        JLabel tableTitle = new JLabel("Identity Headers/Cookies to Save");
        tableTitle.setFont(new Font("SansSerif", Font.BOLD, 12));
        tablePanel.add(tableTitle, BorderLayout.NORTH);
        tablePanel.add(headerScroll, BorderLayout.CENTER);

        JPanel tableButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton addRowBtn = new JButton("Add Header");
        JButton removeRowBtn = new JButton("Remove Selected");
        JButton selectAuthBtn = new JButton("Select Auth Only");
        JButton clearSelBtn = new JButton("Clear Selection");

        addRowBtn.addActionListener(e -> headerModel.addRow(new Object[]{Boolean.TRUE, "", ""}));
        removeRowBtn.addActionListener(e -> {
            int row = headerTable.getSelectedRow();
            if (row >= 0) headerModel.removeRow(row);
        });
        selectAuthBtn.addActionListener(e -> selectAuthHeaders());
        clearSelBtn.addActionListener(e -> setAllHeaderSelection(false));

        tableButtons.add(addRowBtn);
        tableButtons.add(removeRowBtn);
        tableButtons.add(selectAuthBtn);
        tableButtons.add(clearSelBtn);
        tablePanel.add(tableButtons, BorderLayout.SOUTH);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 10));
        JButton cancel = new JButton("Cancel");
        JButton save = new JButton("Save Actor");
        cancel.addActionListener(e -> dispose());
        save.addActionListener(e -> doSave(status));
        actions.add(cancel);
        actions.add(save);

        root.add(banner, BorderLayout.NORTH);
        root.add(meta, BorderLayout.CENTER);
        root.add(tablePanel, BorderLayout.SOUTH);

        JPanel outer = new JPanel(new BorderLayout());
        outer.add(root, BorderLayout.CENTER);
        outer.add(actions, BorderLayout.SOUTH);
        setContentPane(outer);
    }

    private void setAllHeaderSelection(boolean selected) {
        for (int i = 0; i < headerModel.getRowCount(); i++) {
            headerModel.setValueAt(selected, i, 0);
        }
    }

    private void selectAuthHeaders() {
        for (int i = 0; i < headerModel.getRowCount(); i++) {
            String name = String.valueOf(headerModel.getValueAt(i, 1));
            boolean use = IdParameterDetector.isAuthHeader(name) && !IdParameterDetector.isSkippableHeader(name);
            headerModel.setValueAt(use, i, 0);
        }
    }

    private JPanel buildColorPicker() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        String detected = com.acas.util.PwnFoxColors.fromRequest(fullRequest);
        if (detected != null) {
            selectedColor = com.acas.util.PwnFoxColors.hex(detected);
            JPanel swatch = new JPanel();
            swatch.setBackground(Color.decode(selectedColor));
            swatch.setPreferredSize(new Dimension(18, 18));
            swatch.setBorder(BorderFactory.createLineBorder(p.getForeground()));
            p.add(swatch);
            p.add(new JLabel("PwnFox: " + detected + " (automatic)"));
            return p;
        }
        String[][] colors = {
            {"Blue", "#0a84ff"},
            {"Turquoise", "#00feff"},
            {"Green", "#30e60b"},
            {"Yellow", "#ffe900"},
            {"Orange", "#ff9400"},
            {"Red", "#ff0039"}, {"Pink", "#ff1ad9"}, {"Purple", "#9400ff"}
        };

        ButtonGroup bg = new ButtonGroup();
        for (String[] c : colors) {
            JToggleButton btn = new JToggleButton();
            btn.setPreferredSize(new Dimension(20, 20));
            btn.setBackground(Color.decode(c[1]));
            btn.setBorder(BorderFactory.createLineBorder(Color.WHITE, 1));
            btn.setToolTipText(c[0]);
            btn.addActionListener(e -> selectedColor = c[1]);
            if (c[1].equals(selectedColor)) btn.setSelected(true);
            bg.add(btn);
            p.add(btn);
        }
        return p;
    }

    private void doSave(int originalStatus) {
        String name = nameField.getText().trim();
        if (name.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Actor name cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (originalStatus != 200 && originalStatus != 0) {
            int choice = JOptionPane.showConfirmDialog(this,
                "This request returned " + originalStatus + ". Save anyway?",
                "Ambiguous Request",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.YES_OPTION) return;
        }

        List<String[]> selectedHeaders = new ArrayList<>();
        for (int i = 0; i < headerModel.getRowCount(); i++) {
            Object useObj = headerModel.getValueAt(i, 0);
            boolean use = useObj instanceof Boolean && (Boolean) useObj;
            if (!use) continue;

            String headerName = String.valueOf(headerModel.getValueAt(i, 1)).trim();
            String headerValue = String.valueOf(headerModel.getValueAt(i, 2)).trim();
            if (headerName.isEmpty()) continue;
            selectedHeaders.add(new String[]{headerName, headerValue});
        }

        if (selectedHeaders.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "Select at least one Cookie/Auth header for manual actor profile.",
                "No Identity Headers",
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        String role = (String) roleCombo.getSelectedItem();
        result = new ActorProfile(name, role, selectedHeaders, fullRequest);
        result.setIdentitySourceUrl(identitySourceUrl);
        result.setRoleLevel(ActorProfile.levelForRole(role));
        result.setColor(selectedColor);
        result.setPwnfoxColor(com.acas.util.PwnFoxColors.fromRequest(fullRequest));
        confirmed = true;
        dispose();
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public ActorProfile getResult() {
        return result;
    }
}
