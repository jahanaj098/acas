package com.acas.ui;

import com.acas.model.ActorProfile;
import com.acas.util.IdParameterDetector;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class SaveActorDialog extends JDialog {

    private boolean confirmed = false;
    private ActorProfile result;
    private String fullRequest;
    private String identitySourceUrl;

    private final JTextField nameField = new JTextField(20);
    private final JComboBox<String> roleCombo = new JComboBox<>(ActorProfile.ROLE_OPTIONS);
    private final List<String[]> detectedHeaders;
    private final int originalStatus;


    public SaveActorDialog(Frame parent, List<String[]> detectedHeaders, String capturedUrl, String fullRequest, int originalStatus) {
        this(parent, detectedHeaders, capturedUrl, fullRequest, originalStatus, null);
    }

    public SaveActorDialog(Frame parent, List<String[]> detectedHeaders, String capturedUrl, String fullRequest, int originalStatus, String suggestedActorName) {
        super(parent, "ACAS — Save Actor Profile", true);
        this.fullRequest = fullRequest;
        this.identitySourceUrl = capturedUrl;
        this.detectedHeaders = detectedHeaders;
        this.originalStatus = originalStatus;

        if (suggestedActorName != null && !suggestedActorName.trim().isEmpty()) {
            nameField.setText(suggestedActorName.trim());
            nameField.selectAll();
        }

        buildUI(capturedUrl);
        pack();
        setMinimumSize(new Dimension(500, 240));
        setLocationRelativeTo(parent);
    }

    private void buildUI(String url) {
        JPanel root = new JPanel(new BorderLayout(0, 0));

        // Header banner
        JPanel banner = new JPanel(new BorderLayout());
        banner.setBorder(new EmptyBorder(12, 16, 12, 16));
        JLabel title = new JLabel("  Save Actor Profile");
        title.setFont(new Font("SansSerif", Font.BOLD, 15));
        banner.add(title, BorderLayout.WEST);
        
        if (originalStatus != 200 && originalStatus != 0) {
            JLabel warning = new JLabel("⚠️ Request originally returned " + originalStatus + ". 200 OK is recommended.");
            warning.setForeground(new Color(180, 83, 9));
            warning.setFont(new Font("SansSerif", Font.BOLD, 11));
            banner.add(warning, BorderLayout.SOUTH);
        }

        // Form panel
        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(new EmptyBorder(14, 16, 8, 16));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 4, 6, 4);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0; gbc.gridy = 0; form.add(new JLabel("Actor Name:"), gbc);
        gbc.gridx = 1;
        form.add(nameField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; form.add(new JLabel("Privilege:"), gbc);
        gbc.gridx = 1;
        roleCombo.setSelectedItem("User");
        roleCombo.setToolTipText("<html>Low → high privilege. ACAS uses this to tell escalation apart:<br>"
            + "a <b>lower</b> actor reaching a <b>higher</b> actor's resource is a privilege-escalation IDOR.<br>"
            + "Set one actor to <b>Super Admin</b> to enable the admin reference baseline.</html>");
        form.add(roleCombo, gbc);

        gbc.gridx = 0; gbc.gridy = 2; form.add(new JLabel("Color:"), gbc);
        gbc.gridx = 1;
        form.add(buildColorPicker(), gbc);

        gbc.gridx = 0; gbc.gridy = 3; form.add(new JLabel("Captured From:"), gbc);
        gbc.gridx = 1;
        JLabel urlLabel = new JLabel(url.length() > 50 ? url.substring(0, 50) + "..." : url);
        urlLabel.setForeground(new Color(140, 180, 255));
        urlLabel.setFont(new Font("Monospaced", Font.PLAIN, 11));
        form.add(urlLabel, gbc);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 10));
        JButton cancel = new JButton("Cancel");
        JButton save = new JButton("Save Actor");
        cancel.addActionListener(e -> dispose());
        save.addActionListener(e -> doSave(url));
        buttonPanel.add(cancel);
        buttonPanel.add(save);

        root.add(banner, BorderLayout.NORTH);
        root.add(form, BorderLayout.CENTER);
        root.add(buttonPanel, BorderLayout.SOUTH);

        setContentPane(root);
    }

    private String selectedColor = "#0a84ff"; // Default Indigo

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

    private void doSave(String url) {
        String name = nameField.getText().trim();
        if (name.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Actor name cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (originalStatus != 200 && originalStatus != 0) {
            int choice = JOptionPane.showConfirmDialog(this, 
                "This request originally returned " + originalStatus + ".\n" +
                "For best results, use a 200 OK request to register an actor.\n\n" +
                "Save anyway?", "Ambiguous Request", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            
            if (choice != JOptionPane.YES_OPTION) return;
        }

        List<String[]> selectedHeaders = new ArrayList<>();
        for (String[] h : detectedHeaders) {
            if (!IdParameterDetector.isSkippableHeader(h[0])) {
                selectedHeaders.add(h);
            }
        }

        if (selectedHeaders.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No valid session headers found in this request.", "Warning", JOptionPane.WARNING_MESSAGE);
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


    public boolean isConfirmed() { return confirmed; }
    public ActorProfile getResult() { return result; }
}
