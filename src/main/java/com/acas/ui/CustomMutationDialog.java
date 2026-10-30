package com.acas.ui;

import com.acas.engine.CustomMutationDefinition;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.function.Consumer;

/**
 * CustomMutationDialog allows users to create custom mutations via GUI, no coding required.
 */
public class CustomMutationDialog extends JDialog {
    private final JTextField nameField = new JTextField(20);
    private final JComboBox<CustomMutationDefinition.Strategy> strategyCombo;
    private final JTextArea descriptionArea = new JTextArea(3, 40);
    
    private final JCheckBox useHarvestedIdsBox = new JCheckBox("Use live harvested IDs", true);
    private final JCheckBox useUrlParamsBox = new JCheckBox("URL path parameters", true);
    private final JCheckBox useQueryParamsBox = new JCheckBox("Query parameters", false);
    private final JCheckBox useBodyFieldsBox = new JCheckBox("JSON body fields", false);
    private final JCheckBox useHeadersBox = new JCheckBox("Headers", false);
    private final JCheckBox useCookiesBox = new JCheckBox("Cookies", false);
    
    private final JComboBox<String> encodingCombo = new JComboBox<>(
        new String[]{"None", "URL Encode", "Base64", "Double Encode", "HTML Encode"}
    );
    
    private final JTextArea customPayloadsArea = new JTextArea(4, 40);
    private final JCheckBox scriptModeCheckBox = new JCheckBox("Use script-based mutation", false);
    private final JTextArea scriptArea = new JTextArea(6, 40);
    private final JLabel statusLabel = new JLabel("Ready to create mutation");
    
    private CustomMutationDefinition result = null;

    public CustomMutationDialog(Window parent) {
        super(parent, "Custom Mutation Builder (No Coding Required)", ModalityType.APPLICATION_MODAL);
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        strategyCombo = new JComboBox<>(CustomMutationDefinition.Strategy.values());
        strategyCombo.addActionListener(e -> updateDescriptionPreview());

        JPanel contentPanel = new JPanel(new BorderLayout(10, 10));
        contentPanel.setBorder(new EmptyBorder(15, 15, 15, 15));

        // Header
        JLabel titleLabel = new JLabel("Create Custom Mutation");
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 16));
        contentPanel.add(titleLabel, BorderLayout.NORTH);

        // Main form
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Mutation name
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1; gbc.weightx = 0.3;
        formPanel.add(new JLabel("Mutation Name:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 0.7;
        nameField.setFont(new Font("Monospaced", Font.PLAIN, 12));
        formPanel.add(nameField, gbc);

        // Strategy
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1; gbc.weightx = 0.3;
        formPanel.add(new JLabel("Strategy:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 0.7;
        formPanel.add(strategyCombo, gbc);

        // Description (preview)
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 3; gbc.weighty = 0.15;
        gbc.fill = GridBagConstraints.BOTH;
        JPanel descPanel = new JPanel(new BorderLayout());
        descPanel.setBorder(new TitledBorder("Description Preview"));
        descriptionArea.setEditable(false);
        descriptionArea.setLineWrap(true);
        descriptionArea.setWrapStyleWord(true);
        descriptionArea.setText("(Description will appear here based on your selections)");
        descPanel.add(new JScrollPane(descriptionArea), BorderLayout.CENTER);
        formPanel.add(descPanel, gbc);

        // --- Payload Options Section ---
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3; gbc.weighty = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JPanel payloadPanel = new JPanel(new GridLayout(3, 2, 8, 6));
        payloadPanel.setBorder(new TitledBorder("Where to get payloads?"));
        payloadPanel.add(useHarvestedIdsBox);
        payloadPanel.add(new JLabel("(Recommended - uses discovered IDs)"));
        payloadPanel.add(new JLabel(""));
        payloadPanel.add(new JLabel("Or paste custom payloads below ↓"));
        payloadPanel.add(new JLabel(""));
        payloadPanel.add(new JLabel(""));
        formPanel.add(payloadPanel, gbc);

        // Custom payloads
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 3; gbc.weighty = 0.15;
        gbc.fill = GridBagConstraints.BOTH;
        JPanel customPanel = new JPanel(new BorderLayout());
        customPanel.setBorder(new TitledBorder("Custom Payloads (one per line, optional)"));
        customPayloadsArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        customPayloadsArea.setLineWrap(false);
        customPanel.add(new JScrollPane(customPayloadsArea), BorderLayout.CENTER);
        formPanel.add(customPanel, gbc);

        // --- Injection Points Section ---
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 3; gbc.weighty = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JPanel injectionPanel = new JPanel(new GridLayout(3, 2, 8, 6));
        injectionPanel.setBorder(new TitledBorder("Where to inject?"));
        injectionPanel.add(useUrlParamsBox);
        injectionPanel.add(useQueryParamsBox);
        injectionPanel.add(useBodyFieldsBox);
        injectionPanel.add(useHeadersBox);
        injectionPanel.add(useCookiesBox);
        injectionPanel.add(new JLabel(""));
        formPanel.add(injectionPanel, gbc);

        // --- Encoding Section ---
        gbc.gridx = 0; gbc.gridy = 6; gbc.gridwidth = 1; gbc.weighty = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(new JLabel("Encoding:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2;
        formPanel.add(encodingCombo, gbc);

        // --- Script Mutation Section ---
        gbc.gridx = 0; gbc.gridy = 7; gbc.gridwidth = 3; gbc.weighty = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JPanel scriptTogglePanel = new JPanel(new BorderLayout(8, 4));
        scriptTogglePanel.setBorder(new TitledBorder("Script Mutation Mode"));
        scriptModeCheckBox.setToolTipText("Enable a safe mutation script instead of manual GUI fields");
        scriptModeCheckBox.addActionListener(e -> scriptArea.setEnabled(scriptModeCheckBox.isSelected()));
        scriptTogglePanel.add(scriptModeCheckBox, BorderLayout.NORTH);

        JPanel scriptPanel = new JPanel(new BorderLayout(4, 4));
        JLabel scriptHelp = new JLabel("Format: key=value per line. Example: target=path, find=([A-Za-z]+)(\\d+), replace=$1*.");
        scriptHelp.setFont(new Font("SansSerif", Font.PLAIN, 11));
        scriptHelp.setForeground(new Color(100, 100, 100));
        scriptArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        scriptArea.setText("target=path\nfind=([A-Za-z]+)(\\d+)\nreplace=$1*\nscope=first");
        scriptArea.setEnabled(false);
        scriptPanel.add(scriptHelp, BorderLayout.NORTH);
        scriptPanel.add(new JScrollPane(scriptArea), BorderLayout.CENTER);
        scriptTogglePanel.add(scriptPanel, BorderLayout.CENTER);
        formPanel.add(scriptTogglePanel, gbc);

        // Status label
        gbc.gridx = 0; gbc.gridy = 8; gbc.gridwidth = 3;
        statusLabel.setFont(new Font("SansSerif", Font.ITALIC, 11));
        statusLabel.setForeground(new Color(100, 100, 100));
        formPanel.add(statusLabel, gbc);

        JScrollPane formScroll = new JScrollPane(formPanel);
        contentPanel.add(formScroll, BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        
        JButton saveBtn = new JButton("Save & Register Mutation");
        saveBtn.addActionListener(e -> {
            if (saveMutation()) {
                statusLabel.setText("✓ Mutation created successfully!");
                statusLabel.setForeground(new Color(34, 139, 34));
                dispose();
            }
        });
        buttonPanel.add(saveBtn);

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());
        buttonPanel.add(cancelBtn);

        contentPanel.add(buttonPanel, BorderLayout.SOUTH);

        setContentPane(contentPanel);
        setSize(700, 800);
        setLocationRelativeTo(parent);
        updateDescriptionPreview();
    }

    private void updateDescriptionPreview() {
        CustomMutationDefinition.Strategy strategy = 
            (CustomMutationDefinition.Strategy) strategyCombo.getSelectedItem();
        
        String desc = "Strategy: " + strategy.label + "\n\n";
        desc += "Payloads from: " + (useHarvestedIdsBox.isSelected() ? "Live harvested IDs" : "Custom list") + "\n";
        desc += "Inject into: ";
        
        java.util.List<String> locations = new java.util.ArrayList<>();
        if (useUrlParamsBox.isSelected()) locations.add("URL params");
        if (useQueryParamsBox.isSelected()) locations.add("Query");
        if (useBodyFieldsBox.isSelected()) locations.add("Body");
        if (useHeadersBox.isSelected()) locations.add("Headers");
        if (useCookiesBox.isSelected()) locations.add("Cookies");
        
        desc += locations.isEmpty() ? "URL params" : String.join(", ", locations) + "\n";
        desc += "Encoding: " + (String) encodingCombo.getSelectedItem();
        
        descriptionArea.setText(desc);
    }

    private boolean saveMutation() {
        String name = nameField.getText().trim();
        if (name.isEmpty()) {
            statusLabel.setText("❌ Mutation name is required");
            statusLabel.setForeground(Color.RED);
            return false;
        }

        boolean scriptMode = scriptModeCheckBox.isSelected();
        if (scriptMode && scriptArea.getText().trim().isEmpty()) {
            statusLabel.setText("❌ Script mode requires a script");
            statusLabel.setForeground(Color.RED);
            return false;
        }

        // Validate at least one injection point for GUI mode
        if (!scriptMode && !useUrlParamsBox.isSelected() && !useQueryParamsBox.isSelected() &&
            !useBodyFieldsBox.isSelected() && !useHeadersBox.isSelected() && 
            !useCookiesBox.isSelected()) {
            statusLabel.setText("❌ Select at least one injection point");
            statusLabel.setForeground(Color.RED);
            return false;
        }

        // Create the custom mutation definition
        CustomMutationDefinition mutation = new CustomMutationDefinition(
            name,
            (CustomMutationDefinition.Strategy) strategyCombo.getSelectedItem()
        );

        mutation.setUseHarvestedIds(useHarvestedIdsBox.isSelected());
        mutation.setUseUrlParams(useUrlParamsBox.isSelected());
        mutation.setUseQueryParams(useQueryParamsBox.isSelected());
        mutation.setUseBodyFields(useBodyFieldsBox.isSelected());
        mutation.setUseHeaders(useHeadersBox.isSelected());
        mutation.setUseCookies(useCookiesBox.isSelected());
        
        String encoding = ((String) encodingCombo.getSelectedItem()).toLowerCase().replace(" ", "_");
        mutation.setEncoding(encoding);

        mutation.setScriptMode(scriptMode);
        if (scriptMode) {
            mutation.setCustomScript(scriptArea.getText().trim());
        }
        
        String customPayloads = customPayloadsArea.getText().trim();
        if (!customPayloads.isEmpty()) {
            mutation.setCustomPayloads(customPayloads);
        }

        this.result = mutation;
        return true;
    }

    public CustomMutationDefinition getResult() {
        return result;
    }
}
