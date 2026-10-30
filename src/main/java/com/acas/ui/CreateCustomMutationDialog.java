package com.acas.ui;

import com.acas.engine.MutationDefinition;
import com.acas.engine.MutationRegistry;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;

public class CreateCustomMutationDialog extends JDialog {
    private JTextField nameField;
    private JTextArea descArea;
    private JComboBox<MutationDefinition.Category> categoryBox;
    private JCheckBox enabledBox;
    private MutationRegistry registry;

    public CreateCustomMutationDialog(Window parent, MutationRegistry registry) {
        super(parent, "Create Custom Mutation", ModalityType.APPLICATION_MODAL);
        this.registry = registry;

        JPanel content = new JPanel(new BorderLayout(10, 10));
        content.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        // Title
        JLabel titleLabel = new JLabel("➕ Add Custom Mutation");
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 18));
        JPanel titlePanel = new JPanel(new BorderLayout());
        titlePanel.add(titleLabel, BorderLayout.WEST);
        content.add(titlePanel, BorderLayout.NORTH);

        // Form panel
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Name field
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.2;
        form.add(new JLabel("Name:"), gbc);
        nameField = new JTextField();
        nameField.setFont(new Font("SansSerif", Font.PLAIN, 12));
        gbc.gridx = 1; gbc.weightx = 0.8;
        form.add(nameField, gbc);

        // Category dropdown
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.2;
        form.add(new JLabel("Category:"), gbc);
        categoryBox = new JComboBox<>(MutationDefinition.Category.values());
        categoryBox.setSelectedItem(MutationDefinition.Category.I); // Default to I (custom)
        gbc.gridx = 1; gbc.weightx = 0.8;
        form.add(categoryBox, gbc);

        // Description area
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0.2; gbc.weighty = 0.5;
        gbc.anchor = GridBagConstraints.NORTH;
        form.add(new JLabel("Description:"), gbc);
        descArea = new JTextArea(5, 40);
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        descArea.setFont(new Font("SansSerif", Font.PLAIN, 12));
        gbc.gridx = 1; gbc.weightx = 0.8;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        form.add(new JScrollPane(descArea), gbc);

        // Enabled checkbox
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0.2; gbc.weighty = 0;
        gbc.anchor = GridBagConstraints.WEST;
        form.add(new JLabel("Enabled:"), gbc);
        enabledBox = new JCheckBox("Yes", true);
        gbc.gridx = 1; gbc.weightx = 0.8;
        form.add(enabledBox, gbc);

        // Note
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2; gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        JLabel noteLabel = new JLabel("💡 Custom mutations in category I-J will be saved to Burp's persistence.");
        noteLabel.setFont(new Font("SansSerif", Font.ITALIC, 11));
        noteLabel.setForeground(new Color(100, 100, 100));
        form.add(noteLabel, gbc);

        content.add(form, BorderLayout.CENTER);

        // Buttons
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveBtn = new JButton("✅ Save Custom Mutation");
        saveBtn.setBackground(new Color(34, 197, 94));
        saveBtn.setForeground(Color.WHITE);
        saveBtn.setFont(new Font("SansSerif", Font.BOLD, 12));
        saveBtn.addActionListener(e -> saveCustomMutation());
        buttons.add(saveBtn);

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());
        buttons.add(cancelBtn);

        content.add(buttons, BorderLayout.SOUTH);

        setContentPane(content);
        setSize(500, 400);
        setLocationRelativeTo(parent);
    }

    private void saveCustomMutation() {
        String name = nameField.getText().trim();
        String desc = descArea.getText().trim();
        MutationDefinition.Category cat = (MutationDefinition.Category) categoryBox.getSelectedItem();
        boolean enabled = enabledBox.isSelected();

        if (name.isEmpty() || desc.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Name and description cannot be empty.", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        MutationDefinition custom = new MutationDefinition(name, desc, cat, enabled, true);
        registry.addCustom(custom);
        JOptionPane.showMessageDialog(this, "Custom mutation '" + name + "' created successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
        dispose();
    }
}
