package com.acas.ui;

import com.acas.model.AccessPolicy;
import com.acas.model.ActorProfile;
import com.acas.model.CapturedEndpoint;
import com.acas.model.OperationSafety;
import com.acas.store.ActorStore;

import javax.swing.*;
import java.awt.*;

public final class EndpointResourceDialog extends JDialog {
    private final ActorStore store;
    private final CapturedEndpoint endpoint;
    private final JComboBox<String> owner = new JComboBox<>();
    private final JComboBox<String> policy = new JComboBox<>();
    private final JTextField type = new JTextField(18);
    private final JTextField resourceId = new JTextField(18);
    private final JTextField tenantId = new JTextField(18);
    private final JComboBox<String> safety = new JComboBox<>();
    private final JCheckBox approved = new JCheckBox("Approve this exact operation for review");
    private final JCheckBox confirmed = new JCheckBox("I confirm this ownership and access classification");
    private final JTextArea reason = new JTextArea(3, 40);
    private boolean saved;

    public EndpointResourceDialog(Window ownerWindow, ActorStore store, CapturedEndpoint endpoint) {
        super(ownerWindow, "ACAS - Resource ownership and operation safety", ModalityType.APPLICATION_MODAL);
        this.store = store;
        this.endpoint = endpoint;
        owner.addItem("(unresolved)");
        for (ActorProfile actor : store.getAllActors()) owner.addItem(actor.getId() + " | " + actor.getName());
        if (endpoint.getResourceOwnerActorId() != null)
            for (int i = 0; i < owner.getItemCount(); i++)
                if (owner.getItemAt(i).startsWith(endpoint.getResourceOwnerActorId() + " |")) owner.setSelectedIndex(i);
        for (AccessPolicy value : AccessPolicy.values()) policy.addItem(value.name());
        policy.setSelectedItem(endpoint.getAccessPolicy().name());
        for (OperationSafety value : OperationSafety.values()) safety.addItem(value.name());
        safety.setSelectedItem(endpoint.getOperationSafety().name());
        type.setText(endpoint.getResourceType());
        resourceId.setText(endpoint.getResourceId() == null ? "" : endpoint.getResourceId());
        tenantId.setText(endpoint.getTenantId() == null ? "" : endpoint.getTenantId());
        approved.setSelected(endpoint.isOperationApproved());
        reason.setText(endpoint.getOperationSafetyReason() == null ? "" : endpoint.getOperationSafetyReason());
        reason.setLineWrap(true);
        reason.setWrapStyleWord(true);

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        int row = 0;
        row = add(form, row, "Captured request", new JLabel(endpoint.getMethod() + " " + endpoint.getOriginalUrl()));
        row = add(form, row, "Resource owner", owner);
        row = add(form, row, "Access policy", policy);
        row = add(form, row, "Resource type", type);
        row = add(form, row, "Resource ID", resourceId);
        row = add(form, row, "Tenant ID", tenantId);
        row = add(form, row, "Operation safety", safety);
        row = add(form, row, "Reason", new JScrollPane(reason));
        row = add(form, row, "", approved);
        add(form, row, "", confirmed);
        JButton cancel = new JButton("Cancel");
        JButton save = new JButton("Save confirmation");
        cancel.addActionListener(e -> dispose());
        save.addActionListener(e -> save());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(cancel);
        buttons.add(save);
        add(form, BorderLayout.CENTER);
        add(new JLabel("Resources never grant testing permission. Active replay still requires a separate exact authorization."), BorderLayout.NORTH);
        add(buttons, BorderLayout.SOUTH);
        pack();
        setLocationRelativeTo(ownerWindow);
    }

    private int add(JPanel panel, int row, String label, JComponent component) {
        GridBagConstraints left = new GridBagConstraints();
        left.gridx = 0; left.gridy = row; left.anchor = GridBagConstraints.NORTHWEST;
        left.insets = new Insets(4, 4, 4, 8);
        panel.add(new JLabel(label), left);
        GridBagConstraints right = new GridBagConstraints();
        right.gridx = 1; right.gridy = row; right.weightx = 1; right.fill = GridBagConstraints.HORIZONTAL;
        right.insets = new Insets(4, 4, 4, 4);
        panel.add(component, right);
        return row + 1;
    }

    private void save() {
        String selectedOwner = null;
        if (owner.getSelectedIndex() > 0) {
            String value = owner.getSelectedItem().toString();
            selectedOwner = value.substring(0, value.indexOf(" |"));
        }
        String safetyValue = OperationSafety.parse(safety.getSelectedItem().toString()).name();
        try {
            if (!confirmed.isSelected()) throw new IllegalArgumentException("Explicit operator confirmation is required");
            if ("UNKNOWN".equals(safetyValue) && approved.isSelected())
                throw new IllegalArgumentException("An operation with unknown safety cannot be approved");
            if (!"UNKNOWN".equals(safetyValue) && reason.getText().isBlank())
                throw new IllegalArgumentException("Describe why this operation safety value applies");
            store.confirmEndpointResource(endpoint, selectedOwner,
                AccessPolicy.parse(policy.getSelectedItem().toString()), type.getText(),
                resourceId.getText(), tenantId.getText(), OperationSafety.parse(safetyValue),
                approved.isSelected(), reason.getText());
            saved = true;
            dispose();
        } catch (RuntimeException invalid) {
            JOptionPane.showMessageDialog(this, invalid.getMessage(), "ACAS - Resource confirmation", JOptionPane.ERROR_MESSAGE);
        }
    }

    public boolean saved() {
        return saved;
    }
}
