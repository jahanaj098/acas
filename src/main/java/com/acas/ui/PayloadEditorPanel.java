package com.acas.ui;

import com.acas.store.PayloadStore;
import com.acas.store.PayloadStore.PayloadGroup;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.Set;

public class PayloadEditorPanel extends JPanel {

    private static class PayloadOption {
        private final String key;
        private final String label;
        private final String mutationCode;
        private final boolean separator;

        private PayloadOption(String key, String mutationCode, String label, boolean separator) {
            this.key = key;
            this.label = label;
            this.mutationCode = mutationCode;
            this.separator = separator;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private final PayloadStore payloadStore;
    private final JComboBox<PayloadOption> mutationDropdown = new JComboBox<>();
    private final JTextArea payloadArea = new JTextArea(16, 80);
    private final JLabel statusBar = new JLabel("Ready");

    public PayloadEditorPanel(PayloadStore payloadStore) {
        this.payloadStore = payloadStore;
        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel top = new JPanel(new BorderLayout(6, 6));
        top.add(new JLabel("Mutation:"), BorderLayout.WEST);

        fillDropdown();
        mutationDropdown.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                Component c = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof PayloadOption) {
                    PayloadOption opt = (PayloadOption) value;
                    setText(opt.label);
                    if (opt.separator) {
                        setFont(getFont().deriveFont(Font.BOLD));
                    }
                }
                return c;
            }
        });
        mutationDropdown.addActionListener(e -> {
            PayloadOption option = (PayloadOption) mutationDropdown.getSelectedItem();
            if (option != null && option.separator) {
                SwingUtilities.invokeLater(() -> moveToFirstRealOption());
                return;
            }
            loadSelected();
        });

        top.add(mutationDropdown, BorderLayout.CENTER);

        payloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        payloadArea.setLineWrap(false);

        JPanel bottomButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton save = new JButton("Save Changes");
        JButton reset = new JButton("Reset to Default");
        JButton fromClipboard = new JButton("Add from Clipboard");

        save.addActionListener(e -> saveSelected());
        reset.addActionListener(e -> resetSelected());
        fromClipboard.addActionListener(e -> addFromClipboard());

        bottomButtons.add(save);
        bottomButtons.add(reset);
        bottomButtons.add(fromClipboard);

        JPanel bottom = new JPanel(new BorderLayout(0, 6));
        bottom.add(bottomButtons, BorderLayout.NORTH);
        statusBar.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        bottom.add(statusBar, BorderLayout.SOUTH);

        add(top, BorderLayout.NORTH);
        add(new JScrollPane(payloadArea), BorderLayout.CENTER);
        add(bottom, BorderLayout.SOUTH);

        moveToFirstRealOption();
        loadSelected();
    }

    private void fillDropdown() {
        Set<String> seenMutations = new LinkedHashSet<>();
        for (PayloadGroup group : payloadStore.getAllGroups()) {
            if (!seenMutations.contains(group.getMutationCode())) {
                seenMutations.add(group.getMutationCode());
                mutationDropdown.addItem(new PayloadOption(null, null, "-- " + group.getMutationCode() + "-SET --", true));
            }
            mutationDropdown.addItem(new PayloadOption(group.getKey(), group.getMutationCode(),
                group.getMutationCode() + " · " + group.getDisplayLabel(), false));
        }
    }

    private void moveToFirstRealOption() {
        for (int i = 0; i < mutationDropdown.getItemCount(); i++) {
            PayloadOption option = mutationDropdown.getItemAt(i);
            if (!option.separator) {
                mutationDropdown.setSelectedIndex(i);
                break;
            }
        }
    }

    private void loadSelected() {
        PayloadOption option = (PayloadOption) mutationDropdown.getSelectedItem();
        if (option == null || option.separator) return;
        List<String> payloads = payloadStore.getPayloads(option.key);
        payloadArea.setText(String.join("\n", payloads));
        payloadArea.setCaretPosition(0);
        refreshStatus(option, payloads.size());
    }

    private void saveSelected() {
        PayloadOption option = (PayloadOption) mutationDropdown.getSelectedItem();
        if (option == null || option.separator) return;
        List<String> lines = parseLines(payloadArea.getText());
        payloadStore.setPayloads(option.key, lines);
        refreshStatus(option, lines.size());
        JOptionPane.showMessageDialog(this, "Payloads saved for " + option.label, "ACAS Payloads", JOptionPane.INFORMATION_MESSAGE);
    }

    private void resetSelected() {
        PayloadOption option = (PayloadOption) mutationDropdown.getSelectedItem();
        if (option == null || option.separator) return;
        payloadStore.resetToDefault(option.key);
        loadSelected();
        JOptionPane.showMessageDialog(this, "Reset to defaults for " + option.label, "ACAS Payloads", JOptionPane.INFORMATION_MESSAGE);
    }

    private void addFromClipboard() {
        try {
            String clip = (String) Toolkit.getDefaultToolkit()
                .getSystemClipboard()
                .getData(DataFlavor.stringFlavor);
            if (clip == null || clip.trim().isEmpty()) return;
            String current = payloadArea.getText();
            if (!current.endsWith("\n") && !current.isEmpty()) {
                current += "\n";
            }
            payloadArea.setText(current + clip.trim());
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "Unable to read clipboard: " + e.getMessage(),
                "ACAS Payloads",
                JOptionPane.ERROR_MESSAGE);
        }
    }

    private void refreshStatus(PayloadOption option, int totalCount) {
        int defaults = payloadStore.getDefaultCount(option.key);
        int custom = payloadStore.getCustomOnlyCount(option.key);
        statusBar.setText(option.mutationCode + " · " + option.label + " - " + totalCount + " payloads (" + custom + " custom, " + defaults + " defaults)");
    }

    private List<String> parseLines(String text) {
        List<String> out = new ArrayList<>();
        if (text == null || text.trim().isEmpty()) return out;
        String[] split = text.split("\\r?\\n");
        for (String line : split) {
            if (line == null) continue;
            String v = line.trim();
            if (!v.isEmpty()) out.add(v);
        }
        return out;
    }
}
