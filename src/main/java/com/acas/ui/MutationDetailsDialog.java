package com.acas.ui;

import com.acas.engine.MutationDefinition;
import javax.swing.*;
import java.awt.*;

public class MutationDetailsDialog extends JDialog {
    public MutationDetailsDialog(Window parent, MutationDefinition mutation) {
        super(parent, "Mutation Details: " + mutation.name, ModalityType.APPLICATION_MODAL);
        
        JPanel content = new JPanel(new BorderLayout(10, 10));
        content.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        // Header: Category badge + Name
        JPanel header = new JPanel(new BorderLayout());
        JLabel categoryBadge = new JLabel("[" + mutation.category + "]");
        categoryBadge.setFont(new Font("SansSerif", Font.BOLD, 14));
        categoryBadge.setForeground(getCategoryColor(mutation.category));
        JLabel nameLabel = new JLabel(mutation.name);
        nameLabel.setFont(new Font("SansSerif", Font.BOLD, 16));
        header.add(categoryBadge, BorderLayout.WEST);
        header.add(nameLabel, BorderLayout.CENTER);
        content.add(header, BorderLayout.NORTH);

        // Main: Description + Details
        JPanel main = new JPanel(new BorderLayout(10, 10));
        
        JTextArea descArea = new JTextArea(mutation.description, 4, 50);
        descArea.setEditable(false);
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        descArea.setBorder(BorderFactory.createTitledBorder("Description"));
        descArea.setFont(new Font("SansSerif", Font.PLAIN, 12));
        main.add(new JScrollPane(descArea), BorderLayout.NORTH);

        // Details table
        String[] detailCols = {"Property", "Value"};
        Object[][] detailRows = {
            {"Category", mutation.category.toString()},
            {"Type", mutation.isCustom ? "Custom" : "Built-in"},
            {"Status", mutation.isEnabled() ? "Enabled" : "Disabled"},
            {"Purpose", getCategoryDescription(mutation.category)}
        };
        JTable detailTable = new JTable(detailRows, detailCols) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        detailTable.setRowHeight(24);
        detailTable.setFont(new Font("SansSerif", Font.PLAIN, 11));
        detailTable.setShowGrid(false);
        main.add(new JScrollPane(detailTable), BorderLayout.CENTER);

        content.add(main, BorderLayout.CENTER);

        // Footer: Close button
        JPanel footer = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dispose());
        footer.add(closeBtn);
        content.add(footer, BorderLayout.SOUTH);

        setContentPane(content);
        setSize(600, 400);
        setLocationRelativeTo(parent);
    }

    private Color getCategoryColor(MutationDefinition.Category cat) {
        switch (cat) {
            case A: return new Color(239, 68, 68);   // Red
            case B: return new Color(251, 146, 60);  // Orange
            case C: return new Color(250, 204, 21);  // Yellow
            case D: return new Color(34, 197, 94);   // Green
            case E: return new Color(59, 130, 246);  // Blue
            case F: return new Color(139, 92, 246);  // Purple
            case G: return new Color(20, 184, 166);  // Teal
            case H: return new Color(244, 114, 182); // Pink
            case I: return new Color(96, 165, 250);  // Light blue
            case J: return new Color(245, 158, 11);  // Amber
            case K: return new Color(168, 85, 247);  // Violet
            default: return new Color(100, 150, 200);// Blue
        }
    }

    private String getCategoryDescription(MutationDefinition.Category cat) {
        switch (cat) {
            case A: return "Anonymous/Unauthenticated bypass attempts";
            case B: return "Session swap and privilege escalation";
            case C: return "Path and resource relationship mutations";
            case D: return "GraphQL-specific attacks";
            case E: return "Stateful/dangerous mutations";
            case F: return "Uniqueness and identity-format bypass attempts";
            case G: return "Encoding-based bypass attempts";
            case H: return "Whitespace and normalization bypass attempts";
            case I: return "Common developer mistake patterns";
            case J: return "Protocol and transport edge cases";
            case K: return "High-value combined attack triggers";
            default: return "Unknown category";
        }
    }
}
