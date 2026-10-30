package com.acas.ui;

import javax.swing.*;
import javax.swing.table.JTableHeader;
import java.awt.*;

/**
 * Centralized ACAS visual language so every panel reads as one tool.
 * Colors are chosen to sit well under both Burp's light and dark themes;
 * helpers only adjust fonts, spacing, grid and accents — never the L&F's
 * own foreground/background for text, so themes keep working.
 */
public final class AcasTheme {

    private AcasTheme() {}

    // Brand palette
    public static final Color ACCENT       = new Color(99, 102, 241);   // indigo
    public static final Color ACCENT_ALT   = new Color(139, 92, 246);   // violet
    public static final Color OK           = new Color(34, 197, 94);    // green
    public static final Color WARN         = new Color(245, 158, 11);   // amber
    public static final Color DANGER       = new Color(239, 68, 68);    // red
    public static final Color MUTED        = new Color(140, 140, 150);
    public static final Color GRID         = new Color(60, 62, 72);
    public static final Color HEADER_BG     = new Color(40, 42, 58);

    public static final Font  UI_PLAIN     = new Font("SansSerif", Font.PLAIN, 12);
    public static final Font  UI_BOLD      = new Font("SansSerif", Font.BOLD, 12);
    public static final Font  UI_SMALL     = new Font("SansSerif", Font.PLAIN, 11);
    public static final Font  MONO         = new Font("Monospaced", Font.PLAIN, 12);

    // ── Native-look helpers ──────────────────────────────────────────────
    // These intentionally do NOT impose custom colors/fonts, so every panel
    // inherits Burp Suite's own Look-and-Feel (light or dark) and looks like a
    // normal Burp extension. Only comfortable row height / minor spacing is set.

    public static void styleTable(JTable table) {
        if (table == null) return;
        table.setRowHeight(22);
        table.setFillsViewportHeight(true);
        // Force the table to follow the same theme colors as the rest of the
        // extension (some Burp L&Fs give JTable a different background than the
        // surrounding panels, which looked out of place).
        Color bg = UIManager.getColor("Table.background");
        if (bg == null) bg = UIManager.getColor("Panel.background");
        Color fg = UIManager.getColor("Table.foreground");
        if (fg == null) fg = UIManager.getColor("Panel.foreground");
        if (bg != null) table.setBackground(bg);
        if (fg != null) table.setForeground(fg);
        JTableHeader header = table.getTableHeader();
        if (header != null) header.setReorderingAllowed(false);
    }

    /** A background shade for group-header rows, derived from the table theme. */
    public static Color groupHeaderBg() {
        Color base = UIManager.getColor("Table.background");
        if (base == null) base = UIManager.getColor("Panel.background");
        if (base == null) return new Color(230, 230, 235);
        double lum = 0.299 * base.getRed() + 0.587 * base.getGreen() + 0.114 * base.getBlue();
        int d = lum < 128 ? 22 : -18; // lighten on dark themes, darken on light themes
        return new Color(clamp(base.getRed() + d), clamp(base.getGreen() + d), clamp(base.getBlue() + d));
    }

    private static int clamp(int v) { return v < 0 ? 0 : (v > 255 ? 255 : v); }

    public static void styleTabs(JTabbedPane tabs) {
        // Native — no custom styling.
    }

    /** A plain bold section-title label using the theme's own colors. */
    public static JLabel sectionTitle(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 13f));
        l.setBorder(BorderFactory.createEmptyBorder(4, 2, 4, 2));
        return l;
    }

    /** A plain horizontal separator (native). */
    public static JComponent accentDivider() {
        return new JSeparator(SwingConstants.HORIZONTAL);
    }

    /** Native button — no custom styling. */
    public static void styleButton(AbstractButton b) {
        // Intentionally empty: keep Burp's native button look.
    }

    /** Emphasize the primary action with bold text only (no custom fill). */
    public static void stylePrimaryButton(AbstractButton b) {
        if (b != null) b.setFont(b.getFont().deriveFont(Font.BOLD));
    }

    public static void stylePrimaryButton(AbstractButton b, Color fill) {
        stylePrimaryButton(b);
    }

    /** A slim, native page header: bold title + muted subtitle, then a separator. */
    public static JComponent pageHeader(String title, String subtitle) {
        JPanel wrap = new JPanel(new BorderLayout());
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JLabel t = new JLabel(title);
        t.setFont(t.getFont().deriveFont(Font.BOLD, 13f));
        row.add(t);
        if (subtitle != null && !subtitle.isEmpty()) {
            JLabel sub = new JLabel(subtitle);
            sub.setFont(sub.getFont().deriveFont(Font.PLAIN, 11f));
            Color muted = UIManager.getColor("Label.disabledForeground");
            if (muted != null) sub.setForeground(muted);
            row.add(sub);
        }
        wrap.add(row, BorderLayout.CENTER);
        wrap.add(new JSeparator(SwingConstants.HORIZONTAL), BorderLayout.SOUTH);
        return wrap;
    }

    public static JLabel badge(String text, Color fg) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 10f));
        if (fg != null) l.setForeground(fg);
        l.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
        return l;
    }
}
