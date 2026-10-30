package com.acas.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;
import java.awt.*;

/** Compact history table using the host's look-and-feel colours and fonts. */
class NativeHistoryTable extends JTable {
    private java.util.function.IntFunction<Color> actorColors;

    void setActorColors(java.util.function.IntFunction<Color> colors) {
        actorColors = colors;
        repaint();
    }
    NativeHistoryTable(TableModel model) {
        super(model);
        setFillsViewportHeight(true);
        setShowGrid(false);
        setIntercellSpacing(new Dimension(0, 0));
        setRowHeight(Math.max(22, getFontMetrics(getFont()).getHeight() + 4));
        getTableHeader().setReorderingAllowed(false);
        setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean selected, boolean focused, int row, int column) {
                super.getTableCellRendererComponent(table, value, selected, focused, row, column);
                setToolTipText(value == null ? null : value.toString());
                return this;
            }
        });
    }

    @Override
    public boolean getScrollableTracksViewportWidth() {
        return getParent() == null || getParent().getWidth() >= getMinimumSize().width;
    }

    @Override
    public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
        Component cell = super.prepareRenderer(renderer, row, column);
        Color background = getBackground();
        if (isRowSelected(row)) {
            background = getSelectionBackground();
        } else if (row % 2 == 1) {
            Color alternate = UIManager.getColor("Table.alternateRowColor");
            if (alternate == null) {
                // Some host themes omit a stripe colour. Blend subtly toward text.
                Color foreground = getForeground();
                alternate = new Color(
                    (background.getRed() * 95 + foreground.getRed() * 5) / 100,
                    (background.getGreen() * 95 + foreground.getGreen() * 5) / 100,
                    (background.getBlue() * 95 + foreground.getBlue() * 5) / 100);
            }
            background = alternate;
        }
        if (!isRowSelected(row) && actorColors != null) {
            Color actor = actorColors.apply(convertRowIndexToModel(row));
            if (actor != null) {
                background = new Color(
                    (background.getRed() * 84 + actor.getRed() * 16) / 100,
                    (background.getGreen() * 84 + actor.getGreen() * 16) / 100,
                    (background.getBlue() * 84 + actor.getBlue() * 16) / 100);
            }
        }
        cell.setBackground(background);
        cell.setForeground(isRowSelected(row) ? getSelectionForeground() : getForeground());
        cell.setFont(getFont());
        if (cell instanceof JComponent component) component.setOpaque(true);
        return cell;
    }
}
