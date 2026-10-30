package com.acas.util;

import java.util.ArrayList;
import java.util.List;

public class DiffUtils {

    /**
     * Generates a side-by-side or unified HTML diff between two texts.
     * Highlights added lines in green and removed lines in red.
     */
    public static String generateHtmlDiff(String oldText, String newText) {
        return generateHtmlDiff(oldText, newText, true);
    }

    /**
     * @param dark true for a dark Burp theme, false for a light one — picks colors
     *             so both the changed and unchanged lines stay readable.
     */
    public static String generateHtmlDiff(String oldText, String newText, boolean dark) {
        if (oldText == null) oldText = "";
        if (newText == null) newText = "";

        // Theme-aware palette
        String unchangedColor = dark ? "#b8b8b8" : "#444444";
        String delBg   = dark ? "#4a1d1d" : "#ffe2e2";
        String delText = dark ? "#ffb4b4" : "#a11616";
        String addBg   = dark ? "#1d4a2a" : "#def3e0";
        String addText = dark ? "#b4f0bf" : "#176a2b";

        String[] oldLines = oldText.split("\n");
        String[] newLines = newText.split("\n");

        StringBuilder sb = new StringBuilder();
        sb.append("<div style='font-family: monospace; white-space: pre-wrap; font-size: 12px; line-height: 1.4;'>");

        int oldIdx = 0;
        int newIdx = 0;

        // A very simple greedy matching diff for quick UI rendering
        while (oldIdx < oldLines.length || newIdx < newLines.length) {
            if (oldIdx < oldLines.length && newIdx < newLines.length && oldLines[oldIdx].equals(newLines[newIdx])) {
                // Unchanged
                sb.append("<span style='color: ").append(unchangedColor).append(";'>  ")
                  .append(escapeHtml(oldLines[oldIdx])).append("</span><br>");
                oldIdx++;
                newIdx++;
            } else {
                // Lookahead to find next match
                int nextMatchOld = -1;
                int nextMatchNew = -1;
                boolean foundMatch = false;

                for (int i = 0; i < 50 && !foundMatch; i++) { // Limit lookahead for performance
                    for (int o = 0; o <= i; o++) {
                        int n = i - o;
                        if (oldIdx + o < oldLines.length && newIdx + n < newLines.length) {
                            if (oldLines[oldIdx + o].equals(newLines[newIdx + n])) {
                                nextMatchOld = oldIdx + o;
                                nextMatchNew = newIdx + n;
                                foundMatch = true;
                                break;
                            }
                        }
                    }
                }

                if (foundMatch) {
                    // Flush deletions
                    while (oldIdx < nextMatchOld) {
                        sb.append("<span style='background-color: ").append(delBg).append("; color: ").append(delText).append("; display: block;'>- ")
                          .append(escapeHtml(oldLines[oldIdx])).append("</span>");
                        oldIdx++;
                    }
                    // Flush additions
                    while (newIdx < nextMatchNew) {
                        sb.append("<span style='background-color: ").append(addBg).append("; color: ").append(addText).append("; display: block;'>+ ")
                          .append(escapeHtml(newLines[newIdx])).append("</span>");
                        newIdx++;
                    }
                } else {
                    // No match found in lookahead window, just output as delete + add
                    if (oldIdx < oldLines.length) {
                        sb.append("<span style='background-color: ").append(delBg).append("; color: ").append(delText).append("; display: block;'>- ")
                          .append(escapeHtml(oldLines[oldIdx])).append("</span>");
                        oldIdx++;
                    }
                    if (newIdx < newLines.length) {
                        sb.append("<span style='background-color: ").append(addBg).append("; color: ").append(addText).append("; display: block;'>+ ")
                          .append(escapeHtml(newLines[newIdx])).append("</span>");
                        newIdx++;
                    }
                }
            }
        }

        sb.append("</div>");
        return sb.toString();
    }

    private static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("\r", "");
    }
}
