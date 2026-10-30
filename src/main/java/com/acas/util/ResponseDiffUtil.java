package com.acas.util;

import java.util.ArrayList;
import java.util.List;

public final class ResponseDiffUtil {
    private ResponseDiffUtil() {}

    public enum DiffType {
        ADDED,
        REMOVED,
        CHANGED,
        SAME
    }

    public static class DiffLine {
        public final String text;
        public final DiffType type;

        public DiffLine(String text, DiffType type) {
            this.text = text;
            this.type = type;
        }
    }

    public static class DiffResult {
        public final List<DiffLine> leftLines;
        public final List<DiffLine> rightLines;

        public DiffResult(List<DiffLine> leftLines, List<DiffLine> rightLines) {
            this.leftLines = leftLines;
            this.rightLines = rightLines;
        }
    }

    public static DiffResult diff(String leftText, String rightText) {
        String[] a = splitLines(leftText);
        String[] b = splitLines(rightText);

        int[][] lcs = buildLcsTable(a, b);

        List<DiffLine> left = new ArrayList<>();
        List<DiffLine> right = new ArrayList<>();

        int i = 0;
        int j = 0;
        while (i < a.length && j < b.length) {
            if (a[i].equals(b[j])) {
                left.add(new DiffLine(a[i], DiffType.SAME));
                right.add(new DiffLine(b[j], DiffType.SAME));
                i++;
                j++;
            } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
                left.add(new DiffLine(a[i], DiffType.ADDED));
                right.add(new DiffLine("", DiffType.ADDED));
                i++;
            } else {
                left.add(new DiffLine("", DiffType.REMOVED));
                right.add(new DiffLine(b[j], DiffType.REMOVED));
                j++;
            }
        }

        while (i < a.length) {
            left.add(new DiffLine(a[i], DiffType.ADDED));
            right.add(new DiffLine("", DiffType.ADDED));
            i++;
        }

        while (j < b.length) {
            left.add(new DiffLine("", DiffType.REMOVED));
            right.add(new DiffLine(b[j], DiffType.REMOVED));
            j++;
        }

        markChangedPairs(left, right);
        return new DiffResult(left, right);
    }

    private static void markChangedPairs(List<DiffLine> left, List<DiffLine> right) {
        for (int k = 0; k < left.size() - 1; k++) {
            DiffLine l1 = left.get(k);
            DiffLine r1 = right.get(k);
            DiffLine l2 = left.get(k + 1);
            DiffLine r2 = right.get(k + 1);

            boolean firstIsAdd = l1.type == DiffType.ADDED && r1.text.isEmpty();
            boolean firstIsRem = r1.type == DiffType.REMOVED && l1.text.isEmpty();
            boolean secondIsAdd = l2.type == DiffType.ADDED && r2.text.isEmpty();
            boolean secondIsRem = r2.type == DiffType.REMOVED && l2.text.isEmpty();

            if ((firstIsAdd && secondIsRem) || (firstIsRem && secondIsAdd)) {
                left.set(k, new DiffLine(l1.text, DiffType.CHANGED));
                right.set(k, new DiffLine(r1.text, DiffType.CHANGED));
                left.set(k + 1, new DiffLine(l2.text, DiffType.CHANGED));
                right.set(k + 1, new DiffLine(r2.text, DiffType.CHANGED));
            }
        }
    }

    private static int[][] buildLcsTable(String[] a, String[] b) {
        int[][] lcs = new int[a.length + 1][b.length + 1];
        for (int i = a.length - 1; i >= 0; i--) {
            for (int j = b.length - 1; j >= 0; j--) {
                if (a[i].equals(b[j])) {
                    lcs[i][j] = lcs[i + 1][j + 1] + 1;
                } else {
                    lcs[i][j] = Math.max(lcs[i + 1][j], lcs[i][j + 1]);
                }
            }
        }
        return lcs;
    }

    private static String[] splitLines(String s) {
        if (s == null || s.isEmpty()) return new String[0];
        return s.replace("\r\n", "\n").replace("\r", "\n").split("\n", -1);
    }
}
