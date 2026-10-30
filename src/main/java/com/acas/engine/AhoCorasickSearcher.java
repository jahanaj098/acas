package com.acas.engine;

import java.util.*;

/**
 * AhoCorasickSearcher — High-performance multi-pattern search engine.
 *
 * Problem it solves:
 *   The previous ComparisonEngine.checkCrossActorLeak() compiled and ran a separate
 *   regex per actor object against the response body. With 5 actors × 100 objects each,
 *   this meant 500 regex operations per mutated response, causing severe Burp Suite slowdowns.
 *
 * Solution:
 *   Aho-Corasick is a string search automaton that finds all occurrences of any pattern
 *   in a text in a single O(N + M) pass, where N = text length and M = total pattern length.
 *   All actor values are compiled into a single automaton at hunt start and reused across
 *   every response — reducing 500 regex ops to 1 linear scan.
 *
 * Minimum entropy guard:
 *   Values shorter than 5 chars are excluded from the automaton. Short values like "1" or "on"
 *   would produce enormous false positive rates in a single-pass scan. They are handled
 *   separately via key-value context matching in ComparisonEngine.
 */
public class AhoCorasickSearcher {

    private static final int MIN_VALUE_LENGTH = 5;

    /**
     * A match found during search — contains the matched value and the actor it belongs to.
     */
    public static class Match {
        public final String value;
        public final String actorId;

        public Match(String value, String actorId) {
            this.value = value;
            this.actorId = actorId;
        }
    }

    // Trie node structure
    private static class Node {
        final Map<Character, Node> children = new HashMap<>();
        Node failLink = null;
        // If this node is the end of a pattern, store its actor ID and value
        String patternValue = null;
        String patternActorId = null;
        // Output link for chained matches
        Node outputLink = null;
    }

    private final Node root;

    private AhoCorasickSearcher(Node root) {
        this.root = root;
    }

    /**
     * Build the Aho-Corasick automaton from a map of actorId → list of values.
     * Call this once at hunt start and cache the result.
     *
     * @param actorValues Map of actorId to their list of sensitive object values
     * @return A ready-to-use AhoCorasickSearcher
     */
    public static AhoCorasickSearcher build(Map<String, List<String>> actorValues) {
        Node root = new Node();

        // Phase 1: Build the trie
        for (Map.Entry<String, List<String>> entry : actorValues.entrySet()) {
            String actorId = entry.getKey();
            for (String value : entry.getValue()) {
                if (value == null || value.length() < MIN_VALUE_LENGTH) continue;

                Node current = root;
                for (char c : value.toCharArray()) {
                    current = current.children.computeIfAbsent(c, k -> new Node());
                }
                // Mark the end of this pattern
                if (current.patternValue == null) {
                    current.patternValue = value;
                    current.patternActorId = actorId;
                }
            }
        }

        // Phase 2: Build fail links using BFS (standard Aho-Corasick construction)
        Queue<Node> queue = new LinkedList<>();
        root.failLink = root;

        for (Node child : root.children.values()) {
            child.failLink = root;
            queue.add(child);
        }

        while (!queue.isEmpty()) {
            Node current = queue.poll();
            for (Map.Entry<Character, Node> entry : current.children.entrySet()) {
                char c = entry.getKey();
                Node child = entry.getValue();

                Node fail = current.failLink;
                while (fail != root && !fail.children.containsKey(c)) {
                    fail = fail.failLink;
                }
                Node failTarget = fail.children.get(c);
                child.failLink = (failTarget != null && failTarget != child) ? failTarget : root;

                // Build output link: point to the nearest ancestor that is a pattern end
                if (child.failLink.patternValue != null) {
                    child.outputLink = child.failLink;
                } else {
                    child.outputLink = child.failLink.outputLink;
                }

                queue.add(child);
            }
        }

        return new AhoCorasickSearcher(root);
    }

    /**
     * Search the given text for all patterns compiled into this automaton.
     * Returns a list of matches, each containing the matched value and the actor it belongs to.
     *
     * Applies a custom word-boundary check using lookahead/lookbehind logic to prevent
     * matching "9001" inside "90010" or "account_90010".
     *
     * @param text The HTTP response body to search
     * @return List of matches found (may be empty, never null)
     */
    public List<Match> search(String text) {
        List<Match> matches = new ArrayList<>();
        if (text == null || text.isEmpty() || root == null) return matches;

        Node current = root;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);

            // Follow fail links until we find a match or reach the root
            while (current != root && !current.children.containsKey(c)) {
                current = current.failLink;
            }
            if (current.children.containsKey(c)) {
                current = current.children.get(c);
            }

            // Collect all matches at this position (via output links)
            Node output = current;
            while (output != null) {
                if (output.patternValue != null) {
                    int endPos = i + 1;
                    int startPos = endPos - output.patternValue.length();

                    // Custom word-boundary check: ensure the match is not surrounded by alphanumeric chars
                    boolean leftOk  = (startPos == 0)            || !Character.isLetterOrDigit(text.charAt(startPos - 1));
                    boolean rightOk = (endPos == text.length())  || !Character.isLetterOrDigit(text.charAt(endPos));

                    if (leftOk && rightOk) {
                        matches.add(new Match(output.patternValue, output.patternActorId));
                    }
                }
                output = output.outputLink;
            }
        }
        return matches;
    }

    /**
     * Quick check: returns true if ANY pattern from the given actor set exists in the text.
     * More efficient than search() when you only need a boolean result.
     *
     * @param text The HTTP response body
     * @param excludeActorId The actor ID to exclude from matching (the replay actor's own ID)
     * @return true if a cross-actor value was found
     */
    public boolean containsCrossActorValue(String text, String excludeActorId) {
        List<Match> matches = search(text);
        for (Match m : matches) {
            if (!m.actorId.equals(excludeActorId)) {
                return true;
            }
        }
        return false;
    }
}
