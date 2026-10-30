package com.acas.util;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FieldDiffUtils {

    // Sensitive field patterns to look for in the response bodies
    private static final String[] SENSITIVE_FIELDS = {
        "id", "uuid", "email", "token", "auth", "secret", "total", "price", 
        "address", "phone", "name", "username", "account", "balance", "credit"
    };

    /**
     * Extracts common JSON keys or Form fields from two responses 
     * and identifies which sensitive ones match.
     */
    public static String findLeakedFields(byte[] baseline, byte[] attacker) {
        if (baseline == null || attacker == null) return "---";

        String baseBody = extractBody(baseline);
        String atkBody = extractBody(attacker);

        if (baseBody.isEmpty() || atkBody.isEmpty()) return "---";

        Set<String> baseFields = extractKeys(baseBody);
        Set<String> atkFields = extractKeys(atkBody);

        List<String> leaked = new ArrayList<>();
        for (String field : SENSITIVE_FIELDS) {
            if (baseFields.contains(field) && atkFields.contains(field)) {
                // If both share the key, it's a potential leak
                leaked.add(field);
            }
        }

        if (leaked.isEmpty()) return "---";
        return String.join(", ", leaked);
    }

    private static String extractBody(byte[] response) {
        // Fix #7: Use explicit UTF-8 to prevent charset corruption on non-UTF-8 platforms (e.g. Windows CP1252)
        String s = new String(response, java.nio.charset.StandardCharsets.UTF_8);
        int split = s.indexOf("\r\n\r\n");
        if (split == -1) return "";
        return s.substring(split + 4);
    }

    private static Set<String> extractKeys(String body) {
        Set<String> keys = new HashSet<>();
        
        // Fix #8: Expanded JSON Key Extraction — now captures keys with hyphens and dots
        // e.g. "user-id": OR "user.name":
        Pattern jsonPattern = Pattern.compile("\"([a-zA-Z0-9_\\-\\.]+)\"\\s*:");
        Matcher jsonMatcher = jsonPattern.matcher(body);
        while (jsonMatcher.find()) {
            keys.add(jsonMatcher.group(1).toLowerCase());
        }

        // Fix #8: Expanded Form/Query Extraction — now captures keys with hyphens and dots
        // e.g. user-id= OR user.name=
        Pattern formPattern = Pattern.compile("([a-zA-Z0-9_\\-\\.]+)=");
        Matcher formMatcher = formPattern.matcher(body);
        while (formMatcher.find()) {
            keys.add(formMatcher.group(1).toLowerCase());
        }

        return keys;
    }
}
