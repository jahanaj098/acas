package com.acas.engine;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DiscoveryEngine {

    private final ObjectManager objectManager;
    private static final Pattern UUID_PATTERN = Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern ID_KEY_PATTERN = Pattern.compile("(?i).*(_id|uid|uuid|key|owner|creator|user|account|org).*");
    private static final Pattern ID_VAL_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{4,64}$");
    private static final Pattern NUMERIC_ID_PATTERN = Pattern.compile("^\\d+$");
    private static final Pattern HASH_PATTERN = Pattern.compile("^[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}$");
    private static final Pattern SENSITIVE_KEYWORDS = Pattern.compile("(?i)(internal|admin|debug|test|dev|staging|beta|private|restricted|system|manage|root|superuser|config|setup)");

    public DiscoveryEngine(ObjectManager objectManager) {
        this.objectManager = objectManager;
    }

    private static final Pattern VERSION_PATTERN = Pattern.compile("(?i)^(v\\d+|beta|alpha|dev|stable|prod|internal|v[0-9.]+)$");

    public java.util.List<String> getSegments(String path) {
        if (path == null || path.isEmpty()) return java.util.Collections.emptyList();
        
        java.util.List<String> segments = new java.util.ArrayList<>();
        
        // Handle Query Params
        String mainPath = path;
        if (path.contains("?")) {
            String[] parts = path.split("\\?", 2);
            mainPath = parts[0];
            String query = parts[1];
            for (String param : query.split("&")) {
                if (!param.isEmpty()) segments.add(param); // Add "view=socials"
            }
        }

        // Handle Path Segments
        for (String s : mainPath.split("/")) {
            if (s.isEmpty()) continue;
            
            // 1. Add original
            segments.add(s);
            
            // 2. Handle Hyphens (user-profile)
            if (s.contains("-")) {
                String[] parts = s.split("-");
                for (String p : parts) if (!p.isEmpty()) segments.add(p);
                segments.add(s.replace("-", "")); // userprofile
            }
        }
        
        return segments;
    }

    public boolean isVersionToken(String segment) {
        return VERSION_PATTERN.matcher(segment).matches();
    }

    public boolean isPriorityPath(String path) {
        if (path == null) return false;
        return SENSITIVE_KEYWORDS.matcher(path).find();
    }

    public String normalizePath(String path) {
        if (path == null || path.isEmpty()) return path;
        
        String[] segments = path.split("/");
        StringBuilder sb = new StringBuilder();
        
        for (int i = 0; i < segments.length; i++) {
            String s = segments[i];
            if (s.isEmpty()) {
                if (i == 0) sb.append("/");
                continue;
            }
            
            String normalized = s;
            if (NUMERIC_ID_PATTERN.matcher(s).matches()) {
                normalized = "{id}";
            } else if (UUID_PATTERN.matcher(s).matches()) {
                normalized = "{uuid}";
            } else if (HASH_PATTERN.matcher(s).matches()) {
                normalized = "{hash}";
            } else if (i > 0 && segments[i-1].toLowerCase().contains("search") || segments[i-1].toLowerCase().contains("query")) {
                // Keep as-is if preceded by search/query
            } else if (s.length() > 20 && s.matches(".*\\d.*") && s.matches(".*[a-zA-Z].*")) {
                // Likely some other random ID/token
                normalized = "{token}";
            }
            
            sb.append(normalized);
            if (i < segments.length - 1 || path.endsWith("/")) {
                sb.append("/");
            }
        }
        
        return sb.toString();
    }

    public void discover(String actorId, String source, String contentType) {
        if (source == null || source.isEmpty()) return;

        // 1. JSON Tree Walking (AST-style)
        if (contentType != null && contentType.toLowerCase().contains("json")) {
            try {
                JsonElement root = JsonParser.parseString(source);
                walkJson(actorId, root, "$");
            } catch (Exception ignored) {
                // Not valid JSON, fallback to regex
            }
        }

        // 2. High-Fidelity Regex (Always run as fallback/addition)
        discoverRegex(actorId, source);
    }

    private void walkJson(String actorId, JsonElement element, String path) {
        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                String key = entry.getKey();
                JsonElement val = entry.getValue();
                String currentPath = path + "." + key;

                if (val.isJsonPrimitive()) {
                    String valStr = val.getAsString();
                    if (ID_KEY_PATTERN.matcher(key).matches() && ID_VAL_PATTERN.matcher(valStr).matches()) {
                        if (!isNoise(valStr)) {
                            objectManager.registerOwnership(actorId, key, valStr, 1.0, "JSON Path: " + currentPath);
                        }
                    } else {
                        // Even if key doesn't match, if value is a UUID, we want it
                        if (UUID_PATTERN.matcher(valStr).matches()) {
                            objectManager.registerOwnership(actorId, key, valStr, 0.9, "JSON UUID at " + currentPath);
                        }
                    }
                } else {
                    walkJson(actorId, val, currentPath);
                }
            }
        } else if (element.isJsonArray()) {
            int i = 0;
            for (JsonElement sub : element.getAsJsonArray()) {
                walkJson(actorId, sub, path + "[" + (i++) + "]");
            }
        }
    }

    private void discoverRegex(String actorId, String source) {
        // Find UUIDs
        Matcher m = UUID_PATTERN.matcher(source);
        while (m.find()) {
            objectManager.registerOwnership(actorId, "inferred_uuid", m.group(), 0.8, "Regex: UUID Pattern");
        }

        // Find common ID patterns in URL/Params
        Matcher paramM = Pattern.compile("(?i)([a-z0-9_-]*id|uid|uuid)(=|:|\")([a-z0-9_-]{4,64})", Pattern.CASE_INSENSITIVE).matcher(source);
        while (paramM.find()) {
            String key = paramM.group(1);
            String val = paramM.group(3);
            if (!isNoise(val)) {
                objectManager.registerOwnership(actorId, key, val, 0.9, "Regex: Param/Key match");
            }
        }
    }

    private boolean isNoise(String val) {
        return val.equals("null") || val.equals("true") || val.equals("false") || val.equals("undefined") || val.equals("void");
    }
}
