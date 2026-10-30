package com.acas.export;

import com.acas.model.MutationPoint;
import com.acas.model.OperationSafety;
import com.google.gson.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Extracts exact request locations without guessing object ownership or safety. */
public final class MutationPointExtractor {
    private MutationPointExtractor() {}

    private static final Set<String> SKIP_HEADERS = Set.of(
        "host", "content-length", "cookie", "authorization", "proxy-authorization",
        "connection", "accept-encoding", "x-pwnfox-color", "x-request-id",
        "traceparent", "tracestate", "x-correlation-id");

    public static List<MutationPoint> extract(byte[] raw) {
        if (raw == null) return List.of();
        String text = new String(raw, StandardCharsets.ISO_8859_1);
        int split = text.indexOf("\r\n\r\n");
        int skip = 4;
        if (split < 0) { split = text.indexOf("\n\n"); skip = 2; }
        String head = split < 0 ? text : text.substring(0, split);
        String body = split < 0 ? "" : text.substring(split + skip);
        String[] lines = head.split("\r?\n", -1);
        List<MutationPoint> points = new ArrayList<>();
        if (lines.length == 0) return points;
        String[] first = lines[0].trim().split("\\s+");
        if (first.length < 2) return points;
        addPath(points, first[1]);
        addQuery(points, first[1]);
        Map<String,String> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon <= 0) continue;
            String name = lines[i].substring(0, colon).trim();
            String value = lines[i].substring(colon + 1).trim();
            headers.put(name.toLowerCase(Locale.ROOT), value);
            String lowerName = name.toLowerCase(Locale.ROOT);
            // Only extract security-relevant custom headers (skip standard browser fluff to save Hermes context)
            if ((lowerName.startsWith("x-") || lowerName.contains("tenant") || lowerName.contains("org") || lowerName.contains("account"))
                && !SKIP_HEADERS.contains(lowerName) && !credentialName(name)) {
                MutationPoint point = point("header", name, "header[" + lowerName + "]", "text", value);
                points.add(point);
            }
        }
        addBody(points, headers.getOrDefault("content-type", ""), body);
        return List.copyOf(points);
    }

    private static void addPath(List<MutationPoint> points, String target) {
        String path = target == null ? "" : target.split("\\?", 2)[0];
        String[] segments = path.split("/", -1);
        for (int i = 0; i < segments.length; i++) {
            String segment = segments[i];
            if (dynamicSegment(segment)) {
                MutationPoint point = point("path", "segment[" + i + "]", "path[" + i + "]", "raw", decode(segment));
                point.valueType = segment.matches("[0-9]+") ? "number" : "string";
                points.add(point);
            }
        }
    }

    private static boolean dynamicSegment(String value) {
        if (value == null || value.isBlank()) return false;
        return value.matches("[0-9]+")
            || value.matches("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            || value.matches("[A-Za-z0-9_-]{12,}");
    }

    private static void addQuery(List<MutationPoint> points, String target) {
        if (target == null) return;
        int mark = target.indexOf('?');
        if (mark < 0) return;
        Map<String,Integer> occurrences = new HashMap<>();
        for (String pair : target.substring(mark + 1).split("&", -1)) {
            if (pair.isEmpty()) continue;
            int equals = pair.indexOf('=');
            String rawName = equals < 0 ? pair : pair.substring(0, equals);
            String rawValue = equals < 0 ? "" : pair.substring(equals + 1);
            String name = decode(rawName);
            if (credentialName(name)) continue;
            int index = occurrences.merge(rawName, 1, Integer::sum) - 1;
            String selector = "query[" + rawName + "][" + index + "]";
            MutationPoint point = point("query", name, selector, "url", decode(rawValue));
            point.valueType = rawValue.matches("[0-9]+") ? "number" : "string";
            points.add(point);
        }
    }

    private static void addBody(List<MutationPoint> points, String contentType, String body) {
        String type = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        if (body == null || body.isEmpty()) return;
        if (type.contains("application/json") || body.trim().startsWith("{") || body.trim().startsWith("[")) {
            addJson(points, body);
        } else if (type.contains("application/x-www-form-urlencoded")) {
            addForm(points, body);
        } else if (type.contains("multipart/form-data")) {
            addMultipart(points, contentType, body);
        }
    }

    private static void addJson(List<MutationPoint> points, String body) {
        try {
            JsonElement root = JsonParser.parseString(body);
            if (root.isJsonObject()) {
                JsonObject object = root.getAsJsonObject();
                if (object.has("query") && object.get("query").isJsonPrimitive()) {
                    String operation = object.get("query").getAsString();
                    boolean mutation = operation.regionMatches(true, 0, "mutation", 0, 8);
                    MutationPoint point = point("graphql", "operation", "graphql.operation", "json", operation);
                    point.valueType = "operation";
                    point.replayable = false;
                    point.metadata.put("graphqlOperation", mutation ? "MUTATION" : "QUERY");
                    point.mutationSafety = OperationSafety.UNKNOWN;
                    points.add(point);
                }
            }
            walkJson(points, root, "");
        } catch (JsonParseException ignored) {
            // Unknown bytes stay opaque; do not invent selectors.
        }
    }

    private static void walkJson(List<MutationPoint> points, JsonElement element, String pointer) {
        if (element == null || element.isJsonNull()) return;
        if (element.isJsonObject()) {
            for (Map.Entry<String,JsonElement> entry : element.getAsJsonObject().entrySet()) {
                String child = pointer + "/" + entry.getKey().replace("~", "~0").replace("/", "~1");
                walkJson(points, entry.getValue(), child);
            }
        } else if (element.isJsonArray()) {
            JsonArray array = element.getAsJsonArray();
            for (int i = 0; i < array.size(); i++) walkJson(points, array.get(i), pointer + "/" + i);
        } else if (element.isJsonPrimitive()) {
            JsonPrimitive primitive = element.getAsJsonPrimitive();
            String name = pointer.isEmpty() ? "value" : pointer.substring(pointer.lastIndexOf('/') + 1);
            if (credentialName(name)) return;
            String location = pointer.startsWith("/variables/") ? "graphql.variables" : "json";
            MutationPoint point = point(location, name, location + ":" + (pointer.isEmpty() ? "/" : pointer),
                "json", primitive.getAsString());
            point.valueType = primitive.isBoolean() ? "boolean" : primitive.isNumber() ? "number" : "string";
            point.schema = point.valueType;
            points.add(point);
        }
    }

    private static void addForm(List<MutationPoint> points, String body) {
        Map<String,Integer> occurrences = new HashMap<>();
        for (String pair : body.split("&", -1)) {
            if (pair.isEmpty()) continue;
            int equals = pair.indexOf('=');
            String rawName = equals < 0 ? pair : pair.substring(0, equals);
            String rawValue = equals < 0 ? "" : pair.substring(equals + 1);
            String name = decode(rawName);
            if (credentialName(name)) continue;
            int index = occurrences.merge(rawName, 1, Integer::sum) - 1;
            MutationPoint point = point("form", name, "form[" + rawName + "][" + index + "]", "url", decode(rawValue));
            point.valueType = rawValue.matches("[0-9]+") ? "number" : "string";
            points.add(point);
        }
    }

    private static void addMultipart(List<MutationPoint> points, String contentType, String body) {
        String marker = "boundary=";
        int at = contentType.toLowerCase(Locale.ROOT).indexOf(marker);
        if (at < 0) return;
        String boundary = contentType.substring(at + marker.length()).split("[;\\s]", 2)[0].replace("\"", "");
        if (boundary.isBlank()) return;
        for (String part : body.split(java.util.regex.Pattern.quote("--" + boundary))) {
            int name = part.indexOf("name=\"");
            if (name < 0) continue;
            int end = part.indexOf('"', name + 6);
            if (end < 0) continue;
            String field = part.substring(name + 6, end);
            if (credentialName(field)) continue;
            MutationPoint point = point("multipart", field, "multipart[" + field + "]", "multipart", "");
            point.replayable = false;
            point.metadata.put("filenamePresent", String.valueOf(part.contains("filename=\"")));
            points.add(point);
        }
    }

    private static MutationPoint point(String location, String name, String selector, String encoding, String value) {
        MutationPoint point = new MutationPoint();
        point.location = location;
        point.name = name;
        point.selector = selector;
        point.encoding = encoding;
        point.originalValue = redact(name, value);
        point.valueHash = HermesExport.hash(value == null ? "<null>" : value);
        point.schema = "string";
        point.mutationSafety = OperationSafety.UNKNOWN;
        point.pointId = "mutation-point:" + HermesExport.hash(location + "|" + selector + "|" + point.valueHash);
        return point;
    }

    private static String redact(String name, String value) {
        if (credentialName(name)) return "<redacted>";
        if (value == null) return null;
        return value.length() <= 512 ? value : value.substring(0, 512);
    }

    private static boolean credentialName(String name) {
        String n = name == null ? "" : name.toLowerCase(Locale.ROOT);
        return n.contains("password") || n.contains("passwd") || n.contains("secret") || n.contains("token")
            || n.equals("authorization") || n.equals("cookie") || n.equals("jwt") || n.contains("api_key")
            || n.contains("apikey") || n.equals("session") || n.equals("sid") || n.equals("csrf");
    }

    private static String decode(String value) {
        try { return URLDecoder.decode(value, StandardCharsets.UTF_8); }
        catch (IllegalArgumentException invalid) { return value; }
    }
}
