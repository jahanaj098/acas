package com.acas.engine;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ResponseComparator {
    public enum Verdict {
        TRUE_POSITIVE,
        LIKELY_TRUE,
        LIKELY_FALSE,
        FALSE_POSITIVE,
        NEEDS_MANUAL_REVIEW
    }

    public static class ComparisonResult {
        public final Verdict verdict;
        public final String reason;
        public final double similarityToOwner;
        public final double similarityToAnon;
        public final double similarityToInvalid;

        public ComparisonResult(Verdict verdict, String reason, double similarityToOwner, double similarityToAnon, double similarityToInvalid) {
            this.verdict = verdict;
            this.reason = reason;
            this.similarityToOwner = similarityToOwner;
            this.similarityToAnon = similarityToAnon;
            this.similarityToInvalid = similarityToInvalid;
        }
    }

    public static class AccessPatternSignal {
        public final int score;
        public final boolean shouldPromote;
        public final boolean autoPromote;
        public final double semanticSimilarity;
        public final double similarityToAnon;
        public final String reason;

        public AccessPatternSignal(int score,
                                   boolean shouldPromote,
                                   boolean autoPromote,
                                   double semanticSimilarity,
                                   double similarityToAnon,
                                   String reason) {
            this.score = score;
            this.shouldPromote = shouldPromote;
            this.autoPromote = autoPromote;
            this.semanticSimilarity = semanticSimilarity;
            this.similarityToAnon = similarityToAnon;
            this.reason = reason;
        }
    }

    private static final List<String> ERROR_STRINGS = List.of(
        "not found", "does not exist", "no such", "invalid id", "resource not found", "unauthorized",
        "forbidden", "access denied", "permission denied", "not authorized", "invalid request",
        "bad request", "error", "exception", "stack trace", "\"success\":false", "\"status\":\"error\"",
        "\"ok\":false", "\"result\":\"error\""
    );

    private static final Set<String> VOLATILE_FIELD_NAMES = new HashSet<>(List.of(
        "date", "time", "timestamp", "updated_at", "updatedat", "requestid", "request_id", "traceid",
        "trace_id", "nonce", "etag", "expires", "cache", "x-vercel-id", "x-vercel-cache", "x-request-id"
    ));

    private static final Set<String> SENSITIVE_FIELD_NAMES = new HashSet<>(List.of(
        "content", "title", "email", "phone", "passport", "ssn", "token", "address", "dob",
        "account", "user_id", "userid", "document_id", "documentid", "secret"
    ));

    public ComparisonResult compare(HttpResponse probeResponse,
                                    HttpResponse original,
                                    HttpResponse anonymous,
                                    HttpResponse invalidId,
                                    HttpRequest probeRequest) {
        if (probeResponse == null || original == null) {
            return new ComparisonResult(Verdict.NEEDS_MANUAL_REVIEW, "Missing baseline responses", 0, 0, 0);
        }

        double similarityToAnon = bodyEquality(probeResponse, anonymous);
        double similarityToInvalid = bodyEquality(probeResponse, invalidId);
        double similarityToOwner = bodyEquality(probeResponse, original);

        int probeStatus = probeResponse.statusCode();
        int anonStatus = anonymous != null ? anonymous.statusCode() : -1;

        if (!is2xx(original.statusCode())) {
            return new ComparisonResult(Verdict.NEEDS_MANUAL_REVIEW, "Owner baseline was not successful",
                similarityToOwner, similarityToAnon, similarityToInvalid);
        }

        AccessPatternSignal accessSignal = analyzeAccessPattern(
            original.statusCode(),
            safeBody(original),
            anonStatus,
            safeBody(anonymous),
            probeStatus,
            safeBody(probeResponse),
            probeRequest != null ? probeRequest.method() : null,
            probeRequest != null ? probeRequest.path() : null
        );

        if (probeStatus == 401 || probeStatus == 403 || probeStatus == 404 || probeStatus == 429) {
            return new ComparisonResult(Verdict.FALSE_POSITIVE, "Probe blocked by status code", similarityToOwner, similarityToAnon, similarityToInvalid);
        }

        if (!hasOwnerDataEvidence(safeBody(original), safeBody(probeResponse))) {
            return new ComparisonResult(Verdict.NEEDS_MANUAL_REVIEW,
                "No matching owner data: status, response length and shared formatting are not authorization evidence",
                similarityToOwner, similarityToAnon, similarityToInvalid);
        }

        if (accessSignal.autoPromote) {
            return new ComparisonResult(
                Verdict.TRUE_POSITIVE,
                "Strong IDOR signal (owner 2xx / anonymous denied / swapped 2xx + semantic match, score=" + accessSignal.score + ")",
                similarityToOwner,
                similarityToAnon,
                similarityToInvalid
            );
        }

        if (accessSignal.shouldPromote && accessSignal.score >= 80) {
            return new ComparisonResult(
                Verdict.TRUE_POSITIVE,
                "Access-pattern analysis marked as high confidence (score=" + accessSignal.score + ")",
                similarityToOwner,
                similarityToAnon,
                similarityToInvalid
            );
        }

        if (anonStatus == probeStatus && similarityToAnon > 0.95) {
            return new ComparisonResult(Verdict.FALSE_POSITIVE, "Probe matches anonymous baseline (public endpoint)", similarityToOwner, similarityToAnon, similarityToInvalid);
        }

        if (similarityToAnon > 0.90) {
            return new ComparisonResult(Verdict.FALSE_POSITIVE, "Response too similar to anonymous", similarityToOwner, similarityToAnon, similarityToInvalid);
        }

        if (similarityToInvalid > 0.90) {
            return new ComparisonResult(Verdict.FALSE_POSITIVE, "Response too similar to invalid-ID baseline", similarityToOwner, similarityToAnon, similarityToInvalid);
        }

        int probeLen = probeResponse.body().length();
        int authLen = original.body().length();
        if (probeLen < 50 && authLen > 200) {
            return new ComparisonResult(Verdict.FALSE_POSITIVE, "Probe response too short vs owner baseline", similarityToOwner, similarityToAnon, similarityToInvalid);
        }

        String probeBody = probeResponse.bodyToString() != null ? probeResponse.bodyToString().toLowerCase() : "";
        if (containsErrorString(probeBody)) {
            return new ComparisonResult(Verdict.FALSE_POSITIVE, "Error-like response content detected", similarityToOwner, similarityToAnon, similarityToInvalid);
        }

        if (similarityToOwner > 0.95) {
            return new ComparisonResult(Verdict.TRUE_POSITIVE, "Probe highly similar to owner baseline", similarityToOwner, similarityToAnon, similarityToInvalid);
        }

        if (Math.abs(probeLen - authLen) < 50 && authLen > 100) {
            return new ComparisonResult(Verdict.LIKELY_TRUE, "Probe length close to owner baseline", similarityToOwner, similarityToAnon, similarityToInvalid);
        }

        if (accessSignal.shouldPromote && accessSignal.score >= 65) {
            return new ComparisonResult(
                Verdict.LIKELY_TRUE,
                "Access-pattern analysis suggests likely IDOR (score=" + accessSignal.score + ")",
                similarityToOwner,
                similarityToAnon,
                similarityToInvalid
            );
        }

        return new ComparisonResult(Verdict.NEEDS_MANUAL_REVIEW, "Inconclusive differential signal", similarityToOwner, similarityToAnon, similarityToInvalid);
    }

    public AccessPatternSignal analyzeAccessPattern(int baselineStatus,
                                                    String baselineBody,
                                                    int anonymousStatus,
                                                    String anonymousBody,
                                                    int swapStatus,
                                                    String swapBody,
                                                    String method,
                                                    String path) {
        int score = 0;

        boolean gate = is2xx(baselineStatus) && isDenied(anonymousStatus) && is2xx(swapStatus);
        if (gate) {
            score += 40;
        }

        double semanticSimilarity = semanticSimilarity(baselineBody, swapBody);
        double anonSimilarity = semanticSimilarity(swapBody, anonymousBody);
        if (semanticSimilarity >= 0.85) {
            score += 35;
        } else if (semanticSimilarity >= 0.80) {
            score += 20;
        }

        int sensitiveOverlap = sharedSensitiveFieldCount(baselineBody, swapBody);
        if (sensitiveOverlap >= 2) {
            score += 20;
        } else if (sensitiveOverlap == 1) {
            score += 10;
        }

        if (hasObjectContext(path, method, baselineBody, swapBody)) {
            score += 10;
        }

        if (isGenericShortBody(swapBody) && sensitiveOverlap == 0) {
            score -= 15;
        }

        if (isLikelyPublicResource(path)) {
            score -= 30;
        }

        if (score < 0) score = 0;
        if (score > 100) score = 100;

        boolean ownerData = hasOwnerDataEvidence(baselineBody, swapBody);
        boolean autoPromote = gate && ownerData && semanticSimilarity >= 0.85;
        boolean shouldPromote = gate && ownerData && (autoPromote || score >= 65);
        if (!ownerData) score = Math.min(score, 30);
        String reason = "gate=" + gate + ", ownerData=" + ownerData + ", semantic=" + round2(semanticSimilarity) + ", anonSimilarity=" + round2(anonSimilarity) + ", score=" + score;
        return new AccessPatternSignal(score, shouldPromote, autoPromote, semanticSimilarity, anonSimilarity, reason);
    }

    /** Shared templates are not evidence. Require an unchanged data value. */
    public boolean hasOwnerDataEvidence(String baselineBody, String swapBody) {
        String owner = responseBody(baselineBody);
        String swapped = responseBody(swapBody);
        JsonElement a = parseJson(owner);
        JsonElement b = parseJson(swapped);
        if (a != null && b != null && (a.isJsonObject() || a.isJsonArray())) {
            return sharedSensitiveFieldCount(owner, swapped) > 0;
        }
        // Plain-text profiles (and embedded emails) must retain actual identity
        // values, not merely the labels or the surrounding welcome message.
        Set<String> ownerValues = identityValues(owner);
        Set<String> swapValues = identityValues(swapped);
        if (!ownerValues.isEmpty()) {
            ownerValues.retainAll(swapValues);
            return !ownerValues.isEmpty();
        }
        return owner.trim().length() >= 60 && !isGenericShortBody(owner)
            && normalizeBody(owner).equals(normalizeBody(swapped));
    }

    private Set<String> identityValues(String body) {
        Set<String> values = new HashSet<>();
        java.util.regex.Matcher email = java.util.regex.Pattern.compile(
            "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}").matcher(body);
        while (email.find()) values.add("email:" + email.group());
        java.util.regex.Matcher field = java.util.regex.Pattern.compile(
            "(?im)^\\s*(username|user_id|userid|account_id|email|id)\\s*[:=]\\s*([^\\r\\n]+)").matcher(body);
        while (field.find()) {
            String value = field.group(2).trim();
            if (!value.isEmpty()) values.add(field.group(1).toLowerCase(java.util.Locale.ROOT) + ":" + value);
        }
        return values;
    }

    /** Probe snapshots contain HTTP headers; never count those as shared data. */
    public static String responseBody(String raw) {
        if (raw == null) return "";
        if (!raw.startsWith("HTTP/")) return raw;
        int separator = raw.indexOf("\r\n\r\n");
        if (separator >= 0) return raw.substring(separator + 4);
        separator = raw.indexOf("\n\n");
        return separator >= 0 ? raw.substring(separator + 2) : "";
    }

    public double textSimilarity(String bodyA, String bodyB) {
        String normA = normalizeBody(bodyA);
        String normB = normalizeBody(bodyB);
        if (normA.isEmpty() && normB.isEmpty()) return 1.0;
        if (normA.isEmpty() || normB.isEmpty()) return 0.0;
        int maxLen = Math.max(normA.length(), normB.length());
        int distance = levenshteinDistance(normA, normB);
        return 1.0 - ((double) distance / maxLen);
    }

    private boolean is2xx(int status) {
        return status >= 200 && status < 300;
    }

    private boolean isDenied(int status) {
        return status == 401 || status == 403;
    }

    private String safeBody(HttpResponse response) {
        return response != null && response.bodyToString() != null ? response.bodyToString() : "";
    }

    public double semanticSimilarity(String baselineBody, String swapBody) {
        JsonElement a = parseJson(baselineBody);
        JsonElement b = parseJson(swapBody);

        if (a == null || b == null) {
            return textSimilarity(baselineBody, swapBody);
        }

        double shape = jsonShapeSimilarity(a, b);
        double stable = stableFieldSimilarity(a, b);
        return Math.max((shape * 0.45) + (stable * 0.55), textSimilarity(baselineBody, swapBody));
    }

    private int sharedSensitiveFieldCount(String baselineBody, String swapBody) {
        JsonElement a = parseJson(baselineBody);
        JsonElement b = parseJson(swapBody);
        if (a == null || b == null) {
            return 0;
        }

        Map<String, String> fieldsA = flattenStableFields(a);
        Map<String, String> fieldsB = flattenStableFields(b);
        int matched = 0;

        for (Map.Entry<String, String> entry : fieldsA.entrySet()) {
            String path = entry.getKey().toLowerCase();
            String valueA = entry.getValue();
            String valueB = fieldsB.get(entry.getKey());
            if (valueB == null) continue;
            if (!isSensitivePath(path)) continue;
            if (valueA != null && !valueA.isBlank() && !valueA.equals("true")
                    && !valueA.equals("false") && !valueA.equals("null") && valueA.equals(valueB)) {
                matched++;
            }
        }
        return matched;
    }

    private boolean hasObjectContext(String path, String method, String baselineBody, String swapBody) {
        String p = path != null ? path.toLowerCase() : "";
        if (p.matches(".*(/\\d+|/\\{[^}]*id[^}]*\\}).*")) return true;
        if (p.matches(".*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}.*")) return true;
        if (p.contains("/documents/") || p.contains("/users/") || p.contains("/orders/")) return true;
        if (method != null && ("PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method) || "DELETE".equalsIgnoreCase(method))) return true;

        JsonElement a = parseJson(baselineBody);
        JsonElement b = parseJson(swapBody);
        if (a != null && b != null) {
            Set<String> keys = new HashSet<>();
            collectKeys(a, keys);
            collectKeys(b, keys);
            for (String k : keys) {
                String low = k.toLowerCase();
                if (low.equals("id") || low.endsWith("_id") || low.endsWith("id")) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isGenericShortBody(String body) {
        String b = body != null ? body.trim().toLowerCase() : "";
        if (b.length() < 60) return true;
        return b.contains("ok") || b.contains("success") || b.contains("unauthorized") || b.contains("forbidden");
    }

    private boolean isLikelyPublicResource(String path) {
        if (path == null) return false;
        String p = path.toLowerCase();
        return p.contains("/public") || p.contains("/health") || p.contains("/status") || p.contains("/ping");
    }

    private JsonElement parseJson(String body) {
        if (body == null) return null;
        String trimmed = body.trim();
        if (trimmed.isEmpty()) return null;
        try {
            return JsonParser.parseString(trimmed);
        } catch (Exception ignored) {
            return null;
        }
    }

    private double jsonShapeSimilarity(JsonElement a, JsonElement b) {
        Set<String> keysA = new HashSet<>();
        Set<String> keysB = new HashSet<>();
        collectKeys(a, keysA);
        collectKeys(b, keysB);
        if (keysA.isEmpty() && keysB.isEmpty()) return 1.0;
        Set<String> intersection = new HashSet<>(keysA);
        intersection.retainAll(keysB);
        Set<String> union = new HashSet<>(keysA);
        union.addAll(keysB);
        if (union.isEmpty()) return 0.0;
        return (double) intersection.size() / union.size();
    }

    private double stableFieldSimilarity(JsonElement a, JsonElement b) {
        Map<String, String> mapA = flattenStableFields(a);
        Map<String, String> mapB = flattenStableFields(b);
        if (mapA.isEmpty() && mapB.isEmpty()) return 1.0;
        if (mapA.isEmpty() || mapB.isEmpty()) return 0.0;

        int overlap = 0;
        int equal = 0;
        for (Map.Entry<String, String> e : mapA.entrySet()) {
            if (mapB.containsKey(e.getKey())) {
                overlap++;
                if (e.getValue().equals(mapB.get(e.getKey()))) {
                    equal++;
                }
            }
        }
        if (overlap == 0) return 0.0;
        return (double) equal / overlap;
    }

    private Map<String, String> flattenStableFields(JsonElement root) {
        Map<String, String> out = new HashMap<>();
        flattenStableFields(root, "$", out);
        return out;
    }

    private void flattenStableFields(JsonElement e, String path, Map<String, String> out) {
        if (e == null || e instanceof JsonNull) return;

        if (e.isJsonObject()) {
            JsonObject obj = e.getAsJsonObject();
            List<String> keys = new ArrayList<>();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                keys.add(entry.getKey());
            }
            Collections.sort(keys);
            for (String key : keys) {
                if (isVolatileField(key)) continue;
                flattenStableFields(obj.get(key), path + "." + key, out);
            }
            return;
        }

        if (e.isJsonArray()) {
            JsonArray arr = e.getAsJsonArray();
            for (int i = 0; i < arr.size(); i++) {
                flattenStableFields(arr.get(i), path + "[" + i + "]", out);
            }
            return;
        }

        if (e.isJsonPrimitive()) {
            JsonPrimitive p = e.getAsJsonPrimitive();
            String value;
            if (p.isString()) {
                value = p.getAsString().trim();
            } else if (p.isBoolean()) {
                value = String.valueOf(p.getAsBoolean());
            } else if (p.isNumber()) {
                value = p.getAsString();
            } else {
                value = p.toString();
            }
            out.put(path, value);
        }
    }

    private void collectKeys(JsonElement e, Set<String> out) {
        if (e == null || e instanceof JsonNull) return;
        if (e.isJsonObject()) {
            JsonObject obj = e.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                out.add(entry.getKey());
                collectKeys(entry.getValue(), out);
            }
        } else if (e.isJsonArray()) {
            for (JsonElement child : e.getAsJsonArray()) {
                collectKeys(child, out);
            }
        }
    }

    private boolean isVolatileField(String key) {
        if (key == null) return false;
        String low = key.toLowerCase();
        if (VOLATILE_FIELD_NAMES.contains(low)) return true;
        return low.contains("time") || low.contains("cache") || low.contains("trace") || low.contains("request") || low.contains("vercel");
    }

    private boolean isSensitivePath(String path) {
        if (path == null) return false;
        String low = path.toLowerCase();
        if (low.matches(".*\\.(id|username|user_id|userid|account_id|owner_id)(\\[\\d+\\])?$")) return true;
        for (String s : SENSITIVE_FIELD_NAMES) {
            if (low.contains("." + s) || low.endsWith("_" + s) || low.contains(s)) {
                return true;
            }
        }
        return false;
    }

    private String round2(double value) {
        return String.format(java.util.Locale.ROOT, "%.2f", value);
    }

    private boolean containsErrorString(String body) {
        for (String s : ERROR_STRINGS) {
            if (body.contains(s)) return true;
        }
        return false;
    }

    public double bodyEquality(HttpResponse a, HttpResponse b) {
        return textSimilarity(a != null ? a.bodyToString() : "", b != null ? b.bodyToString() : "");
    }

    // Removed duplicate semanticSimilarity

    private String normalizeBody(String body) {
        if (body == null) return "";
        return body
            .replaceAll("\"requestId\"\\s*:\\s*\"[^\"]+\"", "\"requestId\":\"REQ\"")
            .replaceAll("\"traceId\"\\s*:\\s*\"[^\"]+\"", "\"traceId\":\"TRACE\"")
            .replaceAll("\\s+", " ")
            .trim();
    }

    private int levenshteinDistance(String s1, String s2) {
        int[] prev = new int[s2.length() + 1];
        int[] curr = new int[s2.length() + 1];

        for (int j = 0; j <= s2.length(); j++) prev[j] = j;

        for (int i = 1; i <= s1.length(); i++) {
            curr[0] = i;
            for (int j = 1; j <= s2.length(); j++) {
                int cost = s1.charAt(i - 1) == s2.charAt(j - 1) ? 0 : 1;
                curr[j] = Math.min(Math.min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            int[] tmp = prev;
            prev = curr;
            curr = tmp;
        }

        return prev[s2.length()];
    }
}
