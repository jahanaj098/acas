package com.acas.harvest;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.acas.model.ActorProfile;
import com.acas.store.ActorStore;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IdHarvester {
    private static final Pattern NUMERIC_PATH_ID = Pattern.compile("/([0-9]{2,19})(?:/|$|\\?)");
    private static final Pattern UUID_PATH_ID = Pattern.compile(
        "/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\\?)",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern PREFIXED_PATH_ID = Pattern.compile("/([A-Z]{2,8}-[0-9]{1,15})(?:/|$|\\?)");
    private static final Pattern COOKIE_PAIR = Pattern.compile("\\s*([^=;\\s]+)\\s*=\\s*([^;]*)");
    private static final Pattern HTML_ID_ATTR = Pattern.compile(
        "(?:data-|aria-)?([a-zA-Z0-9_\\-]*(?:id|uuid|token|ref))\\s*=\\s*[\"']([^\"']{2,128})[\"']",
        Pattern.CASE_INSENSITIVE
    );

    private static final Set<String> ID_FIELD_NAMES = Set.of(
        "id", "user_id", "order_id", "product_id", "account_id",
        "customer_id", "transaction_id", "invoice_id", "file_id",
        "document_id", "message_id", "session_id", "request_id",
        "payment_id", "subscription_id", "profile_id", "post_id",
        "comment_id", "ticket_id", "case_id", "lead_id", "contact_id",
        "org_id", "organization_id", "company_id", "team_id", "group_id",
        "uid", "uuid", "guid", "ref", "reference", "token"
    );

    private static final List<String> REQUEST_HEADER_CANDIDATES = List.of(
        "X-User-Id", "X-Account-Id", "X-Resource-Id", "X-Request-Id", "X-Correlation-Id"
    );
    private static final List<String> RESPONSE_HEADER_CANDIDATES = List.of(
        "X-User-Id", "X-Account-Id", "X-Resource-Id", "X-Request-Id", "X-Correlation-Id", "Location"
    );

    private final ResourceRegistry registry;
    private final ActorStore actorStore;

    public IdHarvester(ResourceRegistry registry, ActorStore actorStore) {
        this.registry = registry;
        this.actorStore = actorStore;
    }

    public void harvest(HttpRequest request, HttpResponse response) {
        if (request == null) {
            return;
        }

        String actorId = identifyActorId(request);
        if (actorId == null) {
            return;
        }

        String endpointPattern = extractPattern(request);
        harvestFromPath(request.path(), endpointPattern, actorId);
        harvestFromQueryParams(request.url(), endpointPattern, actorId);
        harvestFromHeaders(request, endpointPattern, actorId, REQUEST_HEADER_CANDIDATES, "REQUEST_HEADER");
        harvestFromCookies(request.headerValue("Cookie"), endpointPattern, actorId);

        String reqBody = request.bodyToString();
        if (reqBody != null && !reqBody.isBlank()) {
            harvestFromJson(reqBody, endpointPattern, actorId, "REQUEST_BODY");
        }

        if (response == null) {
            return;
        }

        harvestFromHeaders(response, endpointPattern, actorId, RESPONSE_HEADER_CANDIDATES, "RESPONSE_HEADER");
        String resBody = response.bodyToString();
        if (resBody == null || resBody.isBlank()) {
            return;
        }

        String contentType = response.headerValue("Content-Type");
        String ct = contentType == null ? "" : contentType.toLowerCase();
        if (ct.contains("json")) {
            harvestFromJson(resBody, endpointPattern, actorId, "RESPONSE_BODY");
        } else if (ct.contains("html") || resBody.contains("data-") || resBody.contains("id=")) {
            harvestFromHtml(resBody, endpointPattern, actorId);
        }
    }

    private void harvestFromPath(String path, String pattern, String actor) {
        Matcher m = NUMERIC_PATH_ID.matcher(path);
        while (m.find()) {
            register(m.group(1), IdType.NUMERIC, "path_id", pattern, actor, "URL_PATH");
        }

        Matcher u = UUID_PATH_ID.matcher(path);
        while (u.find()) {
            register(u.group(1), IdType.UUID, "path_uuid", pattern, actor, "URL_PATH");
        }

        Matcher p = PREFIXED_PATH_ID.matcher(path);
        while (p.find()) {
            register(p.group(1), IdType.PREFIXED, "path_prefixed", pattern, actor, "URL_PATH");
        }
    }

    private void harvestFromQueryParams(String url, String pattern, String actor) {
        if (url == null || !url.contains("?")) {
            return;
        }

        String query = url.substring(url.indexOf('?') + 1);
        for (String param : query.split("&")) {
            String[] kv = param.split("=", 2);
            if (kv.length < 2) {
                continue;
            }
            String key = decode(kv[0]).toLowerCase();
            String val = decode(kv[1]);
            if (isIdFieldName(key) && isLikelyId(val)) {
                register(val, detectType(val), key, pattern, actor, "QUERY_PARAM");
            }
        }
    }

    private void harvestFromJson(String json, String pattern, String actor, String source) {
        try {
            JsonElement root = JsonParser.parseString(json);
            extractFromNode(root, pattern, actor, source);
        } catch (Exception ignored) {
        }
    }

    private void extractFromNode(JsonElement node, String pattern, String actor, String source) {
        if (node == null || node.isJsonNull()) {
            return;
        }

        if (node.isJsonObject()) {
            JsonObject obj = node.getAsJsonObject();
            for (String rawKey : obj.keySet()) {
                JsonElement val = obj.get(rawKey);
                String key = rawKey.toLowerCase();

                if (isIdFieldName(key) && val != null && val.isJsonPrimitive()) {
                    String value = val.getAsString();
                    if (isLikelyId(value)) {
                        register(value, detectType(value), rawKey, pattern, actor, source);
                    }
                }

                extractFromNode(val, pattern, actor, source);
            }
            return;
        }

        if (node.isJsonArray()) {
            JsonArray arr = node.getAsJsonArray();
            for (JsonElement child : arr) {
                extractFromNode(child, pattern, actor, source);
            }
        }
    }

    private void harvestFromHeaders(HttpRequest request,
                                    String pattern,
                                    String actor,
                                    List<String> candidates,
                                    String source) {
        for (String header : candidates) {
            String val = request.headerValue(header);
            if (val != null && isLikelyId(val)) {
                register(val, detectType(val), header.toLowerCase(), pattern, actor, source);
            }
        }
    }

    private void harvestFromHeaders(HttpResponse response,
                                    String pattern,
                                    String actor,
                                    List<String> candidates,
                                    String source) {
        for (String header : candidates) {
            String val = response.headerValue(header);
            if (val != null && isLikelyId(val)) {
                register(val, detectType(val), header.toLowerCase(), pattern, actor, source);
            }
        }
    }

    private void harvestFromCookies(String cookieHeader, String pattern, String actor) {
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return;
        }

        String[] pairs = cookieHeader.split(";");
        for (String pair : pairs) {
            Matcher m = COOKIE_PAIR.matcher(pair);
            if (!m.matches()) {
                continue;
            }
            String key = m.group(1).trim().toLowerCase();
            String value = m.group(2).trim();
            if (isIdFieldName(key) && isLikelyId(value)) {
                register(value, detectType(value), key, pattern, actor, "COOKIE");
            }
        }
    }

    private void harvestFromHtml(String html, String pattern, String actor) {
        Matcher m = HTML_ID_ATTR.matcher(html);
        while (m.find()) {
            String field = m.group(1);
            String value = m.group(2);
            if (isLikelyId(value)) {
                register(value, detectType(value), field, pattern, actor, "HTML_ATTR");
            }
        }
    }

    private String identifyActorId(HttpRequest request) {
        String actorId = actorStore.getActorIdByRequest(request);
        if (actorId != null) {
            return actorId;
        }
        // Unknown traffic has no actor ownership.
        return null;
    }

    private void register(String value,
                          IdType type,
                          String field,
                          String pattern,
                          String actorId,
                          String source) {
        ActorProfile actor = actorStore.getActor(actorId);
        String actorLabel = actor != null ? actor.getName() : actorId;
        registry.register(new HarvestedId(value, type, field, pattern, actorLabel, source));
    }

    private boolean isIdFieldName(String key) {
        if (key == null || key.isBlank()) {
            return false;
        }
        return ID_FIELD_NAMES.contains(key)
            || key.endsWith("_id")
            || key.endsWith("id")
            || key.endsWith("_uuid")
            || key.equals("id");
    }

    private boolean isLikelyId(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        if (value.length() > 128) {
            return false;
        }
        if (value.contains(" ")) {
            return false;
        }
        return value.matches("[a-zA-Z0-9\\-_.@:+/=]{2,}");
    }

    private IdType detectType(String value) {
        if (value.matches("\\d+")) {
            return IdType.NUMERIC;
        }
        if (value.matches("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) {
            return IdType.UUID;
        }
        if (value.matches("[A-Z]{2,8}-\\d+")) {
            return IdType.PREFIXED;
        }
        if (value.contains("@")) {
            return IdType.EMAIL;
        }
        if (value.matches("(?i)[0-9a-f]{32,}")) {
            return IdType.HASH;
        }
        if (value.matches("[a-zA-Z0-9+/=_-]{16,}")) {
            return IdType.BASE64;
        }
        if (value.matches("[a-z0-9]+(?:-[a-z0-9]+)+")) {
            return IdType.SLUG;
        }
        return IdType.UNKNOWN;
    }

    private String extractPattern(HttpRequest request) {
        String path = request.path();
        path = path.replaceAll("/\\d{2,}", java.util.regex.Matcher.quoteReplacement("/{id}"));
        path = path.replaceAll(
            "/(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            java.util.regex.Matcher.quoteReplacement("/{uuid}")
        );
        path = path.replaceAll("/[A-Z]{2,8}-\\d+", java.util.regex.Matcher.quoteReplacement("/{prefixed_id}"));
        return request.method() + " " + path;
    }

    private String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            return value;
        }
    }
}
