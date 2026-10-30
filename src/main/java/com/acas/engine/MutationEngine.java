package com.acas.engine;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.HttpParameter;
import com.acas.harvest.ResourceRegistry;
import com.acas.model.ActorProfile;
import com.acas.model.CapturedEndpoint;
import com.acas.store.ActorStore;
import com.acas.store.PayloadStore;
import com.acas.util.HttpUtils;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonElement;

public class MutationEngine {

    private final ActorStore store;
    private final ObjectManager objectManager;
    private final MutationRegistry mutationRegistry;
    private final PayloadStore payloadStore;
    private final ResourceRegistry resourceRegistry;
    private final ParameterPivotEngine parameterPivotEngine;

    public MutationEngine(ActorStore store, ObjectManager objectManager, MutationRegistry mutationRegistry, PayloadStore payloadStore) {
        this(store, objectManager, mutationRegistry, payloadStore, null);
    }

    public MutationEngine(ActorStore store,
                          ObjectManager objectManager,
                          MutationRegistry mutationRegistry,
                          PayloadStore payloadStore,
                          ResourceRegistry resourceRegistry) {
        this.store = store;
        this.objectManager = objectManager;
        this.mutationRegistry = mutationRegistry;
        this.payloadStore = payloadStore;
        this.resourceRegistry = resourceRegistry;
        this.parameterPivotEngine = new ParameterPivotEngine();
    }

    public List<MutationVector> generateVectors(CapturedEndpoint endpoint, List<ActorProfile> actors, List<CapturedEndpoint> allCaptured) {
        return generateVectors(endpoint, actors, allCaptured, null);
    }

    public List<MutationVector> generateVectors(CapturedEndpoint endpoint,
                                                List<ActorProfile> actors,
                                                List<CapturedEndpoint> allCaptured,
                                                Set<String> overrideMutationCodes) {
        // ACAS focused mode — this engine performs ONLY the two deterministic
        // authorization-consistency tests. Every other mutation technique
        // (path tricks, header spoofing, JWT, ID guessing, GraphQL, etc.) is
        // intentionally delegated to the Hermes agent and is no longer emitted.
        //   A1  Clean Anonymous  — strip all session headers, fire with zero auth
        //   B1  Session Swap     — replay the identical request as every other actor
        List<MutationVector> vectors = new ArrayList<>();
        if (endpoint == null) return vectors;
        HttpRequest original = endpoint.getOriginalRequest();
        if (original == null) return vectors;

        // A1 — Anonymous (no session)
        HttpRequest clean = HttpUtils.stripAuthHeaders(original, store.getAllIdentityHeaderNames());
        vectors.add(new MutationVector("A1", null, "Clean Anonymous", clean));

        // B1 — Session swap against every other actor (self is skipped)
        if (actors != null) {
            for (ActorProfile actor : actors) {
                if (actor == null || actor.getId() == null) continue;
                if (actor.getId().equals(endpoint.getActorId())) continue;
                vectors.add(new MutationVector("B1", actor, "Session Swap", original));
            }
        }

        return vectors;
    }

    private void addAnonymousMutations(List<MutationVector> vectors, HttpRequest original) {
        // A1: Clean Anonymous (No Session - Stage 2 baseline)
        HttpRequest clean = HttpUtils.stripAuthHeaders(original, store.getAllIdentityHeaderNames());
        vectors.add(new MutationVector("A1", null, "Clean Anonymous", clean));

        // A2: IP Spoofing
        List<String> ipHeaders = payloadsOrDefault("A2_IP_HEADER_NAMES", Arrays.asList(
            "X-Forwarded-For", "X-Real-IP", "X-Client-IP", "True-Client-IP", "X-ProxyUser-IP", "X-Originating-IP"
        ));
        List<String> ipValues = payloadsOrDefault("A2_IP_VALUES", Arrays.asList("127.0.0.1"));
        for (String h : ipHeaders) {
            for (String ip : ipValues) {
                vectors.add(new MutationVector("A2", null, "IP Spoof: " + h + "=" + ip, clean.withHeader(h, ip)));
            }
        }

        // A3: URL Override
        List<String> overridePaths = payloadsOrDefault("A3_OVERRIDE_PATHS", Arrays.asList(original.path()));
        List<String> overrideHeaders = payloadsOrDefault("A3_OVERRIDE_HEADER_NAMES", Arrays.asList("X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Path", "X-Override-URL"));
        for (String targetPath : overridePaths) {
            for (String h : overrideHeaders) {
                vectors.add(new MutationVector("A3", null, "URL Override: " + h + "=" + targetPath,
                    clean.withHeader(h, targetPath)));
            }
        }

        // A4: Host Header
        List<String> hostValues = payloadsOrDefault("A4_HOST_VALUES", Arrays.asList("localhost", "127.0.0.1"));
        String originalHost = original.headerValue("Host");
        for (String host : hostValues) {
            vectors.add(new MutationVector("A4", null, "Host Header: " + host, clean.withHeader("Host", host)));
            vectors.add(new MutationVector("A4", null, "X-Forwarded-Host: " + host, clean.withHeader("X-Forwarded-Host", host)));
            if (originalHost != null && !originalHost.isEmpty()) {
                vectors.add(new MutationVector("A4", null, "Dual Host/XFH: " + host,
                    clean.withHeader("Host", originalHost).withHeader("X-Forwarded-Host", host)));
            }
        }

        // A5: Auth Confusion
        List<String> authConfusionValues = payloadsOrDefault("A5_AUTH_VALUES", Arrays.asList("null", "undefined"));
        for (String val : authConfusionValues) {
            vectors.add(new MutationVector("A5", null, "Auth Confusion: Bearer " + val,
                clean.withHeader("Authorization", "Bearer " + val)));
        }

        // A6: Path Null Byte & Extensions
        String path = original.path();
        vectors.add(new MutationVector("A6", null, "Path Null Byte", clean.withPath(path + "%00")));
        List<String> a6Extensions = payloadsOrDefault("A6_EXTENSIONS", Arrays.asList(".json", ".xml"));
        for (String ext : a6Extensions) {
            vectors.add(new MutationVector("A6", null, "Path Extension: " + ext, clean.withPath(path + ext)));
        }

        // A7: Duplicate Slashes & Case
        vectors.add(new MutationVector("A7", null, "Duplicate Slashes", clean.withPath("/" + path)));
        vectors.add(new MutationVector("A7", null, "Case Variation", clean.withPath(path.toUpperCase())));

        // A8: Path Traversal
        List<String> a8Patterns = payloadsOrDefault("A8_TRAVERSAL_PATTERNS", Arrays.asList("/../", "/./"));
        for (String pattern : a8Patterns) {
            vectors.add(new MutationVector("A8", null, "Path Traversal: " + pattern, clean.withPath(path + pattern)));
        }

        // A9: Admin param injection (unauthenticated escalation attempt)
        List<String> adminParams = payloadsOrDefault("A9_ADMIN_PARAMS", Arrays.asList(
            "admin=true","is_admin=1","role=admin","debug=true","sudo=1","superuser=true","privilege=admin"
        ));
        for (String p : adminParams) {
            String sep = original.path().contains("?") ? "&" : "?";
            vectors.add(new MutationVector("A9", null, "Admin Param: " + p,
                clean.withPath(original.path() + sep + p)));
        }

        // A10: Content-Type confusion (anon probe with different content type)
        List<String> ctypes = payloadsOrDefault("A10_CONTENT_TYPES", Arrays.asList("application/x-www-form-urlencoded","text/plain","application/xml","multipart/form-data"));
        for (String ct : ctypes) {
            vectors.add(new MutationVector("A10", null, "Content-Type: " + ct,
                clean.withHeader("Content-Type", ct)));
        }

        // A11: Accept header variation (may expose different serializer with different fields)
        String[] accepts = {"application/xml","text/html","application/csv","*/*"};
        for (String ac : accepts) {
            vectors.add(new MutationVector("A11", null, "Accept: " + ac,
                clean.withHeader("Accept", ac)));
        }

        // A12: TRACE method (reflects headers, detects token leakage)
        vectors.add(new MutationVector("A12", null, "TRACE method",
            clean.withMethod("TRACE")));

        // A13: Path suffix bypass (trailing slash, semicolon confusion)
        List<String> a13Suffixes = payloadsOrDefault("A13_PATH_SUFFIXES", Arrays.asList("/", ";foo=bar", "%23admin"));
        for (String suffix : a13Suffixes) {
            vectors.add(new MutationVector("A13", null, "Path suffix: " + suffix,
                clean.withPath(original.path() + suffix)));
        }

        // A14: Internal prefix probing (unauthenticated internal path access)
        List<String> internalPrefixes = payloadsOrDefault("A14_INTERNAL_PREFIXES", Arrays.asList("/internal", "/private", "/admin", "/sys", "/management"));
        String rawPath = original.path();
        for (String prefix : internalPrefixes) {
            vectors.add(new MutationVector("A14", null, "Internal prefix: " + prefix,
                clean.withPath(prefix + rawPath)));
        }

        // A15: Method tunneling via query
        List<String> methodParamNames = payloadsOrDefault("A15_METHOD_PARAMS", Arrays.asList("_method", "method"));
        String[] methodValues = {"DELETE", "PUT", "PATCH"};
        for (String name : methodParamNames) {
            for (String value : methodValues) {
                String sep = original.path().contains("?") ? "&" : "?";
                vectors.add(new MutationVector("A15", null, "Method tunnel query: " + name + "=" + value,
                    clean.withPath(original.path() + sep + name + "=" + value)));
            }
        }

        // A16: Origin header bypass
        List<String> origins = payloadsOrDefault("A16_ORIGIN_VALUES", Arrays.asList("null", "http://localhost", "https://target.com.evil.com", "http://127.0.0.1"));
        for (String origin : origins) {
            vectors.add(new MutationVector("A16", null, "Origin: " + origin,
                clean.withHeader("Origin", origin)));
        }

        // A17: Referer header bypass
        String host = original.headerValue("Host");
        if (host == null || host.trim().isEmpty()) host = "target.com";
        List<String> refererPaths = payloadsOrDefault("A17_REFERER_PATHS", Arrays.asList("/admin"));
        for (String rp : refererPaths) {
            vectors.add(new MutationVector("A17", null, "Referer spoof: " + rp,
                clean.withHeader("Referer", "https://" + host + rp)));
        }

        // A18: Cache buster without auth
        List<String> cacheBusterParams = payloadsOrDefault("A18_CACHE_PARAMS", Arrays.asList("cb", "_", "nocache", "bust"));
        for (String cb : cacheBusterParams) {
            String sep = original.path().contains("?") ? "&" : "?";
            vectors.add(new MutationVector("A18", null, "Cache buster: " + cb,
                clean.withPath(original.path() + sep + cb + "=1")));
        }

        // A19: HTTP version downgrade probe (header-level approximation)
        vectors.add(new MutationVector("A19", null, "HTTP/1.0 probe",
            clean.withHeader("X-ACAS-HTTP-Version", "1.0").withHeader("Connection", "close")));

        // A20: Absolute URI request-line style probe (path-level approximation)
        vectors.add(new MutationVector("A20", null, "Absolute URI path probe",
            clean.withPath(original.url())));
    }

    private void addSessionSwapMutations(List<MutationVector> vectors,
                                         HttpRequest original,
                                         ActorProfile targetActor,
                                         String requestingActorId) {
        // B1: Direct Swap (Base IDOR)
        vectors.add(new MutationVector("B1", targetActor, "Session Swap", original));

        // B2: Method Mutations
        List<String> methods = payloadsOrDefault("B2_HTTP_METHODS", Arrays.asList("PUT", "DELETE", "PATCH", "POST", "HEAD", "OPTIONS"));
        List<String> overrideHeaders = payloadsOrDefault("B2_OVERRIDE_HEADERS", Arrays.asList("X-HTTP-Method-Override"));
        for (String m : methods) {
            if (!original.method().equalsIgnoreCase(m)) {
                vectors.add(new MutationVector("B2", targetActor, "Method Mutation: " + m, original.withMethod(m)));
                for (String oh : overrideHeaders) {
                    vectors.add(new MutationVector("B2", targetActor, "Method Override: " + oh + "=" + m, original.withHeader(oh, m)));
                }
            }
        }

        // B3: Parameter Pollution (Attacker ID as cover)
        List<ObjectManager.ObjectEntry> targetObjects = objectManager.getObjectsForActor(targetActor.getId());
        List<String> pollutionPatterns = payloadsOrDefault("B3_POLLUTION_PATTERNS", Arrays.asList("[]", "[0]", "dup"));
        for (ObjectManager.ObjectEntry obj : targetObjects) {
                if (original.url().contains("?")) {
                    vectors.add(new MutationVector("B3", targetActor, "Pollution: " + obj.type + "=" + obj.value,
                        original.withUpdatedParameters(burp.api.montoya.http.message.params.HttpParameter.parameter(obj.type, obj.value, HttpParameterType.URL))
                    ));
                    for (String p : pollutionPatterns) {
                        String paramName = "dup".equalsIgnoreCase(p) ? obj.type : obj.type + p;
                        vectors.add(new MutationVector("B3", targetActor, "Pollution Pattern: " + paramName + "=" + obj.value,
                            original.withUpdatedParameters(burp.api.montoya.http.message.params.HttpParameter.parameter(paramName, obj.value, HttpParameterType.URL))
                        ));
                    }

                }
        }

        // B4: Version Swapping — detect ANY version pattern in path
        String path = original.path();
        List<String> versions = payloadsOrDefault("B4_API_VERSIONS", Arrays.asList("v0", "v1", "v2", "v3", "beta", "api/v2"));
        java.util.regex.Matcher versionMatcher = java.util.regex.Pattern
            .compile("/(v\\d+|beta|alpha|staging|latest)/", java.util.regex.Pattern.CASE_INSENSITIVE)
            .matcher(path);
        if (versionMatcher.find()) {
            String currentVersion = versionMatcher.group(1);
            for (String v : versions) {
                if (!v.equalsIgnoreCase(currentVersion)) {
                    vectors.add(new MutationVector("B4", targetActor,
                        "Version Swap: " + currentVersion + "→" + v,
                        original.withPath(path.replace("/" + currentVersion + "/", "/" + v + "/"))));
                }
            }
        }

        // B5: ID replacement with cross-actor IDs from ResourceRegistry (fallback: object map)
        java.util.regex.Pattern idPattern = java.util.regex.Pattern.compile("([a-f0-9]{24})|([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})|(\\b\\d{1,12}\\b)");
        java.util.regex.Matcher idMatcher = idPattern.matcher(path);
        if (idMatcher.find()) {
            String detectedId = idMatcher.group();
            List<String> crossActorIds = getCrossActorIdsForPath(original, requestingActorId, targetActor.getId());

            if (!crossActorIds.isEmpty()) {
                int count = 0;
                for (String id : crossActorIds) {
                    if (id == null || id.equals(detectedId)) continue;
                    vectors.add(new MutationVector("B5", targetActor,
                        "ID Swap (harvested): " + detectedId + "->" + id,
                        original.withPath(path.replace(detectedId, id))));
                    count++;
                    if (count >= 5) break;
                }
            } else {
                List<ObjectManager.ObjectEntry> crossObjects = objectManager.getObjectsForActor(targetActor.getId());
                int count = 0;
                for (ObjectManager.ObjectEntry obj : crossObjects) {
                    if (obj.value == null || obj.value.equals(detectedId)) continue;
                    vectors.add(new MutationVector("B5", targetActor,
                        "ID Swap: " + detectedId + "->" + obj.value,
                        original.withPath(path.replace(detectedId, obj.value))));
                    count++;
                    if (count >= 5) break;
                }
            }
        }

        String bodyStr = original.bodyToString();
        // B6: JSON body ID swap
        if (bodyStr != null && bodyStr.trim().startsWith("{")) {
            java.util.regex.Pattern jsonIdPattern = java.util.regex.Pattern.compile("\"([a-zA-Z0-9_]*(?:id|_id|_key|_ref))\"\\s*:\\s*\"?([A-Za-z0-9_\\-]{2,64})\"?");
            java.util.regex.Matcher bodyMatcher = jsonIdPattern.matcher(bodyStr);
            List<String> harvestedCrossIds = getCrossActorIdsForPath(original, requestingActorId, targetActor.getId());
            List<ObjectManager.ObjectEntry> crossObjects = objectManager.getObjectsForActor(targetActor.getId());
            while (bodyMatcher.find()) {
                String fieldName = bodyMatcher.group(1);
                String fieldValue = bodyMatcher.group(2);
                int count = 0;
                if (!harvestedCrossIds.isEmpty()) {
                    for (String id : harvestedCrossIds) {
                        if (id == null || id.equals(fieldValue)) continue;
                        String updatedBody = bodyStr.replace("\"" + fieldName + "\": \"" + fieldValue + "\"", "\"" + fieldName + "\": \"" + id + "\"");
                        if (!updatedBody.equals(bodyStr)) {
                            vectors.add(new MutationVector("B6", targetActor,
                                "Body ID Swap (harvested): " + fieldName + "=" + fieldValue + "->" + id,
                                original.withBody(updatedBody)));
                            count++;
                        }
                        if (count >= 3) break;
                    }
                } else {
                    for (ObjectManager.ObjectEntry obj : crossObjects) {
                        if (obj.value == null || obj.value.equals(fieldValue)) continue;
                        String updatedBody = bodyStr.replace("\"" + fieldName + "\": \"" + fieldValue + "\"", "\"" + fieldName + "\": \"" + obj.value + "\"");
                        if (!updatedBody.equals(bodyStr)) {
                            vectors.add(new MutationVector("B6", targetActor,
                                "Body ID Swap: " + fieldName + "=" + fieldValue + "->" + obj.value,
                                original.withBody(updatedBody)));
                            count++;
                        }
                        if (count >= 3) break;
                    }
                }
            }
        }

        // B7: Array ID wrap — match any ID-like field (id, user_id, account_id, *_key, *_ref, etc.)
        if (bodyStr != null) {
            java.util.regex.Pattern b7Pattern = java.util.regex.Pattern
                .compile("\"([a-zA-Z0-9_]*(?:id|Id|ID|_id|_key|_ref|_uuid))\"\\s*:\\s*\"?([A-Za-z0-9_\\-]{2,64})\"?");
            java.util.regex.Matcher arrMatcher = b7Pattern.matcher(bodyStr);
            while (arrMatcher.find()) {
                String matchedFieldName = arrMatcher.group(1);
                String origId = arrMatcher.group(2);
                List<String> harvestedCrossIds = getCrossActorIdsForPath(original, requestingActorId, targetActor.getId());
                String xId = null;
                if (!harvestedCrossIds.isEmpty()) {
                    xId = harvestedCrossIds.get(0);
                } else {
                    List<ObjectManager.ObjectEntry> crossObjects = objectManager.getObjectsForActor(targetActor.getId());
                    if (!crossObjects.isEmpty()) {
                        xId = crossObjects.get(0).value;
                    }
                }
                if (xId != null && !xId.equals(origId)) {
                    List<String> arrayPatterns = payloadsOrDefault("B7_ARRAY_PATTERNS", Arrays.asList("[{id}]", "[{id},{id}]"));
                    for (String arrPattern : arrayPatterns) {
                        String replaced = arrPattern.replace("{id}", "\"" + xId + "\"");
                        String newIdBlock = "\"" + matchedFieldName + "\": " + replaced;
                        String fieldRegex = "\"" + java.util.regex.Pattern.quote(matchedFieldName) + "\"\\s*:\\s*\"?([A-Za-z0-9_\\-]{2,64})\"?";
                        String wrappedBody = bodyStr.replaceFirst(fieldRegex, java.util.regex.Matcher.quoteReplacement(newIdBlock));
                        if (!wrappedBody.equals(bodyStr)) {
                            vectors.add(new MutationVector("B7", targetActor,
                                (harvestedCrossIds.isEmpty() ? "Array ID Wrap (" : "Array ID Wrap (harvested, ") + matchedFieldName + "): " + arrPattern,
                                original.withBody(wrappedBody)));
                        }
                    }
                }
                break; // process first matching ID field to avoid vector explosion
            }
        }

        // B8: ID Neighbor Enumeration
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\d+").matcher(path);
        if (m.find()) {
            String originalId = m.group();
            long id = Long.parseLong(originalId);
            List<String> offsets = payloadsOrDefault("B8_NEIGHBOR_OFFSETS", Arrays.asList("1", "2", "5"));
            java.util.Set<String> emitted = new java.util.LinkedHashSet<>();
            for (String offset : offsets) {
                try {
                    long off = Long.parseLong(offset);
                    String cand = String.valueOf(id + off);
                    if (emitted.add(cand)) {
                        vectors.add(new MutationVector("B8", targetActor, "Neighbor ID: +" + off, original.withPath(path.replace(originalId, cand))));
                    }
                } catch (Exception ignored) {
                }
            }

            // Smart neighbor targeting from harvested endpoint IDs
            if (resourceRegistry != null) {
                String endpointPattern = endpointPatternForRequest(original);
                List<String> known = resourceRegistry.getKnownNeighbours(endpointPattern, id, 100);
                for (String candidate : known) {
                    if (candidate.equals(originalId)) continue;
                    if (emitted.add(candidate)) {
                        vectors.add(new MutationVector("B8", targetActor,
                            "Neighbor ID (harvested): " + candidate,
                            original.withPath(path.replace(originalId, candidate))));
                    }
                }
            }
        }

        // B9: Numeric neighbors — extended (test -1, -2, +2, +5, -5, 0, 1, -1)
        java.util.regex.Matcher m2 = java.util.regex.Pattern.compile("\\d+").matcher(path);
        if (m2.find()) {
            String originalId = m2.group();
            long id = Long.parseLong(originalId);
            List<String> edgeValues = payloadsOrDefault("B9_EDGE_IDS", Arrays.asList("1", "0", "-1"));
            List<Long> candidates = new ArrayList<>();
            candidates.add(id - 1);
            candidates.add(id + 2);
            candidates.add(id - 2);
            candidates.add(id + 5);
            candidates.add(id - 5);
            for (String edge : edgeValues) {
                try {
                    candidates.add(Long.parseLong(edge));
                } catch (Exception ignored) {
                }
            }

            // Smart min/max edge probes from harvested actor IDs
            if (resourceRegistry != null) {
                List<String> numericIds = resourceRegistry.getNumericIdsByActor(targetActor.getName());
                if (!numericIds.isEmpty()) {
                    java.util.List<Long> nums = new java.util.ArrayList<>();
                    for (String v : numericIds) {
                        try { nums.add(Long.parseLong(v)); } catch (Exception ignored) {}
                    }
                    if (!nums.isEmpty()) {
                        long min = nums.stream().mapToLong(Long::longValue).min().orElse(id);
                        long max = nums.stream().mapToLong(Long::longValue).max().orElse(id);
                        candidates.add(0L);
                        candidates.add(-1L);
                        candidates.add(min - 1);
                        candidates.add(max + 1);
                        candidates.add(max + 2);
                    }
                }
            }

            java.util.Set<Long> uniqueCandidates = new java.util.LinkedHashSet<>(candidates);
            for (long neighbor : uniqueCandidates) {
                if (neighbor != id) {
                    vectors.add(new MutationVector("B9", targetActor,
                        "Neighbor ID: " + neighbor,
                        original.withPath(path.replace(originalId, String.valueOf(neighbor)))));
                }
            }
        }

        // B10: Type juggling — string id → int, int id → string
        if (bodyStr != null) {
            // string "9901" → int 9901
            String intBody = bodyStr.replaceAll("\"id\"\\s*:\\s*\"(\\d+)\"", "\"id\": $1");
            if (!intBody.equals(bodyStr)) {
                vectors.add(new MutationVector("B10", targetActor,
                    "Type Juggling: string→int", original.withBody(intBody)));
            }
            // int 9901 → string "9901"
            String strBody = bodyStr.replaceAll("\"id\"\\s*:\\s*(\\d+)(?=[,}])", "\"id\": \"$1\"");
            if (!strBody.equals(bodyStr)) {
                vectors.add(new MutationVector("B10", targetActor,
                    "Type Juggling: int→string", original.withBody(strBody)));
            }

            List<String> typeValues = payloadsOrDefault("B10_TYPE_JUGGLING", Arrays.asList("true", "false", "null"));
            for (String typeVal : typeValues) {
                String customBody = bodyStr.replaceAll("\"id\"\\s*:\\s*\"?[^\",}]+\"?", "\"id\": " + typeVal);
                if (!customBody.equals(bodyStr)) {
                    vectors.add(new MutationVector("B10", targetActor,
                        "Type Juggling: custom=" + typeVal, original.withBody(customBody)));
                }
            }
        }

        // B11: JSON privilege injection (mass assignment)
        if (bodyStr != null && bodyStr.trim().startsWith("{")) {
            List<String> privFields = payloadsOrDefault("B11_MASS_ASSIGN_FIELDS", Arrays.asList("role", "is_admin", "permissions"));
            for (String fieldName : privFields) {
                int lastBrace = bodyStr.lastIndexOf("}");
                if (lastBrace > 0) {
                    String injectedBody = bodyStr.substring(0, lastBrace)
                        + ", \"" + fieldName + "\": true}";
                    vectors.add(new MutationVector("B11", targetActor,
                        "Priv Inject: " + fieldName, original.withBody(injectedBody)));
                }
            }
        }

        // B12: JWT manipulation (if Authorization: Bearer <token>)
        String authHeader = original.headerValue("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            String[] parts = token.split("\\.");
            if (parts.length == 3) {
                // Attempt alg:none
                String noneHeader = java.util.Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes());
                String noneToken = noneHeader + "." + parts[1] + ".";
                vectors.add(new MutationVector("B12", targetActor,
                    "JWT alg:none", original.withHeader("Authorization", "Bearer " + noneToken)));

                List<String> algValues = payloadsOrDefault("B12_JWT_ALG_VALUES", Arrays.asList("none", "HS256", "RS256"));
                for (String alg : algValues) {
                    String hdr = java.util.Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(("{\"alg\":\"" + alg + "\",\"typ\":\"JWT\"}").getBytes());
                    String forged = hdr + "." + parts[1] + "." + parts[2];
                    vectors.add(new MutationVector("B12", targetActor,
                        "JWT alg=" + alg, original.withHeader("Authorization", "Bearer " + forged)));
                }

                List<String> kidPayloads = payloadsOrDefault("B12_KID_PAYLOADS", Arrays.asList("../../dev/null"));
                for (String kid : kidPayloads) {
                    String kidHeader = java.util.Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"" + kid + "\"}").getBytes());
                    String kidToken = kidHeader + "." + parts[1] + "." + parts[2];
                    vectors.add(new MutationVector("B12", targetActor,
                        "JWT kid payload=" + kid,
                        original.withHeader("Authorization", "Bearer " + kidToken)));
                }

                // Decode payload and try role escalation
                try {
                    String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
                    if (payload.contains("\"role\"")) {
                        String escalated = payload
                            .replace("\"user\"", "\"admin\"")
                            .replace("\"viewer\"", "\"admin\"")
                            .replace("\"member\"", "\"admin\"");
                        String escalatedB64 = java.util.Base64.getUrlEncoder().withoutPadding()
                            .encodeToString(escalated.getBytes());
                        String escalatedToken = parts[0] + "." + escalatedB64 + "." + parts[2];
                        vectors.add(new MutationVector("B12", targetActor,
                            "JWT Role Escalation", original.withHeader("Authorization", "Bearer " + escalatedToken)));
                    }
                } catch (Exception ignored) {}
            }
        }

        // B13: Session partial strip — strip individual session cookies one at a time
        String cookieHeader = original.headerValue("Cookie");
        if (cookieHeader != null && cookieHeader.contains(";")) {
            String[] cookies = cookieHeader.split(";\\s*");
            List<String> stripPatterns = payloadsOrDefault("B13_COOKIE_STRIP", Arrays.asList("session", "auth", "token"));
            for (String cookie : cookies) {
                String cookieName = cookie.split("=")[0].trim().toLowerCase();
                boolean shouldStrip = stripPatterns.stream().anyMatch(p -> cookieName.contains(p.toLowerCase()));
                if (!shouldStrip) continue;
                String stripped = java.util.Arrays.stream(cookies)
                    .filter(c -> !c.trim().equals(cookie.trim()))
                    .collect(java.util.stream.Collectors.joining("; "));
                vectors.add(new MutationVector("B13", targetActor,
                    "Partial Session Strip: -" + cookie.split("=")[0].trim(),
                    original.withHeader("Cookie", stripped)));
            }
        }

        // B14: Custom role headers
        List<String> roleHeaders = payloadsOrDefault("B14_ROLE_HEADERS", Arrays.asList(
            "X-User-Role:admin", "X-Role:superuser", "X-Privilege:1",
            "X-Admin:true", "X-Internal:1", "X-Service:internal",
            "X-Is-Admin:true", "X-User-Level:0"
        ));
        for (String rh : roleHeaders) {
            String[] kv = rh.split(":", 2);
            if (kv.length == 2) {
                vectors.add(new MutationVector("B14", targetActor,
                    "Role Header: " + rh, original.withHeader(kv[0], kv[1])));
            }
        }

        // B15: Horizontal IDOR same-role using ResourceRegistry (fallback: object map)
        java.util.regex.Matcher sameLevelId = java.util.regex.Pattern.compile("([a-f0-9]{24}|[0-9a-fA-F-]{36}|\\d{1,12})").matcher(path);
        if (sameLevelId.find()) {
            String ownId = sameLevelId.group(1);

            ActorProfile requestor = store.getActor(requestingActorId);
            boolean sameRoleLevel = requestor != null && requestor.getRoleLevel() == targetActor.getRoleLevel();

            if (sameRoleLevel) {
                List<String> harvestedCrossIds = getCrossActorIdsForPath(original, requestingActorId, targetActor.getId());
                if (!harvestedCrossIds.isEmpty()) {
                    for (String id : harvestedCrossIds) {
                        if (id != null && !id.equals(ownId)) {
                            vectors.add(new MutationVector("B15", targetActor,
                                "Horizontal same-role ID swap (harvested): " + id,
                                original.withPath(path.replace(ownId, id))));
                            break;
                        }
                    }
                } else {
                    for (ObjectManager.ObjectEntry obj : objectManager.getObjectsForActor(targetActor.getId())) {
                        if (obj.value != null && !obj.value.equals(ownId)) {
                            vectors.add(new MutationVector("B15", targetActor,
                                "Horizontal shared resource ID swap: " + obj.value,
                                original.withPath(path.replace(ownId, obj.value))));
                            break;
                        }
                    }
                }
            }
        }

        // B16: Second-order IDOR seed payload (store then trigger behavior)
        if (bodyStr != null && bodyStr.trim().startsWith("{")) {
            int brace = bodyStr.lastIndexOf('}');
            if (brace > 0) {
                String stagedBody = bodyStr.substring(0, brace)
                    + ", \"acas_second_order_ref\": \"cross_actor_probe\"}''";
                vectors.add(new MutationVector("B16", targetActor,
                    "Second-order IDOR seed payload",
                    original.withBody(stagedBody.replace("}''", "}"))));
            }
        }

        // B17: Wildcard / Match-All Param Injection (ORM/PostgREST bypass)
        List<String> wildcards = payloadsOrDefault("B17_WILDCARD_IDS", Arrays.asList("*", "%", "_"));
        for (burp.api.montoya.http.message.params.HttpParameter param : original.parameters()) {
            if (param == null || (param.type() != burp.api.montoya.http.message.params.HttpParameterType.URL && param.type() != burp.api.montoya.http.message.params.HttpParameterType.BODY)) {
                continue;
            }
            for (String wc : wildcards) {
                HttpRequest mutated = original.withUpdatedParameters(
                    burp.api.montoya.http.message.params.HttpParameter.parameter(param.name(), wc, param.type())
                );
                vectors.add(new MutationVector("B17", targetActor, 
                    "Wildcard Param Injection: " + param.name() + "=" + wc, mutated));
            }
        }

        // B19: Advanced NoSQL & Array ID Wrap
        for (burp.api.montoya.http.message.params.HttpParameter param : original.parameters()) {
            if (param == null) continue;
            
            // Only target parameters that look like IDs (numeric or common names)
            boolean looksLikeId = param.name().toLowerCase().contains("id") || 
                                  param.name().toLowerCase().endsWith("_key") ||
                                  param.value().matches("^\\d+$") ||
                                  param.value().matches("^[0-9a-fA-F-]{36}$");
                                  
            if (!looksLikeId) continue;
            
            String origVal = param.value();
            
            if (param.type() == burp.api.montoya.http.message.params.HttpParameterType.URL || 
                param.type() == burp.api.montoya.http.message.params.HttpParameterType.BODY) {
                
                // 1. Array Wrap URL/Body
                vectors.add(new MutationVector("B19", targetActor, 
                    "Array Wrap Param: " + param.name() + "[]=" + origVal,
                    original.withUpdatedParameters(burp.api.montoya.http.message.params.HttpParameter.parameter(param.name() + "[]", origVal, param.type()))));
                
                // 2. Array Wrap with Math Offset (if numeric)
                if (origVal.matches("^\\d+$")) {
                    try {
                        long id = Long.parseLong(origVal);
                        HttpRequest arrReq = original.withUpdatedParameters(
                            burp.api.montoya.http.message.params.HttpParameter.parameter(param.name() + "[]", origVal, param.type()),
                            burp.api.montoya.http.message.params.HttpParameter.parameter(param.name() + "[]", String.valueOf(id + 1), param.type())
                        );
                        vectors.add(new MutationVector("B19", targetActor, 
                            "Array Wrap Math Offset: " + param.name() + "[]=" + origVal + "&" + param.name() + "[]=" + (id+1), arrReq));
                    } catch (NumberFormatException ignored) {}
                }
            }
        }
        
        // B19: NoSQL and JSON Array injection for JSON bodies
        if (bodyStr != null && bodyStr.trim().startsWith("{")) {
            java.util.regex.Pattern jsonFieldPattern = java.util.regex.Pattern.compile("\"([a-zA-Z0-9_]*(?:id|Id|ID|_id|_key|_ref))\"\\s*:\\s*(\"?)([A-Za-z0-9_\\-]{1,64})\\2");
            java.util.regex.Matcher m19 = jsonFieldPattern.matcher(bodyStr);
            while (m19.find()) {
                String fieldName = m19.group(1);
                String quote = m19.group(2);
                String origVal = m19.group(3);
                
                String rawVal = quote.isEmpty() ? origVal : "\"" + origVal + "\"";
                
                // Math array
                if (origVal.matches("^\\d+$")) {
                    try {
                        long id = Long.parseLong(origVal);
                        String mathArray = "[" + id + ", " + (id + 1) + ", " + (id + 2) + "]";
                        String mutated = bodyStr.replaceFirst(java.util.regex.Pattern.quote(m19.group(0)), java.util.regex.Matcher.quoteReplacement("\"" + fieldName + "\": " + mathArray));
                        if (!mutated.equals(bodyStr)) {
                            vectors.add(new MutationVector("B19", targetActor, "JSON Array Offset Wrap: " + fieldName + "=" + mathArray, original.withBody(mutated)));
                        }
                    } catch(Exception ignored){}
                }
                
                // Cross-Actor Array
                List<String> xIds = getCrossActorIdsForPath(original, requestingActorId, targetActor.getId());
                if (!xIds.isEmpty()) {
                    String xId = xIds.get(0);
                    String xRaw = quote.isEmpty() && xId.matches("^\\d+$") ? xId : "\"" + xId + "\"";
                    String xArray = "[" + rawVal + ", " + xRaw + "]";
                    String mutated = bodyStr.replaceFirst(java.util.regex.Pattern.quote(m19.group(0)), java.util.regex.Matcher.quoteReplacement("\"" + fieldName + "\": " + xArray));
                    if (!mutated.equals(bodyStr)) {
                        vectors.add(new MutationVector("B19", targetActor, "JSON Array Cross-Actor Wrap: " + fieldName + "=" + xArray, original.withBody(mutated)));
                    }
                }
                
                // NoSQL Operators
                String[] nosqlPayloads = { "{\"$gt\": 0}", "{\"$ne\": null}", "{\"$ne\": -1}", "{\"$nin\": []}" };
                for (String payload : nosqlPayloads) {
                    String mutated = bodyStr.replaceFirst(java.util.regex.Pattern.quote(m19.group(0)), java.util.regex.Matcher.quoteReplacement("\"" + fieldName + "\": " + payload));
                    if (!mutated.equals(bodyStr)) {
                        vectors.add(new MutationVector("B19", targetActor, "JSON NoSQL Injection: " + fieldName + "=" + payload, original.withBody(mutated)));
                    }
                }
                break; // target first matched ID
            }
        }

        // B16b: Replay actor A's latest harvested ID with actor B session
        if (resourceRegistry != null && requestingActorId != null) {
            ActorProfile requestor = store.getActor(requestingActorId);
            if (requestor != null) {
                String endpointPattern = endpointPatternForRequest(original);
                String latestId = resourceRegistry.getLatestIdForPatternActor(endpointPattern, requestor.getName());
                if (latestId != null && !latestId.isBlank()) {
                    java.util.regex.Matcher pathIdMatcher = java.util.regex.Pattern
                        .compile("([a-f0-9]{24}|[0-9a-fA-F-]{36}|\\d{1,12}|[A-Z]{2,8}-\\d+)")
                        .matcher(path);
                    if (pathIdMatcher.find()) {
                        String ownId = pathIdMatcher.group(1);
                        if (!latestId.equals(ownId)) {
                            vectors.add(new MutationVector("B16", targetActor,
                                "Second-order IDOR replay (harvested latest): " + latestId,
                                original.withPath(path.replace(ownId, latestId))));
                        }
                    }
                }
            }
        }

        // B17: Wildcard and glob ID
        List<String> wildcardIds = payloadsOrDefault("B17_WILDCARD_IDS", Arrays.asList("*", "%", "_", "..", "**", "?", "[0-9]*"));
        java.util.regex.Matcher wid = java.util.regex.Pattern.compile("([a-f0-9]{24}|[0-9a-fA-F-]{36}|\\d{1,12})").matcher(path);
        if (wid.find()) {
            String originalId = wid.group(1);
            for (String wildcard : wildcardIds) {
                vectors.add(new MutationVector("B17", targetActor,
                    "Wildcard ID: " + wildcard,
                    original.withPath(path.replace(originalId, wildcard))));
            }
        }

        // B18: Reference-swap ID mutation with double-encode guards
        if (resourceRegistry != null) {
            String endpointPattern = endpointPatternForRequest(original);
            ActorProfile requestor = requestingActorId == null ? null : store.getActor(requestingActorId);
            String requestorName = requestor != null ? requestor.getName() : null;

            java.util.regex.Pattern referenceSwapIdPattern = java.util.regex.Pattern.compile("([a-f0-9]{24}|[0-9a-fA-F-]{36}|\\d{1,12}|[A-Z]{2,8}-\\d+)");
            java.util.regex.Matcher pathMatcher = referenceSwapIdPattern.matcher(path);
            if (pathMatcher.find()) {
                String ownId = pathMatcher.group(1);
                List<String> harvestedRefs = new ArrayList<>(resourceRegistry.getIdsByPatternAndActor(endpointPattern, targetActor.getName()));
                if (harvestedRefs.isEmpty() && requestorName != null) {
                    harvestedRefs.addAll(resourceRegistry.getCrossActorIds(endpointPattern, requestorName, targetActor.getName()));
                }
                if (harvestedRefs.isEmpty()) {
                    harvestedRefs.addAll(resourceRegistry.getAllKnownIds());
                }
                harvestedRefs.addAll(resourceRegistry.getManualCandidatesByPatternAndActor(endpointPattern, targetActor.getName()));
                harvestedRefs.addAll(resourceRegistry.getManualCandidates());

                java.util.LinkedHashSet<String> uniqueRefs = new java.util.LinkedHashSet<>(harvestedRefs);
                int emitted = 0;
                for (String ref : uniqueRefs) {
                    if (ref == null || ref.isBlank() || ref.equals(ownId)) continue;
                    for (String variant : referenceSwapVariants(ref)) {
                        String mutatedPath = path.replace(ownId, variant);
                        if (!mutatedPath.equals(path)) {
                            vectors.add(new MutationVector("B18", targetActor,
                                "Reference Swap: " + ownId + " -> " + variant,
                                original.withPath(mutatedPath)));
                        }
                    }
                    emitted++;
                    if (emitted >= 4) break;
                }
            }

            String jsonBody = original.bodyToString();
            if (jsonBody != null && jsonBody.trim().startsWith("{")) {
                java.util.regex.Pattern jsonIdPattern = java.util.regex.Pattern.compile("\\\"([a-zA-Z0-9_]*(?:id|_id|_key|_ref|_uuid|_token|_code))\\\"\\s*:\\s*\\\"?([A-Za-z0-9_\\-]{2,128})\\\"?");
                java.util.regex.Matcher bodyMatcher = jsonIdPattern.matcher(jsonBody);
                int emitted = 0;
                while (bodyMatcher.find()) {
                    String fieldName = bodyMatcher.group(1);
                    String ownValue = bodyMatcher.group(2);
                    List<String> harvestedRefs = new ArrayList<>(resourceRegistry.getIdsByPatternAndActor(endpointPattern, targetActor.getName()));
                    if (harvestedRefs.isEmpty() && requestorName != null) {
                        harvestedRefs.addAll(resourceRegistry.getCrossActorIds(endpointPattern, requestorName, targetActor.getName()));
                    }
                    if (harvestedRefs.isEmpty()) {
                        harvestedRefs.addAll(resourceRegistry.getAllKnownIds());
                    }
                    harvestedRefs.addAll(resourceRegistry.getManualCandidatesByPatternAndActor(endpointPattern, targetActor.getName()));
                    harvestedRefs.addAll(resourceRegistry.getManualCandidates());

                    java.util.LinkedHashSet<String> uniqueRefs = new java.util.LinkedHashSet<>(harvestedRefs);
                    for (String ref : uniqueRefs) {
                        if (ref == null || ref.isBlank() || ref.equals(ownValue)) continue;
                        for (String variant : referenceSwapVariants(ref)) {
                            String updatedBody = replaceJsonFieldValue(jsonBody, fieldName, ownValue, variant);
                            if (updatedBody != null && !updatedBody.equals(jsonBody)) {
                                vectors.add(new MutationVector("B18", targetActor,
                                    "Reference Swap Body: " + fieldName + "=" + ownValue + " -> " + variant,
                                    original.withBody(updatedBody)));
                            }
                        }
                        emitted++;
                        if (emitted >= 4) break;
                    }
                    if (emitted >= 4) break;
                }
            }
        }
    }

    private void addPathRelationshipMutations(List<MutationVector> vectors, CapturedEndpoint current, List<ActorProfile> actors, List<CapturedEndpoint> all) {
        if (all == null) return;
        
        for (CapturedEndpoint other : all) {
            if (other.getNormalizedPath().equals(current.getNormalizedPath())) continue;

            // 1. Segment Swapping
            List<String> curSegs = current.getSegments();
            List<String> othSegs = other.getSegments();
            
            // Find commonality
            boolean related = false;
            for (String s : curSegs) {
                if (othSegs.contains(s)) { related = true; break; }
            }

            if (related) {
                // Swap segments (Test 2)
                if (curSegs.size() > 0 && othSegs.size() > 0) {
                    // Try replacing last segment of cur with last of oth
                    List<String> combined = new ArrayList<>(curSegs);
                    combined.set(combined.size() - 1, othSegs.get(othSegs.size() - 1));
                    String newPath = "/" + String.join("/", combined);
                    
                    for (ActorProfile actor : actors) {
                        vectors.add(new MutationVector("C1", actor, "Segment Swap Path: " + newPath, current.getOriginalRequest().withPath(newPath)));
                    }
                }

                // Prefix Variation (Test 3)
                if (curSegs.size() > 1 && othSegs.size() > 1) {
                    String prefix1 = curSegs.get(0);
                    String prefix2 = othSegs.get(0);
                    if (!prefix1.equals(prefix2)) {
                        String newPath = "/" + prefix2 + current.getOriginalRequest().path().substring(prefix1.length() + 1);
                        for (ActorProfile actor : actors) {
                            vectors.add(new MutationVector("C2", actor, "Prefix Swap Path: " + newPath, current.getOriginalRequest().withPath(newPath)));
                        }
                    }
                }
            }
        }

        // 2. Keyword Pivot (Test 4)
        if (current.isPriority()) {
            String[] pivots = {"admin", "internal", "test", "config", "debug"};
            List<String> segs = current.getSegments();
            for (String p : pivots) {
                // Try substituting segments with keywords
                for (int i = 0; i < segs.size(); i++) {
                    List<String> modified = new ArrayList<>(segs);
                    modified.set(i, p);
                    String newPath = "/" + String.join("/", modified);
                    for (ActorProfile actor : actors) {
                        vectors.add(new MutationVector("C3", actor, "Keyword Pivot: " + newPath, current.getOriginalRequest().withPath(newPath)));
                    }
                }
            }
        }

        // C4: Missing resource boundary
        List<String> tails = payloadsOrDefault("C4_CHILD_PATHS", Arrays.asList("/admin", "/debug", "/raw", "/full", "/export", "/internal"));
        for (String tail : tails) {
            for (ActorProfile actor : actors) {
                vectors.add(new MutationVector("C4", actor,
                    "Missing boundary tail: " + tail,
                    current.getOriginalRequest().withPath(current.getOriginalRequest().path() + tail)));
            }
        }

        // C5: Relative path in ID field
        String body = current.getOriginalRequest().bodyToString();
        if (body != null && body.trim().startsWith("{")) {
            String rel = body.replaceAll("\"id\"\\s*:\\s*\"[^\"]*\"", "\"id\": \"../admin\"");
            if (!rel.equals(body)) {
                for (ActorProfile actor : actors) {
                    vectors.add(new MutationVector("C5", actor,
                        "Relative path in ID field",
                        current.getOriginalRequest().withBody(rel)));
                }
            }
        }

        // C5b: Relative path traversal in path ID segment (works for GET/path-only requests)
        String path = current.getOriginalRequest().path();
        java.util.regex.Matcher idInPath = java.util.regex.Pattern.compile("([a-f0-9]{24}|[0-9a-fA-F-]{36}|\\d{1,12})").matcher(path);
        if (idInPath.find()) {
            String id = idInPath.group(1);
            List<String> traversalIds = payloadsOrDefault("C5_TRAVERSAL_IDS", Arrays.asList("../admin", "../../config", "%2e%2e/admin"));
            for (String traversal : traversalIds) {
                String newPath = path.replace(id, traversal);
                for (ActorProfile actor : actors) {
                    vectors.add(new MutationVector("C5", actor,
                        "Path traversal in ID segment",
                        current.getOriginalRequest().withPath(newPath)));
                }
            }
        }

        // C1/C3: Registry-driven parent/sibling ID swap using harvested IDs
        if (resourceRegistry != null) {
            HttpRequest req = current.getOriginalRequest();
            String currentPattern = endpointPatternForRequest(req);
            String currentPath = req.path();
            java.util.regex.Matcher currIdMatcher = java.util.regex.Pattern
                .compile("([a-f0-9]{24}|[0-9a-fA-F-]{36}|\\d{1,12}|[A-Z]{2,8}-\\d+)")
                .matcher(currentPath);
            if (currIdMatcher.find()) {
                String ownId = currIdMatcher.group(1);
                String currentResource = resourceSegmentForPattern(currentPattern);

                for (ActorProfile actor : actors) {
                    if (actor.getId().equals(current.getActorId())) continue;

                    // C1: Parent-context IDs for this actor
                    java.util.List<String> parentLikeIds = new java.util.ArrayList<>();
                    for (com.acas.harvest.HarvestedId hid : resourceRegistry.getAllIdsByActor(actor.getName())) {
                        String f = hid.getFieldName() == null ? "" : hid.getFieldName().toLowerCase();
                        if (f.contains("org") || f.contains("account") || f.contains("team") || f.contains("company") || f.contains("parent")) {
                            parentLikeIds.add(hid.getValue());
                        }
                    }
                    java.util.LinkedHashSet<String> uniqueParentIds = new java.util.LinkedHashSet<>(parentLikeIds);
                    int c1Count = 0;
                    for (String id : uniqueParentIds) {
                        if (id == null || id.equals(ownId)) continue;
                        vectors.add(new MutationVector("C1", actor,
                            "Parent ID swap (harvested): " + id,
                            req.withPath(currentPath.replace(ownId, id))));
                        c1Count++;
                        if (c1Count >= 3) break;
                    }

                    // C3: Sibling pattern/resource swaps for this actor
                    int c3Count = 0;
                    for (String pattern : resourceRegistry.getAllPatterns()) {
                        if (pattern.equals(currentPattern)) continue;
                        if (!sameMethod(currentPattern, pattern)) continue;

                        String siblingResource = resourceSegmentForPattern(pattern);
                        if (siblingResource == null || siblingResource.equals(currentResource)) continue;

                        java.util.List<String> siblingIds = resourceRegistry.getIdsByPatternAndActor(pattern, actor.getName());
                        for (String siblingId : siblingIds) {
                            if (siblingId == null || siblingId.isBlank()) continue;
                            String swappedPath = swapResourceAndId(currentPath, currentResource, siblingResource, ownId, siblingId);
                            if (swappedPath != null && !swappedPath.equals(currentPath)) {
                                vectors.add(new MutationVector("C3", actor,
                                    "Sibling resource swap (harvested): " + siblingResource + " -> " + siblingId,
                                    req.withPath(swappedPath)));
                                c3Count++;
                            }
                            if (c3Count >= 5) break;
                        }
                        if (c3Count >= 5) break;
                    }
                }
            }
        }
    }

    private void addGraphQLMutations(List<MutationVector> vectors, CapturedEndpoint endpoint, List<ActorProfile> actors) {
        String body = endpoint.getOriginalRequest().bodyToString();
        String path = endpoint.getOriginalRequest().path();
        if (body == null) return;
        if (!path.contains("graphql") && !body.contains("\"query\"")) return;

        HttpRequest original = endpoint.getOriginalRequest();

        // D1: Introspection probe
        String introspectionBody = "{\"query\":\"{__schema{types{name fields{name}}}}\"}";
        for (ActorProfile actor : actors) {
            if (actor.getId().equals(endpoint.getActorId())) continue;
            vectors.add(new MutationVector("D1", actor,
                "GraphQL Introspection", original.withBody(introspectionBody)));
        }

        // D2: __typename field injection
        String withTypename = body.replaceAll("\\{(?!\\s*__typename)", "{ __typename ");
        if (!withTypename.equals(body)) {
            for (ActorProfile actor : actors) {
                if (actor.getId().equals(endpoint.getActorId())) continue;
                vectors.add(new MutationVector("D2", actor,
                    "GraphQL __typename", original.withBody(withTypename)));
            }
        }

        List<String> suggestWords = payloadsOrDefault("D2_FIELD_SUGGESTIONS", Arrays.asList("admin", "token", "secret"));
        for (String word : suggestWords) {
            String q = "{\"query\":\"query{ " + word + " __typename }\"}";
            for (ActorProfile actor : actors) {
                if (actor.getId().equals(endpoint.getActorId())) continue;
                vectors.add(new MutationVector("D2", actor,
                    "GraphQL field suggestion: " + word, original.withBody(q)));
            }
        }

        // D3: Batch query
        if (body.contains("\"id\"")) {
            java.util.regex.Matcher gqlId = java.util.regex.Pattern
                .compile("\"id\"\\s*:\\s*\"?([A-Za-z0-9_\\-]{2,64})\"?")
                .matcher(body);
            if (gqlId.find()) {
                String ownId = gqlId.group(1);
                try {
                    String batchBody = "[" + body + "," +
                        body.replace("\"" + ownId + "\"", "\"X" + ownId + "\"") + "]";
                    for (ActorProfile actor : actors) {
                        if (actor.getId().equals(endpoint.getActorId())) continue;
                        vectors.add(new MutationVector("D3", actor,
                            "GraphQL Batch: own+cross", original.withBody(batchBody)));
                    }
                } catch (Exception ignored) {}
            }
        }

        // D4: Fragment injection
        List<String> fragments = payloadsOrDefault("D4_FRAGMENT_STRINGS", Arrays.asList("fragment acasFrag on User { id __typename }"));
        for (String fragment : fragments) {
            String fragmentInjected = body + "\n" + fragment;
            vectors.add(new MutationVector("D4", null, "GraphQL fragment injection", original.withBody(fragmentInjected)));
        }

        // D5: OperationName manipulation
        java.util.regex.Matcher opMatcher = java.util.regex.Pattern.compile("\"operationName\"\\s*:\\s*\"([^\"]+)\"").matcher(body);
        if (opMatcher.find()) {
            String opName = opMatcher.group(1);
            String mod = body.replace("\"" + opName + "\"", "\"admin" + opName + "\"");
            vectors.add(new MutationVector("D5", null, "GraphQL operationName spoofing", original.withBody(mod)));
        }

        // D6: Advanced Variables AST Parsing
        try {
            JsonObject root = JsonParser.parseString(body).getAsJsonObject();
            if (root.has("variables") && root.get("variables").isJsonObject()) {
                String variablesJson = root.get("variables").toString();
                
                // Find anything that looks like an ID inside variables
                java.util.regex.Matcher varIdMatcher = java.util.regex.Pattern
                    .compile("\"[^\"]*id[^\"]*\"\\s*:\\s*\"?([A-Za-z0-9_\\-]{2,64})\"?", java.util.regex.Pattern.CASE_INSENSITIVE)
                    .matcher(variablesJson);
                
                while (varIdMatcher.find()) {
                    String ownId = varIdMatcher.group(1);
                    
                    for (ActorProfile actor : actors) {
                        if (actor.getId().equals(endpoint.getActorId())) continue;
                        List<ObjectManager.ObjectEntry> crossObjects = objectManager.getObjectsForActor(actor.getId());
                        
                        int count = 0;
                        for (ObjectManager.ObjectEntry obj : crossObjects) {
                            if (obj.value == null || obj.value.equals(ownId)) continue;
                            
                            // Safe injection using string replace strictly within the variables block
                            String mutatedVars = variablesJson.replace(ownId, obj.value);
                            root.add("variables", JsonParser.parseString(mutatedVars));
                            
                            vectors.add(new MutationVector("D6", actor,
                                "GraphQL Variables ID Swap: " + obj.value,
                                original.withBody(root.toString())));
                            
                            count++;
                            if (count >= 3) break;
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Not valid JSON, ignore D6
        }
    }

    private void addStatefulMutations(List<MutationVector> vectors, CapturedEndpoint endpoint, List<ActorProfile> actors) {
        HttpRequest original = endpoint.getOriginalRequest();
        String method = original.method();
        String path = original.path();

        // E1: DELETE cross-actor path ID swap
        if ("DELETE".equalsIgnoreCase(method)) {
            java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("\\b([a-f0-9]{24}|[0-9a-fA-F-]{36}|\\d{1,12})\\b")
                .matcher(path);
            if (m.find()) {
                String ownId = m.group(1);
                for (ActorProfile actor : actors) {
                    if (actor.getId().equals(endpoint.getActorId())) continue;
                    List<ObjectManager.ObjectEntry> crossObjects = objectManager.getObjectsForActor(actor.getId());
                    int count = 0;
                    for (ObjectManager.ObjectEntry obj : crossObjects) {
                        if (obj.value == null || obj.value.equals(ownId)) continue;
                        vectors.add(new MutationVector("E1", actor,
                            "Stateful DELETE cross-actor: " + obj.value,
                            original.withPath(path.replace(ownId, obj.value))));
                        count++;
                        if (count >= 3) break;
                    }
                }
            }
        }

        // E2: PUT/PATCH ownership hijack via body
        if ("PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method)) {
            String body = original.bodyToString();
            if (body != null && body.contains("}")) {
                int lastBrace = body.lastIndexOf("}");
                for (ActorProfile actor : actors) {
                    if (actor.getId().equals(endpoint.getActorId())) continue;
                    String hijackBody = body.substring(0, lastBrace)
                        + ", \"user_id\": \"" + actor.getId() + "\""
                        + ", \"owner\": \"" + actor.getId() + "\""
                        + "}";
                    vectors.add(new MutationVector("E2", actor,
                        "Stateful ownership hijack -> " + actor.getName(),
                        original.withBody(hijackBody)));
                }
            }
        }

        // E3: Dangerous action endpoint replay via alternate actor
        String lowerPath = path.toLowerCase();
        List<String> statePaths = payloadsOrDefault("E3_STATE_PATHS", Arrays.asList("/confirm", "/publish"));
        for (String sp : statePaths) {
            if (lowerPath.contains(sp.replace("/", ""))) {
                for (ActorProfile actor : actors) {
                    if (actor.getId().equals(endpoint.getActorId())) continue;
                    vectors.add(new MutationVector("E3", actor,
                        "Stateful transition path: " + sp,
                        original.withPath(path + sp)));
                }
            }
        }

        // E4: Token reuse after invalidation (replay baseline token)
        vectors.add(new MutationVector("E4", null,
            "Token reuse replay",
            original));

        // E5: Concurrent resource creation probe marker
        if ("POST".equalsIgnoreCase(method)) {
            vectors.add(new MutationVector("E5", null,
                "Concurrent creation probe",
                original.withHeader("X-ACAS-Race-Probe", "true")));
        }

        List<String> forcedBrowse = payloadsOrDefault("E5_FORCED_BROWSE", Arrays.asList("/admin/setup", "/setup/complete"));
        for (String fb : forcedBrowse) {
            vectors.add(new MutationVector("E5", null,
                "Forced browse: " + fb,
                original.withPath(fb)));
        }
    }

    private void addUniquenessMutations(List<MutationVector> vectors, CapturedEndpoint endpoint, List<ActorProfile> actors) {
        HttpRequest original = endpoint.getOriginalRequest();
        String body = original.bodyToString();
        if (body == null) return;

        List<String> ws = payloadsOrDefault("F1_WHITESPACE_CHARS", Arrays.asList("\\u0020", "\\u200B"));
        for (String w : ws) {
            vectors.add(new MutationVector("F1", null, "Whitespace suffix on unique fields", original.withBody(body + decodeEscaped(w))));
        }
        vectors.add(new MutationVector("F2", null, "Case variation on unique fields", original.withBody(body.toUpperCase())));
        List<String> homoglyphMap = payloadsOrDefault("F3_HOMOGLYPH_MAP", Arrays.asList("a->а", "e->е"));
        for (String map : homoglyphMap) {
            String[] parts = map.split("->", 2);
            if (parts.length == 2) {
                vectors.add(new MutationVector("F3", null, "Unicode homoglyph substitution", original.withBody(body.replace(parts[0], parts[1]))));
            }
        }
        vectors.add(new MutationVector("F4", null, "Subdomain/TLD variation", original.withBody(body.replace(".com", ".co"))));
        List<String> pluses = payloadsOrDefault("F5_EMAIL_PLUS", Arrays.asList("+acas"));
        for (String plus : pluses) {
            vectors.add(new MutationVector("F5", null, "Email plus addressing", original.withBody(body.replace("@", plus + "@"))));
        }
        vectors.add(new MutationVector("F6", null, "Gmail dot variation", original.withBody(body.replace("@", ".@"))));
    }

    private void addEncodingMutations(List<MutationVector> vectors, CapturedEndpoint endpoint, List<ActorProfile> actors) {
        HttpRequest original = endpoint.getOriginalRequest();
        String path = original.path();
        String idSegment = extractLastPathSegment(path);
        if (idSegment != null && !idSegment.isEmpty()) {
            String basePath = path.substring(0, path.lastIndexOf('/') + 1);
            vectors.add(new MutationVector("G1", null, "Single URL encoding", original.withPath(basePath + urlEncode(idSegment))));
            vectors.add(new MutationVector("G2", null, "Double URL encoding", original.withPath(basePath + urlEncode(urlEncode(idSegment)))));
            List<String> targetChars = payloadsOrDefault("G1_ENCODE_CHARS", Arrays.asList("/", ".", "-", "_"));
            for (int i = 0; i < idSegment.length(); i++) {
                char ch = idSegment.charAt(i);
                if (!targetChars.contains(String.valueOf(ch))) continue;
                String partial = idSegment.substring(0, i) + urlEncode(String.valueOf(ch)) + idSegment.substring(i + 1);
                vectors.add(new MutationVector("G1", null, "Single URL encoding partial", original.withPath(basePath + partial)));
            }
        }
        vectors.add(new MutationVector("G3", null, "Triple URL encoding", original.withPath(urlEncode(urlEncode(urlEncode(path))))));
        List<String> overlongTargets = payloadsOrDefault("G3_OVERLONG_CHARS", Arrays.asList("/"));
        for (String ch : overlongTargets) {
            vectors.add(new MutationVector("G4", null, "Overlong UTF-8 approximation", original.withPath(path.replace(ch, "%C0%AF"))));
        }
        vectors.add(new MutationVector("G5", null, "HTML entity encoding", original.withPath(path.replace("9", "&#57;"))));
        vectors.add(new MutationVector("G6", null, "Unicode escape in JSON", original.withBody(original.bodyToString() != null ? original.bodyToString().replace("admin", "\\u0061\\u0064\\u006d\\u0069\\u006e") : "")));
        if (idSegment != null && !idSegment.isEmpty()) {
            String g7BasePath = path.substring(0, path.lastIndexOf('/') + 1);
            String base64Id = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(idSegment.getBytes());
            vectors.add(new MutationVector("G7", null, "Base64 encoding (ID segment)", original.withPath(g7BasePath + base64Id)));
        }
        vectors.add(new MutationVector("G8", null, "Hex encoding", original.withPath(path.replaceAll("(\\d+)", "0x$1"))));
        vectors.add(new MutationVector("G9", null, "Octal encoding", original.withPath(path.replaceAll("(\\d+)", "0$1"))));
        vectors.add(new MutationVector("G10", null, "Unicode normalization", original.withPath(path.replace("a", "ａ"))));
        vectors.add(new MutationVector("G11", null, "Mixed one-char encoding", original.withPath(oneCharEncode(path))));
        vectors.add(new MutationVector("G12", null, "Case variation encoding", original.withPath(mixedCaseEncode(path))));
    }

    /**
     * WAF Bypass Encoding Layer.
     * For each numeric or UUID ID found in the path or JSON body, generates encoding variants
     * that are commonly used to evade WAF pattern matching:
     *   - Single URL encoding  (%XX)
     *   - Double URL encoding  (%25XX)
     *   - Unicode escape (backslash-u XXXX format for each character)
     *   - JSON Unicode escape  in the body field value
     *   - Mixed case (for alpha segments)
     *
     * These vectors are added WITH an actor so the session context is applied.
     * If the original mutation was blocked (403), retrying with these variants may succeed.
     */
    private void addWafBypassEncodings(List<MutationVector> vectors, CapturedEndpoint endpoint, List<ActorProfile> actors) {
        HttpRequest original = endpoint.getOriginalRequest();
        String path = original.path();

        // Find the first ID-like segment in the path
        java.util.regex.Matcher idMatcher = java.util.regex.Pattern
            .compile("([a-f0-9]{24}|[0-9a-fA-F-]{36}|\\d{3,})")
            .matcher(path);

        if (idMatcher.find()) {
            String idSegment = idMatcher.group(1);

            // WAF1: Single URL encoding of each digit/char
            String singleEncoded = urlEncodeEach(idSegment);
            String waf1Path = path.replace(idSegment, singleEncoded);
            if (!waf1Path.equals(path)) {
                for (ActorProfile actor : actors) {
                    if (actor.getId().equals(endpoint.getActorId())) continue;
                    vectors.add(new MutationVector("WAF1", actor,
                        "WAF Bypass: single URL encode ID", original.withPath(waf1Path)));
                }
            }

            // WAF2: Double URL encoding
            String doubleEncoded = urlEncodeEach(singleEncoded);
            String waf2Path = path.replace(idSegment, doubleEncoded);
            if (!waf2Path.equals(path)) {
                for (ActorProfile actor : actors) {
                    if (actor.getId().equals(endpoint.getActorId())) continue;
                    vectors.add(new MutationVector("WAF2", actor,
                        "WAF Bypass: double URL encode ID", original.withPath(waf2Path)));
                }
            }

            // WAF3: Unicode escape sequence per character (backslash-u 00XX format)
            String unicodeEscaped = toUnicodeEscape(idSegment);
            String waf3Path = path.replace(idSegment, unicodeEscaped);
            if (!waf3Path.equals(path)) {
                for (ActorProfile actor : actors) {
                    if (actor.getId().equals(endpoint.getActorId())) continue;
                    vectors.add(new MutationVector("WAF3", actor,
                        "WAF Bypass: unicode escape ID", original.withPath(waf3Path)));
                }
            }
        }

        // WAF4: JSON body Unicode escape of ID field values
        String body = original.bodyToString();
        if (body != null && body.trim().startsWith("{")) {
            java.util.regex.Matcher bodyIdMatcher = java.util.regex.Pattern
                .compile("(\"[a-zA-Z0-9_]*(?:id|Id|ID|_id)[a-zA-Z0-9_]*\"\\s*:\\s*\")([A-Za-z0-9_\\-]{3,64})(\")")
                .matcher(body);
            if (bodyIdMatcher.find()) {
                String fieldValue = bodyIdMatcher.group(2);
                String unicodeValue = toUnicodeEscape(fieldValue);
                String waf4Body = body.replace(
                    bodyIdMatcher.group(1) + fieldValue + bodyIdMatcher.group(3),
                    bodyIdMatcher.group(1) + unicodeValue + bodyIdMatcher.group(3));
                if (!waf4Body.equals(body)) {
                    for (ActorProfile actor : actors) {
                        if (actor.getId().equals(endpoint.getActorId())) continue;
                        vectors.add(new MutationVector("WAF4", actor,
                            "WAF Bypass: JSON unicode escape ID field", original.withBody(waf4Body)));
                    }
                }
            }
        }

        // WAF5: Mixed-case path segment (for alphabetic segments that may be case-checked by WAF)
        String mixedCasePath = path;
        boolean changed = false;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (Character.isLetter(c)) {
                sb.append(i % 2 == 0 ? Character.toUpperCase(c) : Character.toLowerCase(c));
                changed = true;
            } else {
                sb.append(c);
            }
        }
        if (changed) {
            mixedCasePath = sb.toString();
            for (ActorProfile actor : actors) {
                if (actor.getId().equals(endpoint.getActorId())) continue;
                vectors.add(new MutationVector("WAF5", actor,
                    "WAF Bypass: mixed-case path", original.withPath(mixedCasePath)));
            }
        }
    }

    /** URL-encodes each character in the value individually (for WAF bypass). */
    private String urlEncodeEach(String value) {
        if (value == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : value.toCharArray()) {
            sb.append(String.format("%%%02X", (int) c));
        }
        return sb.toString();
    }

    /** Converts each character to a Unicode escape format (for WAF bypass, e.g. \u0031 for '1'). */
    private String toUnicodeEscape(String value) {
        if (value == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : value.toCharArray()) {
            sb.append("").append("\\u").append(String.format("%04X", (int) c));
        }
        return sb.toString();
    }

    private void addWhitespaceMutations(List<MutationVector> vectors, CapturedEndpoint endpoint, List<ActorProfile> actors) {
        HttpRequest original = endpoint.getOriginalRequest();
        String path = original.path();
        List<String> wsChars = payloadsOrDefault("H_WHITESPACE_CHARS", Arrays.asList("\\u0020", "\\u200B"));
        String wsChar = wsChars.isEmpty() ? " " : decodeEscaped(wsChars.get(0));
        vectors.add(new MutationVector("H1", null, "Whitespace in path segment", original.withPath(path + urlEncode(wsChar))));
        vectors.add(new MutationVector("H2", null, "Whitespace in query key", original.withPath(path.contains("?") ? path + "&" + urlEncode(wsChar) + "id=1" : path + "?" + urlEncode(wsChar) + "id=1")));
        vectors.add(new MutationVector("H3", null, "Whitespace in query value", original.withPath(path.contains("?") ? path + "&id=" + urlEncode(wsChar) + "9901" : path + "?id=" + urlEncode(wsChar) + "9901")));
        vectors.add(new MutationVector("H4", null, "Whitespace in JSON key", original.withBody(original.bodyToString() != null ? original.bodyToString().replace("\"id\"", "\" id\"") : "")));
        vectors.add(new MutationVector("H5", null, "Whitespace in JSON value", original.withBody(original.bodyToString() != null ? original.bodyToString().replace("\"id\":\"", "\"id\":\" ") : "")));
        String h6AuthValue = original.headerValue("Authorization");
        if (h6AuthValue != null && !h6AuthValue.isEmpty()) {
            String wsAuth = h6AuthValue.replaceFirst(" ", "  ");
            vectors.add(new MutationVector("H6", null, "Whitespace in Authorization (double-space)", original.withHeader("Authorization", wsAuth)));
            vectors.add(new MutationVector("H6", null, "Whitespace in Authorization (trailing)", original.withHeader("Authorization", h6AuthValue + " ")));
        } else {
            String h6CookieValue = original.headerValue("Cookie");
            if (h6CookieValue != null && !h6CookieValue.isEmpty()) {
                vectors.add(new MutationVector("H6", null, "Whitespace in Cookie", original.withHeader("Cookie", h6CookieValue.replace(";", " ; "))));
            }
        }
        vectors.add(new MutationVector("H7", null, "Whitespace between JSON tokens", original.withBody(original.bodyToString() != null ? original.bodyToString().replace(":", " : ") : "")));
        vectors.add(new MutationVector("H8", null, "Null byte in values", original.withPath(path + "%00")));
    }

    private void addDeveloperMistakeMutations(List<MutationVector> vectors, CapturedEndpoint endpoint, List<ActorProfile> actors, List<CapturedEndpoint> allCaptured) {
        HttpRequest original = endpoint.getOriginalRequest();
        String path = original.path();
        List<String> debugParams = payloadsOrDefault("I1_DEBUG_PARAMS", Arrays.asList("debug", "test"));
        for (String dp : debugParams) {
            vectors.add(new MutationVector("I1", null, "Debug param probe", original.withPath(path.contains("?") ? path + "&" + dp + "=true" : path + "?" + dp + "=true")));
        }
        vectors.add(new MutationVector("I2", null, "Method auth inconsistency", original.withMethod("DELETE")));
        List<String> batchPaths = payloadsOrDefault("I3_BATCH_PATHS", Arrays.asList("/batch"));
        for (String batchSuffix : batchPaths) {
            vectors.add(new MutationVector("I3", null, "Batch endpoint without per-item auth", original.withPath(path + batchSuffix)));
        }
        if (resourceRegistry != null) {
            java.util.LinkedHashSet<String> knownIds = new java.util.LinkedHashSet<>(resourceRegistry.getAllKnownIds());
            java.util.List<String> top = new java.util.ArrayList<>();
            for (String id : knownIds) {
                if (id == null || id.isBlank()) continue;
                top.add(id);
                if (top.size() >= 50) break;
            }
            if (!top.isEmpty()) {
                StringBuilder idsJson = new StringBuilder();
                idsJson.append("{\"ids\":[");
                for (int i = 0; i < top.size(); i++) {
                    if (i > 0) idsJson.append(',');
                    idsJson.append('"').append(top.get(i).replace("\\", "\\\\").replace("\"", "\\\"")).append('"');
                }
                idsJson.append("]}");

                for (String batchSuffix : batchPaths) {
                    vectors.add(new MutationVector("I3", null,
                        "Batch endpoint with harvested IDs (" + top.size() + ")",
                        original.withPath(path + batchSuffix).withBody(idsJson.toString())));
                }
            }
        }
        List<String> exportSuffixes = payloadsOrDefault("I4_EXPORT_SUFFIXES", Arrays.asList("/export"));
        for (String suffix : exportSuffixes) {
            vectors.add(new MutationVector("I4", null, "Export/download route", original.withPath(path + suffix)));
        }

        List<String> previewSuffixes = payloadsOrDefault("I5_PREVIEW_SUFFIXES", Arrays.asList("/preview"));
        for (String suffix : previewSuffixes) {
            vectors.add(new MutationVector("I5", null, "Preview/draft route", original.withPath(path + suffix)));
        }

        List<String> softDeleteParams = payloadsOrDefault("I6_SOFTDELETE_PARAMS", Arrays.asList("include_deleted=true"));
        for (String param : softDeleteParams) {
            vectors.add(new MutationVector("I6", null, "Soft delete bypass", original.withPath(path.contains("?") ? path + "&" + param : path + "?" + param)));
        }
        List<String> paginationValues = payloadsOrDefault("I7_PAGINATION_ABUSE", Arrays.asList("limit=10000"));
        for (String pv : paginationValues) {
            vectors.add(new MutationVector("I7", null, "Pagination without ownership", original.withPath(path.contains("?") ? path + "&" + pv : path + "?" + pv)));
        }
        List<String> ssrfUrls = payloadsOrDefault("I8_SSRF_URLS", Arrays.asList("http://127.0.0.1/admin"));
        for (String ssrf : ssrfUrls) {
            vectors.add(new MutationVector("I8", null, "Webhook forgery", original.withPath(path.contains("?") ? path + "&url=" + urlEncode(ssrf) : path + "?url=" + urlEncode(ssrf))));
        }
        List<String> logInject = payloadsOrDefault("I9_LOG_INJECTION", Arrays.asList("%0a"));
        for (String li : logInject) {
            vectors.add(new MutationVector("I9", null, "Open redirect internal endpoint", original.withPath(path.contains("?") ? path + "&redirect=" + li : path + "?redirect=" + li)));
        }
        vectors.add(new MutationVector("I10", null, "Race condition state change", original.withHeader("X-ACAS-Race", "true")));
        List<String> objRefParams = payloadsOrDefault("I11_OBJECT_REF_PARAMS", Arrays.asList("file", "url"));
        for (String p : objRefParams) {
            vectors.add(new MutationVector("I11", null, "Object reference in upload", original.withPath(path.contains("?") ? path + "&" + p + "=/etc/passwd" : path + "?" + p + "=/etc/passwd")));
        }
        vectors.add(new MutationVector("I12", null, "Email template object reference", original.withHeader("X-ACAS-Email-Template", "victim")));
        List<String> redirectValues = payloadsOrDefault("I13_REDIRECT_VALUES", Arrays.asList("//evil.com"));
        for (String rv : redirectValues) {
            vectors.add(new MutationVector("I13", null, "Response field harvesting", original.withPath(path.contains("?") ? path + "&redirect=" + urlEncode(rv) : path + "?redirect=" + urlEncode(rv))));
        }
        List<String> deser = payloadsOrDefault("I14_DESERIAL_PROBES", Arrays.asList("rO0ABXNyAA=="));
        for (String probe : deser) {
            vectors.add(new MutationVector("I14", null, "Insecure deserialization probe", original.withHeader("Content-Type", "application/x-java-serialized-object").withBody(probe)));
        }
        List<String> ssti = payloadsOrDefault("I15_SSTI_PROBES", Arrays.asList("{{7*7}}"));
        for (String s : ssti) {
            String safeReplacement = java.util.regex.Matcher.quoteReplacement(s);
            vectors.add(new MutationVector("I15", null, "SSTI in ID fields", original.withPath(path.replaceAll("(\\d+)", safeReplacement))));
        }
    }

    private void addProtocolMutations(List<MutationVector> vectors, CapturedEndpoint endpoint, List<ActorProfile> actors) {
        HttpRequest original = endpoint.getOriginalRequest();
        vectors.add(new MutationVector("J1", null, "CL/TE smuggling setup", original.withHeader("Content-Length", "4").withHeader("Transfer-Encoding", "chunked")));
        List<String> crlfs = payloadsOrDefault("J2_CRLF_STRINGS", Arrays.asList("%0d%0aX-Injected:true"));
        for (String crlf : crlfs) {
            vectors.add(new MutationVector("J2", null, "CRLF injection in header", original.withHeader("Referer", "https://a.com" + crlf)));
        }
        List<String> dupHosts = payloadsOrDefault("J3_DUPLICATE_HOSTS", Arrays.asList("admin.target.com"));
        for (String dh : dupHosts) {
            vectors.add(new MutationVector("J3", null, "Multiple host header approximation", original.withHeader("X-Forwarded-Host", dh)));
        }
        vectors.add(new MutationVector("J4", null, "Long header overflow", original.withHeader("X-Padding", "A".repeat(4096))));
        vectors.add(new MutationVector("J5", null, "Slow header attack marker", original.withHeader("X-ACAS-Slow", "1")));
        List<String> pseudo = payloadsOrDefault("J6_H2_PSEUDO_HEADERS", Arrays.asList(":authority: localhost"));
        for (String header : pseudo) {
            String[] kv = header.split(":", 3);
            if (kv.length >= 3) {
                String hName = ":" + kv[1].trim();
                String hVal = kv[2].trim();
                vectors.add(new MutationVector("J6", null, "HTTP/2 pseudo-header approximation", original.withHeader(hName, hVal)));
            }
        }
        List<String> protoTargets = payloadsOrDefault("J7_PROTO_DOWNGRADES", Arrays.asList("HTTP/1.0"));
        for (String p : protoTargets) {
            vectors.add(new MutationVector("J7", null, "Protocol downgrade", original.withHeader("X-ACAS-Proto", p)));
        }
    }

    private void addCombinationMutations(List<MutationVector> vectors, CapturedEndpoint endpoint, List<ActorProfile> actors) {
        HttpRequest original = endpoint.getOriginalRequest();
        HttpRequest clean = HttpUtils.stripAuthHeaders(original, store.getAllIdentityHeaderNames());
        List<String> adminParams = payloadsOrDefault("A9_ADMIN_PARAMS", Arrays.asList("admin=true"));

        // K1: B1 + A9 (actor-bound)
        for (ActorProfile actor : actors) {
            if (actor.getId().equals(endpoint.getActorId())) continue;
            for (String p : adminParams) {
                vectors.add(new MutationVector("K1", actor, "B1 + A9",
                    original.withPath(original.path() + (original.path().contains("?") ? "&" : "?") + p)));
            }
        }

        // K2: B1 + G2 (actor-bound; double-encode ID segment when available)
        String idSegment = extractLastPathSegment(original.path());
        if (idSegment != null && !idSegment.isEmpty()) {
            String basePath = original.path().substring(0, original.path().lastIndexOf('/') + 1);
            for (ActorProfile actor : actors) {
                if (actor.getId().equals(endpoint.getActorId())) continue;
                vectors.add(new MutationVector("K2", actor, "B1 + G2",
                    original.withPath(basePath + urlEncode(urlEncode(idSegment)))));
            }
        }

        // K3 A1 + B11
        vectors.add(new MutationVector("K3", null, "A1 + B11", clean.withBody(injectAdminField(clean.bodyToString()))));

        // K4: B4 + B1 (actor-bound)
        for (ActorProfile actor : actors) {
            if (actor.getId().equals(endpoint.getActorId())) continue;
            vectors.add(new MutationVector("K4", actor, "B4 + B1", original.withPath(original.path().replace("/v2/", "/v1/"))));
        }

        // K5 B12 + B11
        vectors.add(new MutationVector("K5", null, "B12 + B11", original.withHeader("Authorization", "Bearer null").withBody(injectAdminField(original.bodyToString()))));
        // K6 A14 + G1
        vectors.add(new MutationVector("K6", null, "A14 + G1", clean.withPath("/%69nternal" + original.path())));
        // K7 B5 + H5
        vectors.add(new MutationVector("K7", null, "B5 + H5", original.withBody(original.bodyToString() != null ? original.bodyToString().replace("\"id\":\"", "\"id\":\"\u200B") : "")));
        // K8 B3 + G11
        vectors.add(new MutationVector("K8", null, "B3 + G11", original.withPath(original.path().contains("?") ? original.path() + "&%75ser_id=2" : original.path() + "?%75ser_id=2")));
        // K9: Session swap + parallel replay (emit per actor for actual cross-session race)
        for (ActorProfile k9Actor : actors) {
            if (k9Actor.getId().equals(endpoint.getActorId())) continue;
            vectors.add(new MutationVector("K9", k9Actor, "Race: session swap duplicate", original));
        }
        // K10: Unicode confusable username in body (F1 + B1)
        String bodyK10 = original.bodyToString();
        if (bodyK10 != null && bodyK10.contains("\"username\"")) {
            for (ActorProfile k10Actor : actors) {
                if (k10Actor.getId().equals(endpoint.getActorId())) continue;
                String confusedBody = bodyK10.replaceAll(
                    "\"username\"\\s*:\\s*\"([^\"]+)\"",
                    "\"username\": \"$1\\u200B\"");
                if (!confusedBody.equals(bodyK10)) {
                    vectors.add(new MutationVector("K10", k10Actor,
                        "Unicode confusable username + B1", original.withBody(confusedBody)));
                }
            }
        }

        // K custom combinations from PayloadStore
        List<String> customCombos = payloadsOrDefault("K_CUSTOM_COMBOS", Arrays.asList("B1+A9", "B1+G2", "B18+G2"));
        for (String combo : customCombos) {
            String[] parts = combo.split("\\+");
            if (parts.length != 2) continue;
            String first = parts[0].trim().toUpperCase();
            String second = parts[1].trim().toUpperCase();
            boolean actorBound = "B1".equals(first) || "B1".equals(second);

            if (actorBound) {
                for (ActorProfile actor : actors) {
                    if (actor.getId().equals(endpoint.getActorId())) continue;
                    HttpRequest mutated = applySimpleCode(applySimpleCode(original, first), second);
                    vectors.add(new MutationVector("K", actor, "Custom Combo: " + combo, mutated));
                }
            } else {
                HttpRequest mutated = applySimpleCode(applySimpleCode(original, first), second);
                vectors.add(new MutationVector("K", null, "Custom Combo: " + combo, mutated));
            }
        }
    }

    private HttpRequest applySimpleCode(HttpRequest req, String code) {
        if (req == null || code == null) return req;
        String upper = code.toUpperCase();
        if ("A9".equals(upper)) {
            String sep = req.path().contains("?") ? "&" : "?";
            return req.withPath(req.path() + sep + "admin=true");
        }
        if ("G2".equals(upper)) {
            String path = req.path();
            String idSegment = extractLastPathSegment(path);
            if (idSegment == null || idSegment.isEmpty()) return req;
            String base = path.substring(0, path.lastIndexOf('/') + 1);
            return req.withPath(base + urlEncode(urlEncode(idSegment)));
        }
        if ("A14".equals(upper)) {
            return req.withPath("/internal" + req.path());
        }
        if ("B4".equals(upper)) {
            return req.withPath(req.path().replace("/v2/", "/v1/"));
        }
        if ("B11".equals(upper)) {
            return req.withBody(injectAdminField(req.bodyToString()));
        }
        if ("I15".equals(upper)) {
            return req.withPath(req.path().replaceAll("(\\d+)", "{{7*7}}"));
        }
        if ("B18".equals(upper)) {
            String path = req.path();
            String ownPathId = firstIdToken(path);
            List<String> harvestedRefs = new ArrayList<>();
            if (resourceRegistry != null) {
                harvestedRefs.addAll(resourceRegistry.getAllKnownIds());
                harvestedRefs.addAll(resourceRegistry.getManualCandidates());
            }

            if (ownPathId != null && !harvestedRefs.isEmpty()) {
                for (String ref : harvestedRefs) {
                    if (ref == null || ref.isBlank() || ref.equals(ownPathId)) continue;
                    for (String variant : referenceSwapVariants(ref)) {
                        String mutatedPath = path.replace(ownPathId, variant);
                        if (!mutatedPath.equals(path)) {
                            return req.withPath(mutatedPath);
                        }
                    }
                }
            }

            String body = req.bodyToString();
            if (body != null && body.trim().startsWith("{")) {
                java.util.regex.Pattern jsonIdPattern = java.util.regex.Pattern.compile("\\\"([a-zA-Z0-9_]*(?:id|_id|_key|_ref|_uuid|_token|_code))\\\"\\s*:\\s*\\\"?([A-Za-z0-9_\\-]{2,128})\\\"?");
                java.util.regex.Matcher bodyMatcher = jsonIdPattern.matcher(body);
                if (bodyMatcher.find()) {
                    String fieldName = bodyMatcher.group(1);
                    String ownValue = bodyMatcher.group(2);
                    for (String ref : harvestedRefs) {
                        if (ref == null || ref.isBlank() || ref.equals(ownValue)) continue;
                        for (String variant : referenceSwapVariants(ref)) {
                            String updatedBody = replaceJsonFieldValue(body, fieldName, ownValue, variant);
                            if (updatedBody != null && !updatedBody.equals(body)) {
                                return req.withBody(updatedBody);
                            }
                        }
                    }
                }
            }

            return req;
        }
        if ("B14".equals(upper)) {
            return req.withHeader("X-User-Role", "admin");
        }
        return req;
    }

    private String urlEncode(String value) {
        try {
            return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8.toString());
        } catch (Exception e) {
            return value;
        }
    }

    private String oneCharEncode(String value) {
        if (value == null || value.isEmpty()) return value;
        int idx = Math.min(1, value.length() - 1);
        char c = value.charAt(idx);
        return value.substring(0, idx) + String.format("%%%02X", (int) c) + value.substring(idx + 1);
    }

    private String mixedCaseEncode(String value) {
        if (value == null) return null;
        String encoded = urlEncode(value);
        return encoded.replace("%2F", "%2f").replace("%3A", "%3a");
    }

    private String injectAdminField(String body) {
        if (body == null || !body.contains("}")) return body != null ? body : "";
        int lastBrace = body.lastIndexOf('}');
        return body.substring(0, lastBrace) + ", \"role\":\"admin\", \"is_admin\":true}";
    }

    private String firstIdToken(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        java.util.regex.Matcher matcher = java.util.regex.Pattern
            .compile("([a-f0-9]{24}|[0-9a-fA-F-]{36}|\\d{1,12}|[A-Z]{2,8}-\\d+)")
            .matcher(value);
        return matcher.find() ? matcher.group(1) : null;
    }

    private List<String> referenceSwapVariants(String value) {
        java.util.LinkedHashSet<String> variants = new java.util.LinkedHashSet<>();
        if (value == null || value.isBlank()) {
            return new ArrayList<>();
        }

        variants.add(value);
        String singleEncoded = urlEncode(value);
        variants.add(singleEncoded);
        variants.add(urlEncode(singleEncoded));
        variants.add(mixedCaseEncode(value));
        variants.add(oneCharEncode(value));

        List<String> digitGuards = payloadsOrDefault("B18_DIGIT_GUARDS", Arrays.asList("0", "1", "9"));
        for (String digit : digitGuards) {
            if (digit == null || digit.isBlank()) continue;
            variants.add(digit + value);
            variants.add(value + digit);
            variants.add(digit + value + digit);
        }

        variants.removeIf(v -> v == null || v.isBlank());
        return new ArrayList<>(variants);
    }

    private String replaceJsonFieldValue(String json, String fieldName, String oldValue, String newValue) {
        if (json == null || fieldName == null || oldValue == null || newValue == null) {
            return json;
        }

        String quoted = "\"" + fieldName + "\"\\s*:\\s*\"" + java.util.regex.Pattern.quote(oldValue) + "\"";
        String quotedReplacement = "\"" + fieldName + "\": \"" + newValue + "\"";
        String updated = json.replaceFirst(quoted, java.util.regex.Matcher.quoteReplacement(quotedReplacement));
        if (!updated.equals(json)) {
            return updated;
        }

        String unquoted = "\"" + fieldName + "\"\\s*:\\s*" + java.util.regex.Pattern.quote(oldValue);
        String unquotedReplacement = "\"" + fieldName + "\": " + newValue;
        updated = json.replaceFirst(unquoted, java.util.regex.Matcher.quoteReplacement(unquotedReplacement));
        if (!updated.equals(json)) {
            return updated;
        }

        return json;
    }

    private String decodeEscaped(String value) {
        if (value == null) return "";
        String out = value;
        try {
            if (out.startsWith("\\u") && out.length() >= 6) {
                int code = Integer.parseInt(out.substring(2, 6), 16);
                return String.valueOf((char) code);
            }
            out = out.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t");
            return out;
        } catch (Exception e) {
            return value;
        }
    }

    private List<String> payloadsOrDefault(String code, List<String> fallback) {
        if (payloadStore == null) {
            return new ArrayList<>(fallback);
        }
        List<String> values = payloadStore.getPayloads(code);
        if (values == null || values.isEmpty()) {
            return new ArrayList<>(fallback);
        }
        return values;
    }

    private String extractLastPathSegment(String path) {
        if (path == null || path.isEmpty()) return null;
        int q = path.indexOf('?');
        String cleanPath = q >= 0 ? path.substring(0, q) : path;
        int slash = cleanPath.lastIndexOf('/');
        if (slash < 0 || slash == cleanPath.length() - 1) return null;
        return cleanPath.substring(slash + 1);
    }

    private boolean sameMethod(String patternA, String patternB) {
        if (patternA == null || patternB == null) return false;
        int a = patternA.indexOf(' ');
        int b = patternB.indexOf(' ');
        if (a <= 0 || b <= 0) return false;
        return patternA.substring(0, a).equalsIgnoreCase(patternB.substring(0, b));
    }

    private String resourceSegmentForPattern(String pattern) {
        if (pattern == null) return null;
        int sp = pattern.indexOf(' ');
        if (sp < 0 || sp == pattern.length() - 1) return null;
        String p = pattern.substring(sp + 1);
        String[] segs = p.split("/");
        for (int i = 0; i < segs.length - 1; i++) {
            if ("{id}".equals(segs[i + 1]) || "{uuid}".equals(segs[i + 1]) || "{prefixed_id}".equals(segs[i + 1])) {
                return segs[i];
            }
        }
        return null;
    }

    private String swapResourceAndId(String currentPath,
                                     String currentResource,
                                     String siblingResource,
                                     String ownId,
                                     String siblingId) {
        if (currentPath == null || currentResource == null || siblingResource == null || ownId == null || siblingId == null) {
            return null;
        }

        String out = currentPath.replace("/" + currentResource + "/", "/" + siblingResource + "/");
        out = out.replace(ownId, siblingId);
        return out;
    }

    private List<MutationVector> filterEnabledVectors(List<MutationVector> vectors, Set<String> overrideMutationCodes) {
        if (mutationRegistry == null || vectors == null || vectors.isEmpty()) {
            return vectors;
        }

        boolean hasOverride = overrideMutationCodes != null && !overrideMutationCodes.isEmpty();

        List<MutationVector> filtered = new ArrayList<>();
        for (MutationVector vector : vectors) {
            if (vector == null) continue;
            String typeName = vector.getTypeName();
            if (hasOverride) {
                if (typeName != null && overrideMutationCodes.contains(typeName.trim().toUpperCase())) {
                    filtered.add(vector);
                }
            } else if (mutationRegistry.isEnabledCode(typeName)) {
                filtered.add(vector);
            }
        }
        return filtered;
    }

    private void addCustomMutations(List<MutationVector> vectors, HttpRequest original, Set<String> overrideMutationCodes) {
        if (mutationRegistry == null || original == null) {
            return;
        }

        boolean hasOverride = overrideMutationCodes != null && !overrideMutationCodes.isEmpty();

        for (MutationDefinition definition : mutationRegistry.getAll()) {
            if (definition == null || !definition.isCustom) {
                continue;
            }

            String mutationCode = firstToken(definition.name);
            if (hasOverride) {
                if (mutationCode == null || !overrideMutationCodes.contains(mutationCode.trim().toUpperCase())) {
                    continue;
                }
            } else if (!definition.isEnabled()) {
                continue;
            }

            HttpRequest mutated;
            String descriptionPrefix;
            if (definition.isScriptMode()) {
                String script = definition.getCustomScript();
                if (script == null || script.trim().isEmpty()) {
                    continue;
                }
                mutated = applyCustomMutationScript(original, script);
                descriptionPrefix = "Custom Script: ";
            } else {
                mutated = applyCustomManualMutation(original, definition);
                descriptionPrefix = "Custom Manual: ";
            }

            if (mutated != null && !mutated.toString().equals(original.toString())) {
                vectors.add(new MutationVector(
                    mutationCode,
                    null,
                    descriptionPrefix + definition.name,
                    mutated
                ));
            }
        }
    }

    private HttpRequest applyCustomManualMutation(HttpRequest original, MutationDefinition definition) {
        if (original == null || definition == null) {
            return null;
        }

        HttpRequest mutated = original;
        boolean changed = false;

        if (definition.customHeaderName != null && !definition.customHeaderName.trim().isEmpty()) {
            String value = definition.customHeaderValue != null ? definition.customHeaderValue : "1";
            mutated = mutated.withHeader(definition.customHeaderName.trim(), value);
            changed = true;
        }

        if (definition.customMethod != null && !definition.customMethod.trim().isEmpty()) {
            String method = definition.customMethod.trim().toUpperCase();
            if (!method.equalsIgnoreCase(mutated.method())) {
                mutated = mutated.withMethod(method);
                changed = true;
            }
        }

        if (!changed) {
            String marker = definition.name != null ? definition.name : "custom";
            marker = marker.replaceAll("[^A-Za-z0-9_\\-]", "_");
            mutated = mutated.withHeader("X-ACAS-Custom-Mutation", marker);
            changed = true;
        }

        return changed ? mutated : null;
    }

    private Set<String> normalizeMutationCodes(Set<String> overrideMutationCodes) {
        if (overrideMutationCodes == null || overrideMutationCodes.isEmpty()) {
            return java.util.Collections.emptySet();
        }
        Set<String> normalized = new HashSet<>();
        for (String code : overrideMutationCodes) {
            if (code == null) {
                continue;
            }
            String trimmed = code.trim();
            if (!trimmed.isEmpty()) {
                normalized.add(trimmed.toUpperCase());
            }
        }
        return normalized;
    }

    private List<MutationVector> applyMatchReplaceRules(List<MutationVector> vectors) {
        if (vectors == null || vectors.isEmpty() || mutationRegistry == null) {
            return vectors;
        }

        List<MatchReplaceRule> rules = mutationRegistry.getMatchReplaceRules();
        if (rules == null || rules.isEmpty()) {
            return vectors;
        }

        List<MutationVector> out = new ArrayList<>(vectors.size());
        for (MutationVector vector : vectors) {
            if (vector == null || vector.getMutatedRequest() == null) {
                out.add(vector);
                continue;
            }
            HttpRequest req = vector.getMutatedRequest();
            boolean changed = false;
            for (MatchReplaceRule rule : rules) {
                if (rule == null || !rule.isUsable()) {
                    continue;
                }
                if (!matchesRuleRequestFilter(req, rule)) {
                    continue;
                }
                HttpRequest updated = applyRule(req, rule);
                if (updated != null && !updated.toString().equals(req.toString())) {
                    req = updated;
                    changed = true;
                }
            }
            if (changed) {
                out.add(new MutationVector(
                    vector.getTypeName(),
                    vector.getActor(),
                    vector.getDescription() + " [M/R]",
                    req
                ));
            } else {
                out.add(vector);
            }
        }
        return out;
    }

    private HttpRequest applyRule(HttpRequest request, MatchReplaceRule rule) {
        if (request == null || rule == null || !rule.isUsable()) {
            return request;
        }

        switch (rule.target) {
            case PATH:
                return replacePath(request, rule);
            case BODY:
                return replaceBody(request, rule);
            case QUERY_KEY:
                return replaceQueryKey(request, rule);
            case QUERY_VALUE:
                return replaceQueryValue(request, rule);
            case HEADER_NAME:
                return replaceHeaderName(request, rule);
            case HEADER_VALUE:
                return replaceHeaderValue(request, rule);
            default:
                return request;
        }
    }

    private HttpRequest replacePath(HttpRequest request, MatchReplaceRule rule) {
        String path = request.path();
        String replaced = applyTextRule(path, rule);
        if (replaced.equals(path)) {
            return request;
        }
        return request.withPath(replaced);
    }

    private HttpRequest replaceBody(HttpRequest request, MatchReplaceRule rule) {
        String body = request.bodyToString();
        if (body == null) {
            return request;
        }
        String replaced = applyTextRule(body, rule);
        if (replaced.equals(body)) {
            return request;
        }
        return request.withBody(replaced);
    }

    private HttpRequest replaceQueryKey(HttpRequest request, MatchReplaceRule rule) {
        HttpRequest out = request;
        boolean any = false;
        for (burp.api.montoya.http.message.params.HttpParameter param : request.parameters()) {
            if (param == null || param.type() != HttpParameterType.URL) {
                continue;
            }
            String updatedName = applyTextRule(param.name(), rule);
            if (!updatedName.equals(param.name())) {
                out = out.withUpdatedParameters(HttpParameter.parameter(updatedName, param.value(), param.type()));
                any = true;
                if (rule.scope == MatchReplaceRule.Scope.FIRST) {
                    break;
                }
            }
        }
        return any ? out : request;
    }

    private HttpRequest replaceQueryValue(HttpRequest request, MatchReplaceRule rule) {
        HttpRequest out = request;
        boolean any = false;
        for (burp.api.montoya.http.message.params.HttpParameter param : request.parameters()) {
            if (param == null || param.type() != HttpParameterType.URL) {
                continue;
            }
            String updatedValue = applyTextRule(param.value(), rule);
            if (!updatedValue.equals(param.value())) {
                out = out.withUpdatedParameters(HttpParameter.parameter(param.name(), updatedValue, param.type()));
                any = true;
                if (rule.scope == MatchReplaceRule.Scope.FIRST) {
                    break;
                }
            }
        }
        return any ? out : request;
    }

    private HttpRequest replaceHeaderName(HttpRequest request, MatchReplaceRule rule) {
        HttpRequest out = request;
        boolean any = false;
        for (burp.api.montoya.http.message.HttpHeader header : request.headers()) {
            if (header == null) {
                continue;
            }
            String updatedName = applyTextRule(header.name(), rule);
            if (!updatedName.equals(header.name())) {
                out = out.withRemovedHeader(header.name()).withHeader(updatedName, header.value());
                any = true;
                if (rule.scope == MatchReplaceRule.Scope.FIRST) {
                    break;
                }
            }
        }
        return any ? out : request;
    }

    private HttpRequest replaceHeaderValue(HttpRequest request, MatchReplaceRule rule) {
        HttpRequest out = request;
        boolean any = false;
        for (burp.api.montoya.http.message.HttpHeader header : request.headers()) {
            if (header == null) {
                continue;
            }
            String updatedValue = applyTextRule(header.value(), rule);
            if (!updatedValue.equals(header.value())) {
                out = out.withHeader(header.name(), updatedValue);
                any = true;
                if (rule.scope == MatchReplaceRule.Scope.FIRST) {
                    break;
                }
            }
        }
        return any ? out : request;
    }

    private String applyTextRule(String source, MatchReplaceRule rule) {
        if (source == null || rule == null || rule.pattern == null) {
            return source;
        }
        String pattern = rule.pattern;
        String replacement = rule.replacement != null ? rule.replacement : "";

        switch (rule.matchType) {
            case EXACT:
                return exactReplace(source, pattern, replacement, rule);
            case REGEX:
                return regexReplace(source, pattern, replacement, rule);
            case CONTAINS:
            default:
                return containsReplace(source, pattern, replacement, rule);
        }
    }

    private String exactReplace(String source, String pattern, String replacement, MatchReplaceRule rule) {
        if (rule.caseSensitive) {
            return source.equals(pattern) ? replacement : source;
        }
        return source.equalsIgnoreCase(pattern) ? replacement : source;
    }

    private String containsReplace(String source, String pattern, String replacement, MatchReplaceRule rule) {
        if (pattern.isEmpty()) {
            return source;
        }
        if (rule.caseSensitive) {
            if (!source.contains(pattern)) {
                return source;
            }
            return rule.scope == MatchReplaceRule.Scope.FIRST
                ? source.replaceFirst(java.util.regex.Pattern.quote(pattern), java.util.regex.Matcher.quoteReplacement(replacement))
                : source.replace(pattern, replacement);
        }

        java.util.regex.Pattern p = java.util.regex.Pattern.compile(java.util.regex.Pattern.quote(pattern), java.util.regex.Pattern.CASE_INSENSITIVE);
        java.util.regex.Matcher m = p.matcher(source);
        if (!m.find()) {
            return source;
        }
        m.reset();
        return rule.scope == MatchReplaceRule.Scope.FIRST
            ? m.replaceFirst(java.util.regex.Matcher.quoteReplacement(replacement))
            : m.replaceAll(java.util.regex.Matcher.quoteReplacement(replacement));
    }

    private String regexReplace(String source, String pattern, String replacement, MatchReplaceRule rule) {
        int flags = rule.caseSensitive ? 0 : java.util.regex.Pattern.CASE_INSENSITIVE;
        java.util.regex.Pattern p;
        try {
            p = java.util.regex.Pattern.compile(pattern, flags);
        } catch (Exception ex) {
            return source;
        }
        java.util.regex.Matcher m = p.matcher(source);
        if (!m.find()) {
            return source;
        }
        m.reset();
        return rule.scope == MatchReplaceRule.Scope.FIRST
            ? m.replaceFirst(replacement)
            : m.replaceAll(replacement);
    }

    private boolean matchesRuleRequestFilter(HttpRequest request, MatchReplaceRule rule) {
        if (request == null || rule == null || !rule.useRequestFilters) {
            return true;
        }

        String includeRegex = rule.includeUrlRegex != null ? rule.includeUrlRegex.trim() : "";
        String excludeRegex = rule.excludeUrlRegex != null ? rule.excludeUrlRegex.trim() : "";
        String methodsCsv = rule.allowedMethodsCsv != null ? rule.allowedMethodsCsv.trim() : "";

        String url = request.url();
        if (url == null || url.isEmpty()) {
            url = request.path();
        }

        if (!methodsCsv.isEmpty()) {
            String method = request.method() != null ? request.method().trim().toUpperCase() : "";
            boolean allowed = false;
            for (String token : methodsCsv.split(",")) {
                String normalized = token == null ? "" : token.trim().toUpperCase();
                if (!normalized.isEmpty() && normalized.equals(method)) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                return false;
            }
        }

        if (!includeRegex.isEmpty() && !safeRegexMatch(url, includeRegex)) {
            return false;
        }

        if (!excludeRegex.isEmpty() && safeRegexMatch(url, excludeRegex)) {
            return false;
        }

        return true;
    }

    private boolean safeRegexMatch(String value, String regex) {
        if (value == null || regex == null || regex.trim().isEmpty()) {
            return false;
        }
        try {
            return java.util.regex.Pattern.compile(regex).matcher(value).find();
        } catch (Exception ignored) {
            return false;
        }
    }

    private HttpRequest applyCustomMutationScript(HttpRequest original, String script) {
        if (original == null || script == null) {
            return original;
        }

        java.util.Map<String, String> config = parseScript(script);
        String target = config.getOrDefault("target", "path").trim().toLowerCase();
        String find = config.get("find");
        String replace = config.getOrDefault("replace", "");
        String scope = config.getOrDefault("scope", "first").trim().toLowerCase();
        String headerName = config.get("header");
        String method = config.get("method");

        try {
            if (method != null && !method.isBlank()) {
                original = original.withMethod(method.trim());
            }

            if (find == null || find.isBlank()) {
                return original;
            }

            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(find);
            java.util.regex.Matcher matcher;

            switch (target) {
                case "body": {
                    String body = original.bodyToString();
                    if (body == null || body.isEmpty()) return original;
                    matcher = pattern.matcher(body);
                    String newBody = scope.equals("all") ? matcher.replaceAll(replace) : matcher.replaceFirst(replace);
                    return newBody.equals(body) ? original : original.withBody(newBody);
                }
                case "header": {
                    if (headerName == null || headerName.isBlank()) {
                        return original;
                    }
                    String headerValue = original.headerValue(headerName.trim());
                    if (headerValue == null) return original;
                    matcher = pattern.matcher(headerValue);
                    String newHeaderValue = scope.equals("all") ? matcher.replaceAll(replace) : matcher.replaceFirst(replace);
                    return newHeaderValue.equals(headerValue) ? original : original.withHeader(headerName.trim(), newHeaderValue);
                }
                case "path":
                default: {
                    String path = original.path();
                    if (path == null || path.isEmpty()) return original;
                    matcher = pattern.matcher(path);
                    String newPath = scope.equals("all") ? matcher.replaceAll(replace) : matcher.replaceFirst(replace);
                    return newPath.equals(path) ? original : original.withPath(newPath);
                }
            }
        } catch (Exception e) {
            return original;
        }
    }

    private java.util.Map<String, String> parseScript(String script) {
        java.util.Map<String, String> values = new java.util.LinkedHashMap<>();
        String[] lines = script.split("\\r?\\n");
        for (String line : lines) {
            if (line == null) continue;
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
            int idx = trimmed.indexOf('=');
            if (idx <= 0) continue;
            String key = trimmed.substring(0, idx).trim().toLowerCase();
            String value = trimmed.substring(idx + 1).trim();
            values.put(key, value);
        }
        return values;
    }

    private String firstToken(String value) {
        if (value == null || value.isBlank()) {
            return "CUSTOM";
        }
        String[] parts = value.trim().split("\\s+");
        return parts.length > 0 ? parts[0] : "CUSTOM";
    }

    private List<String> getCrossActorIdsForPath(HttpRequest request, String requestingActorId, String targetActorId) {
        if (resourceRegistry == null || requestingActorId == null || targetActorId == null) {
            return java.util.Collections.emptyList();
        }

        ActorProfile requestor = store.getActor(requestingActorId);
        ActorProfile target = store.getActor(targetActorId);
        if (requestor == null || target == null) {
            return java.util.Collections.emptyList();
        }

        String endpointPattern = endpointPatternForRequest(request);
        return resourceRegistry.getCrossActorIds(endpointPattern, requestor.getName(), target.getName());
    }

    private String endpointPatternForRequest(HttpRequest request) {
        String path = request.path();
        path = path.replaceAll("/\\d{2,}", java.util.regex.Matcher.quoteReplacement("/{id}"));
        path = path.replaceAll(
            "/(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            java.util.regex.Matcher.quoteReplacement("/{uuid}")
        );
        path = path.replaceAll("/[A-Z]{2,8}-\\d+", java.util.regex.Matcher.quoteReplacement("/{prefixed_id}"));
        return request.method() + " " + path;
    }
}
