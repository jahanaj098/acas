package com.acas.engine;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.acas.model.AcasFinding;
import com.acas.model.CapturedEndpoint;

import java.util.Set;
import java.nio.charset.StandardCharsets;

public class ComparisonEngine {

    private final ObjectManager objectManager;
    private final WriteOperationClassifier writeClassifier;
    // Optional high-performance multi-pattern searcher (Aho-Corasick).
    // When provided, replaces the O(N*M) per-object regex loop with a single O(N+M) pass.
    private volatile AhoCorasickSearcher ahoCorasickSearcher;

    private static final Set<String> SENSITIVE_TYPES = Set.of(
        "email", "name", "balance", "address", "phone", "token", "password", "card", "ssn", "account_id", "admin", "internal", "debug", "test", "dev"
    );

    public ComparisonEngine(ObjectManager objectManager) {
        this.objectManager = objectManager;
        this.writeClassifier = new WriteOperationClassifier();
        this.ahoCorasickSearcher = null;
    }

    /**
     * Provide a pre-built Aho-Corasick searcher for high-performance cross-actor leak detection.
     * Call this once at hunt start after building the searcher from all actor values.
     */
    public void setAhoCorasickSearcher(AhoCorasickSearcher searcher) {
        this.ahoCorasickSearcher = searcher;
    }

    public AcasFinding compare(CapturedEndpoint endpoint, MutationVector vector, HttpResponse baseResp, HttpResponse mutatedResp) {
        if (baseResp == null || mutatedResp == null) return null;

        int baseStatus = baseResp.statusCode();
        int mutStatus = mutatedResp.statusCode();
        int baseLen = baseResp.body().length();
        int mutLen = mutatedResp.body().length();

        double similarity = com.acas.util.HttpUtils.calculateSimilarity(baseLen, mutLen);
        boolean sensitiveLeaked = checkSensitiveLeaked(endpoint.getActorId(), mutatedResp.bodyToString());
        boolean crossActorLeak = checkCrossActorLeak(mutatedResp.bodyToString(), vector.getActor() != null ? vector.getActor().getId() : null);

        // Part 8 & Phase 9 logic
        String label = "PASS";
        String severity = "INFO";
        boolean isAnonymousVector = vector.getActor() == null;
        boolean hasCorroboratingEvidence = sensitiveLeaked || crossActorLeak;

        if (mutStatus == baseStatus && similarity > 0.85) {
            if (hasCorroboratingEvidence) {
                label = "DATA_LEAK";
                severity = "CRITICAL";
            } else if (isAnonymousVector && mutStatus >= 200 && mutStatus < 300) {
                label = "ANON_BROKEN";
                severity = "MEDIUM";
            } else {
                // No strong proof yet: avoid reporting as a confirmed issue.
                return null;
            }
        } else if (mutStatus == baseStatus && similarity > 0.5 && hasCorroboratingEvidence) {
            label = "PARTIAL_BYPASS";
            severity = "MEDIUM";
        } else if (mutStatus == baseStatus && hasCorroboratingEvidence) {
            label = "SUSPICIOUS_STATUS";
            severity = "LOW";
        }
        
        // Phase 12: Write Operation Severity Override
        WriteOperationClassifier.Result writeRes = writeClassifier.classify(endpoint.getMethod(), mutStatus, baseStatus);
        if (writeRes != null) {
            severity = writeRes.severity;
            if (label.equals("PASS")) label = "WRITE_BYPASS";
        }

        if (label.equals("PASS")) return null;

        AcasFinding finding = new AcasFinding();
        finding.setSource("Hunt Hub");
        finding.setSeverity(severity);
        finding.setLabel(label);
        finding.setMutationType(vector.getTypeName());
        finding.setMutationDescription(vector.getDescription());
        finding.setOwnerActorName(endpoint.getActorId());
        finding.setReplayerActorName(vector.getActor() != null ? vector.getActor().getName() : "Anonymous");
        finding.setMethod(endpoint.getMethod());
        finding.setUrl(endpoint.getOriginalUrl());
        finding.setEndpointPattern(endpoint.getNormalizedPath());
        
        finding.setBaseStatus(baseStatus);
        finding.setBaseLength(baseLen);
        finding.setMutatedStatus(mutStatus);
        finding.setMutatedLength(mutLen);
        finding.setSizeSimilarity(similarity);

        StringBuilder note = new StringBuilder();
        note.append("Compared baseline status ").append(baseStatus)
            .append(" (length ").append(baseLen).append(") against mutated status ").append(mutStatus)
            .append(" (length ").append(mutLen).append(") using similarity ")
            .append(String.format("%.2f", similarity)).append(". ");
        if (vector.getDescription() != null) {
            note.append("Mutation applied: ").append(vector.getDescription()).append(". ");
        }
        if (vector.getTypeName() != null) {
            note.append("Mutation type: ").append(vector.getTypeName()).append(". ");
        }
        note.append("Replay actor: ").append(vector.getActor() != null ? vector.getActor().getName() : "Anonymous").append(". ");
        if (sensitiveLeaked) {
            note.append("Owner sensitive value was echoed in the mutated response. ");
        }
        if (crossActorLeak) {
            note.append("A value belonging to another actor was found in the mutated response. ");
        }
        if (writeRes != null) {
            note.append("Write classifier override produced severity ").append(writeRes.severity).append(". ");
        }
        finding.setAnalysisNote(note.toString().trim());
        
        if (crossActorLeak) {
            finding.setLabel("IDOR_DATA_LEAK");
            finding.setSeverity("CRITICAL");
        }
        
        return finding;
    }


    private boolean checkSensitiveLeaked(String ownerId, String mutBody) {
        if (ownerId == null || mutBody == null) return false;
        
        java.util.List<ObjectManager.ObjectEntry> ownerObjects = objectManager.getObjectsForActor(ownerId);
        for (ObjectManager.ObjectEntry obj : ownerObjects) {
            boolean isSensitiveType = SENSITIVE_TYPES.stream().anyMatch(t -> obj.type.toLowerCase().contains(t));
            if (isSensitiveType) {
                if (!valuePassesEntropyCheck(obj.value)) {
                    // Fix #1: Short value — use key-value context match instead of blind regex
                    if (keyValueContextMatch(obj.type, obj.value, mutBody)) return true;
                } else {
                    // Fix #2: Custom boundary regex (handles symbol-edged IDs like @user123 or -abc-)
                    java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                        "(?<![a-zA-Z0-9])" + java.util.regex.Pattern.quote(obj.value) + "(?![a-zA-Z0-9])");
                    if (p.matcher(mutBody).find()) return true;
                }
            }
        }
        return false;
    }

    private boolean checkCrossActorLeak(String body, String currentActorId) {
        if (body == null || body.isEmpty()) return false;

        // Fix #3: Properly implement error-context guard — skip cross-actor leak check on error responses
        String lowerBody = body.toLowerCase();
        if (lowerBody.contains("error") || lowerBody.contains("not found") || lowerBody.contains("invalid")) {
            // Response is an error context. IDs reflected in error messages (e.g. "User 9001 not found")
            // are extremely common and not reliable indicators of a data leak. Skip check.
            return false;
        }

        // Performance fast-path: use pre-built Aho-Corasick automaton if available (O(N+M) single scan)
        if (ahoCorasickSearcher != null) {
            return ahoCorasickSearcher.containsCrossActorValue(body, currentActorId != null ? currentActorId : "");
        }

        // Fallback: per-object regex loop (O(N*M) — acceptable for small object maps)
        for (String otherActorId : objectManager.getAllActorIds()) {
            if (otherActorId.equals(currentActorId)) continue;
            
            java.util.List<ObjectManager.ObjectEntry> others = objectManager.getObjectsForActor(otherActorId);
            for (ObjectManager.ObjectEntry obj : others) {
                if (!valuePassesEntropyCheck(obj.value)) {
                    // Fix #1: Short value — require key-value context to avoid false positives
                    if (keyValueContextMatch(obj.type, obj.value, body)) return true;
                } else {
                    // Fix #2: Custom boundary regex (handles symbol-edged IDs, replaces broken \b)
                    java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                        "(?<![a-zA-Z0-9])" + java.util.regex.Pattern.quote(obj.value) + "(?![a-zA-Z0-9])");
                    if (p.matcher(body).find()) return true;

                    // Fix #4: UTF-8 enforced Base64 encoding (prevents charset corruption on Windows)
                    try {
                        String b64 = java.util.Base64.getEncoder().encodeToString(
                            obj.value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        if (body.contains(b64)) return true;
                    } catch (Exception ignored) {}
                }
            }
        }
        return false;
    }

    /**
     * Fix #1: Entropy/length guard.
     * Values shorter than 5 characters are too short for reliable blind regex body scanning.
     * They must fall back to key-value context matching.
     */
    private boolean valuePassesEntropyCheck(String value) {
        return value != null && value.length() >= 5;
    }

    /**
     * Fix #1: Key-value context matching for short values.
     * Instead of blindly matching "1" anywhere in the body, look for:
     *   "user_id": 1  OR  "user_id":"1"  OR  user_id=1
     * This prevents false positives from counters, page numbers, and other generic integers.
     */
    private boolean keyValueContextMatch(String key, String value, String body) {
        if (key == null || value == null || body == null) return false;
        String quotedKey = java.util.regex.Pattern.quote(key);
        String quotedValue = java.util.regex.Pattern.quote(value);
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "\"" + quotedKey + "\"\\s*:\\s*\"?" + quotedValue + "\"?" +
            "|" + quotedKey + "=" + quotedValue,
            java.util.regex.Pattern.CASE_INSENSITIVE);
        return p.matcher(body).find();
    }
}
