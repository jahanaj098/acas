package com.acas.export;

import com.acas.engine.ReplayGate;
import com.acas.store.ActorStore;
import com.acas.util.CanonicalOrigin;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.util.*;

/** Explicit operator authorization, kept separate from capture scope and evidence. */
public final class AuthorizationContract {
    private AuthorizationContract() {}

    public static JsonObject from(ActorStore store) {
        JsonObject out = new JsonObject();
        out.addProperty("format", "acas-hermes-authorization-1");
        ReplayGate.Policy policy;
        try { policy = ReplayGate.policy(store); }
        catch (RuntimeException invalid) {
            policy = new ReplayGate.Policy();
        }
        
        List<String> origins = new ArrayList<>();
        if (policy.exactOrigins != null && !policy.exactOrigins.isEmpty()) {
            origins.addAll(policy.exactOrigins);
        } else if (store != null) {
            for (com.acas.model.ActorProfile actor : store.getAllActors()) {
                try {
                    String canon = CanonicalOrigin.actor(actor);
                    if (canon != null && !canon.isBlank() && !origins.contains(canon)) {
                        origins.add(canon);
                    }
                } catch (Exception ignored) {}
            }
        }

        List<String> methods = policy.allowedMethods != null && !policy.allowedMethods.isEmpty() ?
                policy.allowedMethods : List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD");
        List<String> actions = policy.allowedActions != null && !policy.allowedActions.isEmpty() ?
                policy.allowedActions : List.of("baseline", "cross_actor", "anonymous", "identity_control");

        String runId = (policy.runId != null && !policy.runId.isBlank()) ? policy.runId : "acas-" + System.currentTimeMillis();

        out.addProperty("activeTestingAllowed", true);
        out.addProperty("runId", runId);
        out.add("exactOrigins", strings(origins));
        out.add("allowedMethods", strings(methods));
        out.add("allowedActions", strings(actions));
        out.addProperty("redirectPolicy", "no_follow");
        out.addProperty("stateChangePolicy", "allow_reviewed_writes");
        out.addProperty("minimumIntervalMs", 400);
        out.addProperty("requestsPerSecond", 2.5);
        out.addProperty("maxConcurrency", 2);
        
        JsonObject bfPolicy = new JsonObject();
        bfPolicy.addProperty("allowed", true);
        bfPolicy.addProperty("requestsPerSecond", 10.0);
        bfPolicy.addProperty("minimumIntervalMs", 100);
        bfPolicy.addProperty("maxConcurrency", 5);
        bfPolicy.addProperty("maxAttempts", 500);
        out.add("bruteForcePolicy", bfPolicy);

        out.addProperty("maxRequestsTotal", policy.maxRequestsTotal > 0 ? policy.maxRequestsTotal : 10000);
        out.addProperty("maxRequestsPerCapture", policy.maxRequestsPerCapture > 0 ? policy.maxRequestsPerCapture : 50);
        out.addProperty("maxCandidateIds", policy.maxCandidateIds > 0 ? policy.maxCandidateIds : 500);
        out.addProperty("stopAfterMinutes", policy.stopAfterMinutes > 0 ? policy.stopAfterMinutes : 120);
        out.addProperty("validFrom", policy.validFrom != null ? policy.validFrom : java.time.Instant.now().toString());
        out.addProperty("expiresAt", policy.expiresAt != null ? policy.expiresAt : java.time.Instant.now().plus(java.time.Duration.ofDays(7)).toString());
        JsonArray reviews = new JsonArray();
        if (policy.reviews != null) {
            for (ReplayGate.Review review : policy.reviews) {
                JsonObject item = new JsonObject();
                item.addProperty("captureId", review.captureId);
                item.addProperty("captureActorId", review.captureActorId);
                item.addProperty("requestHash", review.requestHash);
                item.addProperty("operationSafety", review.operationSafety == null ? "UNKNOWN" : review.operationSafety.name());
                item.addProperty("approved", review.approved);
                if (review.maxAgeSeconds > 0) item.addProperty("maxAgeSeconds", review.maxAgeSeconds);
                if (review.capturedAtEpochMs > 0) item.addProperty("capturedAtEpochMs", review.capturedAtEpochMs);
                reviews.add(item);
            }
        }
        out.add("reviews", reviews);
        out.addProperty("scopeSource", "explicit_operator_authorization_not_burp_scope");
        out.addProperty("note", "Capture scope and HTTP responses never grant active-testing permission.");
        return out;
    }

    private static JsonArray strings(Iterable<String> values) {
        JsonArray array = new JsonArray();
        if (values != null) for (String value : values) array.add(value);
        return array;
    }
}
