package com.acas.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.acas.model.ActorProfile;
import com.acas.model.TestResult;
import com.acas.util.IdParameterDetector;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

public class ReplayEngine {

    public static final String ACAS_INTERNAL_HEADER = "X-ACAS-Internal";
    private final MontoyaApi api;
    private final ExecutorService executor = Executors.newFixedThreadPool(5);

    private final com.acas.store.ActorStore actorStore;
    private final com.acas.util.CredentialPolicy credentials;
    public ReplayEngine(MontoyaApi api) { this(api,null); }
    public ReplayEngine(MontoyaApi api,com.acas.store.ActorStore store) {
        this.api=api;this.actorStore=store;
        this.credentials=store==null?new com.acas.util.CredentialPolicy():new com.acas.util.CredentialPolicy(store);
    }
    private java.util.Set<String> managedHeaders() {
        return actorStore==null?java.util.Set.of():actorStore.getAllIdentityHeaderNames();
    }

    public void replayVectors(HttpRequest originalRequest,
                              List<MutationVector> vectors,
                              Consumer<TestResult> onResult,
                              Runnable onComplete) {
        executor.submit(() -> {
            for (MutationVector vector : vectors) {
                try {
                    TestResult result = executeVector(vector);
                    onResult.accept(result);
                } catch (Exception e) {
                    api.logging().logToError("ACAS: Replay error for " + vector.getDescription() + ": " + e.getMessage());
                    onResult.accept(buildErrorResult(vector, e.getMessage()));
                }
            }
            onComplete.run();
        });
    }

    private TestResult executeVector(MutationVector vector) {
        HttpRequest mutated = vector.getMutatedRequest();
        
        String type = vector.getTypeName();
        
        // 1. Handle specialized mutations that require field swapping
        if ("ID swap cross-user".equals(type)) {
            mutated = performIdSwap(mutated, vector.getDescription());
        }

        // 2. Handle Authentication / Session swaps
        if ("Anonymous check".equals(type)) {
            mutated = stripAuthHeaders(mutated);
        } else if (vector.getActor() != null) {
            mutated = injectActorHeaders(mutated, vector.getActor());
        }

        long start = System.currentTimeMillis();
        burp.api.montoya.http.message.HttpRequestResponse rr = null;
        HttpRequest currentReq = mutated.withHeader(ACAS_INTERNAL_HEADER, "true");
        rr = com.acas.engine.ReplayGate.send(api,currentReq);
        String redirectChain = rr.response()!=null && rr.response().statusCode()>=300 && rr.response().statusCode()<400
            ? "HELD_REDIRECT: no_follow; inspect the captured response Location" : "";
        long elapsed = System.currentTimeMillis() - start;

        TestResult result = new TestResult();
        result.setActorName(vector.getActor() != null ? vector.getActor().getName() : "Anonymous");
        result.setActorRole(vector.getActor() != null ? vector.getActor().getRole() : "None");
        result.setMutationDescription(vector.getDescription() + (!redirectChain.isEmpty() ? " [" + redirectChain + "]" : ""));
        result.setMethod(mutated.method());
        result.setUrl(mutated.url()); // original URL
        result.setResponseTime(elapsed);

        if (rr != null && rr.response() != null) {
            result.setStatusCode(rr.response().statusCode());
            result.setResponseLength(rr.response().body().length());
            result.setResponseBody(rr.response().bodyToString());
            
        } else {
            result.setStatusCode(0);
            result.setFlagged(true);
            result.setFlagReason("No response received");
        }
        return result;
    }

    private HttpRequest performIdSwap(HttpRequest request, String description) {
        try {
            // "ID Swap: Injecting type=value for Actor"
            if (description.contains("Injecting ")) {
                String pair = description.split("Injecting ")[1].split(" for ")[0];
                String[] parts = pair.split("=");
                if (parts.length == 2) {
                    String key = parts[0];
                    String value = parts[1];
                    String raw = request.toString();
                    String swapped = raw.replaceAll("(?i)([?&/]" + key + "=)[^&/# ]+", "$1" + value);
                    return burp.api.montoya.http.message.requests.HttpRequest.httpRequest(swapped).withService(request.httpService());
                }
            }
        } catch (Exception e) {
            api.logging().logToError("ACAS: ID Swap logic failed: " + e.getMessage());
        }
        return request;
    }

    private HttpRequest injectActorHeaders(HttpRequest request, ActorProfile actor) {
        return credentials.swap(request,actor,managedHeaders());
    }

    private HttpRequest stripAuthHeaders(HttpRequest request) {
        return credentials.anonymous(request,managedHeaders());
    }

    public HttpRequest buildActorRequest(HttpRequest originalRequest, ActorProfile actor) {
        return injectActorHeaders(originalRequest, actor);
    }

    private TestResult buildErrorResult(MutationVector vector, String error) {
        TestResult r = new TestResult();
        r.setActorName(vector.getActor() != null ? vector.getActor().getName() : "Anonymous");
        r.setActorRole(vector.getActor() != null ? vector.getActor().getRole() : "None");
        r.setMutationDescription(vector.getDescription());
        r.setStatusCode(-1);
        r.setFlagged(true);
        r.setFlagReason("Error: " + error);
        return r;
    }

    public void shutdown() {
        executor.shutdown();
    }
}
