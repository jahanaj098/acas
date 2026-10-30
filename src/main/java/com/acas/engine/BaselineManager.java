package com.acas.engine;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.acas.util.HttpUtils;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class BaselineManager {
    private final Map<String, EndpointBaseline> baselines = new ConcurrentHashMap<>();

    public EndpointBaseline get(String endpointPattern) {
        return baselines.get(endpointPattern);
    }

    public EndpointBaseline get(String endpointPattern, int ttlMinutes) {
        EndpointBaseline baseline = baselines.get(endpointPattern);
        if (baseline == null) return null;
        long ttlMs = Math.max(1, ttlMinutes) * 60_000L;
        long now = System.currentTimeMillis();
        if (baseline.capturedAtEpochMs <= 0 || baseline.capturedAtEpochMs < (now - ttlMs)) {
            baselines.remove(endpointPattern);
            return null;
        }
        return baseline;
    }

    public void put(String endpointPattern, EndpointBaseline baseline) {
        if (endpointPattern == null || baseline == null) return;
        baseline.capturedAtEpochMs = System.currentTimeMillis();
        baselines.put(endpointPattern, baseline);
    }

    public void invalidateAll() {
        baselines.clear();
    }

    public void invalidate(String endpointPattern) {
        if (endpointPattern == null) return;
        baselines.remove(endpointPattern);
    }

    public HttpRequest buildAnonymous(HttpRequest request, Set<String> identityHeaders) {
        return HttpUtils.stripAuthHeaders(request, identityHeaders);
    }

    public HttpRequest replaceIdWith(HttpRequest request, String replacement) {
        if (request == null || replacement == null) return request;

        String updatedPath = request.path()
            .replaceAll("/([0-9]{1,19})(?=/|$|\\?)", "/" + java.util.regex.Matcher.quoteReplacement(replacement))
            .replaceAll("/([A-Z]{2,8}-[0-9]{1,15})(?=/|$|\\?)", "/" + java.util.regex.Matcher.quoteReplacement(replacement))
            .replaceAll("/(?i)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$|\\?)", "/" + java.util.regex.Matcher.quoteReplacement(replacement));

        HttpRequest out = request.withPath(updatedPath);
        String body = request.bodyToString();
        if (body != null && !body.isBlank()) {
            String replacedBody = body
                .replaceAll("\"([a-zA-Z0-9_]*(?:id|_id|uuid|ref))\"\\s*:\\s*\"?([A-Za-z0-9_\\-]{1,64})\"?", "\"$1\":\"" + java.util.regex.Matcher.quoteReplacement(replacement) + "\"");
            out = out.withBody(replacedBody);
        }
        return out;
    }
}
