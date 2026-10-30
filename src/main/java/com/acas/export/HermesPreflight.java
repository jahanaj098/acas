package com.acas.export;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class HermesPreflight {
    private HermesPreflight() {}

    public record Summary(List<String> origins, int captures, int probes, int findings, int resources,
                          int mutationPoints, int executablePlans, Map<String, Integer> operationSafety,
                          String runId, int maxRequestsTotal, int maxRequestsPerCapture,
                          int reviewedRequests, boolean activeTestingAllowed, String redirectPolicy) {
        public String text() {
            StringBuilder out = new StringBuilder();
            out.append("Exact origins: ").append(origins.isEmpty() ? "(none)" : String.join(", ", origins)).append('\n');
            out.append("Captures: ").append(captures).append("; probes: ").append(probes)
                .append("; findings: ").append(findings).append('\n');
            out.append("Resources: ").append(resources).append("; mutation points: ").append(mutationPoints)
                .append("; executable reviewed plans: ").append(executablePlans).append('\n');
            out.append("Operation safety: ");
            if (operationSafety.isEmpty()) out.append("(none)");
            else {
                List<String> values = new ArrayList<>();
                operationSafety.forEach((key, count) -> values.add(key + "=" + count));
                out.append(String.join(", ", values));
            }
            out.append('\n');
            out.append("Replay budget: run ").append(runId == null ? "(not configured)" : runId)
                .append(", total ").append(maxRequestsTotal)
                .append(", per capture ").append(maxRequestsPerCapture)
                .append(", reviews ").append(reviewedRequests).append('\n');
            out.append("Active testing allowed: ").append(activeTestingAllowed)
                .append("; redirects: ").append(redirectPolicy == null ? "unset" : redirectPolicy);
            return out.toString();
        }
    }

    public static Summary of(JsonObject document) {
        if (document == null) throw new IllegalArgumentException("A Hermes export document is required");
        JsonObject authorization = object(document, "authorization");
        Set<String> origins = new LinkedHashSet<>();
        for (JsonElement item : array(authorization, "exactOrigins"))
            if (item.isJsonPrimitive()) origins.add(item.getAsString());
        JsonObject actor = object(document, "actor");
        if (actor != null && actor.has("origin") && !actor.get("origin").isJsonNull())
            origins.add(actor.get("origin").getAsString());
        for (JsonElement item : array(document, "actors")) {
            if (!item.isJsonObject()) continue;
            String origin = string(item.getAsJsonObject(), "origin");
            if (origin != null) origins.add(origin);
        }
        int captures = 0, probes = 0, findings = 0;
        Map<String, Integer> safety = new LinkedHashMap<>();
        for (JsonElement item : array(document, "records")) {
            if (!item.isJsonObject()) continue;
            JsonObject record = item.getAsJsonObject();
            String kind = string(record, "kind");
            if ("capture".equals(kind)) {
                captures++;
                String value = string(record, "operationSafety");
                safety.merge(value == null ? "UNKNOWN" : value, 1, Integer::sum);
                String url = string(record, "url");
                if (url != null) {
                    try { origins.add(com.acas.util.CanonicalOrigin.of(url)); }
                    catch (RuntimeException ignored) { }
                }
            } else if ("probe".equals(kind)) probes++;
            else if ("finding".equals(kind)) findings++;
        }
        int executable = 0;
        for (JsonElement item : array(document, "mutationPlan"))
            if (item.isJsonObject() && bool(item.getAsJsonObject(), "executable")) executable++;
        JsonObject authorizationValue = authorization == null ? new JsonObject() : authorization;
        return new Summary(List.copyOf(origins), captures, probes, findings,
            array(document, "resources").size(), array(document, "mutationPoints").size(), executable,
            safety, string(authorizationValue, "runId"), integer(authorizationValue, "maxRequestsTotal"),
            integer(authorizationValue, "maxRequestsPerCapture"), array(authorizationValue, "reviews").size(),
            bool(authorizationValue, "activeTestingAllowed"), string(authorizationValue, "redirectPolicy"));
    }

    private static JsonObject object(JsonObject parent, String name) {
        if (parent == null || !parent.has(name) || !parent.get(name).isJsonObject()) return null;
        return parent.getAsJsonObject(name);
    }

    private static JsonArray array(JsonObject parent, String name) {
        if (parent == null || !parent.has(name) || !parent.get(name).isJsonArray()) return new JsonArray();
        return parent.getAsJsonArray(name);
    }

    private static String string(JsonObject parent, String name) {
        if (parent == null || !parent.has(name) || parent.get(name).isJsonNull()) return null;
        try { return parent.get(name).getAsString(); }
        catch (RuntimeException ignored) { return null; }
    }

    private static boolean bool(JsonObject parent, String name) {
        if (parent == null || !parent.has(name) || !parent.get(name).isJsonPrimitive()) return false;
        try { return parent.get(name).getAsBoolean(); }
        catch (RuntimeException ignored) { return false; }
    }

    private static int integer(JsonObject parent, String name) {
        if (parent == null || !parent.has(name) || !parent.get(name).isJsonPrimitive()) return 0;
        try { return parent.get(name).getAsInt(); }
        catch (RuntimeException ignored) { return 0; }
    }
}
