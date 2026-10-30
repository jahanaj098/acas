package com.acas.export;

import com.acas.util.CanonicalOrigin;
import com.google.gson.*;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Fail-closed structural validation used for generated handoffs and imports. */
public final class HermesSchemaValidator {
    private HermesSchemaValidator() {}

    public static final String EXPORT = "acas-hermes-1.schema.json";
    public static final String SESSION_UPDATE = "acas-hermes-session-update-1.schema.json";
    public static final String LEDGER = "acas-hermes-ledger-1.schema.json";
    public static final String HISTORY = "acas-hermes-history-1.schema.json";
    public static final String MANIFEST = "acas-hermes-manifest-1.schema.json";
    public static final String OUTBOX = "acas-hermes-outbox-1.schema.json";

    public static String schema(String name) {
        if (name == null || !name.matches("[a-zA-Z0-9._-]+\\.schema\\.json")) throw new IllegalArgumentException("Invalid schema name");
        try (InputStream input = HermesSchemaValidator.class.getResourceAsStream("/schemas/" + name)) {
            if (input == null) throw new IllegalStateException("Bundled schema is missing: " + name);
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } catch (java.io.IOException error) { throw new IllegalStateException("Bundled schema cannot be read", error); }
    }

    public static JsonObject parseObject(String json) {
        try {
            JsonElement value = JsonParser.parseString(json);
            if (!value.isJsonObject()) throw new IllegalArgumentException("A JSON object is required");
            return value.getAsJsonObject();
        } catch (JsonParseException invalid) { throw new IllegalArgumentException("Invalid JSON document"); }
    }

    public static void validateExport(JsonObject document) {
        requireString(document, "format");
        if (!"acas-hermes-1".equals(document.get("format").getAsString())) throw invalid("Not an ACAS Hermes export");
        requireInt(document, "schemaVersion");
        if (document.get("schemaVersion").getAsInt() != 2) throw invalid("Only schemaVersion 2 live handoffs are accepted");
        requireString(document, "batchId");
        requireString(document, "projectId");
        requireObject(document, "authorization");
        requireArray(document, "actors");
        requireArray(document, "resources");
        requireArray(document, "records");
        requireArray(document, "mutationPoints");
        requireArray(document, "mutationPlan");
        requireArray(document, "requestDependencies");
        requireObject(document, "exportHistory");
        JsonObject authorization = document.getAsJsonObject("authorization");
        if (!"no_follow".equals(string(authorization, "redirectPolicy"))) throw invalid("Redirects must be disabled");
        for (JsonElement origin : array(authorization, "exactOrigins")) {
            if (!origin.isJsonPrimitive()) throw invalid("Authorization origins must be exact strings");
            CanonicalOrigin.of(origin.getAsString());
        }
        Set<String> actorIds = new LinkedHashSet<>(), actorOrigins = new LinkedHashSet<>();
        for (JsonElement item : array(document, "actors")) {
            JsonObject actor = object(item, "actor");
            String actorId = string(actor, "actorId");
            if (!actorIds.add(actorId)) throw invalid("Duplicate actor identity");
            String origin = string(actor, "origin");
            CanonicalOrigin.of(origin);
            actorOrigins.add(origin);
        }
        Set<String> resourceRefs = new HashSet<>();
        for (JsonElement item : array(document, "resources")) {
            JsonObject resource = object(item, "resource");
            if (!resourceRefs.add(string(resource, "resourceRef"))) throw invalid("Duplicate resource reference");
            CanonicalOrigin.of(string(resource, "origin"));
            if (resource.has("activeTestingAllowed") && resource.get("activeTestingAllowed").getAsBoolean())
                throw invalid("Resources cannot grant testing permission");
            if (resource.has("ownerActorId") && !resource.get("ownerActorId").isJsonNull()
                && !actorIds.contains(resource.get("ownerActorId").getAsString())) throw invalid("Unknown resource owner");
        }
        Set<String> recordIds = new LinkedHashSet<>(), captureIds = new LinkedHashSet<>();
        Set<String> captureRecordIds = new HashSet<>(), evidenceIds = new HashSet<>();
        for (JsonElement item : array(document, "records")) {
            JsonObject record = object(item, "record");
            String recordId = string(record, "recordId");
            if (!recordIds.add(recordId)) throw invalid("Duplicate record identity");
            evidenceIds.add(recordId);
            String kind = string(record, "kind");
            if (kind.equals("capture")) {
                String captureId = string(record, "captureId");
                captureIds.add(captureId);
                captureRecordIds.add(recordId);
                string(record, "captureActorId");
                string(record, "method");
                string(record, "operationSafety");
                if (record.has("resourceOwnerActorId") && !record.get("resourceOwnerActorId").isJsonNull()
                    && !actorIds.contains(record.get("resourceOwnerActorId").getAsString())) throw invalid("Unknown resource owner in capture");
                if (record.has("resourceRef") && !record.get("resourceRef").isJsonNull()) {
                    String ref = record.get("resourceRef").getAsString();
                    if (!resourceRefs.contains(ref)) throw invalid("Capture references a missing resource");
                }
            } else if (!Set.of("probe", "probeSkipped", "finding").contains(kind)) throw invalid("Unknown record kind");
        }
        Set<String> pointIds = new HashSet<>();
        for (JsonElement item : array(document, "mutationPoints")) {
            JsonObject point = object(item, "mutationPoint");
            String pointId = string(point, "pointId");
            if (!pointIds.add(pointId)) throw invalid("Duplicate mutation point");
            String captureId = string(point, "captureId");
            if (!captureIds.contains(captureId) && "full".equals(string(document, "mode"))) throw invalid("Mutation point references an unknown capture");
            string(point, "selector");
            string(point, "mutationSafety");
        }
        for (JsonElement item : array(document, "mutationPlan")) {
            JsonObject plan = object(item, "mutationPlanEntry");
            String pointId = string(plan, "pointId");
            if (!pointIds.contains(pointId) && "full".equals(string(document, "mode"))) throw invalid("Mutation plan references an unknown point");
            if (plan.has("executable") && plan.get("executable").getAsBoolean()) {
                String safety = string(plan, "operationSafety");
                if ((!"SAFE_READ".equals(safety) && !"REVERSIBLE_WRITE".equals(safety) && !"IDEMPOTENT_WRITE".equals(safety)) || !plan.get("approved").getAsBoolean())
                    throw invalid("Executable mutation must be approved safe read or reversible write");
            }
            if (!string(plan, "requestHash").matches("[a-f0-9]{64}")) throw invalid("Invalid mutation request hash");
        }
        if ("full".equals(string(document, "mode"))) {
            for (JsonElement item : array(document, "records")) {
                JsonObject record = object(item, "record");
                if (!"finding".equals(string(record, "kind"))) continue;
                if (record.has("captureId") && !record.get("captureId").isJsonNull()
                    && !captureIds.contains(record.get("captureId").getAsString())) throw invalid("Finding references an unknown capture");
                if (record.has("evidenceRecordIds")) for (JsonElement evidence : record.getAsJsonArray("evidenceRecordIds"))
                    if (!evidenceIds.contains(evidence.getAsString())) throw invalid("Finding references missing evidence");
            }
        }
        HermesExport.readLedger(document.get("exportHistory").toString());
    }

    public static void validateSessionUpdate(JsonObject document) {
        if (!HermesSessionUpdate.FORMAT.equals(string(document, "format"))) throw invalid("Not a session update");
        requireInt(document, "schemaVersion");
        if (document.get("schemaVersion").getAsInt() != 2) throw invalid("Only schemaVersion 2 session updates are accepted");
        requireString(document, "updateId");
        requireString(document, "revisionStreamId");
        requireInt(document, "credentialRevision");
        if (document.get("credentialRevision").getAsLong() < 1) throw invalid("Invalid credential revision");
        if (!"replace_managed_credentials".equals(string(document, "applicationMode"))) throw invalid("Unknown session application mode");
        JsonObject actor = object(document.get("actor"), "actor");
        CanonicalOrigin.of(string(actor, "origin"));
        if (!actor.has("currentAuthenticationHeaders") || !actor.get("currentAuthenticationHeaders").isJsonArray())
            throw invalid("Session update has no authentication headers");
    }

    public static void validateLedger(JsonObject document) {
        if (!"acas-hermes-ledger-1".equals(string(document, "format"))) throw invalid("Not export history");
        requireString(document, "projectId");
        requireArray(document, "exported");
        requireObject(document, "actorKeys");
        requireObject(document, "actorNames");
        for (var entry : document.getAsJsonObject("actorKeys").entrySet())
            if (entry.getValue() == null || !entry.getValue().isJsonPrimitive()
                || entry.getValue().getAsString().isBlank())
                throw invalid("Export history has an empty actor mapping");
    }

    private static void requireString(JsonObject object, String field) {
        if (!object.has(field) || !object.get(field).isJsonPrimitive() || object.get(field).getAsString().isBlank())
            throw invalid("Missing or invalid field: " + field);
    }
    private static void requireInt(JsonObject object, String field) {
        if (!object.has(field) || !object.get(field).isJsonPrimitive() || !object.get(field).getAsJsonPrimitive().isNumber())
            throw invalid("Missing or invalid field: " + field);
    }
    private static void requireArray(JsonObject object, String field) {
        if (!object.has(field) || !object.get(field).isJsonArray()) throw invalid("Missing array: " + field);
    }
    private static void requireObject(JsonObject object, String field) {
        if (!object.has(field) || !object.get(field).isJsonObject()) throw invalid("Missing object: " + field);
    }
    private static String string(JsonObject object, String field) {
        requireString(object, field);
        return object.get(field).getAsString();
    }
    private static JsonArray array(JsonObject object, String field) {
        requireArray(object, field);
        return object.getAsJsonArray(field);
    }
    private static JsonObject object(JsonElement value, String label) {
        if (value == null || !value.isJsonObject()) throw invalid("Invalid " + label);
        return value.getAsJsonObject();
    }
    private static IllegalArgumentException invalid(String reason) {
        return new IllegalArgumentException("HELD: invalid Hermes document: " + reason);
    }
}
