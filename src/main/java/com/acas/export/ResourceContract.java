package com.acas.export;

import com.acas.model.CapturedEndpoint;
import com.acas.util.CanonicalOrigin;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.List;

/** Resource ownership is explicit. Unknown ownership is exported as unknown, never guessed. */
public final class ResourceContract {
    private ResourceContract() {}

    public static String ref(CapturedEndpoint endpoint) {
        if (endpoint == null) throw new IllegalArgumentException("Resource requires a capture");
        String origin = CanonicalOrigin.of(endpoint.getOriginalUrl());
        String path = endpoint.getNormalizedPath() == null ? "" : endpoint.getNormalizedPath();
        String explicit = endpoint.getResourceId() == null ? "" : endpoint.getResourceId();
        return "resource:" + HermesExport.hash(origin + "|" + path + "|" + endpoint.getResourceType() + "|" + explicit);
    }

    public static JsonObject serialize(String mappedOwner, String captureId, CapturedEndpoint endpoint,
                                       String resourceRef, List<String> evidenceIds, List<String> mutationPointIds) {
        JsonObject resource = new JsonObject();
        resource.addProperty("resourceRef", resourceRef);
        resource.addProperty("type", endpoint.getResourceType());
        resource.addProperty("canonicalId", endpoint.getResourceId());
        resource.addProperty("origin", CanonicalOrigin.of(endpoint.getOriginalUrl()));
        resource.addProperty("path", endpoint.getNormalizedPath());
        boolean confirmed = endpoint.isResourceOwnerConfirmed() && mappedOwner != null && !mappedOwner.isBlank();
        String template = confirmed ? template(endpoint.getNormalizedPath(), endpoint.getResourceId()) : endpoint.getNormalizedPath();
        resource.addProperty("urlTemplate", template);
        resource.addProperty("urlTemplateConfirmed", confirmed && !java.util.Objects.equals(template, endpoint.getNormalizedPath()));
        resource.addProperty("ownerActorId", confirmed ? mappedOwner : null);
        resource.addProperty("tenantId", endpoint.getTenantId());
        resource.addProperty("ownershipBasis", confirmed ? "operator_confirmed" : "unresolved");
        resource.addProperty("confidence", confirmed ? 1.0 : 0.0);
        resource.addProperty("confirmedByOperator", confirmed);
        resource.addProperty("accessPolicy", endpoint.getAccessPolicy().name().toLowerCase(java.util.Locale.ROOT));
        resource.addProperty("activeTestingAllowed", false);
        JsonArray evidence = new JsonArray();
        for (String id : evidenceIds) evidence.add(id);
        resource.add("sourceEvidenceRecordIds", evidence);
        JsonArray points = new JsonArray();
        for (String id : mutationPointIds) points.add(id);
        resource.add("mutationPointIds", points);
        return resource;
    }

    private static String template(String path, String resourceId) {
        if (path == null || path.isBlank()) return path;
        String[] segments = path.split("/", -1);
        StringBuilder out = new StringBuilder();
        int identifiers = 0;
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) out.append('/');
            String segment = segments[i];
            boolean identifier = segment.matches("[0-9]+")
                || segment.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
                || resourceId != null && !resourceId.isBlank() && resourceId.equals(segment);
            if (identifier) {
                identifiers++;
                out.append(identifiers == 1 ? "{id}" : "{id" + identifiers + "}");
            } else out.append(segment);
        }
        return out.toString();
    }
}
