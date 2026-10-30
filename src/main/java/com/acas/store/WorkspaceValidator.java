package com.acas.store;

import com.acas.model.ActorProfile;
import com.acas.model.CapturedEndpoint;
import com.acas.model.ScopeConfig;
import com.acas.util.CanonicalOrigin;

import java.util.*;

/** Validate a complete import before clearing or mutating the live workspace. */
public final class WorkspaceValidator {
    private WorkspaceValidator() {}
    public static final int MAX_ACTORS = 10_000;
    public static final int MAX_ENDPOINTS = 100_000;
    public static final int MAX_PROBES_PER_ENDPOINT = 64;
    public static final int MAX_HEADERS_PER_ACTOR = 500;
    public static final long MAX_MESSAGE_BYTES = 16L * 1024 * 1024;
    public static final long MAX_TOTAL_EVIDENCE_BYTES = 512L * 1024 * 1024;

    public static void validate(List<ActorProfile> actors, ScopeConfig scope,
                                List<CapturedEndpoint> endpoints, String activeActorId) {
        if (actors == null || endpoints == null) throw invalid("Workspace lists are missing");
        if (actors.size() > MAX_ACTORS || endpoints.size() > MAX_ENDPOINTS) throw invalid("Workspace exceeds the item limit");
        Set<String> actorIds = new HashSet<>();
        long total = 0;
        for (ActorProfile actor : actors) {
            if (actor == null || actor.getId() == null || actor.getId().isBlank() || !actorIds.add(actor.getId()))
                throw invalid("Actor identifiers must be unique and non-empty");
            if (actor.getName() == null || actor.getName().isBlank() || actor.getName().length() > 512)
                throw invalid("Actor name is invalid");
            if (actor.getIdentitySourceUrl() != null && !actor.getIdentitySourceUrl().isBlank())
                CanonicalOrigin.of(actor.getIdentitySourceUrl());
            List<String[]> headers = actor.getHeaders();
            if (headers == null || headers.size() > MAX_HEADERS_PER_ACTOR) throw invalid("Actor header bundle is invalid");
            for (String[] header : headers) {
                if (header == null || header.length != 2 || header[0] == null || header[1] == null
                    || !header[0].matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+")
                    || header[1].indexOf('\r') >= 0 || header[1].indexOf('\n') >= 0 || header[1].indexOf(0) >= 0)
                    throw invalid("Actor header is malformed");
            }
        }
        Set<String> endpointIds = new HashSet<>();
        for (CapturedEndpoint endpoint : endpoints) {
            if (endpoint == null || endpoint.getId() == null || endpoint.getId().isBlank() || !endpointIds.add(endpoint.getId()))
                throw invalid("Capture identifiers must be unique and non-empty");
            if (endpoint.getActorId() == null || !actorIds.contains(endpoint.getActorId()))
                throw invalid("Capture references an unknown actor");
            if (endpoint.getMethod() == null || endpoint.getMethod().isBlank())
                throw invalid("Capture method is missing");
            if (endpoint.getOriginalUrl() != null && !endpoint.getOriginalUrl().isBlank())
                CanonicalOrigin.of(endpoint.getOriginalUrl());
            byte[] request = endpoint.getOriginalRequestBytes();
            byte[] response = endpoint.getOriginalResponseBytes();
            total = addSize(total, request);
            total = addSize(total, response);
            if (endpoint.getProbes() != null) {
                if (endpoint.getProbes().size() > MAX_PROBES_PER_ENDPOINT) throw invalid("Too many probe results");
                for (CapturedEndpoint.ProbeResult probe : endpoint.getProbes()) {
                    if (probe == null || probe.identityType == null) throw invalid("Probe result is malformed");
                    if (probe.identityType == CapturedEndpoint.ProbeIdentity.ACTOR
                        && (probe.actorId == null || !actorIds.contains(probe.actorId)))
                        throw invalid("Probe references an unknown actor");
                    total = addSize(total, probe.request);
                    total = addSize(total, probe.response);
                }
            }
            if (endpoint.getCapturedAtEpochMs() < 0) throw invalid("Capture timestamp is invalid");
        }
        if (activeActorId != null && !activeActorId.isBlank() && !actorIds.contains(activeActorId))
            throw invalid("Active actor is not part of this workspace");
        if (scope == null) throw invalid("Scope configuration is missing");
    }

    private static long addSize(long total, byte[] value) {
        if (value == null) return total;
        if (value.length > MAX_MESSAGE_BYTES) throw invalid("Message exceeds the evidence size limit");
        total += value.length;
        if (total > MAX_TOTAL_EVIDENCE_BYTES) throw invalid("Workspace evidence exceeds the total size limit");
        return total;
    }

    private static IllegalArgumentException invalid(String reason) {
        return new IllegalArgumentException("Cannot import workspace: " + reason);
    }
}
