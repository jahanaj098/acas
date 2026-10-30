package com.acas.engine;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.acas.model.ActorProfile;

public class MutationVector {
    private final String typeName;
    private final ActorProfile actor;
    private final String description;
    private final HttpRequest mutatedRequest;
    private final int priority;

    public MutationVector(String typeName, ActorProfile actor, String description, HttpRequest mutatedRequest) {
        this.typeName = typeName;
        this.actor = actor;
        this.description = description;
        this.mutatedRequest = mutatedRequest;
        this.priority = computePriority(typeName);
    }

    public String getTypeName() { return typeName; }
    public ActorProfile getActor() { return actor; }
    public String getDescription() { return description; }
    public HttpRequest getMutatedRequest() { return mutatedRequest; }
    public int getPriority() { return priority; }

    /**
     * Assigns a numeric priority tier based on mutation code.
     * Lower number = higher priority = survives truncation.
     *
     * Tier 0: Direct IDOR (B1, B5, B6, B15, B18) — never drop
     * Tier 1: Other identity/session mutations (B*)
     * Tier 2: Anonymous bypass (A*)
     * Tier 3: Path relationships & GraphQL (C*, D*)
     * Tier 4: Parameter pivots (P*)
     * Tier 5: Stateful mutations (E*)
     * Tier 6: Encoding, whitespace, exotic (F*, G*, H*, I*, J*, K*)
     */
    private static int computePriority(String code) {
        if (code == null) return 99;
        String upper = code.toUpperCase();
        if ("B1".equals(upper) || "B5".equals(upper) || "B6".equals(upper)
                || "B15".equals(upper) || "B18".equals(upper)) return 0;
        if (upper.startsWith("B")) return 1;
        if (upper.startsWith("A")) return 2;
        if (upper.startsWith("C") || upper.startsWith("D")) return 3;
        if (upper.startsWith("P")) return 4;
        if (upper.startsWith("E")) return 5;
        return 6;
    }
}
