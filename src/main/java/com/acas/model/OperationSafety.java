package com.acas.model;

import java.util.Locale;

/** Operation meaning is never inferred from a successful-looking response. */
public enum OperationSafety {
    SAFE_READ,
    IDEMPOTENT_WRITE,
    REVERSIBLE_WRITE,
    DESTRUCTIVE,
    EXTERNAL_SIDE_EFFECT,
    UNKNOWN;

    public static OperationSafety parse(String value) {
        if (value == null || value.isBlank()) return UNKNOWN;
        try { return valueOf(value.trim().toUpperCase(Locale.ROOT)); }
        catch (IllegalArgumentException ignored) { return UNKNOWN; }
    }

    /**
     * A method alone is not approval. GET/HEAD begin UNKNOWN and only become
     * SAFE_READ after an operator explicitly records that exact request.
     */
    public static OperationSafety effective(String method, boolean approved, OperationSafety reviewed) {
        if (!approved || reviewed == null || reviewed == UNKNOWN) return UNKNOWN;
        if (isReadMethod(method)) return reviewed == SAFE_READ ? SAFE_READ : UNKNOWN;
        return reviewed == SAFE_READ ? UNKNOWN : reviewed;
    }

    public static boolean isReadMethod(String method) {
        return "GET".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method);
    }

    public boolean isReadOnly() { return this == SAFE_READ; }

    public boolean requiresExplicitMutationPlan() { return !isReadOnly(); }
}
