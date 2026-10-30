package com.acas.model;

import java.util.Locale;

/** Operator-declared access model for one resource; never guessed from response shape. */
public enum AccessPolicy {
    OWNER_ONLY,
    SHARED,
    PUBLIC,
    ROLE_RESTRICTED,
    TENANT_RESTRICTED,
    DELEGATED,
    UNKNOWN;

    public static AccessPolicy parse(String value) {
        if (value == null || value.isBlank()) return UNKNOWN;
        try { return valueOf(value.trim().toUpperCase(Locale.ROOT)); }
        catch (IllegalArgumentException ignored) { return UNKNOWN; }
    }
}
