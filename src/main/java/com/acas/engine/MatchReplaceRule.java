package com.acas.engine;

public class MatchReplaceRule {
    public enum Target {
        PATH,
        QUERY_KEY,
        QUERY_VALUE,
        HEADER_NAME,
        HEADER_VALUE,
        BODY
    }

    public enum MatchType {
        CONTAINS,
        EXACT,
        REGEX
    }

    public enum Scope {
        FIRST,
        ALL
    }

    public String id;
    public String name;
    public boolean enabled;
    public Target target;
    public MatchType matchType;
    public Scope scope;
    public boolean caseSensitive;
    public String pattern;
    public String replacement;
    public boolean useRequestFilters;
    public String includeUrlRegex;
    public String excludeUrlRegex;
    public String allowedMethodsCsv;

    public MatchReplaceRule() {
        this.id = java.util.UUID.randomUUID().toString();
        this.name = "Rule";
        this.enabled = true;
        this.target = Target.PATH;
        this.matchType = MatchType.CONTAINS;
        this.scope = Scope.FIRST;
        this.caseSensitive = false;
        this.pattern = "";
        this.replacement = "";
        this.useRequestFilters = false;
        this.includeUrlRegex = "";
        this.excludeUrlRegex = "";
        this.allowedMethodsCsv = "";
    }

    public MatchReplaceRule(String name,
                            Target target,
                            MatchType matchType,
                            Scope scope,
                            boolean caseSensitive,
                            String pattern,
                            String replacement) {
        this();
        this.name = name != null ? name : this.name;
        this.target = target != null ? target : this.target;
        this.matchType = matchType != null ? matchType : this.matchType;
        this.scope = scope != null ? scope : this.scope;
        this.caseSensitive = caseSensitive;
        this.pattern = pattern != null ? pattern : "";
        this.replacement = replacement != null ? replacement : "";
    }

    public void normalize() {
        if (id == null || id.trim().isEmpty()) {
            id = java.util.UUID.randomUUID().toString();
        }
        if (name == null || name.trim().isEmpty()) {
            name = "Rule";
        }
        if (target == null) {
            target = Target.PATH;
        }
        if (matchType == null) {
            matchType = MatchType.CONTAINS;
        }
        if (scope == null) {
            scope = Scope.ALL;
        }
        if (pattern == null) {
            pattern = "";
        }
        if (replacement == null) {
            replacement = "";
        }
        if (includeUrlRegex == null) {
            includeUrlRegex = "";
        }
        if (excludeUrlRegex == null) {
            excludeUrlRegex = "";
        }
        if (allowedMethodsCsv == null) {
            allowedMethodsCsv = "";
        }
    }

    public boolean isUsable() {
        return enabled && pattern != null && !pattern.trim().isEmpty();
    }
}
