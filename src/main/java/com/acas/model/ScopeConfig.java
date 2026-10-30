package com.acas.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ScopeConfig {
    private boolean useBurpScope = false;
    private List<String> includePatterns = new ArrayList<>();
    private List<String> excludePatterns = new ArrayList<>(Arrays.asList("*/logout", "*/login", "*/static/*", "*.css", "*.js", "*.png", "*.jpg"));
    private List<String> methods = new ArrayList<>(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH"));
    private boolean filterIdParameters = true;
    private List<String> customIdParams = new ArrayList<>();

    public boolean isUseBurpScope() { return useBurpScope; }
    public void setUseBurpScope(boolean useBurpScope) { this.useBurpScope = useBurpScope; }
    public List<String> getIncludePatterns() { return includePatterns; }
    public void setIncludePatterns(List<String> includePatterns) { this.includePatterns = includePatterns; }
    public List<String> getExcludePatterns() { return excludePatterns; }
    public void setExcludePatterns(List<String> excludePatterns) { this.excludePatterns = excludePatterns; }
    public List<String> getMethods() { return methods; }
    public void setMethods(List<String> methods) { this.methods = methods; }
    public boolean isFilterIdParameters() { return filterIdParameters; }
    public void setFilterIdParameters(boolean filterIdParameters) { this.filterIdParameters = filterIdParameters; }
    public List<String> getCustomIdParams() { return customIdParams; }
    public void setCustomIdParams(List<String> customIdParams) { this.customIdParams = customIdParams; }
}
