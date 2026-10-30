package com.acas.engine;

public class MutationDefinition {
    public enum Category { A, B, C, D, E, F, G, H, I, J, K }
    
    public final String name;
    public final String description;
    public final Category category;
    private boolean enabled;
    public final boolean isCustom;
    public boolean scriptMode;
    public String customScript;
    
    // For custom rules
    public String customHeaderName;
    public String customHeaderValue;
    public String customMethod;

    public MutationDefinition(String name, String description, Category category, boolean enabled, boolean isCustom) {
        this.name = name;
        this.description = description;
        this.category = category;
        this.enabled = enabled;
        this.isCustom = isCustom;
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public boolean isScriptMode() { return scriptMode; }
    public void setScriptMode(boolean scriptMode) { this.scriptMode = scriptMode; }

    public String getCustomScript() { return customScript; }
    public void setCustomScript(String customScript) { this.customScript = customScript; }
    
    public static MutationDefinition createCustomHeader(String name, String header, String value) {
        MutationDefinition d = new MutationDefinition(name, "Add custom header: " + header, Category.I, true, true);
        d.customHeaderName = header;
        d.customHeaderValue = value;
        return d;
    }
}
