package com.acas.engine;

/**
 * CustomMutationDefinition extends MutationDefinition for user-created mutations.
 */
public class CustomMutationDefinition extends MutationDefinition {
    
    public enum Strategy {
        ID_SUBSTITUTION("ID Substitution"),
        PARAMETER_INJECTION("Parameter Injection"),
        HEADER_INJECTION("Header Injection"),
        ENCODING_BYPASS("Encoding Bypass"),
        METHOD_OVERRIDE("Method Override");

        public final String label;

        Strategy(String label) {
            this.label = label;
        }
    }

    private Strategy strategy;
    private boolean useHarvestedIds;
    private boolean useUrlParams;
    private boolean useBodyFields;
    private boolean useHeaders;
    private boolean useQueryParams;
    private boolean useCookies;
    private String encoding; // "none", "url", "base64", "double"
    private String customPayloads; // User-entered manual payloads
    private long createdAt;

    public CustomMutationDefinition(String name, Strategy strategy) {
        super(name, "Custom: " + name, Category.B, true, true);
        this.strategy = strategy;
        this.encoding = "none";
        this.createdAt = System.currentTimeMillis();
        this.useHarvestedIds = true;
        this.useUrlParams = true;
    }

    // Getters and setters
    public Strategy getStrategy() { return strategy; }
    public void setStrategy(Strategy strategy) { this.strategy = strategy; }

    public boolean isUseHarvestedIds() { return useHarvestedIds; }
    public void setUseHarvestedIds(boolean use) { this.useHarvestedIds = use; }

    public boolean isUseUrlParams() { return useUrlParams; }
    public void setUseUrlParams(boolean use) { this.useUrlParams = use; }

    public boolean isUseBodyFields() { return useBodyFields; }
    public void setUseBodyFields(boolean use) { this.useBodyFields = use; }

    public boolean isUseHeaders() { return useHeaders; }
    public void setUseHeaders(boolean use) { this.useHeaders = use; }

    public boolean isUseQueryParams() { return useQueryParams; }
    public void setUseQueryParams(boolean use) { this.useQueryParams = use; }

    public boolean isUseCookies() { return useCookies; }
    public void setUseCookies(boolean use) { this.useCookies = use; }

    public String getEncoding() { return encoding; }
    public void setEncoding(String encoding) { this.encoding = encoding != null ? encoding : "none"; }

    public String getCustomPayloads() { return customPayloads; }
    public void setCustomPayloads(String payloads) { this.customPayloads = payloads; }

    public boolean isScriptMode() { return super.isScriptMode(); }
    public void setScriptMode(boolean scriptMode) { super.setScriptMode(scriptMode); }

    public String getCustomScript() { return super.getCustomScript(); }
    public void setCustomScript(String script) { super.setCustomScript(script); }

    public long getCreatedAt() { return createdAt; }

    @Override
    public String toString() {
        return "CustomMutation[" + this.name + "] strategy=" + strategy + " encoding=" + encoding;
    }
}
