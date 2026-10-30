package com.acas.model;

import com.acas.engine.MutationDefinition;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class WorkspaceBackup {
    private String schemaVersion = "1.0";
    private List<ActorProfile> actors = new ArrayList<>();
    private ScopeConfig scopeConfig = new ScopeConfig();
    private List<CapturedEndpoint> capturedEndpoints = new ArrayList<>();
    private List<CapturedEndpoint> queuedHuntEndpoints = new ArrayList<>();
    private List<AcasFinding> findings = new ArrayList<>();
    private List<MutationDefinition> customMutations = new ArrayList<>();
    private Map<String, String> settings;
    private String activeActorId;

    public String getSchemaVersion() { return schemaVersion; }
    public void setSchemaVersion(String schemaVersion) { this.schemaVersion = schemaVersion; }
    public List<ActorProfile> getActors() { return actors; }
    public void setActors(List<ActorProfile> actors) { this.actors = actors; }
    public ScopeConfig getScopeConfig() { return scopeConfig; }
    public void setScopeConfig(ScopeConfig scopeConfig) { this.scopeConfig = scopeConfig; }
    public List<CapturedEndpoint> getCapturedEndpoints() { return capturedEndpoints; }
    public void setCapturedEndpoints(List<CapturedEndpoint> capturedEndpoints) { this.capturedEndpoints = capturedEndpoints; }
    public List<CapturedEndpoint> getQueuedHuntEndpoints() { return queuedHuntEndpoints; }
    public void setQueuedHuntEndpoints(List<CapturedEndpoint> queuedHuntEndpoints) { this.queuedHuntEndpoints = queuedHuntEndpoints; }
    public List<AcasFinding> getFindings() { return findings; }
    public void setFindings(List<AcasFinding> findings) { this.findings = findings; }
    public List<MutationDefinition> getCustomMutations() { return customMutations; }
    public void setCustomMutations(List<MutationDefinition> customMutations) { this.customMutations = customMutations; }
    public Map<String, String> getSettings() { return settings; }
    public void setSettings(Map<String, String> settings) { this.settings = settings; }
    public String getActiveActorId() { return activeActorId; }
    public void setActiveActorId(String activeActorId) { this.activeActorId = activeActorId; }
}