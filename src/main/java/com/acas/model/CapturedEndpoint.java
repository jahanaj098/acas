package com.acas.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class CapturedEndpoint implements Cloneable {
    private String automaticProbeNote;
    public String getAutomaticProbeNote(){return automaticProbeNote;}
    public void setAutomaticProbeNote(String note){automaticProbeNote=note;}
    private String id;
    private boolean evidenceFrozen;
    public void freezeEvidence(){evidenceFrozen=true;}
    private void requireSameEvidence(byte[] before,byte[] after){if(evidenceFrozen && !java.util.Arrays.equals(before,after))throw new IllegalArgumentException("Historical evidence is immutable; create a new capture version");}
    private String method;
    private String originalUrl;
    private String normalizedPath;
    private String actorId;
    private String resourceOwnerActorId;
    private boolean resourceOwnerConfirmed;
    private AccessPolicy accessPolicy=AccessPolicy.UNKNOWN;
    private String resourceType="unknown";
    private String resourceId;
    private String tenantId;
    private OperationSafety operationSafety=OperationSafety.UNKNOWN;
    private String operationSafetyReason;
    private boolean operationApproved;
    private long capturedAtEpochMs=System.currentTimeMillis();
    private byte[] originalRequestBytes;
    private byte[] originalResponseBytes;
    private transient burp.api.montoya.http.message.requests.HttpRequest originalRequest;
    private transient burp.api.montoya.http.message.responses.HttpResponse originalResponse;
    private List<String> segments;
    private boolean isPriority; // Path-based priority flag
    
    // Security Classification
    private int priorityScore = 0;   // 1-100 (Value of target)
    private int confidenceScore = 0; // 1-100 (Certainty of bug)
    private String classificationLabel = "PENDING";
    private String subLabel = "";
    private String perpetratorId = ""; // Which actor ID bypassed?
    private List<ProbeResult> probes;

    // ===== Hunt Status Tracking =====
    public enum HuntStatus {
        NEVER,              // ⬜ Never hunted
        QUEUED,             // ⏺ Queued for hunt, not started
        RUNNING,            // 🔄 Currently being hunted
        CLEAN,              // ✅ Hunted — no findings
        FINDING_CRITICAL,   // 🔴 Hunted — Critical finding
        FINDING_HIGH,       // 🔴 Hunted — High finding
        FINDING_MEDIUM,     // 🟡 Hunted — Medium finding
        FINDING_LOW,        // 🔵 Hunted — Low/Info finding
        ERROR,              // ⚠️ Completed with errors
        STALE               // 🔁 Hunted before, endpoint changed since
    }

    private HuntStatus huntStatus = HuntStatus.NEVER;
    private long lastHuntTime = 0;          // epoch millis
    private int huntFindingCount = 0;
    private int huntCriticalCount = 0;
    private int huntHighCount = 0;
    private int huntMediumCount = 0;
    private int huntLowCount = 0;
    private String huntErrorCode = "";
    private long lastTrafficTime = 0;       // for stale detection
    private int huntProbesCompleted = 0;    // live progress
    private int huntProbesTotal = 0;        // live progress
    private int harvestIdCountAtLastHunt = 0;
    private int harvestDeltaCount = 0;
    private long harvestDeltaLastUpdated = 0;

    // ===== Probe State =====
    public enum ProbeState {
        MISSING,   // ⬜ no probe result exists for this actor
        STALE,     // ❌ probe result is 401 or network error
        COMPLETE   // ✅ probe result exists and is valid
    }

    public enum ProbeIdentity { BASELINE, ANONYMOUS, ACTOR, UNRESOLVED }
    public static class ProbeResult implements Cloneable {
        public ProbeIdentity identityType=ProbeIdentity.UNRESOLVED;
        public String actorName;
        public String actorId;
        public int statusCode;
        public int responseLength;
        public boolean isBaseline;
        public byte[] request;
        public byte[] response;
        public String leakedFields = ""; // e.g. "id, email, address"
        public String verdict = "BLOCKED"; // e.g. "BROKEN", "OWNER", "BLOCKED"

        public ProbeResult(String actorName, int statusCode, int responseLength, boolean isBaseline, byte[] request, byte[] response) {
            this.actorName = actorName;
            this.statusCode = statusCode;
            this.responseLength = responseLength;
            this.isBaseline = isBaseline;
            this.request = request;
            this.response = response;
        }
    }

    public CapturedEndpoint() {
        this.id=java.util.UUID.randomUUID().toString();
        this.probes = new java.util.concurrent.CopyOnWriteArrayList<>();
    }

    /** Independent derived results without expanding raw byte arrays into JSON numbers. */
    public synchronized CapturedEndpoint copyForProbe() {
        try {
            CapturedEndpoint copy=(CapturedEndpoint)super.clone();
            copy.segments=segments==null?null:new ArrayList<>(segments);
            copy.probes=new java.util.concurrent.CopyOnWriteArrayList<>();
            for(ProbeResult p:probes) {
                ProbeResult item=new ProbeResult(p.actorName,p.statusCode,p.responseLength,p.isBaseline,p.request,p.response);
                item.actorId=p.actorId;item.identityType=p.identityType;item.leakedFields=p.leakedFields;item.verdict=p.verdict;
                copy.probes.add(item);
            }
            // Raw evidence is immutable here: mutations replace requests/results,
            // never edit these retained arrays in place.
            return copy;
        } catch(CloneNotSupportedException impossible) {throw new AssertionError(impossible);}
    }

    // ===== Hunt Helper Methods =====

    /**
     * Returns true if this endpoint was hunted more than 30 minutes ago
     * AND new traffic has been captured for the same pattern since the last hunt.
     */
    public boolean isStale() {
        if (lastHuntTime <= 0) return false;
        if (lastTrafficTime <= lastHuntTime) return false;
        long thirtyMinutesMs = 30L * 60L * 1000L;
        return (System.currentTimeMillis() - lastHuntTime) > thirtyMinutesMs;
    }

    /**
     * Build a tooltip string describing the hunt status for display in the Hunt column.
     */
    public String getHuntSummaryTooltip() {
        if (huntStatus == HuntStatus.NEVER) return "Not yet hunted — select and click HUNT SELECTED";
        if (huntStatus == HuntStatus.QUEUED) return "Queued in Hunt Hub — click Start to begin";
        
        String timeStr = lastHuntTime > 0 
            ? java.time.Instant.ofEpochMilli(lastHuntTime)
                .atZone(java.time.ZoneId.systemDefault())
                .format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss"))
            : "unknown";
        
        switch (huntStatus) {
            case RUNNING:
                return "Hunting now — " + huntProbesCompleted + "/" + huntProbesTotal + " probes complete";
            case CLEAN:
                return "Last hunted: " + timeStr + " — 0 findings — Click to re-hunt";
            case FINDING_CRITICAL:
            case FINDING_HIGH:
            case FINDING_MEDIUM:
            case FINDING_LOW:
                StringBuilder sb = new StringBuilder();
                sb.append("Last hunted: ").append(timeStr).append(" — ")
                  .append(huntFindingCount).append(" finding(s)");
                if (huntCriticalCount > 0) sb.append(" (").append(huntCriticalCount).append(" Critical)");
                if (huntHighCount > 0) sb.append(" (").append(huntHighCount).append(" High)");
                if (huntMediumCount > 0) sb.append(" (").append(huntMediumCount).append(" Medium)");
                if (huntLowCount > 0) sb.append(" (").append(huntLowCount).append(" Low)");
                sb.append(" — Click to view");
                return sb.toString();
            case ERROR:
                return "Last hunt incomplete — " + (huntErrorCode.isEmpty() ? "UNKNOWN_ERROR" : huntErrorCode) + " — Click to retry";
            case STALE:
                return "New requests captured since last hunt — re-hunt recommended";
            default:
                return "Unknown hunt status";
        }
    }

    /**
     * Reset this endpoint for a re-hunt: clears probe results and sets status to RUNNING.
     * Old findings in ResultMatrix are NOT deleted.
     */
    public void resetForReHunt() {
        // Clear probe data
        probes.clear();
        // Reset hunt counters
        huntFindingCount = 0;
        huntCriticalCount = 0;
        huntHighCount = 0;
        huntMediumCount = 0;
        huntLowCount = 0;
        huntErrorCode = "";
        huntProbesCompleted = 0;
        huntProbesTotal = 0;
        harvestDeltaCount = 0;
        huntStatus = HuntStatus.RUNNING;
    }

    /**
     * After hunt completes, set the final hunt status based on finding counts.
     */
    public void finalizeHuntStatus() {
        lastHuntTime = System.currentTimeMillis();
        if (!huntErrorCode.isEmpty()) {
            huntStatus = HuntStatus.ERROR;
        } else if (huntCriticalCount > 0) {
            huntStatus = HuntStatus.FINDING_CRITICAL;
        } else if (huntHighCount > 0) {
            huntStatus = HuntStatus.FINDING_HIGH;
        } else if (huntMediumCount > 0) {
            huntStatus = HuntStatus.FINDING_MEDIUM;
        } else if (huntLowCount > 0) {
            huntStatus = HuntStatus.FINDING_LOW;
        } else {
            huntStatus = HuntStatus.CLEAN;
        }
    }

    /**
     * Increment finding count by severity during hunt.
     */
    public void addHuntFinding(String severity) {
        huntFindingCount++;
        if (severity == null) return;
        switch (severity.toUpperCase()) {
            case "CRITICAL": huntCriticalCount++; break;
            case "HIGH": huntHighCount++; break;
            case "MEDIUM": huntMediumCount++; break;
            case "LOW": case "INFO": huntLowCount++; break;
        }
    }

    // ===== Standard Getters & Setters =====
    public String getId() { return id; }
    public void setId(String id) { if(evidenceFrozen && !Objects.equals(this.id,id))throw new IllegalArgumentException("Capture ID is immutable");this.id = id; }
    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }
    public String getOriginalUrl() { return originalUrl; }
    public void setOriginalUrl(String originalUrl) { this.originalUrl = originalUrl; }
    public String getNormalizedPath() { return normalizedPath; }
    public void setNormalizedPath(String normalizedPath) { this.normalizedPath = normalizedPath; }
    public String getActorId() { return actorId; }
    public void setActorId(String actorId) { this.actorId = actorId; }
    public String getResourceOwnerActorId() { return resourceOwnerActorId; }
    public void setResourceOwnerActorId(String value) {
        if(resourceOwnerActorId!=null && !Objects.equals(resourceOwnerActorId,value))throw new IllegalArgumentException("Resource ownership must be reconciled explicitly by creating a new record");
        resourceOwnerActorId=value;
        resourceOwnerConfirmed=value!=null && !value.isBlank();
    }
    public boolean isResourceOwnerConfirmed() { return resourceOwnerConfirmed; }
    public AccessPolicy getAccessPolicy() { return accessPolicy==null?AccessPolicy.UNKNOWN:accessPolicy; }
    public void setAccessPolicy(AccessPolicy value) { accessPolicy=value==null?AccessPolicy.UNKNOWN:value; }
    public String getResourceType() { return resourceType; }
    public void setResourceType(String value) { resourceType=value==null||value.isBlank()?"unknown":value; }
    public String getResourceId() { return resourceId; }
    public String getTenantId() { return tenantId; }
    public void setTenantId(String value) { tenantId = value; }
    public void setResourceId(String value) { resourceId=value; }
    public OperationSafety getOperationSafety() { return operationSafety==null?OperationSafety.UNKNOWN:operationSafety; }
    public void setOperationSafety(OperationSafety value) { operationSafety=value==null?OperationSafety.UNKNOWN:value; }
    public String getOperationSafetyReason() { return operationSafetyReason; }
    public void setOperationSafetyReason(String value) { operationSafetyReason=value==null||value.isBlank()?null:value.trim(); }
    public boolean isOperationApproved() { return operationApproved; }
    public void setOperationApproved(boolean value) { operationApproved=value; }
    public long getCapturedAtEpochMs() { return capturedAtEpochMs; }
    public void setCapturedAtEpochMs(long value) { if(value<0)throw new IllegalArgumentException("Invalid capture time");capturedAtEpochMs=value; }
    public burp.api.montoya.http.message.requests.HttpRequest getOriginalRequest() { return originalRequest; }
    public void setOriginalRequest(burp.api.montoya.http.message.requests.HttpRequest originalRequest) {
        byte[] bytes=originalRequest!=null?originalRequest.toByteArray().getBytes():null;
        requireSameEvidence(originalRequestBytes,bytes);
        this.originalRequest = originalRequest;
        this.originalRequestBytes = bytes==null?null:bytes.clone();
    }
    public burp.api.montoya.http.message.responses.HttpResponse getOriginalResponse() { return originalResponse; }
    public void setOriginalResponse(burp.api.montoya.http.message.responses.HttpResponse originalResponse) {
        byte[] bytes=originalResponse!=null?originalResponse.toByteArray().getBytes():null;
        requireSameEvidence(originalResponseBytes,bytes);
        this.originalResponse = originalResponse;
        this.originalResponseBytes = bytes==null?null:bytes.clone();
    }
    public byte[] getOriginalRequestBytes() { return originalRequestBytes==null?null:originalRequestBytes.clone(); }
    public void setOriginalRequestBytes(byte[] bytes) {requireSameEvidence(originalRequestBytes,bytes);this.originalRequestBytes=bytes==null?null:bytes.clone();}
    public byte[] getOriginalResponseBytes() { return originalResponseBytes==null?null:originalResponseBytes.clone(); }
    public void setOriginalResponseBytes(byte[] bytes) {requireSameEvidence(originalResponseBytes,bytes);this.originalResponseBytes=bytes==null?null:bytes.clone();}
    public void restoreTransientMessages() {
        try {
            if (originalRequest == null && originalRequestBytes != null) {
                originalRequest = burp.api.montoya.http.message.requests.HttpRequest.httpRequest(burp.api.montoya.core.ByteArray.byteArray(originalRequestBytes));
            }
        } catch (Exception ignored) {}
        try {
            if (originalResponse == null && originalResponseBytes != null) {
                originalResponse = burp.api.montoya.http.message.responses.HttpResponse.httpResponse(burp.api.montoya.core.ByteArray.byteArray(originalResponseBytes));
            }
        } catch (Exception ignored) {}
    }
    public String getClassificationLabel() { return classificationLabel; }
    public void setClassificationLabel(String label) { this.classificationLabel = label; }
    
    public int getPriorityScore() { return priorityScore; }
    public void setPriorityScore(int score) { this.priorityScore = score; }
    
    public int getConfidenceScore() { return confidenceScore; }
    public void setConfidenceScore(int score) { this.confidenceScore = score; }
    
    public String getSubLabel() { return subLabel; }
    public void setSubLabel(String subLabel) { this.subLabel = subLabel; }

    public String getPerpetratorId() { return perpetratorId; }
    public void setPerpetratorId(String id) { this.perpetratorId = id; }

    public List<String> getSegments() { return segments; }
    public void setSegments(List<String> segments) { this.segments = segments; }
    public boolean isPriority() { return isPriority; }
    public void setPriority(boolean isPriority) { this.isPriority = isPriority; }
    public List<ProbeResult> getProbes() { return probes; }
    public void setProbes(List<ProbeResult> probes) { this.probes = new java.util.concurrent.CopyOnWriteArrayList<>(probes); }

    // Hunt status
    public HuntStatus getHuntStatus() { return huntStatus; }
    public void setHuntStatus(HuntStatus huntStatus) { this.huntStatus = huntStatus; }
    public long getLastHuntTime() { return lastHuntTime; }
    public void setLastHuntTime(long lastHuntTime) { this.lastHuntTime = lastHuntTime; }
    public int getHuntFindingCount() { return huntFindingCount; }
    public void setHuntFindingCount(int huntFindingCount) { this.huntFindingCount = huntFindingCount; }
    public int getHuntCriticalCount() { return huntCriticalCount; }
    public int getHuntHighCount() { return huntHighCount; }
    public int getHuntMediumCount() { return huntMediumCount; }
    public int getHuntLowCount() { return huntLowCount; }
    public String getHuntErrorCode() { return huntErrorCode; }
    public void setHuntErrorCode(String huntErrorCode) { this.huntErrorCode = huntErrorCode; }
    public long getLastTrafficTime() { return lastTrafficTime; }
    public void setLastTrafficTime(long lastTrafficTime) { this.lastTrafficTime = lastTrafficTime; }
    public int getHuntProbesCompleted() { return huntProbesCompleted; }
    public void setHuntProbesCompleted(int huntProbesCompleted) { this.huntProbesCompleted = huntProbesCompleted; }
    public int getHuntProbesTotal() { return huntProbesTotal; }
    public void setHuntProbesTotal(int huntProbesTotal) { this.huntProbesTotal = huntProbesTotal; }
    public int getHarvestIdCountAtLastHunt() { return harvestIdCountAtLastHunt; }
    public void setHarvestIdCountAtLastHunt(int harvestIdCountAtLastHunt) { this.harvestIdCountAtLastHunt = Math.max(0, harvestIdCountAtLastHunt); }
    public int getHarvestDeltaCount() { return harvestDeltaCount; }
    public void setHarvestDeltaCount(int harvestDeltaCount) {
        this.harvestDeltaCount = Math.max(0, harvestDeltaCount);
        this.harvestDeltaLastUpdated = System.currentTimeMillis();
    }
    public long getHarvestDeltaLastUpdated() { return harvestDeltaLastUpdated; }
    public boolean hasHarvestDelta() { return harvestDeltaCount > 0; }
    
    public void addProbeResult(String actorName, int statusCode, int length, boolean isBaseline, byte[] request, byte[] response) {
        ProbeResult result=new ProbeResult(actorName,statusCode,length,isBaseline,request,response);
        if(isBaseline && actorId!=null && !actorId.isBlank()) {
            result.identityType=ProbeIdentity.BASELINE;result.actorId=actorId;
        }
        // Legacy name-only evidence remains unresolved, never guessed or merged by display name.
        this.probes.add(result);
    }

    public void addActorProbeResult(String actorId,String actorName,int status,int length,byte[] request,byte[] response) {
        if(actorId!=null && actorId.isBlank())throw new IllegalArgumentException("Replay actor identity is empty");
        ProbeIdentity type=actorId==null?ProbeIdentity.ANONYMOUS:ProbeIdentity.ACTOR;
        ProbeResult result=new ProbeResult(actorName,status,length,false,request,response);
        result.actorId=actorId;result.identityType=type;
        probes.add(result);
    }

    public ProbeResult getProbeByActor(String actorName) {
        return probes.stream().filter(p -> p.actorName.equals(actorName)).findFirst().orElse(null);
    }

    public ProbeState getProbeState(String actorName) {
        ProbeResult result = getProbeByActor(actorName);
        if (result == null) return ProbeState.MISSING;
        
        if (result.statusCode == 401 || result.statusCode == 403 || result.statusCode <= 0) {
            return ProbeState.STALE;
        }
        return ProbeState.COMPLETE;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CapturedEndpoint that = (CapturedEndpoint) o;
        return method.equals(that.method) &&
               normalizedPath.equals(that.normalizedPath) &&
               actorId.equals(that.actorId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method, normalizedPath, actorId);
    }
}
