package com.acas.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

public class AcasFinding {
    private String id;
    private String timestamp;
    private String source; // "Hunt Hub" or "Passive Probe"
    private String severity; // CRITICAL, HIGH, MEDIUM, LOW, INFO
    private String label; // VULNERABLE, DATA_LEAK, PARTIAL_BYPASS, etc.
    private String mutationType;
    private String mutationDescription;
    
    // Who
    private String ownerActorName;
    private String replayerActorName;
    private String captureActorId;
    private String resourceOwnerActorId;
    private String replayActorId;
    private String captureId;
    private String resourceRef;
    private java.util.List<String> evidenceRecordIds;
    private boolean isReplayed;
    
    // What
    private String method;
    private String url;
    private String endpointPattern;
    
    // Proof (Base)
    private byte[] baseRequest;
    private byte[] baseResponse;
    private int baseStatus;
    private int baseLength;

    // Proof (Anonymous)
    private byte[] anonymousRequest;
    private byte[] anonymousResponse;
    private int anonymousStatus;
    private int anonymousLength;
    
    // Proof (Replay)
    private byte[] mutatedRequest;
    private byte[] mutatedResponse;
    private int mutatedStatus;
    private int mutatedLength;
    
    // Analysis
    private double sizeSimilarity; // 0.0 to 1.0
    private String analysisNote;

    // False-positive analysis
    private int confidenceScore; // 0-100
    private String fpReason;
    private boolean confirmedByDiff;
    private boolean matchesAnonymous;
    private boolean matchesInvalidId;
    private boolean containsOwnerData;
    private double similarityToOwner;
    private double similarityToAnon;
    private double similarityToInvalid;
    private long baselineCapturedAtEpochMs;

    public AcasFinding() {
        this.id = UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    // Getters & Setters
    public String getId() { return id; }
    public String getTimestamp() { return timestamp; }
    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    public String getLabel() { return label; }
    public void setLabel(String label) { this.label = label; }
    public String getMutationType() { return mutationType; }
    public void setMutationType(String mutationType) { this.mutationType = mutationType; }
    public String getMutationDescription() { return mutationDescription; }
    public void setMutationDescription(String mutationDescription) { this.mutationDescription = mutationDescription; }
    public String getOwnerActorName() { return ownerActorName; }
    public void setOwnerActorName(String ownerActorName) { this.ownerActorName = ownerActorName; }
    public String getReplayerActorName() { return replayerActorName; }
    public void setReplayerActorName(String replayerActorName) { this.replayerActorName = replayerActorName; }
    public String getCaptureActorId() { return captureActorId; }
    public void setCaptureActorId(String value) { captureActorId = value; }
    public String getResourceOwnerActorId() { return resourceOwnerActorId; }
    public void setResourceOwnerActorId(String value) { resourceOwnerActorId = value; }
    public String getReplayActorId() { return replayActorId; }
    public void setReplayActorId(String value) { replayActorId = value; }
    public String getCaptureId() { return captureId; }
    public void setCaptureId(String value) { captureId = value; }
    public String getResourceRef() { return resourceRef; }
    public void setResourceRef(String value) { resourceRef = value; }
    public java.util.List<String> getEvidenceRecordIds() { return evidenceRecordIds; }
    public void setEvidenceRecordIds(java.util.List<String> value) { evidenceRecordIds = value; }
    public boolean isReplayed() { return isReplayed; }
    public void setReplayed(boolean replayed) { isReplayed = replayed; }
    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public String getEndpointPattern() { return endpointPattern; }
    public void setEndpointPattern(String endpointPattern) { this.endpointPattern = endpointPattern; }
    public byte[] getBaseRequest() { return baseRequest; }
    public void setBaseRequest(byte[] baseRequest) { this.baseRequest = baseRequest; }
    public byte[] getBaseResponse() { return baseResponse; }
    public void setBaseResponse(byte[] baseResponse) { this.baseResponse = baseResponse; }
    public int getBaseStatus() { return baseStatus; }
    public void setBaseStatus(int baseStatus) { this.baseStatus = baseStatus; }
    public int getBaseLength() { return baseLength; }
    public void setBaseLength(int baseLength) { this.baseLength = baseLength; }
    public byte[] getAnonymousRequest() { return anonymousRequest; }
    public void setAnonymousRequest(byte[] anonymousRequest) { this.anonymousRequest = anonymousRequest; }
    public byte[] getAnonymousResponse() { return anonymousResponse; }
    public void setAnonymousResponse(byte[] anonymousResponse) { this.anonymousResponse = anonymousResponse; }
    public int getAnonymousStatus() { return anonymousStatus; }
    public void setAnonymousStatus(int anonymousStatus) { this.anonymousStatus = anonymousStatus; }
    public int getAnonymousLength() { return anonymousLength; }
    public void setAnonymousLength(int anonymousLength) { this.anonymousLength = anonymousLength; }
    public byte[] getMutatedRequest() { return mutatedRequest; }
    public void setMutatedRequest(byte[] mutatedRequest) { this.mutatedRequest = mutatedRequest; }
    public byte[] getMutatedResponse() { return mutatedResponse; }
    public void setMutatedResponse(byte[] mutatedResponse) { this.mutatedResponse = mutatedResponse; }
    public int getMutatedStatus() { return mutatedStatus; }
    public void setMutatedStatus(int mutatedStatus) { this.mutatedStatus = mutatedStatus; }
    public int getMutatedLength() { return mutatedLength; }
    public void setMutatedLength(int mutatedLength) { this.mutatedLength = mutatedLength; }
    public double getSizeSimilarity() { return sizeSimilarity; }
    public void setSizeSimilarity(double sizeSimilarity) { this.sizeSimilarity = sizeSimilarity; }
    public String getAnalysisNote() { return analysisNote; }
    public void setAnalysisNote(String analysisNote) { this.analysisNote = analysisNote; }

    public int getConfidenceScore() { return confidenceScore; }
    public void setConfidenceScore(int confidenceScore) { this.confidenceScore = confidenceScore; }
    public String getFpReason() { return fpReason; }
    public void setFpReason(String fpReason) { this.fpReason = fpReason; }
    public boolean isConfirmedByDiff() { return confirmedByDiff; }
    public void setConfirmedByDiff(boolean confirmedByDiff) { this.confirmedByDiff = confirmedByDiff; }
    public boolean isMatchesAnonymous() { return matchesAnonymous; }
    public void setMatchesAnonymous(boolean matchesAnonymous) { this.matchesAnonymous = matchesAnonymous; }
    public boolean isMatchesInvalidId() { return matchesInvalidId; }
    public void setMatchesInvalidId(boolean matchesInvalidId) { this.matchesInvalidId = matchesInvalidId; }
    public boolean isContainsOwnerData() { return containsOwnerData; }
    public void setContainsOwnerData(boolean containsOwnerData) { this.containsOwnerData = containsOwnerData; }
    public double getSimilarityToOwner() { return similarityToOwner; }
    public void setSimilarityToOwner(double similarityToOwner) { this.similarityToOwner = similarityToOwner; }
    public double getSimilarityToAnon() { return similarityToAnon; }
    public void setSimilarityToAnon(double similarityToAnon) { this.similarityToAnon = similarityToAnon; }
    public double getSimilarityToInvalid() { return similarityToInvalid; }
    public void setSimilarityToInvalid(double similarityToInvalid) { this.similarityToInvalid = similarityToInvalid; }
    public long getBaselineCapturedAtEpochMs() { return baselineCapturedAtEpochMs; }
    public void setBaselineCapturedAtEpochMs(long baselineCapturedAtEpochMs) { this.baselineCapturedAtEpochMs = baselineCapturedAtEpochMs; }
}
