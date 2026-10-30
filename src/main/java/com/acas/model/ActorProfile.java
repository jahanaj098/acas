package com.acas.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class ActorProfile {
    private String id;
    private String name;
    private String role;
    private List<String[]> headers; // [name, value] pairs
    private String savedAt;
    private String capturedFrom;
    private String identitySourceUrl;
    private String identityLookupStatus = "Not checked";
    private String recognisedAccount;
    private String recognisedAccountSignature;
    public String getRecognisedAccount(){return recognisedAccount;}
    public String getRecognisedAccountSignature(){return recognisedAccountSignature;}
    public void setRecognisedAccount(String value,String signature){recognisedAccount=value;recognisedAccountSignature=signature;}
    private java.util.Map<String,String> automaticIdentityProofs = new java.util.concurrent.ConcurrentHashMap<>();
    public String getIdentitySourceUrl(){return identitySourceUrl;}
    public void setIdentitySourceUrl(String url){identitySourceUrl=url;}
    public String getIdentityLookupStatus(){return identityLookupStatus==null?"Not checked":identityLookupStatus;}
    public void setIdentityLookupStatus(String status){identityLookupStatus=status;if(!"Identity recognized".equals(status)){recognisedAccount=null;recognisedAccountSignature=null;}}
    public synchronized java.util.Map<String,String> getAutomaticIdentityProofs(){if(automaticIdentityProofs==null)automaticIdentityProofs=new java.util.concurrent.ConcurrentHashMap<>();else if(!(automaticIdentityProofs instanceof java.util.concurrent.ConcurrentMap))automaticIdentityProofs=new java.util.concurrent.ConcurrentHashMap<>(automaticIdentityProofs);return automaticIdentityProofs;}
    private boolean isRecording = true;
    private List<HistoryEntry> captureHistory;
    private VerificationStatus verificationStatus = VerificationStatus.UNKNOWN;
    private String color = "#6366f1"; // Default ACAS Indigo
    private String pwnfoxColor;
    private int lastStatusCode = 200;
    private int roleLevel = 1; // 0=Anon, 1=User, 2=Privileged, 3=Admin, 4=Super
    private boolean autoProbeEnabled = true;

    public enum VerificationStatus {
        VERIFIED,
        EXPIRED,
        UNVERIFIED,
        UNKNOWN
    }

    public static class HistoryEntry {
        public final String request;
        public final String response;
        public final String method;
        public final String url;
        public final int status;
        public final int length;

        public HistoryEntry(String request, String response, String method, String url, int status, int length) {
            this.request = request;
            this.response = response;
            this.method = method;
            this.url = url;
            this.status = status;
            this.length = length;
        }
    }

    public ActorProfile() {
        this.id = UUID.randomUUID().toString();
        this.savedAt = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        this.headers = new ArrayList<>();
        this.captureHistory = new java.util.concurrent.CopyOnWriteArrayList<>();
    }

    public ActorProfile(String name, String role, List<String[]> headers, String capturedFrom) {
        this();
        this.name = name;
        this.role = role;
        this.headers = headers;
        this.capturedFrom = capturedFrom;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
    public List<String[]> getHeaders() { return headers; }
    public void setHeaders(List<String[]> headers) { this.headers = headers; }
    public String getSavedAt() { return savedAt; }
    public void setSavedAt(String savedAt) { this.savedAt = savedAt; }
    public String getCapturedFrom() { return capturedFrom; }
    public void setCapturedFrom(String capturedFrom) { this.capturedFrom = capturedFrom; }

    public int getRoleLevel() { return roleLevel; }
    public void setRoleLevel(int roleLevel) { this.roleLevel = roleLevel; }

    /**
     * Privilege ladder shown in the Save Actor dialogs, ordered low → high.
     * The index into this array IS the roleLevel the engines compare against
     * (0=Anonymous … 4=Super Admin).
     */
    public static final String[] ROLE_OPTIONS = {
        "Anonymous", "User", "Privileged", "Admin", "Super Admin"
    };

    /**
     * Maps a role label (from the dropdown, persisted data, or legacy values)
     * to its numeric privilege level. Lower number = lower privilege.
     * Unknown labels fall back to User (1).
     */
    public static int levelForRole(String role) {
        if (role == null) return 1;
        switch (role.trim().toLowerCase()) {
            case "anonymous":
            case "anon":
            case "guest":
                return 0;
            case "user":
            case "custom":
                return 1;
            case "privileged":
            case "manager":
            case "staff":
                return 2;
            case "admin":
            case "administrator":
                return 3;
            case "super admin":
            case "superadmin":
            case "super":
            case "root":
            case "superuser":
                return 4;
            default:
                return 1;
        }
    }

    /** Convenience: keep role string and numeric level in sync from one label. */
    public void setRoleWithLevel(String role) {
        this.role = role;
        this.roleLevel = levelForRole(role);
    }

    /**
     * Heals profiles saved before privilege levels were wired to the dropdown,
     * where every actor was persisted at the default level 1. Only upgrades a
     * still-default level to the level its role label implies; never downgrades.
     */
    public void migrateLegacyRoleLevel() {
        int derived = levelForRole(this.role);
        if (this.roleLevel <= 1 && derived > 1) {
            this.roleLevel = derived;
        }
    }
    
    public boolean isAutoProbeEnabled() { return autoProbeEnabled; }
    public void setAutoProbeEnabled(boolean enabled) { this.autoProbeEnabled = enabled; }

    public List<HistoryEntry> getCaptureHistory() { return captureHistory; }
    public void setCaptureHistory(List<HistoryEntry> captureHistory) { this.captureHistory = new java.util.concurrent.CopyOnWriteArrayList<>(captureHistory); }
    
    public boolean isRecording() { return isRecording; }
    public void setRecording(boolean recording) { isRecording = recording; }
    
    public VerificationStatus getVerificationStatus() { return verificationStatus; }
    public void setVerificationStatus(VerificationStatus verificationStatus) { this.verificationStatus = verificationStatus; }
    
    public String getColor() {
        String mapped = com.acas.util.PwnFoxColors.hex(getPwnfoxColor());
        return mapped != null ? mapped : color;
    }
    public void setColor(String color) { this.color = color; }
    public String getPwnfoxColor() {
        String saved = com.acas.util.PwnFoxColors.name(pwnfoxColor);
        return saved != null ? saved : com.acas.util.PwnFoxColors.fromRequest(capturedFrom);
    }
    public void setPwnfoxColor(String value) {
        String name = com.acas.util.PwnFoxColors.name(value);
        if (name != null) {
            pwnfoxColor = name;
            color = com.acas.util.PwnFoxColors.hex(name);
        }
    }
    
    public int getLastStatusCode() { return lastStatusCode; }
    public void setLastStatusCode(int lastStatusCode) { this.lastStatusCode = lastStatusCode; }
    
    public void addHistory(String requestData, String responseData, String method, String url, int status, int length) {
        // Surgical De-duplication: check against the last 2 entries
        int historySize = captureHistory.size();
        for (int i = Math.max(0, historySize - 2); i < historySize; i++) {
            HistoryEntry entry = captureHistory.get(i);
            if (entry.method.equals(method) && entry.url.equals(url) && entry.status == status && entry.length == length) {
                return; // Skip duplicate
            }
        }
        
        if (captureHistory.size() >= 100) captureHistory.remove(0);
        this.lastStatusCode = status;
        captureHistory.add(new HistoryEntry(requestData, responseData, method, url, status, length));
    }

    @Override
    public String toString() { return name + " (" + role + ")"; }

    public boolean hasCredentials() {
        return headers != null && !headers.isEmpty();
    }
}
