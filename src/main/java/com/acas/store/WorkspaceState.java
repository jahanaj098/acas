package com.acas.store;

import com.acas.model.AcasFinding;
import com.acas.model.ActorProfile;
import com.acas.model.CapturedEndpoint;
import java.util.ArrayList;
import java.util.List;

/**
 * WorkspaceState represents the complete persistent state of ACAS.
 * Can be serialized to/from JSON for save/load.
 */
public class WorkspaceState {
    public List<ActorProfile> actors = new ArrayList<>();
    public List<AcasFinding> findings = new ArrayList<>();
    public List<CapturedEndpoint> huntQueue = new ArrayList<>();
    public WorkspaceConfig config = new WorkspaceConfig();
    public long lastSaved = System.currentTimeMillis();

    public static class WorkspaceConfig {
        public int discardThreshold = 30;
        public int reviewThreshold = 60;
        public int autoConfirmThreshold = 90;
        public int baselineTtlMinutes = 5;
        
        public int rateLimitRps = 5;
        public int rateLimitRpm = 300;
        public int rateLimitMaxConcurrent = 2;
        public int rateLimitStopAfterMinutes = 0;
        public boolean rateLimitEnabled = true;
    }

    public WorkspaceState() {
    }

    public WorkspaceState(List<ActorProfile> actors, List<AcasFinding> findings, List<CapturedEndpoint> huntQueue) {
        this.actors = actors != null ? new ArrayList<>(actors) : new ArrayList<>();
        this.findings = findings != null ? new ArrayList<>(findings) : new ArrayList<>();
        this.huntQueue = huntQueue != null ? new ArrayList<>(huntQueue) : new ArrayList<>();
        this.lastSaved = System.currentTimeMillis();
    }

    @Override
    public String toString() {
        return "WorkspaceState{" +
                "actors=" + actors.size() +
                ", findings=" + findings.size() +
                ", huntQueue=" + huntQueue.size() +
                ", lastSaved=" + lastSaved +
                '}';
    }
}
