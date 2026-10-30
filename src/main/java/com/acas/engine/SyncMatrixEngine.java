package com.acas.engine;

import com.acas.model.ActorProfile;
import com.acas.model.CapturedEndpoint;
import java.util.ArrayList;
import java.util.List;

public class SyncMatrixEngine {

    public enum SyncMode {
        FILL_GAPS,      // only MISSING
        FORCE_REFRESH,  // MISSING + STALE + COMPLETE
        FIX_STALE       // only STALE
    }

    public static class SyncTask {
        public final CapturedEndpoint endpoint;
        public final ActorProfile actor;

        public SyncTask(CapturedEndpoint endpoint, ActorProfile actor) {
            this.endpoint = endpoint;
            this.actor = actor;
        }
    }

    public static class SyncPreview {
        public int missingCount = 0;
        public int staleCount = 0;
        public int completeCount = 0;
        public int willProbeCount = 0;

        public SyncPreview(int missing, int stale, int complete, int willProbe) {
            this.missingCount = missing;
            this.staleCount = stale;
            this.completeCount = complete;
            this.willProbeCount = willProbe;
        }
    }

    public List<SyncTask> buildQueue(
            List<CapturedEndpoint> endpoints,
            List<ActorProfile> actors,
            SyncMode mode,
            boolean onlySelected,
            List<String> selectedEndpointIds) {

        List<SyncTask> tasks = new ArrayList<>();

        for (CapturedEndpoint ep : endpoints) {
            // Apply Scope Filter
            if (onlySelected && !selectedEndpointIds.contains(ep.getId())) continue;

            for (ActorProfile actor : actors) {
                // Skip if this actor is the owner of the endpoint
                if (actor.getId().equals(ep.getActorId())) continue;

                CapturedEndpoint.ProbeState state = ep.getProbeState(actor.getName());

                boolean shouldProbe = false;
                switch (mode) {
                    case FILL_GAPS:
                        shouldProbe = state == CapturedEndpoint.ProbeState.MISSING;
                        break;
                    case FORCE_REFRESH:
                        shouldProbe = true;
                        break;
                    case FIX_STALE:
                        shouldProbe = state == CapturedEndpoint.ProbeState.STALE;
                        break;
                }

                if (shouldProbe) {
                    tasks.add(new SyncTask(ep, actor));
                }
            }
        }

        // Sort by Priority Score Descending
        tasks.sort((a, b) -> Integer.compare(b.endpoint.getPriorityScore(), a.endpoint.getPriorityScore()));

        return tasks;
    }

    public SyncPreview calculatePreview(
            List<CapturedEndpoint> endpoints,
            List<ActorProfile> actors,
            SyncMode mode,
            boolean onlySelected,
            List<String> selectedEndpointIds) {

        int missing = 0, stale = 0, complete = 0, willProbe = 0;

        for (CapturedEndpoint ep : endpoints) {
            if (onlySelected && !selectedEndpointIds.contains(ep.getId())) continue;

            for (ActorProfile actor : actors) {
                if (actor.getId().equals(ep.getActorId())) continue;

                CapturedEndpoint.ProbeState state = ep.getProbeState(actor.getName());

                if (state == CapturedEndpoint.ProbeState.MISSING) missing++;
                else if (state == CapturedEndpoint.ProbeState.STALE) stale++;
                else if (state == CapturedEndpoint.ProbeState.COMPLETE) complete++;

                boolean wouldSync = false;
                switch (mode) {
                    case FILL_GAPS:
                        wouldSync = state == CapturedEndpoint.ProbeState.MISSING;
                        break;
                    case FORCE_REFRESH:
                        wouldSync = true;
                        break;
                    case FIX_STALE:
                        wouldSync = state == CapturedEndpoint.ProbeState.STALE;
                        break;
                }

                if (wouldSync) willProbe++;
            }
        }

        return new SyncPreview(missing, stale, complete, willProbe);
    }
}
