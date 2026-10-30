package com.acas.engine;

import com.acas.model.AcasFinding;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class DeduplicationFilter {
    private final Set<String> seenFindings = ConcurrentHashMap.newKeySet();

    public boolean isDuplicate(AcasFinding finding) {
        if (finding == null) return true;
        String mutation = finding.getMutationType() != null ? finding.getMutationType() : "-";
        String key = String.join("|",
            safe(finding.getEndpointPattern()),
            safe(finding.getReplayerActorName()),
            mutation,
            String.valueOf(finding.getMutatedStatus())
        );
        return !seenFindings.add(key);
    }

    public void clear() {
        seenFindings.clear();
    }

    private String safe(String v) {
        return v == null ? "-" : v;
    }
}
