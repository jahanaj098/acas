package com.acas.engine;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.acas.model.ActorProfile;

public class DifferentialAnalyzer {
    private final ResponseComparator comparator = new ResponseComparator();

    public boolean isGenuineDataLeak(HttpResponse probeResponse,
                                     HttpResponse ownerBaseline,
                                     HttpResponse actorBaseline,
                                     ActorProfile actor,
                                     ObjectManager objectManager) {
        if (probeResponse == null) return false;
        String probeBody = probeResponse.bodyToString() != null ? probeResponse.bodyToString() : "";

        if (actor != null && objectManager != null) {
            for (ObjectManager.ObjectEntry obj : objectManager.getObjectsForActor(actor.getId())) {
                if (obj != null && obj.value != null && !obj.value.isBlank() && probeBody.contains(obj.value)) {
                    return true;
                }
            }
        }

        if (actorBaseline != null) {
            double sim = comparator.bodyEquality(probeResponse, actorBaseline);
            if (sim > 0.85) {
                return true;
            }
        }

        String lower = probeBody.toLowerCase();
        return lower.matches("(?s).*[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}.*")
            || lower.matches("(?s).*\\\"password\\\"\\s*:.*")
            || lower.matches("(?s).*\\\"secret\\\"\\s*:.*")
            || lower.matches("(?s).*\\\"private_key\\\"\\s*:.*")
            || lower.matches("(?s).*\\\"api_key\\\"\\s*:.*");
    }
}
