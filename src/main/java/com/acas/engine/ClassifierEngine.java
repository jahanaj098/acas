package com.acas.engine;

import com.acas.model.ActorProfile;
import com.acas.model.CapturedEndpoint;
import com.acas.util.FieldDiffUtils;
import com.acas.util.HttpUtils;
import burp.api.montoya.MontoyaApi;

import java.util.*;

public class ClassifierEngine {

    private final ResponseComparator responseComparator = new ResponseComparator();

    public ClassifierEngine(MontoyaApi api) {
    }

    /**
     * The Main Brain: Classifies an endpoint by evaluating every probe in the matrix.
     */
    public void classify(CapturedEndpoint ep, List<ActorProfile> allActors) {
        List<CapturedEndpoint.ProbeResult> probes = ep.getProbes();
        if (probes.isEmpty()) {
            ep.setClassificationLabel("PENDING");
            return;
        }

        // 1. Calculate Priority (Target Value)
        int priority = calculatePriority(ep);
        ep.setPriorityScore(priority);

        // 2. Identify Baseline (Actor A)
        CapturedEndpoint.ProbeResult baseline = probes.stream().filter(p -> p.isBaseline).findFirst().orElse(null);
        
        // 3. Evaluate each probe
        String bestLabel = "PRIVATE_SECURE";
        ActorProfile owner = findActorById(allActors, ep.getActorId());

        boolean baselineOk = baseline != null && baseline.response != null
                && baseline.statusCode >= 200 && baseline.statusCode < 300;
        boolean unresolved = false;

        for (CapturedEndpoint.ProbeResult pr : probes) {
            if (pr.isBaseline) {
                pr.verdict = "OWNER";
                continue;
            }

            boolean anon = pr.identityType==CapturedEndpoint.ProbeIdentity.ANONYMOUS && pr.actorId==null;
            ActorProfile perpetrator = pr.identityType==CapturedEndpoint.ProbeIdentity.ACTOR ? findActorById(allActors, pr.actorId) : null;
            if (!anon && perpetrator == null) {
                pr.verdict = "UNCERTAIN";
                pr.leakedFields = "---";
                unresolved = true;
                continue;
            }
            if (pr.response == null || pr.statusCode <= 0) {
                pr.verdict = "UNCERTAIN";
                pr.leakedFields = "---";
                unresolved = true;
                continue;
            }

            // Session-health heuristic: 401 means the replayed session is not
            // authenticated at all → that actor's session is likely expired.
            // 403 (authenticated-but-forbidden) and any 2xx mean the session works.
            if (!anon && perpetrator != null && baselineOk) {
                if (pr.statusCode == 401) {
                    perpetrator.setVerificationStatus(ActorProfile.VerificationStatus.EXPIRED);
                } else if ((pr.statusCode >= 200 && pr.statusCode < 300) || pr.statusCode == 403) {
                    perpetrator.setVerificationStatus(ActorProfile.VerificationStatus.VERIFIED);
                }
            }

            boolean success = pr.statusCode >= 200 && pr.statusCode < 300;

            double similarity = 0;
            if (baseline != null && baseline.response != null && pr.response != null) {
                // Semantic body similarity (JSON shape + stable fields) rather than raw
                // byte-length, which is fooled by timestamps and CSRF tokens.
                String baseBody = ResponseComparator.responseBody(new String(baseline.response, java.nio.charset.StandardCharsets.UTF_8));
                String probeBody = ResponseComparator.responseBody(new String(pr.response, java.nio.charset.StandardCharsets.UTF_8));
                similarity = responseComparator.semanticSimilarity(baseBody, probeBody);
            }

            boolean ownerData = baseline != null && baseline.response != null && pr.response != null
                && responseComparator.hasOwnerDataEvidence(
                    new String(baseline.response, java.nio.charset.StandardCharsets.UTF_8),
                    new String(pr.response, java.nio.charset.StandardCharsets.UTF_8));
            // A successful write alone does not establish whose data changed.
            boolean broken = baselineOk && success && ownerData && similarity > 0.85;

            if (broken) {
                pr.verdict = "BROKEN";
                pr.leakedFields = FieldDiffUtils.findLeakedFields(baseline != null ? baseline.response : null, pr.response);

                String currentLabel = anon ? "ANON_BROKEN" : determineLabel(perpetrator, owner);
                if (getSeverityRank(currentLabel) > getSeverityRank(bestLabel)) {
                    bestLabel = currentLabel;
                }
            } else {
                pr.verdict = success ? "ACCESSIBLE" : "BLOCKED";
                pr.leakedFields = "---";
            }
        }

        // Baseline sanity: if the owner couldn't even access the endpoint, we can't
        // honestly call it secure — flag it for manual review instead.
        if ("PRIVATE_SECURE".equals(bestLabel) && (!baselineOk || unresolved)) {
            bestLabel = "UNCERTAIN";
        }

        ep.setClassificationLabel(bestLabel);
    }

    private String determineLabel(ActorProfile perpetrator, ActorProfile owner) {
        if (perpetrator.getRoleLevel() == 0) return "ANON_BROKEN";
        if (owner == null) return "HORIZ_BROKEN";
        
        if (perpetrator.getRoleLevel() < owner.getRoleLevel()) {
            return "PRIV_ESC_BROKEN";
        }
        return "HORIZ_BROKEN";
    }

    private int calculatePriority(CapturedEndpoint ep) {
        int score = 40; 
        String method = ep.getMethod();
        String path = ep.getNormalizedPath().toLowerCase();

        if ("DELETE".equals(method)) score += 15;
        if ("PUT".equals(method) || "PATCH".equals(method)) score += 10;
        if ("POST".equals(method)) score += 5;

        if (path.contains("admin")) score += 15;
        if (path.contains("user") || path.contains("profile")) score += 5;
        if (path.contains("order") || path.contains("data")) score += 5;
        if (path.contains("internal") || path.contains("secret")) score += 15;

        if (containsId(ep.getOriginalUrl())) score += 5;

        return Math.min(100, score);
    }

    private int getSeverityRank(String label) {
        if (label == null) return 0;
        switch (label) {
            case "ANON_BROKEN": return 5;
            case "PRIV_ESC_BROKEN": return 4;
            case "HORIZ_BROKEN": return 3;
            case "UNCERTAIN": return 2;
            case "PRIVATE_SECURE": return 1;
            case "PUBLIC": return 1;
            default: return 2;
        }
    }

    public void promote(CapturedEndpoint ep, List<ActorProfile> actors) {
        // Current evidence can invalidate an older positive result.
        classify(ep, actors);
    }

    private boolean containsId(String input) {
        if (input == null) return false;
        return input.matches(".*[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}.*") || 
               input.matches(".*\\d{3,}.*");
    }

    private ActorProfile findActorById(List<ActorProfile> actors, String id) {
        return actors.stream().filter(a -> a.getId().equals(id)).findFirst().orElse(null);
    }

    private ActorProfile findActorByName(List<ActorProfile> actors, String name) {
        return actors.stream().filter(a -> a.getName().equals(name)).findFirst().orElse(null);
    }
}
