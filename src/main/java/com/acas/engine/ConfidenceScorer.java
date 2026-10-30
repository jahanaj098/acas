package com.acas.engine;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.acas.model.AcasFinding;

public class ConfidenceScorer {
    private final ResponseComparator comparator = new ResponseComparator();

    public int score(AcasFinding finding,
                     ResponseComparator.Verdict verdict,
                     HttpResponse probeResponse,
                     HttpResponse ownerBaseline,
                     HttpResponse anonymousBaseline) {
        int score = 0;

        switch (verdict) {
            case TRUE_POSITIVE: score += 60; break;
            case LIKELY_TRUE: score += 35; break;
            case NEEDS_MANUAL_REVIEW: score += 15; break;
            case LIKELY_FALSE:
            case FALSE_POSITIVE:
            default: score += 0; break;
        }

        if (score == 0 || probeResponse == null) {
            return 0;
        }

        int status = probeResponse.statusCode();
        if (status == 200) score += 15;
        if (status == 201) score += 10;
        if (status == 206) score += 10;

        if (ownerBaseline != null) {
            int probeLen = probeResponse.body().length();
            int ownerLen = ownerBaseline.body().length();
            if (Math.abs(probeLen - ownerLen) < 100) score += 10;
        }

        String body = probeResponse.bodyToString() != null ? probeResponse.bodyToString().toLowerCase() : "";
        if (body.contains("@")) score += 5;
        if (body.contains("password")) score += 10;
        if (body.contains("secret")) score += 10;
        if (body.contains("token")) score += 5;
        if (body.contains("private")) score += 5;

        String mutCode = finding != null ? finding.getMutationType() : null;
        if ("B5".equals(mutCode)) score += 10;
        if ("B1".equals(mutCode)) score += 8;
        if ("B15".equals(mutCode)) score += 8;
        if (mutCode != null && mutCode.startsWith("A")) score -= 5;

        if (anonymousBaseline != null) {
            double anonSimilarity = comparator.bodyEquality(probeResponse, anonymousBaseline);
            if (anonSimilarity > 0.7) score -= 40;
            else if (anonSimilarity > 0.5) score -= 20;
        }

        if (score < 0) score = 0;
        if (score > 100) score = 100;
        return score;
    }
}
