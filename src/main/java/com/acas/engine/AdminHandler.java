package com.acas.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.acas.model.ActorProfile;
import com.acas.model.CapturedEndpoint;
import java.util.HashSet;
import java.util.Set;

public class AdminHandler {
    private final MontoyaApi api;
    private final ReplayEngine replayEngine;

    public AdminHandler(MontoyaApi api, ReplayEngine replayEngine) {
        this.api = api;
        this.replayEngine = replayEngine;
    }

    public static class AdminBaseline {
        public final HttpRequestResponse rr;
        public final HttpResponse response;
        public final Set<String> extraFields;
        public final boolean isolated;

        public AdminBaseline(HttpRequestResponse rr, Set<String> extraFields, boolean isolated) {
            this.rr = rr;
            this.response = rr.response();
            this.extraFields = extraFields;
            this.isolated = isolated;
        }
    }

    public AdminBaseline establishBaseline(CapturedEndpoint endpoint, ActorProfile admin, HttpResponse ownerResponse) {
        if (admin == null || ownerResponse == null) return null;

        HttpRequest adminReq = replayEngine.buildActorRequest(endpoint.getOriginalRequest(), admin);
        HttpRequestResponse rr = com.acas.engine.ReplayGate.send(api,adminReq);

        if (rr.response() == null) return null;

        int status = rr.response().statusCode();
        if (status == 403 || status == 404) {
            return new AdminBaseline(rr, new HashSet<>(), true);
        }

        // Identify extra fields in Admin response not present in Owner response
        Set<String> extraFields = identifyExtraFields(ownerResponse.bodyToString(), rr.response().bodyToString());
        return new AdminBaseline(rr, extraFields, false);
    }

    private Set<String> identifyExtraFields(String ownerBody, String adminBody) {
        Set<String> extra = new HashSet<>();
        // Simple logic: if admin body contains keywords not in owner body
        // In a real implementation, this would be a JSON diff
        String[] keywords = {"admin", "internal", "privileged", "role", "permission", "secret", "config", "debug"};
        for (String k : keywords) {
            if (adminBody.toLowerCase().contains(k) && !ownerBody.toLowerCase().contains(k)) {
                extra.add(k);
            }
        }
        return extra;
    }
}
