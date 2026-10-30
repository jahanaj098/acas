package com.acas.export;

import burp.api.montoya.MontoyaApi;
import com.acas.model.ActorProfile;
import com.acas.store.ActorStore;
import com.acas.util.CredentialPolicy;
import com.google.gson.*;
import java.util.*;

/** Credential-only handoff; never advances the request export ledger. */
public final class HermesSessionUpdate {
    public static final String FORMAT="acas-hermes-session-update-1";
    public static boolean isSession(HermesExport.Batch batch) {
        return batch.document().has("format") && FORMAT.equals(batch.document().get("format").getAsString());
    }
    public static HermesExport.Batch prepare(MontoyaApi api,ActorStore store,HermesExport.Ledger previous,String actorId) {
        ActorProfile actor=store.getActor(actorId);
        if(actor==null)throw new IllegalArgumentException("The selected actor no longer exists.");
        String mapped=previous.actorKeys.get(actorId);
        if(previous.lastBatchId==null || mapped==null || !previous.actorNames.containsKey(mapped))
            throw new IllegalArgumentException("Export this actor normally first. A session update must reuse an established Hermes actor identity.");
        if(previous.actorKeys.values().stream().filter(mapped::equals).count()!=1)
            throw new IllegalArgumentException("Ambiguous Hermes actor mapping; resolve it in export options first.");
        actor=HermesExport.JSON.fromJson(HermesExport.JSON.toJson(actor),ActorProfile.class);
        JsonObject data=ActorContract.serialize(store,actor,mapped);
        String origin=data.get("origin").getAsString();
        if(previous.actorOrigins==null || !origin.equals(previous.actorOrigins.get(mapped)))
            throw new IllegalArgumentException("Actor origin is not established by this export history; complete a new normal export or reconcile the actor binding");
        if(data.getAsJsonObject("credentialClassification").getAsJsonArray("session").isEmpty())
            throw new IllegalArgumentException("No session credentials found; configure custom credential names first");
        String stream;long revision;
        synchronized(HermesSessionUpdate.class) {
            String key="acas_hermes_session_revision_"+HermesExport.hash(previous.projectId+"\n"+mapped+"\n"+origin);
            String saved=api.persistence().preferences().getString(key);
            JsonObject counter=saved==null || saved.isBlank()?new JsonObject():JsonParser.parseString(saved).getAsJsonObject();
            stream=counter.has("stream")?counter.get("stream").getAsString():UUID.randomUUID().toString();
            revision=counter.has("revision")?Math.addExact(counter.get("revision").getAsLong(),1):1;
            counter.addProperty("stream",stream);counter.addProperty("revision",revision);
            api.persistence().preferences().setString(key,counter.toString());
        }
        String id=UUID.randomUUID().toString();
        JsonObject document=new JsonObject();document.addProperty("format",FORMAT);document.addProperty("schemaVersion",2);
        document.addProperty("batchId",id);document.addProperty("updateId",id);
        document.addProperty("projectId",previous.projectId);document.addProperty("previousBatchId",previous.lastBatchId);
        document.addProperty("mode","session_update");document.addProperty("createdAt",java.time.Instant.now().toString());
        document.addProperty("revisionStreamId",stream);document.addProperty("credentialRevision",revision);
        document.addProperty("objective","Refresh only this existing actor's credentials. Keep all captured requests and evidence. Retry only affected failed/pending tests within previously authorized scope; do not rerun completed tests or perform state-changing retries without permission.");
        document.add("actor",data);
        document.addProperty("applicationMode","replace_managed_credentials");
        document.addProperty("verificationNote","Snapshot of current ACAS status, not a new live validation. Credential revision indicates update ordering, not that the login is valid. Endpoint-bound CSRF/signatures may still need fresh requests.");
        document.addProperty("retryPolicy","Only failed/pending tests that used this actor as request identity or require this actor's refreshed control. Keep resource IDs, URLs and bodies. Remove previous managed credentials before applying new ones. Do not alter other actors or infer authorization from this file.");
        HermesSchemaValidator.validateSessionUpdate(document);
        var preview=new HermesExport.Preview(0,0,0,0,0,0,0,1,0,1,false,List.of(),List.of(),List.of(),List.of());
        return new HermesExport.Batch(id,document,HermesExport.readLedger(HermesExport.JSON.toJson(previous)),1,preview);
    }
}
