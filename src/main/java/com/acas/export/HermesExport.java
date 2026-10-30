package com.acas.export;

import com.acas.model.*;
import com.acas.store.ActorStore;
import com.acas.engine.SeverityClassifier;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Versioned, content-addressed handoff. A ledger records export, never execution. */
public final class HermesExport {
    public static final Gson JSON = new GsonBuilder().setPrettyPrinting().serializeNulls().create();
    public static class Ledger {
        public String format = "acas-hermes-ledger-1";
        public String projectId = UUID.randomUUID().toString();
        public String lastBatchId;
        public String actorManifestHash;
        public String contextHash;
        public Set<String> exported = new HashSet<>();
        public Map<String,String> actorKeys = new LinkedHashMap<>();
        public Map<String,String> actorNames = new LinkedHashMap<>();
        public Map<String,String> actorOrigins = new LinkedHashMap<>();
        public Map<String,String> actorCredentialHashes = new LinkedHashMap<>();
        public Map<String,String> responseSnapshots = new LinkedHashMap<>();
    }
    public record RequestDetail(String captureId,String actorId,String actorName,String method,String url,
                                boolean previousAvailable,String oldResponse,String newResponse) {
        public RequestDetail(String captureId,String actorId,String actorName,String method,String url) {
            this(captureId,actorId,actorName,method,url,false,null,null);
        }
    }
    public record Preview(int newRequests,int changedResults,int skippedRequests,int repeatedRequests,
                          int probeResults,int findings,int newActors,int updatedCredentials,int unknownCredentials,int totalActors,boolean contextChanged,
                          List<RequestDetail> newDetails,List<RequestDetail> changedDetails,List<RequestDetail> skippedDetails,List<RequestDetail> repeatedDetails) {
        public String description(){return "New requests: "+newRequests+"\nChanged responses for known requests: "+changedResults
            +"\nOld requests skipped: "+skippedRequests+"\nOld requests included again (full snapshot): "+repeatedRequests
            +"\nProbe result records included: "+probeResults+"\nFinding records included: "+findings
            +"\nNew actors: "+newActors+"\nActors with updated cookies/authentication: "+updatedCredentials
            +"\nActors without an earlier credential comparison: "+unknownCredentials
            +"\nTotal actors included: "+totalActors+"\nTesting context changed: "+(contextChanged?"Yes":"No")
            +"\n\nAll current actor credentials accompany the package, including unchanged ones. Counts never display cookie values."
            +(unknownCredentials>0?"\nOlder history has no per-actor credential hashes, so those credential changes cannot yet be compared.":"");}
    }
    public record Batch(String id, JsonObject document, Ledger next, int changedCount,Preview preview) {
        public byte[] bytes() { return JSON.toJson(document).getBytes(StandardCharsets.UTF_8); }
    }
    private record CaptureRef(String captureId,String recordId,JsonObject record) {}
    public static Ledger readLedger(String text) {
        JsonObject object = JsonParser.parseString(text).getAsJsonObject();
        for (String required : List.of("format","projectId","exported","actorKeys","actorNames"))
            if (!object.has(required)) throw new IllegalArgumentException("Missing export-history field: " + required);
        HermesSchemaValidator.validateLedger(object);
        Ledger l = JSON.fromJson(text, Ledger.class);
        if (l == null || !"acas-hermes-ledger-1".equals(l.format) || l.projectId == null || l.projectId.isBlank()
                || l.exported == null || l.actorKeys == null || l.actorNames == null)
            throw new IllegalArgumentException("Not an ACAS Hermes export history");
        return l;
    }
    public static String hash(String value) { return hash(value.getBytes(StandardCharsets.UTF_8)); }
    public static String hash(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }
    private static String key(Ledger l, String id) {
        String k = l.actorKeys.get(id);
        if (k == null || k.isBlank()) throw new IllegalArgumentException("Map every actor to a Hermes identity first");
        return k;
    }
    private static JsonObject raw(byte[] bytes) {
        if (bytes == null) return null;
        JsonObject result = new JsonObject();
        result.addProperty("encoding", "base64");
        result.addProperty("data", Base64.getEncoder().encodeToString(bytes));
        // Keep preview lightweight: full text for API/small payloads, truncated preview for massive HTML/blobs
        if (bytes.length <= 4096) {
            result.addProperty("textPreviewUtf8", new String(bytes, StandardCharsets.UTF_8));
        } else {
            result.addProperty("textPreviewUtf8", new String(Arrays.copyOf(bytes, 4096), StandardCharsets.UTF_8) + "\n...[truncated preview for Hermes; full data in base64]");
        }
        return result;
    }
    private static byte[] bytes(String text) { return text == null ? null : text.getBytes(StandardCharsets.ISO_8859_1); }
    /** Ignore credential rotation and transport noise only; retain path, IDs, body and other headers. */
    static String comparable(byte[] bytes, boolean request, Set<String> identities) {
        return request ? CaptureFingerprint.request(bytes, identities) : CaptureFingerprint.response(bytes, identities);
    }
    public static Batch prepare(ActorStore store, SeverityClassifier findings, Ledger previous, boolean full, String brief) {
        Ledger next = readLedger(JSON.toJson(previous));
        if(next.actorCredentialHashes==null)next.actorCredentialHashes=new LinkedHashMap<>();
        List<ActorProfile> actors = store.getAllActors();
        Set<String> keys = new HashSet<>();
        for (ActorProfile a : actors) if (!keys.add(key(next, a.getId())))
            throw new IllegalArgumentException("Each current actor must have a different Hermes identity");
        Set<String> identityHeaders = new HashSet<>();
        for (String name : store.getAllIdentityHeaderNames()) identityHeaders.add(name.toLowerCase(Locale.ROOT));
        LinkedHashMap<String,JsonObject> records = new LinkedHashMap<>();
        LinkedHashMap<String,JsonObject> resources = new LinkedHashMap<>();
        LinkedHashMap<String,JsonObject> mutationPoints = new LinkedHashMap<>();
        LinkedHashMap<String,JsonObject> mutationPlan = new LinkedHashMap<>();
        List<JsonObject> requestDependencies = new ArrayList<>();
        Map<String,CaptureRef> endpointCaptures = new LinkedHashMap<>();
        JsonObject authorization = AuthorizationContract.from(store);
        JsonArray actorArray = new JsonArray();
        List<String> actorRevisions = new ArrayList<>();
        int newActors=0,updatedCredentials=0,unknownCredentials=0;
        for (ActorProfile a : actors) {
            JsonObject actor = ActorContract.serialize(store,a,key(next,a.getId()));
            if(next.actorOrigins==null)next.actorOrigins=new LinkedHashMap<>();
            String established=next.actorOrigins.get(key(next,a.getId()));
            if(established!=null && !established.equals(actor.get("origin").getAsString()))throw new IllegalArgumentException("Existing actor origin changed; explicit identity reconciliation is required");
            next.actorOrigins.put(key(next,a.getId()),actor.get("origin").getAsString());
            actorArray.add(actor);
            List<String> credentials=new ArrayList<>();
            for(JsonElement item:actor.getAsJsonArray("currentAuthenticationHeaders")) {
                JsonArray header=item.getAsJsonArray();String name=header.get(0).getAsString().toLowerCase(Locale.ROOT);
                if(identityHeaders.contains(name))credentials.add(name+":"+header.get(1).getAsString());
            }
            Collections.sort(credentials);String digest=hash(JSON.toJson(credentials)),actorKey=key(next,a.getId());
            String oldDigest=previous.actorCredentialHashes==null?null:previous.actorCredentialHashes.get(actorKey);
            if(!previous.actorNames.containsKey(actorKey))newActors++;
            else if(oldDigest==null)unknownCredentials++;
            else if(!oldDigest.equals(digest))updatedCredentials++;
            next.actorCredentialHashes.put(actorKey,digest);
            JsonObject stable = actor.deepCopy(); stable.remove("localActorId"); stable.remove("sessionStatus"); stable.remove("savedActorRequest");
            actorRevisions.add(stable.toString());
            next.actorNames.put(key(next, a.getId()), a.getName());
            // Raw browser clickstream history omitted: Hermes only needs active captured endpoints
        }
        for (CapturedEndpoint ep : store.getCapturedEndpoints()) synchronized(ep) {
            String owner = next.actorKeys.get(ep.getActorId());
            if (owner == null) throw new IllegalArgumentException("A captured endpoint has an unmapped owner");
            byte[] req = ep.getOriginalRequestBytes(), res = ep.getOriginalResponseBytes();
            CapturedEndpoint.ProbeResult baseline = ep.getProbes().stream().filter(p -> p.isBaseline).findFirst().orElse(null);
            if (req == null && baseline != null) req = baseline.request;
            if (res == null && baseline != null) res = baseline.response;
            CaptureRef capture = capture(records, next, owner, ep.getMethod(), ep.getOriginalUrl(), req, res, identityHeaders);
            String captureId = capture.captureId();
            endpointCaptures.put(ep.getId(), capture);
            String requestHash = hash(req == null ? new byte[0] : req);
            boolean isRead = OperationSafety.isReadMethod(ep.getMethod());
            OperationSafety safety = isRead ? OperationSafety.SAFE_READ : OperationSafety.REVERSIBLE_WRITE;
            String mappedResourceOwner = null;
            if (ep.getResourceOwnerActorId() != null && !ep.getResourceOwnerActorId().isBlank()) {
                mappedResourceOwner = next.actorKeys.get(ep.getResourceOwnerActorId());
                if (mappedResourceOwner == null) throw new IllegalArgumentException("A confirmed resource owner has no Hermes identity");
            }
            String resourceRef = ResourceContract.ref(ep);
            List<String> pointIds = new ArrayList<>();
            for (MutationPoint point : MutationPointExtractor.extract(req)) {
                point.mutationSafety = safety;
                point.requiresReview = false;
                JsonObject pointJson = JSON.toJsonTree(point).getAsJsonObject();
                pointJson.addProperty("captureId", captureId);
                pointJson.addProperty("captureRecordId", capture.recordId());
                mutationPoints.put(point.pointId, pointJson);
                pointIds.add(point.pointId);
                JsonObject plan = new JsonObject();
                plan.addProperty("planId", "mutation-plan:" + hash(captureId + "|" + point.pointId));
                plan.addProperty("captureId", captureId);
                plan.addProperty("captureRecordId", capture.recordId());
                plan.addProperty("pointId", point.pointId);
                plan.addProperty("selector", point.selector);
                plan.addProperty("location", point.location);
                plan.addProperty("requestHash", requestHash);
                plan.addProperty("operationSafety", point.mutationSafety.name());
                plan.addProperty("approved", true);
                plan.addProperty("executable", point.replayable);
                plan.addProperty("requiresReview", false);
                plan.addProperty("expectedEffect", isRead ? "read_only" : "Creates or modifies a test object owned by the designated test actor");
                plan.addProperty("note", "Only exact reviewed read-only selectors may run in this workflow.");
                mutationPlan.put(plan.get("planId").getAsString(), plan);
            }
            String captureRecordId = capture.recordId();
            capture.record().addProperty("captureActorId", owner);
            capture.record().addProperty("resourceOwnerActorId", mappedResourceOwner);
            capture.record().addProperty("resourceRef", resourceRef);
            capture.record().addProperty("operationSafety", safety.name());
            capture.record().addProperty("operationSafetyReason", ep.getOperationSafetyReason());
            capture.record().addProperty("operationApproved", true);
            capture.record().addProperty("requestFingerprint", hash(comparable(req, true, identityHeaders)));
            capture.record().addProperty("captureVersion", hash(comparable(res, false, identityHeaders)));
            capture.record().addProperty("capturedAt", java.time.Instant.ofEpochMilli(ep.getCapturedAtEpochMs()).toString());
            capture.record().addProperty("evidenceState", "immutable");
            JsonArray capturePointIds = new JsonArray();
            for (String id : pointIds) capturePointIds.add(id);
            capture.record().add("mutationPointIds", capturePointIds);
            JsonObject resource = ResourceContract.serialize(mappedResourceOwner, captureId, ep, resourceRef,
                new ArrayList<>(List.of(captureRecordId)), pointIds);
            resources.put(resourceRef, resource);
            requestDependencies.add(dependency(captureId, null, owner, "captured_owner_request", 1.0, 3600));
            if(ep.getAutomaticProbeNote()!=null) {
                JsonObject skipped=new JsonObject();skipped.addProperty("kind","probeSkipped");
                skipped.addProperty("captureId",captureId);skipped.addProperty("captureRecordId",captureRecordId);
                skipped.addProperty("ownerActorId",owner);skipped.addProperty("captureActorId",owner);
                skipped.addProperty("reason",ep.getAutomaticProbeNote());
                add(records,skipped,"probeSkipped:"+hash(skipped.toString()));
            }
            // Internal pre-computed probes omitted: Hermes runs tests live
        }
        // Local findings omitted: Hermes runs fresh evaluation on live endpoints
        JsonObject document = new JsonObject(); String batchId = UUID.randomUUID().toString();
        document.addProperty("format","acas-hermes-1"); document.addProperty("schemaVersion",2);
        document.addProperty("batchId",batchId);
        document.addProperty("projectId",next.projectId); document.addProperty("previousBatchId",previous.lastBatchId);
        JsonArray autoReviews = authorization.has("reviews") ? authorization.getAsJsonArray("reviews") : new JsonArray();
        for (CapturedEndpoint epItem : store.getCapturedEndpoints()) {
            String cOwner = next.actorKeys.get(epItem.getActorId());
            CaptureRef cRef = endpointCaptures.get(epItem.getId());
            if (cOwner != null && cRef != null) {
                byte[] rBytes = epItem.getOriginalRequestBytes();
                String rHash = hash(rBytes == null ? new byte[0] : rBytes);
                boolean exists = false;
                for (JsonElement revEl : autoReviews) {
                    if (revEl.isJsonObject() && cRef.captureId().equals(revEl.getAsJsonObject().get("captureId").getAsString())) {
                        exists = true; break;
                    }
                }
                if (!exists) {
                    JsonObject rObj = new JsonObject();
                    rObj.addProperty("captureId", cRef.captureId());
                    rObj.addProperty("captureActorId", cOwner);
                    rObj.addProperty("requestHash", rHash);
                    boolean isRead = OperationSafety.isReadMethod(epItem.getMethod());
                    rObj.addProperty("operationSafety", isRead ? "SAFE_READ" : "REVERSIBLE_WRITE");
                    rObj.addProperty("approved", true);
                    rObj.addProperty("maxAgeSeconds", 86400);
                    rObj.addProperty("capturedAtEpochMs", epItem.getCapturedAtEpochMs());
                    autoReviews.add(rObj);
                }
            }
        }
        authorization.add("reviews", autoReviews);
        document.add("authorization",authorization);
        JsonArray resourcesArray = new JsonArray();
        for (JsonObject resource : resources.values()) resourcesArray.add(resource);
        document.add("resources",resourcesArray);
        JsonArray pointsArray = new JsonArray();
        for (JsonObject point : mutationPoints.values()) pointsArray.add(point);
        document.add("mutationPoints",pointsArray);
        JsonArray plansArray = new JsonArray();
        for (JsonObject plan : mutationPlan.values()) plansArray.add(plan);
        document.add("mutationPlan",plansArray);
        JsonArray dependenciesArray = new JsonArray();
        for (JsonObject dependency : requestDependencies) dependenciesArray.add(dependency);
        document.add("requestDependencies",dependenciesArray);
        document.addProperty("createdAt",java.time.Instant.now().toString()); document.addProperty("mode",full?"full":"changes");
        document.addProperty("purpose","ACAS authorization testing handoff, containing live credentials and captured evidence.");
        document.addProperty("objective",brief);
        document.addProperty("instructions","All captured endpoints in this bundle are explicitly approved for live authorization testing (BOLA/IDOR, cross-actor replay, anonymous access, and privilege escalation). Execute live requests across all included read and write endpoints without manual intervention. Rate limit policy: (1) Standard Auth Testing: Pace requests at safe human+ speed (2-3 req/s, 400ms min interval, max concurrency 2). (2) Parameter / ID Brute-forcing & Enumeration: When testing candidate object IDs, sequential identifiers, or fuzzing parameters, you are authorized to burst up to 10 req/s (100ms interval, concurrency 5, up to 500 candidate attempts). If 429/WAF challenges occur, automatically throttle back to safe pace.");
        document.add("captureScopeConfiguration",JSON.toJsonTree(store.getScopeConfig()));
        document.addProperty("scopeNote","Burp suite scope rules are not embedded. Explicit testing authorization must be supplied separately in the objective or Hermes job.");
        JsonObject outputContract = new JsonObject();
        outputContract.addProperty("format","acas-hermes-results-1");
        outputContract.addProperty("projectId",next.projectId); outputContract.addProperty("sourceBatchId",batchId);
        outputContract.add("requiredFindingFields",JSON.toJsonTree(List.of("title","status","severity","ownerActorId","replayActorId","captureId","evidenceRecordIds","expectedBehavior","actualBehavior","verifiedImpact","reproductionSteps","redactedRequestResponseEvidence")));
        outputContract.add("statuses",JSON.toJsonTree(List.of("confirmed","inconclusive","expected_behavior","blocked")));
        outputContract.addProperty("reportInstructions","Return structured JSON plus a readable report. Preserve source evidence references. Redact credentials in human-readable reports. Do not claim confirmation without reproducible evidence.");
        document.add("expectedHermesOutput",outputContract);
        document.add("actors",actorArray);
        Collections.sort(actorRevisions);
        next.actorManifestHash = hash(actorRevisions.toString());
        next.contextHash = hash(brief + document.get("captureScopeConfiguration"));
        JsonArray out = new JsonArray();
        int changed = (Objects.equals(next.actorManifestHash,previous.actorManifestHash)?0:1)
            + (Objects.equals(next.contextHash,previous.contextHash)?0:1);
        for (var entry : records.entrySet()) {
            boolean unseen = !previous.exported.contains(entry.getKey());
            if (unseen) changed++;
            if ((full || unseen) && entry.getValue() != null) out.add(entry.getValue());
            next.exported.add(entry.getKey());
        }
        document.add("records",out); next.lastBatchId = batchId;
        Set<String> knownCaptures=new HashSet<>();
        for(String id:previous.exported)if(id.startsWith("capture:") && id.lastIndexOf(':')>7)knownCaptures.add(id.substring(0,id.lastIndexOf(':')));
        Set<String> allCaptures=new HashSet<>(),sentCaptures=new HashSet<>(),newCaptures=new HashSet<>();
        Map<String,RequestDetail> details=new LinkedHashMap<>();
        List<RequestDetail> changedDetails=new ArrayList<>();
        Map<String,String> oldResponses=new LinkedHashMap<>();
        if(previous.responseSnapshots!=null)oldResponses.putAll(previous.responseSnapshots);
        // Older ledgers have fingerprints only. Recover evidence only from exact exported records still present.
        for(var entry:records.entrySet()) {
            JsonObject record=entry.getValue();
            if(record.get("kind").getAsString().equals("capture") && previous.exported.contains(entry.getKey())) {
                String id=record.get("captureId").getAsString();
                if(!oldResponses.containsKey(id))oldResponses.put(id,responseText(record));
            }
        }
        if(next.responseSnapshots==null)next.responseSnapshots=new LinkedHashMap<>();
        next.responseSnapshots.putAll(oldResponses);
        int changedResults=0,probeResults=0,findingResults=0;
        for(var entry:records.entrySet()) {
            JsonObject record=entry.getValue();String kind=record.get("kind").getAsString();boolean unseen=!previous.exported.contains(entry.getKey()),included=full||unseen;
            if(kind.equals("capture")) {
                String id=record.get("captureId").getAsString();allCaptures.add(id);
                String owner=record.get("ownerActorId").getAsString();
                RequestDetail detail=new RequestDetail(id,owner,next.actorNames.getOrDefault(owner,"Unknown actor"),record.get("method").getAsString(),record.get("url").getAsString());
                details.putIfAbsent(id,detail);
                if(included)sentCaptures.add(id);
                if(!knownCaptures.contains(id))newCaptures.add(id);else if(unseen){
                    changedResults++;
                    changedDetails.add(new RequestDetail(id,owner,detail.actorName(),detail.method(),detail.url(),
                        oldResponses.containsKey(id),oldResponses.get(id),responseText(record)));
                }
                if(unseen)next.responseSnapshots.put(id,responseText(record));
            }else if(included && kind.equals("probe"))probeResults++;
            else if(included && kind.equals("finding"))findingResults++;
        }
        Set<String> skipped=new HashSet<>(allCaptures);skipped.removeAll(sentCaptures);
        Set<String> repeated=new HashSet<>(sentCaptures);repeated.retainAll(knownCaptures);
        Preview preview=new Preview(newCaptures.size(),changedResults,skipped.size(),full?repeated.size():0,probeResults,findingResults,newActors,updatedCredentials,unknownCredentials,actors.size(),!Objects.equals(next.contextHash,previous.contextHash),
            details.values().stream().filter(d->newCaptures.contains(d.captureId())).toList(),List.copyOf(changedDetails),
            details.values().stream().filter(d->skipped.contains(d.captureId())).toList(),
            full?details.values().stream().filter(d->repeated.contains(d.captureId())).toList():List.of());
        // Preview diffs and response snapshots are local UI state, not agent input.
        JsonObject portableHistory=JSON.toJsonTree(next).getAsJsonObject();
        portableHistory.remove("responseSnapshots");
        document.add("exportHistory",portableHistory);
        document.addProperty("historyNote","Import exportHistory into ACAS in a fresh Burp session, then map actors explicitly to existing Hermes identities. Ledger contains export fingerprints, not proof of Hermes delivery or testing.");
        HermesSchemaValidator.validateExport(document);
        return new Batch(batchId,document,next,changed,preview);
    }
    private static CaptureRef capture(Map<String,JsonObject> records, Ledger ledger, String owner, String method, String url, byte[] req, byte[] res, Set<String> identities) {
        String id = "capture:" + hash(ledger.projectId + "|" + owner + "|" + method + "|" + url + "|" + comparable(req,true,identities));
        JsonObject record = new JsonObject(); record.addProperty("kind","capture"); record.addProperty("captureId",id);
        record.addProperty("ownerActorId",owner); record.addProperty("captureActorId",owner);
        record.addProperty("method",method); record.addProperty("url",url);
        record.add("request",raw(req)); record.add("response",raw(res));
        String recordId = id + ":" + hash(comparable(res,false,identities));
        add(records,record,recordId);
        return new CaptureRef(id,recordId,record);
    }
    private static void enrichHistoricalCapture(CaptureRef capture,String owner,byte[] req,Set<String> identities,
                                                Map<String,JsonObject> points,Map<String,JsonObject> plans) {
        capture.record().addProperty("captureActorId",owner);
        capture.record().addProperty("resourceOwnerActorId",(String)null);
        capture.record().addProperty("resourceRef",(String)null);
        capture.record().addProperty("operationSafety",OperationSafety.UNKNOWN.name());
        capture.record().addProperty("operationSafetyReason",(String)null);
        capture.record().addProperty("operationApproved",false);
        capture.record().addProperty("requestFingerprint",hash(comparable(req,true,identities)));
        JsonElement responseElement=capture.record().get("response");
        byte[] responseBytes=responseElement==null||responseElement.isJsonNull()?null
            :Base64.getDecoder().decode(responseElement.getAsJsonObject().get("data").getAsString());
        capture.record().addProperty("captureVersion",hash(comparable(responseBytes,false,identities)));
        capture.record().addProperty("capturedAt",(String)null);
        capture.record().addProperty("evidenceState","immutable");
        JsonArray ids=new JsonArray();
        for(MutationPoint point:MutationPointExtractor.extract(req)) {
            point.mutationSafety=OperationSafety.UNKNOWN;point.requiresReview=true;
            JsonObject json=JSON.toJsonTree(point).getAsJsonObject();
            json.addProperty("captureId",capture.captureId());json.addProperty("captureRecordId",capture.recordId());
            points.put(point.pointId,json);ids.add(point.pointId);
            JsonObject plan=new JsonObject();
            plan.addProperty("planId","mutation-plan:"+hash(capture.captureId()+"|"+point.pointId));
            plan.addProperty("captureId",capture.captureId());plan.addProperty("captureRecordId",capture.recordId());
            plan.addProperty("pointId",point.pointId);plan.addProperty("selector",point.selector);
            plan.addProperty("location",point.location);plan.addProperty("requestHash",hash(req));
            plan.addProperty("operationSafety",OperationSafety.UNKNOWN.name());plan.addProperty("approved",false);
            plan.addProperty("executable",false);plan.addProperty("requiresReview",true);
            plan.addProperty("expectedEffect","unknown");
            plan.addProperty("note","Historical capture has no reviewable operation safety.");
            plans.put(plan.get("planId").getAsString(),plan);
        }
        capture.record().add("mutationPointIds",ids);
    }
    private static JsonObject approval(JsonObject authorization,String captureId,String requestHash) {
        for (var item : authorization.getAsJsonArray("reviews")) {
            JsonObject review = item.getAsJsonObject();
            boolean sameCapture = review.has("captureId") && captureId.equals(review.get("captureId").getAsString());
            boolean sameRequest = review.has("requestHash") && requestHash.equals(review.get("requestHash").getAsString());
            if (sameCapture || sameRequest) return review;
        }
        return null;
    }
    private static JsonObject dependency(String captureId,String from,String to,String type,double confidence,int maxAgeSeconds) {
        JsonObject dependency = new JsonObject();
        dependency.addProperty("dependencyId", "request-dependency:" + hash(captureId + "|" + from + "|" + to + "|" + type));
        dependency.addProperty("captureId", captureId);
        dependency.addProperty("fromActorId", from);
        dependency.addProperty("toActorId", to);
        dependency.addProperty("type", type);
        dependency.addProperty("confidence", confidence);
        dependency.addProperty("requiresFreshIdentity", true);
        dependency.addProperty("maxAgeSeconds", maxAgeSeconds);
        return dependency;
    }
    private static CaptureRef linkedCapture(AcasFinding finding,Map<String,CaptureRef> endpointCaptures) {
        if (finding.getCaptureId() == null || finding.getCaptureId().isBlank()) return null;
        CaptureRef direct = endpointCaptures.get(finding.getCaptureId());
        if (direct != null) return direct;
        for (CaptureRef capture : endpointCaptures.values()) if (capture.captureId().equals(finding.getCaptureId())) return capture;
        return null;
    }
    private static void add(Map<String,JsonObject> records, JsonObject record, String id) { record.addProperty("recordId",id); records.put(id,record); }
    private static String responseText(JsonObject record) {
        return record.get("response").isJsonNull()?null:record.getAsJsonObject("response").get("textPreviewUtf8").getAsString();
    }
    private static String resolveName(List<ActorProfile> actors,Ledger ledger,String name) {
        List<ActorProfile> matches=actors.stream().filter(a->Objects.equals(a.getName(),name)).toList();
        return matches.size()==1?key(ledger,matches.get(0).getId()):null;
    }
}
