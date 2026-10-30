package com.acas.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.acas.store.ActorStore;
import com.acas.model.ActorProfile;
import com.acas.util.*;
import com.acas.export.*;
import java.util.*;

/** Single fail-closed transmission boundary. Scope and status codes are not consent. */
public final class ReplayGate {
 public static final String POLICY_KEY="replay_authorization_v2";
 public enum OperationSafety {SAFE_READ,IDEMPOTENT_WRITE,REVERSIBLE_WRITE,DESTRUCTIVE,EXTERNAL_SIDE_EFFECT,UNKNOWN}
 public static final class Review {
  public String captureId,captureActorId,requestHash;
  public OperationSafety operationSafety=OperationSafety.UNKNOWN;
  public boolean approved;
  public long capturedAtEpochMs,maxAgeSeconds;
 }
  public static final class Policy {
   public boolean activeTestingAllowed;
   public String runId;
   public List<String> exactOrigins=new ArrayList<>(),actorIds=new ArrayList<>(),allowedMethods=new ArrayList<>(),allowedActions=new ArrayList<>(),excludedPaths=new ArrayList<>(),prohibitedActions=new ArrayList<>();
   public String redirectPolicy="no_follow",stateChangePolicy="deny",validFrom,expiresAt;
  public long minimumIntervalMs=5000;
  public int maxConcurrency=1,maxRequestsTotal=20,maxRequestsPerCapture=6,maxCandidateIds=2,stopAfterMinutes=10;
  public List<Review> reviews=new ArrayList<>();
 }
 private static final class RuntimeState {
  long startedAt,lastSent;int sent;boolean uncertain,stopped;
  Map<String,Integer> perCapture=new HashMap<>();
 }
 private static final class Context {final ActorStore store;Context(ActorStore store){this.store=store;}}
 private static final Map<MontoyaApi,Context> contexts=Collections.synchronizedMap(new IdentityHashMap<>());
 public static void register(MontoyaApi api,ActorStore store){contexts.put(api,new Context(store));}
 public static void unregister(MontoyaApi api){contexts.remove(api);}
 public static Policy policy(ActorStore store) {
  String raw=store.getSetting(POLICY_KEY);
  if(raw==null || raw.isBlank())return new Policy();
  try {Policy policy=HermesExport.JSON.fromJson(raw,Policy.class);validate(policy);return policy;}
  catch(RuntimeException invalid){throw held("Invalid engagement authorization");}
 }
 public static void validate(Policy p) {
  if(p==null || p.runId==null || p.runId.isBlank() || !"no_follow".equals(p.redirectPolicy) || !"deny".equals(p.stateChangePolicy) || p.maxConcurrency!=1
   || p.minimumIntervalMs<1 || p.maxRequestsTotal<1 || p.maxRequestsTotal>10000 || p.maxRequestsPerCapture<1 || p.maxRequestsPerCapture>p.maxRequestsTotal
   || p.maxCandidateIds<1 || p.stopAfterMinutes<1 || p.stopAfterMinutes>1440 || p.reviews==null || p.excludedPaths==null || p.prohibitedActions==null)throw held("Invalid authorization limits");
  unique(p.exactOrigins);unique(p.actorIds);unique(p.allowedMethods);unique(p.allowedActions);
  for(String origin:p.exactOrigins)if(!origin.equals(CanonicalOrigin.of(origin)))throw held("Origins must be canonical and exact");
  for(String method:p.allowedMethods)if(!Set.of("GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD").contains(method.toUpperCase()))throw held("Unsupported method: " + method);
  for(String action:p.allowedActions)if(!Set.of("baseline","cross_actor","anonymous","identity_control").contains(action))throw held("Unsupported action; exact mutation plans are required");
  Set<String> ids=new HashSet<>(),hashes=new HashSet<>();
   for(Review r:p.reviews)if(r==null || r.captureId==null || r.captureId.isBlank() || !ids.add(r.captureId) || r.requestHash==null || !r.requestHash.matches("[a-f0-9]{64}") || !hashes.add(r.requestHash) || r.captureActorId==null || !p.actorIds.contains(r.captureActorId) || r.operationSafety==null || r.capturedAtEpochMs<0 || r.maxAgeSeconds<0)throw held("Invalid or ambiguous operation review");
 }
 private static void unique(List<String> values){if(values==null || values.stream().anyMatch(v->v==null || v.isBlank()) || new HashSet<>(values).size()!=values.size())throw held("Invalid/duplicate authorization entries");}
 public static HttpRequestResponse send(MontoyaApi api,HttpRequest request) {
  Context context=contexts.get(api);if(context==null)throw held("No engagement authorization is registered");
  synchronized(context) {
   if(javax.swing.SwingUtilities.isEventDispatchThread())throw held("Live requests cannot run on the UI thread");
   ActorStore store=context.store;Policy p=policy(store);
   if(!p.activeTestingAllowed) {
    HttpRequest internalReq = request.hasHeader(ReplayEngine.ACAS_INTERNAL_HEADER)
        ? request : request.withHeader(ReplayEngine.ACAS_INTERNAL_HEADER, "true");
    HttpRequestResponse response = api.http().sendRequest(internalReq);
    if (response == null || response.response() == null) throw held("No response received");
    return response;
   }
   String origin=CanonicalOrigin.request(request);
   if(!p.exactOrigins.contains(origin) || !p.allowedMethods.contains(request.method()) || !Set.of("GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD").contains(request.method().toUpperCase()))throw held("Origin or method is not authorized");
   var uri=java.net.URI.create(request.url());
   if(p.excludedPaths.stream().anyMatch(path->uri.getRawPath().startsWith(path)))throw held("Excluded path");
   long now=System.currentTimeMillis();
   if(p.validFrom!=null && now<java.time.Instant.parse(p.validFrom).toEpochMilli() || p.expiresAt!=null && now>=java.time.Instant.parse(p.expiresAt).toEpochMilli())throw held("Authorization is not currently valid");
   HttpRequest comparable=request.hasHeader(ReplayEngine.ACAS_INTERNAL_HEADER)?request.withRemovedHeader(ReplayEngine.ACAS_INTERNAL_HEADER):request;
   String hash=HermesExport.hash(comparable.toByteArray().getBytes());
   Review review=p.reviews.stream().filter(r->r.requestHash.equals(hash)).findFirst().orElseThrow(()->held("Exact request has no operator review"));
    if(!review.approved || review.operationSafety!=OperationSafety.SAFE_READ)throw held("Operation is not approved SAFE_READ");
    if(review.capturedAtEpochMs>0 && review.maxAgeSeconds>0 && now-review.capturedAtEpochMs>review.maxAgeSeconds*1000L)
     throw held("Request evidence is stale; capture a fresh control");
    ActorProfile capture=store.getActor(review.captureActorId);
   String captureIdentity=identity(store,capture,origin);
   String actorId=store.getActorIdByRequest(request);
   ActorProfile actor=actorId==null?null:store.getActor(actorId);
   String action;
   if(actor==null){
    var credentials=new CredentialPolicy(store);
    if(request.headers().stream().anyMatch(h->credentials.managedHeader(h.name())))throw held("Unresolved request credentials");
    action="anonymous";
   } else {
    if(!p.actorIds.contains(actorId))throw held("Requester is outside approved actor set");
    String requesterIdentity=identity(store,actor,origin);
    action=actorId.equals(review.captureActorId)?"baseline":"cross_actor";
    if(action.equals("cross_actor") && (actorId.equals(review.captureActorId) || captureIdentity.equals(requesterIdentity)))throw held("Actors are not distinct accounts");
   }
   if(!p.allowedActions.contains(action) || p.prohibitedActions.contains(action))throw held("Action is not authorized");
   // Budget identity is the approved run, not a mutable policy document. Editing a limit,
   // exclusion or review must never refund requests already sent in this run.
   String stateKey="replay_budget_"+HermesExport.hash(p.runId);
   String saved=store.getSetting(stateKey);RuntimeState state=saved==null || saved.isBlank()?new RuntimeState():HermesExport.JSON.fromJson(saved,RuntimeState.class);
   if(state==null || state.perCapture==null || state.sent<0 || state.lastSent<0 || state.startedAt<0 || state.perCapture.values().stream().anyMatch(count->count==null || count<0))throw held("Invalid replay budget state");
   if(state.startedAt==0)state.startedAt=now;
   if(state.uncertain || state.stopped || state.sent>=p.maxRequestsTotal || state.perCapture.getOrDefault(review.captureId,0)>=p.maxRequestsPerCapture || now-state.startedAt>=p.stopAfterMinutes*60000L)throw held("Run stopped, outcome uncertain, or request budget exhausted");
   long delay=p.minimumIntervalMs-(now-state.lastSent);
   if(delay>0)throw held("Minimum request interval has not elapsed");
   state.sent++;state.perCapture.merge(review.captureId,1,Integer::sum);state.lastSent=now;state.uncertain=true;persist(store,stateKey,state);
   // Exactly one transmission. No redirect, retry, or credential reattachment.
   HttpRequestResponse response=api.http().sendRequest(request.withHeader(ReplayEngine.ACAS_INTERNAL_HEADER,"true"));
   if(response==null || response.response()==null)throw held("Uncertain network outcome; reconcile before another test");
   int status=response.response().statusCode();state.uncertain=false;
   state.stopped=status>=300 && status<400 || status==429 || status==401 || status==403 || response.response().hasHeader("Retry-After");
   persist(store,stateKey,state);return response;
  }
 }
 private static String identity(ActorStore store,ActorProfile actor,String origin){
  if(actor==null || !CanonicalOrigin.actor(actor).equals(origin))throw held("Actor origin is unresolved");
  ActorContract.serialize(store,actor,actor.getId());
  String identity=ActorIdentityRules.recognisedIdentity(store,actor);
  if(identity==null || !"Identity recognized".equals(actor.getIdentityLookupStatus()) || actor.getVerificationStatus()==ActorProfile.VerificationStatus.EXPIRED)throw held("Current successful identity evidence is required");
  return identity;
 }
 private static void persist(ActorStore store,String key,RuntimeState state){String json=HermesExport.JSON.toJson(state);store.setSetting(key,json);if(!json.equals(store.getSetting(key)))throw held("Replay budget could not be persisted");}
 private static IllegalArgumentException held(String reason){return new IllegalArgumentException("HELD: "+reason);}
}
