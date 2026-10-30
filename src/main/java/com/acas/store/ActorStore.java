package com.acas.store;

import burp.api.montoya.MontoyaApi;
import com.acas.model.ActorProfile;
import com.acas.model.ScopeConfig;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

public class ActorStore {
    private static final String ACTORS_KEY = "acas_actors";
    private static final String SCOPE_KEY = "acas_scope";
    private static final String SETTINGS_KEY = "acas_settings";

    private final MontoyaApi api;
    private final Gson gson = new Gson();
    private final java.util.concurrent.ScheduledExecutorService captureSaver=java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"ACAS-capture-save");t.setDaemon(true);return t;});
    private final java.util.concurrent.atomic.AtomicBoolean captureSavePending=new java.util.concurrent.atomic.AtomicBoolean();
    private final Object capturePersistenceLock=new Object();
    private void requestCaptureSave() {
        if(captureSavePending.compareAndSet(false,true))captureSaver.schedule(this::flushCapturePersistence,1,java.util.concurrent.TimeUnit.SECONDS);
    }
    public void flushCapturePersistence() {
        synchronized(capturePersistenceLock) {
            if(!captureSavePending.getAndSet(false))return;
            saveToPersistence();saveEndpointsToPersistence();
        }
    }
    public void close() {com.acas.engine.ReplayGate.unregister(api);captureSaver.shutdown();flushCapturePersistence();}
    private final List<ActorProfile> actors = new CopyOnWriteArrayList<>();
    private final List<Runnable> changeListeners = new CopyOnWriteArrayList<>();
    private ScopeConfig scopeConfig = new ScopeConfig();
    private final List<com.acas.model.CapturedEndpoint> capturedEndpoints = new CopyOnWriteArrayList<>();
    private volatile String activeActorId = null;
    private long captureGeneration;
    private boolean captureStoppedByUser;
    private Runnable captureWorkListener = () -> {};
    public void setCaptureWorkListener(Runnable listener) { captureWorkListener=listener; }
    public synchronized void startCaptureAfterActorSave(String id) {
        if (!captureStoppedByUser) setActiveActorId(id);
    }
    public record CaptureSession(String actorId,long generation,boolean selectedOnly) {}
    public synchronized CaptureSession probeSession(String actorId) {
        return activeActorId!=null && getActor(actorId)!=null?new CaptureSession(actorId,captureGeneration,false):null;
    }
    public synchronized CaptureSession captureSession(String actorId) {
        ActorProfile actor=getActor(actorId);
        return actorId!=null && actorId.equals(activeActorId) && actor!=null && actor.isRecording()
            ?new CaptureSession(actorId,captureGeneration,true):null;
    }
    public synchronized boolean isCaptureCurrent(CaptureSession session) {
        return session!=null && session.generation()==captureGeneration && (session.selectedOnly()?captureSession(session.actorId())!=null:probeSession(session.actorId())!=null);
    }
    public synchronized void whileCaptureCurrent(CaptureSession session,Runnable action) {
        if(isCaptureCurrent(session))action.run();
    }
    public synchronized void stopAllCapture(){captureStoppedByUser=true;setActiveActorId(null);}
    private java.util.function.Consumer<ActorProfile> identityLookup = actor -> {};
    private java.util.function.BiFunction<ActorProfile,com.acas.export.ActorIdentityRules.Rule,java.util.concurrent.CompletableFuture<com.acas.export.ActorIdentityLookup.TestResult>> identityTester = (actor,rule) -> java.util.concurrent.CompletableFuture.completedFuture(new com.acas.export.ActorIdentityLookup.TestResult(false,0,null,"Identity service is not available."));
    public void setIdentityTester(java.util.function.BiFunction<ActorProfile,com.acas.export.ActorIdentityRules.Rule,java.util.concurrent.CompletableFuture<com.acas.export.ActorIdentityLookup.TestResult>> tester){identityTester=tester;}
    public java.util.concurrent.CompletableFuture<com.acas.export.ActorIdentityLookup.TestResult> testActorIdentity(ActorProfile actor,com.acas.export.ActorIdentityRules.Rule rule){return identityTester.apply(actor,rule);}
    public void setIdentityLookup(java.util.function.Consumer<ActorProfile> listener){identityLookup=listener;}
    public void refreshActorIdentities(){for(ActorProfile actor:getAllActors())identityLookup.accept(actor);}
    public void persistIdentityResult(){saveToPersistence();notifyListeners();}

    public ActorStore(MontoyaApi api) {
        this.api = api;
        com.acas.engine.ReplayGate.register(api,this);
        loadFromPersistence();
        actors.forEach(a -> a.setRecording(false));
    }

    public synchronized void addActor(ActorProfile actor) {
        actor.setRecording(false);
        actors.add(actor);
        saveToPersistence();
        notifyListeners();
        identityLookup.accept(actor);
        captureWorkListener.run();
    }

    public synchronized void removeActor(String actorId) {
        Optional<ActorProfile> actor = getActorById(actorId);
        if (actor.isPresent()) {
            String name = actor.get().getName();
            // Remove endpoints OWNED by this actor, and prune this actor's probes
            // from any endpoints owned by others.
            capturedEndpoints.removeIf(ep -> actorId.equals(ep.getActorId()));
            for (com.acas.model.CapturedEndpoint ep : capturedEndpoints) {
                ep.getProbes().removeIf(p -> actorId.equals(p.actorId)
                    || (p.actorId == null && p.actorName != null && p.actorName.equals(name)));
            }
            saveEndpointsToPersistence();

            // If this actor was the active/recording one, clear that.
            if (actorId.equals(activeActorId)) {
                activeActorId = null;captureGeneration++;captureStoppedByUser=true;
                actors.forEach(a -> a.setRecording(false));
            }

            actors.removeIf(a -> a.getId().equals(actorId));
            saveToPersistence();
            notifyListeners();
        }
    }

    public void updateActor(ActorProfile actor) {
        for (int i = 0; i < actors.size(); i++) {
            if (actors.get(i).getId().equals(actor.getId())) {
                actors.set(i, actor);
                break;
            }
        }
        saveToPersistence();
        notifyListeners();
        identityLookup.accept(actor);
    }

    public synchronized void rebindActorOrigin(String actorId, String newOrigin, boolean explicitlyConfirmed) {
        ActorProfile actor = getActor(actorId);
        if (actor == null) throw new IllegalArgumentException("Unknown actor");
        if (!explicitlyConfirmed) throw new IllegalArgumentException("Changing an actor origin requires explicit operator confirmation");
        String origin = com.acas.util.CanonicalOrigin.of(newOrigin);
        String current = null;
        try { current = com.acas.util.CanonicalOrigin.actor(actor); }
        catch (RuntimeException ignored) { }
        if (origin.equals(current)) return;
        String path = "/", query = null;
        if (actor.getIdentitySourceUrl() != null && !actor.getIdentitySourceUrl().isBlank()) {
            try {
                java.net.URI old = java.net.URI.create(actor.getIdentitySourceUrl());
                if (old.getRawPath() != null && !old.getRawPath().isBlank()) path = old.getRawPath();
                query = old.getRawQuery();
            } catch (RuntimeException ignored) { }
        }
        actor.setIdentitySourceUrl(origin + path + (query == null ? "" : "?" + query));
        actor.setIdentityLookupStatus("Not checked");
        actor.setVerificationStatus(ActorProfile.VerificationStatus.UNVERIFIED);
        actor.getAutomaticIdentityProofs().clear();
        for (com.acas.model.CapturedEndpoint capture : capturedEndpoints) {
            if (java.util.Objects.equals(capture.getActorId(), actorId))
                capture.setHuntStatus(com.acas.model.CapturedEndpoint.HuntStatus.STALE);
        }
        saveToPersistence();
        saveEndpointsToPersistence();
        notifyListeners();
    }

    /**
     * Surgically updates only the identity (session) headers of an existing actor
     * from a new request. Non-identity headers (Accept, Content-Type, etc.) are left
     * unchanged. Identity headers present in newRequest replace old values; identity
     * headers NOT in newRequest are removed (they are expired).
     *
     * @param actorId    The actor whose session is being refreshed
     * @param newRequest The right-clicked request containing fresh session headers
     */
    public boolean updateActorSession(String actorId,
                                      burp.api.montoya.http.message.requests.HttpRequest newRequest) {
        ActorProfile actor = getActor(actorId);
        if (actor == null || newRequest == null) return false;
        try {com.acas.util.CanonicalOrigin.requireActorRequest(actor,newRequest);} catch(IllegalArgumentException invalid){return false;}

        // Build a map of the new request's identity headers (name.lower → [name, value])
        java.util.Map<String, String[]> newIdentityHeaders = new java.util.LinkedHashMap<>();
        for (burp.api.montoya.http.message.HttpHeader h : newRequest.headers()) {
            if (isPotentialIdentityHeader(h.name())) {
                newIdentityHeaders.put(h.name().toLowerCase(), new String[]{h.name(), h.value()});
            }
        }

        // Rebuild the actor's header list:
        //   - Keep non-identity headers unchanged
        //   - Replace identity headers with values from newRequest
        List<String[]> merged = new ArrayList<>();
        java.util.Set<String> replacedKeys = new java.util.HashSet<>();
        for (String[] existing : actor.getHeaders()) {
            String lowerName = existing[0].toLowerCase();
            if (isPotentialIdentityHeader(lowerName)) {
                if (newIdentityHeaders.containsKey(lowerName)) {
                    // Replace with fresh value
                    merged.add(newIdentityHeaders.get(lowerName));
                    replacedKeys.add(lowerName);
                }
                // If NOT in newRequest, drop it (the old session token is gone)
            } else {
                // Keep non-identity headers as-is
                merged.add(existing);
            }
        }
        // Add any brand-new identity headers from newRequest not previously stored
        for (java.util.Map.Entry<String, String[]> entry : newIdentityHeaders.entrySet()) {
            if (!replacedKeys.contains(entry.getKey())) {
                merged.add(entry.getValue());
            }
        }

        actor.setHeaders(merged);
        actor.setIdentitySourceUrl(newRequest.url());
        actor.setPwnfoxColor(newRequest.headerValue(com.acas.util.PwnFoxColors.HEADER));
        actor.setVerificationStatus(ActorProfile.VerificationStatus.UNVERIFIED);
        updateActor(actor);
        return true;
    }

    public List<ActorProfile> getAllActors() {
        return new ArrayList<>(actors);
    }

    public Optional<ActorProfile> getActorById(String id) {
        return actors.stream().filter(a -> a.getId().equals(id)).findFirst();
    }

    public ActorProfile getActor(String id) {
        return getActorById(id).orElse(null);
    }

    public void verifyActorSession(ActorProfile actor) {
        if (actor.getCapturedFrom() == null || actor.getCapturedFrom().isEmpty()) {
            actor.setVerificationStatus(ActorProfile.VerificationStatus.UNKNOWN);
            return;
        }

        try {
            burp.api.montoya.http.message.requests.HttpRequest verificationReq = buildVerificationRequest(actor);
            var rr = com.acas.engine.ReplayGate.send(api,verificationReq);
            
            if (rr.response() != null) {
                int code = rr.response().statusCode();
                if (code == 200) {
                    actor.setVerificationStatus(ActorProfile.VerificationStatus.VERIFIED);
                } else {
                    // Spec: Only 200 OK is a reliable proof the session is working
                    actor.setVerificationStatus(ActorProfile.VerificationStatus.UNVERIFIED);
                }
            } else {
                actor.setVerificationStatus(ActorProfile.VerificationStatus.UNVERIFIED);
            }
        } catch (Exception e) {
            api.logging().logToError("ACAS: Session verification failed for " + actor.getName() + ": " + e.getMessage());
            actor.setVerificationStatus(ActorProfile.VerificationStatus.UNVERIFIED);
        }
        updateActor(actor);
    }

    private burp.api.montoya.http.message.requests.HttpRequest buildVerificationRequest(ActorProfile actor) {
        burp.api.montoya.http.message.requests.HttpRequest base = burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(actor.getCapturedFrom());
        for (String[] h : actor.getHeaders()) {
            base = base.withHeader(h[0], h[1]);
        }
        return base;
    }

    private static final java.util.Set<String> IDENTITY_HEADER_NAMES = new java.util.HashSet<>(java.util.Set.of(
        "authorization", "cookie", "x-api-key", "x-auth-token", "token", "x-access-token", "jwt", "session"
    ));

    public java.util.Set<String> getAllIdentityHeaderNames() {
        java.util.Set<String> all = new java.util.HashSet<>(IDENTITY_HEADER_NAMES);
        for(String key:java.util.List.of("session_headers","csrf_headers","context_headers"))
            for(String name:getGlobalSetting("credential_"+key).split("[,\\s]+"))
                if(!name.isBlank())all.add(name.toLowerCase(java.util.Locale.ROOT));
        for (ActorProfile actor : actors) {
            for (String[] h : actor.getHeaders()) {
                if (isPotentialIdentityHeader(h[0])) {
                    all.add(h[0].toLowerCase());
                }
            }
        }
        return all;
    }

    private boolean isPotentialIdentityHeader(String name) {
        return new com.acas.util.CredentialPolicy(this).managedHeader(name);
    }

    private static final java.util.Set<String> NOISE_COOKIES = java.util.Set.of(
        "cf_clearance", "__cf_bm", "_ga", "_gid", "_clck", "_clsk", "_fbp", "amplitude", "mixpanel",
        "lang", "locale", "theme", "tz", "timezone", "currency", "consent"
    );

    public String getActorIdByRequest(burp.api.montoya.http.message.requests.HttpRequest request) {
        String matched=null;
        for(ActorProfile actor:actors) {
            if(request!=null && actorMatchesOrigin(actor,request.url()) && scoreActorMatch(request,actor)>0) {
                if(matched!=null)return null;
                matched=actor.getId();
            }
        }
        return matched;
    }

    public boolean actorMatchesOrigin(ActorProfile actor,String url) {
        try {return com.acas.util.CanonicalOrigin.actor(actor).equals(com.acas.util.CanonicalOrigin.of(url));}
        catch(IllegalArgumentException invalid){return false;}
    }

    private int scoreActorMatch(burp.api.montoya.http.message.requests.HttpRequest request, ActorProfile actor) {
        return request!=null && new com.acas.util.CredentialPolicy(this).matches(request,actor)?1:0;
    }

    public String getActiveActorId() { return activeActorId; }
    
    public synchronized void setActiveActorId(String id) {
        if (id != null && getActor(id)==null) return;
        if (java.util.Objects.equals(activeActorId,id)) return;
        captureGeneration++;
        this.activeActorId = id;
        if(id!=null)captureStoppedByUser=false;
        for(ActorProfile actor:actors)actor.setRecording(id!=null && id.equals(actor.getId()));
        notifyListeners();
        if(id!=null)captureWorkListener.run();
    }

    public void addHistoryEntry(String actorId, burp.api.montoya.http.message.requests.HttpRequest request, burp.api.montoya.http.message.responses.HttpResponse response) {
        getActorById(actorId).ifPresent(actor -> {
            try {
                int status = 0;
                int length = 0;
                String reqText = "";
                String respText = "";
                String method = "";
                String url = "";

                try {
                    if (response != null) {
                        status = response.statusCode();
                    }
                } catch (Throwable ignored) {
                }

                try {
                    if (response != null && response.body() != null) {
                        length = response.body().length();
                    }
                } catch (Throwable ignored) {
                }

                try {
                    if (request != null) {
                        method = request.method();
                    }
                } catch (Throwable ignored) {
                }

                try {
                    if (request != null) {
                        url = request.url();
                    }
                } catch (Throwable ignored) {
                }

                try {
                    if (request != null) {
                        reqText = new String(request.toByteArray().getBytes(), java.nio.charset.StandardCharsets.ISO_8859_1);
                    }
                } catch (Throwable ignored) {
                    try {
                        reqText = request != null ? String.valueOf(request) : "";
                    } catch (Throwable ignored2) {
                        reqText = "";
                    }
                }

                try {
                    if (response != null) {
                        respText = new String(response.toByteArray().getBytes(), java.nio.charset.StandardCharsets.ISO_8859_1);
                    }
                } catch (Throwable ignored) {
                    try {
                        respText = response != null ? String.valueOf(response) : "";
                    } catch (Throwable ignored2) {
                        respText = "";
                    }
                }

                actor.addHistory(reqText, respText, method, url, status, length);
                requestCaptureSave();
                notifyListeners();
            } catch (Throwable t) {
                api.logging().logToError("ACAS: Failed to add history entry: " + t.getMessage());
            }
        });
    }

    private boolean sameCapture(com.acas.model.CapturedEndpoint a,com.acas.model.CapturedEndpoint b) {
        return a.getId()!=null && a.getId().equals(b.getId());
    }
    public synchronized void addObservedEndpoint(com.acas.model.CapturedEndpoint endpoint) {
        // Identical observations can be deduplicated, but never replace earlier evidence.
        boolean duplicate=capturedEndpoints.stream().anyMatch(e->java.util.Objects.equals(e.getActorId(),endpoint.getActorId())
            && java.util.Objects.equals(e.getMethod(),endpoint.getMethod()) && java.util.Objects.equals(e.getOriginalUrl(),endpoint.getOriginalUrl())
            && java.util.Arrays.equals(e.getOriginalRequestBytes(),endpoint.getOriginalRequestBytes())
            && java.util.Arrays.equals(e.getOriginalResponseBytes(),endpoint.getOriginalResponseBytes()));
        if(!duplicate)addCapturedEndpoint(endpoint);
    }
    public synchronized void addCapturedEndpoint(com.acas.model.CapturedEndpoint endpoint) {
        if(endpoint.getId()==null || endpoint.getId().isBlank())endpoint.setId(java.util.UUID.randomUUID().toString());
        endpoint.freezeEvidence();
        // Keep immutable capture versions distinct.
        java.util.Optional<com.acas.model.CapturedEndpoint> existing = capturedEndpoints.stream()
            .filter(e -> sameCapture(e,endpoint))
            .findFirst();
        
        if (existing.isPresent()) {
            // Update the existing entry's results rather than adding a new row
            com.acas.model.CapturedEndpoint e = existing.get();
            e.setClassificationLabel(endpoint.getClassificationLabel());
            e.setAutomaticProbeNote(endpoint.getAutomaticProbeNote());
            if(e!=endpoint) {
                e.setConfidenceScore(endpoint.getConfidenceScore());e.setPriorityScore(endpoint.getPriorityScore());
                e.setSubLabel(endpoint.getSubLabel());e.setPerpetratorId(endpoint.getPerpetratorId());
                if(!java.util.Arrays.equals(e.getOriginalRequestBytes(),endpoint.getOriginalRequestBytes()) || !java.util.Arrays.equals(e.getOriginalResponseBytes(),endpoint.getOriginalResponseBytes()))throw new IllegalArgumentException("Capture evidence changed under an existing ID");
                e.setOriginalRequestBytes(endpoint.getOriginalRequestBytes());e.setOriginalResponseBytes(endpoint.getOriginalResponseBytes());
                synchronized(e){e.getProbes().clear();e.getProbes().addAll(endpoint.getProbes());}
            }
            // Track new traffic time for stale detection
            e.setLastTrafficTime(System.currentTimeMillis());
            // If this endpoint was previously hunted and is now stale, mark it
            if (e.isStale() && e.getHuntStatus() != com.acas.model.CapturedEndpoint.HuntStatus.RUNNING) {
                e.setHuntStatus(com.acas.model.CapturedEndpoint.HuntStatus.STALE);
            }
        } else {
            endpoint.setLastTrafficTime(System.currentTimeMillis());
            capturedEndpoints.add(endpoint);
        }
        
        requestCaptureSave();
        notifyListeners();
    }

    public List<com.acas.model.CapturedEndpoint> getCapturedEndpoints() {
        return new ArrayList<>(capturedEndpoints);
    }

    /**
     * Check completed authorization probes for this actor, method and exact URL.
     * A captured owner response alone is not a completed authorization test.
     */
    public boolean hasBeenProbed(String actorId,String method, String url) {
        return capturedEndpoints.stream()
            .anyMatch(e -> java.util.Objects.equals(e.getActorId(),actorId) &&
                          java.util.Objects.equals(e.getMethod(),method) &&
                          java.util.Objects.equals(e.getOriginalUrl(),url) &&
                          !"PENDING".equals(e.getClassificationLabel()) &&
                          e.getProbes().stream().anyMatch(p->!p.isBaseline));
    }

    public synchronized List<ActorProfile> exportActors() {
        return new ArrayList<>(actors);
    }

    public synchronized List<com.acas.model.CapturedEndpoint> exportCapturedEndpoints() {
        return new ArrayList<>(capturedEndpoints);
    }

    public synchronized java.util.Map<String, String> exportKnownSettings() {
        java.util.Map<String, String> settings = new java.util.HashMap<>();
        settings.put("tg_bot_token", getSetting("tg_bot_token"));
        settings.put("tg_chat_id", getSetting("tg_chat_id"));
        settings.put("discord_webhook", getSetting("discord_webhook"));
        settings.put("alert_trigger", getSetting("alert_trigger"));
        return settings;
    }

    public synchronized void applyKnownSettings(java.util.Map<String, String> settings) {
        if (settings == null) return;
        for (java.util.Map.Entry<String, String> entry : settings.entrySet()) {
            if (entry.getKey() != null) {
                setSetting(entry.getKey(), entry.getValue() != null ? entry.getValue() : "");
            }
        }
    }

    public synchronized void clearKnownSettings() {
        setSetting("tg_bot_token", "");
        setSetting("tg_chat_id", "");
        setSetting("discord_webhook", "");
        setSetting("alert_trigger", "");
    }

    public synchronized void replaceWorkspaceState(List<ActorProfile> importedActors,
                                                   ScopeConfig importedScope,
                                                   List<com.acas.model.CapturedEndpoint> importedEndpoints,
                                                   String importedActiveActorId) {
        List<ActorProfile> nextActors = importedActors == null ? List.of() : List.copyOf(importedActors);
        List<com.acas.model.CapturedEndpoint> nextEndpoints = importedEndpoints == null ? List.of() : List.copyOf(importedEndpoints);
        ScopeConfig nextScope = importedScope != null ? importedScope : new ScopeConfig();
        WorkspaceValidator.validate(nextActors, nextScope, nextEndpoints, importedActiveActorId);
        actors.clear();
        actors.addAll(nextActors);
        scopeConfig = nextScope;
        capturedEndpoints.clear();
        for (com.acas.model.CapturedEndpoint endpoint : nextEndpoints) {
            endpoint.restoreTransientMessages();
            capturedEndpoints.add(endpoint);
        }
        captureGeneration++;
        activeActorId = null;
        actors.forEach(a -> a.setRecording(false));
        reclassifyCapturedEndpoints();
        saveToPersistence();
        saveScopeConfig(scopeConfig);
        saveEndpointsToPersistence();
        notifyListeners();
    }

    public synchronized void clearWorkspaceState() {
        clearWorkspaceState(false);
    }

    public synchronized void clearWorkspaceState(boolean clearSettings) {
        captureGeneration++;
        actors.clear();
        capturedEndpoints.clear();
        scopeConfig = new ScopeConfig();
        activeActorId = null;
        if (clearSettings) {
            clearKnownSettings();
        }
        saveToPersistence();
        saveScopeConfig(scopeConfig);
        saveEndpointsToPersistence();
        notifyListeners();
    }

    public synchronized void confirmEndpointResource(com.acas.model.CapturedEndpoint endpoint, String ownerActorId,
            com.acas.model.AccessPolicy accessPolicy, String resourceType, String resourceId, String tenantId,
            com.acas.model.OperationSafety operationSafety, boolean operationApproved, String operationSafetyReason) {
        if (endpoint == null || !capturedEndpoints.contains(endpoint)) throw new IllegalArgumentException("Unknown captured request");
        String owner = ownerActorId == null || ownerActorId.isBlank() ? null : ownerActorId;
        if (owner != null && getActor(owner) == null) throw new IllegalArgumentException("Unknown resource owner");
        if (endpoint.getResourceOwnerActorId() != null && !java.util.Objects.equals(endpoint.getResourceOwnerActorId(), owner))
            throw new IllegalArgumentException("Resource ownership must be reconciled explicitly by creating a new record");
        if (owner != null) endpoint.setResourceOwnerActorId(owner);
        endpoint.setAccessPolicy(accessPolicy);
        endpoint.setResourceType(resourceType);
        endpoint.setResourceId(resourceId);
        endpoint.setTenantId(tenantId);
        com.acas.model.OperationSafety safety = operationSafety == null ? com.acas.model.OperationSafety.UNKNOWN : operationSafety;
        String reason = operationSafetyReason == null ? null : operationSafetyReason.trim();
        if (safety != com.acas.model.OperationSafety.UNKNOWN && (reason == null || reason.isBlank()))
            throw new IllegalArgumentException("Operation safety requires an operator-visible reason");
        if (operationApproved && safety == com.acas.model.OperationSafety.UNKNOWN)
            throw new IllegalArgumentException("An operation with unknown safety cannot be approved");
        endpoint.setOperationSafety(safety);
        endpoint.setOperationSafetyReason(reason);
        endpoint.setOperationApproved(operationApproved);
        saveEndpointsToPersistence();
        notifyListeners();
    }

    public void removeEndpoint(com.acas.model.CapturedEndpoint ep) {
        capturedEndpoints.remove(ep);
        saveEndpointsToPersistence();
        notifyListeners();
    }

    public void clearCapturedEndpoints() {
        capturedEndpoints.clear();
        saveEndpointsToPersistence();
        notifyListeners();
    }

    public void saveEndpointsToPersistence() {
        try {
            api.persistence().extensionData().setString("acas_captured_endpoints", gson.toJson(capturedEndpoints));
        } catch (Exception e) {
            api.logging().logToError("ACAS: Error saving endpoints: " + e.getMessage());
        }
    }

    /** Refresh derived labels from stored evidence without sending any requests. */
    public void reclassifyCapturedEndpoints() {
        com.acas.engine.ClassifierEngine classifier = new com.acas.engine.ClassifierEngine(api);
        List<ActorProfile> snapshot = getAllActors();
        for (com.acas.model.CapturedEndpoint endpoint : capturedEndpoints) {
            synchronized (endpoint) { classifier.classify(endpoint, snapshot); }
        }
    }

    public void deleteHistoryEntry(String actorId, int index) {
        getActorById(actorId).ifPresent(actor -> {
            List<ActorProfile.HistoryEntry> history = actor.getCaptureHistory();
            if (index >= 0 && index < history.size()) {
                history.remove(index);
                saveToPersistence();
                notifyListeners();
            }
        });
    }

    public void clearActorHistory(String actorId) {
        getActorById(actorId).ifPresent(actor -> {
            actor.getCaptureHistory().clear();
            saveToPersistence();
            notifyListeners();
        });
    }

    public ScopeConfig getScopeConfig() { return scopeConfig; }

    public void saveScopeConfig(ScopeConfig config) {
        this.scopeConfig = config;
        try {
            api.persistence().extensionData().setString(SCOPE_KEY, gson.toJson(config));
        } catch (Exception e) {
            api.logging().logToError("ACAS: Error saving scope: " + e.getMessage());
        }
    }

    public void setSetting(String key, String value) {
        try {
            api.persistence().extensionData().setString(SETTINGS_KEY + "_" + key, value);
        } catch (Exception e) {
            api.logging().logToError("ACAS: Error saving setting: " + e.getMessage());
        }
    }

    public String getSetting(String key) {
        try {
            String val = api.persistence().extensionData().getString(SETTINGS_KEY + "_" + key);
            return val != null ? val : "";
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Global (cross-project, cross-restart) settings backed by Burp user
     * preferences. Used for things that should persist until the user changes
     * them again — e.g. Telegram/Discord credentials and the capture blacklist.
     */
    public void setGlobalSetting(String key, String value) {
        try {
            api.persistence().preferences().setString(SETTINGS_KEY + "_" + key, value != null ? value : "");
        } catch (Exception e) {
            api.logging().logToError("ACAS: Error saving global setting: " + e.getMessage());
        }
    }

    public String getGlobalSetting(String key) {
        try {
            String val = api.persistence().preferences().getString(SETTINGS_KEY + "_" + key);
            return val != null ? val : "";
        } catch (Exception e) {
            return "";
        }
    }

    public void addChangeListener(Runnable listener) {
        changeListeners.add(listener);
    }

    private void notifyListeners() {
        changeListeners.forEach(Runnable::run);
    }

    private void saveToPersistence() {
        try {
            api.persistence().extensionData().setString(ACTORS_KEY, gson.toJson(actors));
        } catch (Exception e) {
            api.logging().logToError("ACAS: Error saving actors: " + e.getMessage());
        }
    }

    private void loadFromPersistence() {
        try {
            String actorsJson = api.persistence().extensionData().getString(ACTORS_KEY);
            if (actorsJson != null && !actorsJson.isEmpty()) {
                Type listType = new TypeToken<List<ActorProfile>>() {}.getType();
                List<ActorProfile> loaded = gson.fromJson(actorsJson, listType);
                if (loaded != null) {
                    for (ActorProfile a : loaded) {
                        if (a != null) {a.migrateLegacyRoleLevel();a.setCaptureHistory(a.getCaptureHistory());}
                    }
                    actors.addAll(loaded);
                }
            }
            String scopeJson = api.persistence().extensionData().getString(SCOPE_KEY);
            if (scopeJson != null && !scopeJson.isEmpty()) {
                ScopeConfig loaded = gson.fromJson(scopeJson, ScopeConfig.class);
                if (loaded != null) scopeConfig = loaded;
            }
            String endpointsJson = api.persistence().extensionData().getString("acas_captured_endpoints");
            if (endpointsJson != null && !endpointsJson.isEmpty()) {
                Type listType = new TypeToken<List<com.acas.model.CapturedEndpoint>>() {}.getType();
                List<com.acas.model.CapturedEndpoint> loaded = gson.fromJson(endpointsJson, listType);
                if (loaded != null) {
                    for (com.acas.model.CapturedEndpoint endpoint : loaded) {
                        endpoint.setProbes(endpoint.getProbes());
                        if(endpoint.getId()==null || endpoint.getId().isBlank())endpoint.setId(java.util.UUID.randomUUID().toString());
                        endpoint.freezeEvidence();
                        endpoint.restoreTransientMessages();
                        capturedEndpoints.add(endpoint);
                    }
                }
            }
            reclassifyCapturedEndpoints();
            saveEndpointsToPersistence();
        } catch (Exception e) {
            api.logging().logToError("ACAS: Error loading data: " + e.getMessage());
        }
    }
}
