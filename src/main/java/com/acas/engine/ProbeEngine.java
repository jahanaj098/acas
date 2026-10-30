package com.acas.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.acas.model.AcasFinding;
import com.acas.model.ActorProfile;
import com.acas.model.CapturedEndpoint;
import com.acas.store.ActorStore;
import com.acas.util.HttpUtils;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

public class ProbeEngine {
    private final MontoyaApi api;
    private final ActorStore store;
    private final ReplayEngine replayer;
    private final DiscoveryEngine discovery;
    private final ClassifierEngine classifier;
    private final ResponseComparator responseComparator = new ResponseComparator();
    private final ExecutorService executor = Executors.newFixedThreadPool(8); // Increased for parallel swaps
    private volatile SeverityClassifier severityClassifier;
    private final java.util.concurrent.ThreadPoolExecutor automaticExecutor=new java.util.concurrent.ThreadPoolExecutor(
        4,8,60L,java.util.concurrent.TimeUnit.SECONDS,new java.util.concurrent.LinkedBlockingQueue<>(),
        r->{Thread t=new Thread(r,"ACAS-automatic-probes");t.setDaemon(true);return t;});
    private final java.util.Set<String> queuedAutomatic=java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final java.util.concurrent.atomic.AtomicBoolean scanPending=new java.util.concurrent.atomic.AtomicBoolean();

    public void scheduleMissingProbes() {
        if(!scanPending.compareAndSet(false,true))return;
        try {
            automaticExecutor.submit(()->{
                scanPending.set(false);
                for(CapturedEndpoint endpoint:store.getCapturedEndpoints())
                    runProbes(store.probeSession(endpoint.getActorId()),endpoint.getOriginalRequest(),store::addCapturedEndpoint,endpoint.getId());
            });
        } catch(java.util.concurrent.RejectedExecutionException stopped) {scanPending.set(false);}
    }


    public ProbeEngine(MontoyaApi api, ActorStore store, ReplayEngine replayer, DiscoveryEngine discovery, ClassifierEngine classifier) {
        this.api = api;
        this.store = store;
        this.replayer = replayer; // Restored
        this.discovery = discovery;
        this.classifier = classifier;
    }

    public void setSeverityClassifier(SeverityClassifier severityClassifier) {
        this.severityClassifier = severityClassifier;
    }

    public HttpRequest buildBaselineRequest(HttpRequest original, String actorId) {
        ActorProfile actor = store.getActor(actorId);
        if (actor == null) return original;
        return replayer.buildActorRequest(original, actor);
    }

    public HttpRequest buildAnonymousRequest(HttpRequest original) {
        return new com.acas.util.CredentialPolicy(store).anonymous(original, store.getAllIdentityHeaderNames());
    }

    public HttpRequest buildSwapRequest(HttpRequest original, String ownerId) {
        List<ActorProfile> allActors = store.getAllActors();
        for (ActorProfile actor : allActors) {
            if (!actor.getId().equals(ownerId)) {
                return replayer.buildActorRequest(original, actor);
            }
        }
        return original;
    }

    public void runProbes(String ownerId, HttpRequest request, Consumer<CapturedEndpoint> onComplete) {
        runProbes(store.captureSession(ownerId),request,onComplete);
    }
    public void recordObserved(String ownerId,HttpRequest request,burp.api.montoya.http.message.responses.HttpResponse response) {
        ActorProfile owner=store.getActor(ownerId);
        if(owner==null)return;
        CapturedEndpoint endpoint=new CapturedEndpoint();
        endpoint.setActorId(ownerId);endpoint.setMethod(request.method());endpoint.setOriginalUrl(request.url());
        endpoint.setNormalizedPath(discovery.normalizePath(request.path()));endpoint.setSegments(discovery.getSegments(request.path()));
        endpoint.setPriority(discovery.isPriorityPath(request.path()));
        endpoint.setOriginalRequest(request);endpoint.setOriginalResponse(response);
        endpoint.addProbeResult(owner.getName(),response==null?0:response.statusCode(),response==null?0:response.body().length(),
            true,endpoint.getOriginalRequestBytes(),endpoint.getOriginalResponseBytes());
        store.addObservedEndpoint(endpoint);
    }
    public void runProbes(ActorStore.CaptureSession session, HttpRequest request, Consumer<CapturedEndpoint> onComplete) {
        runProbes(session,request,onComplete,null);
    }
    private void runProbes(ActorStore.CaptureSession session, HttpRequest request, Consumer<CapturedEndpoint> onComplete,String captureId) {
        if(!store.isCaptureCurrent(session) || request==null)return;
        String key=session.generation()+"\n"+session.actorId()+"\n"+(captureId==null?com.acas.export.HermesExport.hash(request.toByteArray().getBytes()):captureId);
        if(!queuedAutomatic.add(key))return;
        try { automaticExecutor.submit(()->{
            try {
                if(!store.isCaptureCurrent(session))return;
                CapturedEndpoint observed=store.getCapturedEndpoints().stream().filter(ep ->
                    session.actorId().equals(ep.getActorId()) && request.method().equals(ep.getMethod())
                    && request.url().equals(ep.getOriginalUrl()) && (captureId!=null?captureId.equals(ep.getId()):java.util.Arrays.equals(ep.getOriginalRequestBytes(),request.toByteArray().getBytes())))
                    .reduce((older,newer)->newer).orElse(null);
                if(observed==null || observed.getOriginalResponse()==null)return;
                // Work on a private copy. Stop invalidates publication, including in-flight responses.
                CapturedEndpoint endpoint=observed.copyForProbe();
                boolean changed=false;
                if(endpoint.getProbes().stream().noneMatch(p->p.identityType==CapturedEndpoint.ProbeIdentity.ANONYMOUS)) {
                    if(!runAutomaticProbe(session,endpoint,null))return;
                    changed=true;
                }
                List<ActorProfile> actors=store.getAllActors();
                for(ActorProfile actor:actors) {
                    if(actor.getId().equals(session.actorId()) || !actor.isAutoProbeEnabled()
                        || !store.actorMatchesOrigin(actor,request.url()))continue;
                    boolean exists=endpoint.getProbes().stream().anyMatch(p -> !p.isBaseline &&
                        (p.identityType==CapturedEndpoint.ProbeIdentity.ACTOR && actor.getId().equals(p.actorId)));
                    if(exists)continue;
                    if(!runAutomaticProbe(session,endpoint,actor))return;
                    changed=true;
                }
                endpoint.setAutomaticProbeNote(null);
                // Classification can parse large bodies: never hold the capture
                // monitor needed by the EDT's Record/Stop actions while doing it.
                if(changed)classifier.classify(endpoint,actors);
                if(changed)store.whileCaptureCurrent(session,()->{
                    // A newer browser response must not be overwritten by an older in-flight test.
                    if(!java.util.Arrays.equals(observed.getOriginalRequestBytes(),endpoint.getOriginalRequestBytes())
                        || !java.util.Arrays.equals(observed.getOriginalResponseBytes(),endpoint.getOriginalResponseBytes()))return;
                    promoteStrongProbeSignal(endpoint,actors);
                    emitAllResults(endpoint,actors);
                    onComplete.accept(endpoint);
                });
            } catch(IllegalArgumentException error) {
                store.whileCaptureCurrent(session,()->{
                    for(CapturedEndpoint ep:store.getCapturedEndpoints())if(session.actorId().equals(ep.getActorId())
                        && request.method().equals(ep.getMethod()) && request.url().equals(ep.getOriginalUrl())) {
                        ep.setAutomaticProbeNote(error.getMessage());ep.setSubLabel(error.getMessage());
                        store.addCapturedEndpoint(ep);
                    }
                });
                api.logging().logToOutput("ACAS: "+error.getMessage());
            } catch(Throwable error) {
                api.logging().logToError("ACAS automatic probes: "+error.getMessage());
            } finally {queuedAutomatic.remove(key);}
        }); } catch(java.util.concurrent.RejectedExecutionException full) {
            queuedAutomatic.remove(key);
            // The baseline stays captured. Missing probes can be scheduled again
            // after the backlog drains; never run network work on the caller/EDT.
            if(!automaticExecutor.isShutdown())api.logging().logToOutput("ACAS probe queue full: baseline retained; use Re-run Swap + Anonymous for pending tests.");
        }
    }

    private boolean runAutomaticProbe(ActorStore.CaptureSession session,CapturedEndpoint endpoint,ActorProfile actor) {
        if(!store.isCaptureCurrent(session))return false;
        HttpRequest probe=actor==null?buildAnonymousRequest(endpoint.getOriginalRequest())
            :buildBaselineRequest(endpoint.getOriginalRequest(),actor.getId());
        if(!store.isCaptureCurrent(session))return false;
        var result=safeSendRequest(probe);
        if(!store.isCaptureCurrent(session))return false;
        endpoint.addActorProbeResult(actor==null?null:actor.getId(),actor==null?"Anonymous":actor.getName(),
            result.response()==null?0:result.response().statusCode(),result.response()==null?0:result.response().body().length(),
            probe.toByteArray().getBytes(),result.response()==null?null:result.response().toByteArray().getBytes());
        return true;
    }

    /**
     * Re-fires the two authorization tests (baseline owner, anonymous, and a
     * session swap for every other actor) against an already-captured endpoint,
     * replacing its probe results in place. Used by the Captured History
     * "Re-run Swap + Anonymous" action — no Hunt Hub / queue involved.
     */
    public void rerunProbes(CapturedEndpoint endpoint, Runnable onComplete) {
        if (endpoint == null || endpoint.getOriginalRequest() == null) {
            if (onComplete != null) onComplete.run();
            return;
        }
        executor.submit(() -> {
            try {
                HttpRequest request = endpoint.getOriginalRequest();
                String ownerId = endpoint.getActorId();
                ActorProfile owner = store.getActor(ownerId);
                List<ActorProfile> allActors = store.getAllActors();

                // Baseline (owner)
                if (owner != null) {
                    HttpRequest p1 = replayer.buildActorRequest(request, owner);
                    var r1 = safeSendRequest(p1);
                    endpoint.setOriginalResponse(r1.response());
                    synchronized (endpoint) {
                        endpoint.addProbeResult(owner.getName(),
                            r1.response() != null ? r1.response().statusCode() : 0,
                            r1.response() != null ? r1.response().body().length() : 0,
                            true, p1.toByteArray().getBytes(),
                            r1.response() != null ? r1.response().toByteArray().getBytes() : null);
                    }
                }

                // Anonymous
                HttpRequest p2 = buildAnonymousRequest(request);
                var r2 = safeSendRequest(p2);
                synchronized (endpoint) {
                    endpoint.addProbeResult("Anonymous",
                        r2.response() != null ? r2.response().statusCode() : 0,
                        r2.response() != null ? r2.response().body().length() : 0,
                        false, p2.toByteArray().getBytes(),
                        r2.response() != null ? r2.response().toByteArray().getBytes() : null);
                }

                // Session swap for every other actor
                java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(
                    (int) allActors.stream().filter(a -> !a.getId().equals(ownerId)).count());
                for (ActorProfile actor : allActors) {
                    if (actor.getId().equals(ownerId)) continue;
                    executor.submit(() -> {
                        try {
                            HttpRequest swap = replayer.buildActorRequest(request, actor);
                            var rs = safeSendRequest(swap);
                            synchronized (endpoint) {
                                endpoint.addProbeResult(actor.getName(),
                                    rs.response() != null ? rs.response().statusCode() : 0,
                                    rs.response() != null ? rs.response().body().length() : 0,
                                    false, swap.toByteArray().getBytes(),
                                    rs.response() != null ? rs.response().toByteArray().getBytes() : null);
                            }
                        } finally {
                            latch.countDown();
                        }
                    });
                }
                latch.await(60, java.util.concurrent.TimeUnit.SECONDS);

                classifier.classify(endpoint, allActors);
                promoteStrongProbeSignal(endpoint, allActors);
                emitAllResults(endpoint, allActors);
                store.saveEndpointsToPersistence();
            } catch (Throwable e) {
                api.logging().logToError("ACAS Rerun Error: " + e.getMessage());
            } finally {
                if (onComplete != null) onComplete.run();
            }
        });
    }

    protected burp.api.montoya.http.message.HttpRequestResponse safeSendRequest(HttpRequest request) {
        if (request.httpService() == null) {
            try {
                java.net.URI uri = java.net.URI.create(request.url());
                java.net.URL u = uri.toURL();
                request = request.withService(burp.api.montoya.http.HttpService.httpService(u.getHost(), u.getPort() == -1 ? u.getDefaultPort() : u.getPort(), u.getProtocol().equalsIgnoreCase("https")));
            } catch (Exception e) {
                api.logging().logToError("ACAS Probe: Failed to reconstruct HttpService from " + request.url());
            }
        }
        HttpRequest internalReq = request.hasHeader(com.acas.engine.ReplayEngine.ACAS_INTERNAL_HEADER)
            ? request : request.withHeader(com.acas.engine.ReplayEngine.ACAS_INTERNAL_HEADER, "true");
        try {
            return api.http().sendRequest(internalReq);
        } catch (Exception e) {
            return com.acas.engine.ReplayGate.send(api, internalReq);
        }
    }


    public void runSingleProbe(String ownerId, int type, HttpRequest request, CapturedEndpoint ep, java.util.function.BiConsumer<Boolean, burp.api.montoya.http.message.responses.HttpResponse> onComplete) {
        executor.submit(() -> {
            try {
                ActorProfile owner = store.getActor(ownerId);
                List<ActorProfile> allActors = store.getAllActors();
                HttpRequest probeReq;
                String probeActorName;
                
                if (type == 0) { // Baseline
                    probeReq = replayer.buildActorRequest(request, owner);
                    probeActorName = owner.getName();
                } else if (type == 1) { // Anon
                    probeReq = HttpUtils.stripAuthHeaders(request, store.getAllIdentityHeaderNames());
                    probeActorName = "Anonymous";
                } else { // Swap
                    ActorProfile target = allActors.stream().filter(a -> !a.getId().equals(ownerId))
                        .findFirst().orElseThrow(() -> new IllegalStateException("A second actor is required for a swap"));
                    probeReq = replayer.buildActorRequest(request, target);
                    probeActorName = target.getName();
                }

                var rr = safeSendRequest(probeReq);
                int status = rr.response() != null ? rr.response().statusCode() : 0;
                int length = rr.response() != null ? rr.response().body().length() : 0;

                // Update the model
                synchronized (ep) {
                    ep.addProbeResult(probeActorName, status, length, type == 0,
                        probeReq.toByteArray().getBytes(), 
                        rr.response() != null ? rr.response().toByteArray().getBytes() : null);
                }
                
                // Persistence
                classifier.classify(ep, allActors);
                promoteStrongProbeSignal(ep, allActors);
                emitAllResults(ep, allActors);
                store.saveEndpointsToPersistence();
                onComplete.accept(true, rr.response());
            } catch (Throwable e) {
                api.logging().logToError("ACAS Manual Probe Error: " + e.getMessage());
                onComplete.accept(false, null);
            }
        });
    }

    public void runTargetedProbe(CapturedEndpoint ep, ActorProfile actor, Runnable onComplete) {
        executor.submit(() -> {
            try {
                HttpRequest original = ep.getOriginalRequest();
                
                // Build the probe request for this specific actor
                HttpRequest probeReq = replayer.buildActorRequest(original, actor);
                var rr = safeSendRequest(probeReq);
                
                int status = rr.response() != null ? rr.response().statusCode() : 0;
                int length = rr.response() != null ? rr.response().body().length() : 0;
                
                // Update the model (Grid Model aware addProbeResult handles replacement)
                synchronized(ep) {
                    ep.addProbeResult(actor.getName(), 
                        status, 
                        length, 
                        false, 
                        probeReq.toByteArray().getBytes(), 
                        rr.response() != null ? rr.response().toByteArray().getBytes() : null);
                }
                
                // Ensure persistence
                List<ActorProfile> actors = store.getAllActors();
                classifier.classify(ep, actors);
                promoteStrongProbeSignal(ep, actors);
                emitAllResults(ep, actors);
                store.saveEndpointsToPersistence();
                onComplete.run();
                
            } catch (Throwable e) {
                api.logging().logToError("ACAS Targeted Probe Error: " + e.getMessage());
                onComplete.run();
            }
        });
    }

    public void syncMissingProbes(CapturedEndpoint ep, List<ActorProfile> allActors, Runnable onComplete) {
        runProbes(store.captureSession(ep.getActorId()),ep.getOriginalRequest(),updated -> {
            store.addCapturedEndpoint(updated);
            if(onComplete!=null)onComplete.run();
        });
    }

    /**
     * Back-fills the Result Matrix from every already-probed captured endpoint,
     * so endpoints tested before this feature existed (or before a reload) still
     * show up. Safe to call repeatedly — findings dedupe on endpoint+actor+status.
     */
    public void backfillResults() {
        try {
            List<ActorProfile> allActors = store.getAllActors();
            for (CapturedEndpoint ep : store.getCapturedEndpoints()) {
                if (ep == null || ep.getProbes() == null || ep.getProbes().isEmpty()) continue;
                classifier.classify(ep, allActors);
                emitAllResults(ep, allActors);
            }
            store.saveEndpointsToPersistence();
        } catch (Throwable e) {
            api.logging().logToError("ACAS Backfill error: " + e.getMessage());
        }
    }

    /**
     * Emits one Result Matrix row for EVERY swap/anonymous probe of an endpoint
     * (not just auto-promoted strong findings), so the matrix is a complete view
     * of all swap + anonymous outcomes. Secure/blocked results are recorded as
     * INFO; a 2xx that mirrors the owner baseline is raised. Dedup keys on
     * endpoint + actor + mutation + status, so re-runs don't pile up.
     */
    private void emitAllResults(CapturedEndpoint endpoint, List<ActorProfile> allActors) {
        SeverityClassifier sev = this.severityClassifier;
        if (sev == null || endpoint == null || endpoint.getProbes() == null || endpoint.getProbes().isEmpty()) {
            return;
        }

        CapturedEndpoint.ProbeResult baseline = endpoint.getProbes().stream()
            .filter(p -> p != null && p.isBaseline).findFirst().orElse(null);
        CapturedEndpoint.ProbeResult anonProbe = endpoint.getProbes().stream()
            .filter(p -> p != null && !p.isBaseline && p.identityType==CapturedEndpoint.ProbeIdentity.ANONYMOUS)
            .findFirst().orElse(null);
        ActorProfile owner = store.getActor(endpoint.getActorId());
        int baseStatus = baseline != null ? baseline.statusCode : 0;
        sev.revalidateProbeFindings(endpoint.getOriginalUrl(), endpoint.getMethod());

        // Optional: only record actual hits (skip secure/INFO rows) to keep the
        // matrix lean on large scopes. Settings → "record only hits".
        boolean onlyHits = "true".equalsIgnoreCase(store.getGlobalSetting("matrix_only_hits"));

        String epLabel = endpoint.getClassificationLabel() != null ? endpoint.getClassificationLabel() : "";

        for (CapturedEndpoint.ProbeResult pr : endpoint.getProbes()) {
            if (pr == null || pr.isBaseline) continue;

            boolean anon = pr.identityType==CapturedEndpoint.ProbeIdentity.ANONYMOUS;
            boolean broken = "BROKEN".equalsIgnoreCase(pr.verdict);
            boolean accessible = pr.statusCode >= 200 && pr.statusCode < 300;
            boolean blocked = pr.statusCode == 401 || pr.statusCode == 403;

            if (onlyHits && !broken) continue;

            String verdict;
            String severity;
            if (broken) {
                verdict = "BROKEN (" + pr.statusCode + ")";
                if (anon || epLabel.contains("ANON")) severity = "HIGH";
                else if (epLabel.contains("PRIV_ESC")) severity = "HIGH";
                else severity = "MEDIUM";
            } else if (accessible) {
                verdict = "ACCESSIBLE (" + pr.statusCode + ")";
                severity = "INFO";
            } else if (blocked) {
                verdict = "BLOCKED (" + pr.statusCode + ")";
                severity = "INFO";
            } else {
                verdict = "Status " + pr.statusCode;
                severity = "INFO";
            }

            AcasFinding f = new AcasFinding();
            f.setSource(anon ? "Anonymous Test" : "Session Swap");
            f.setSeverity(severity);
            f.setLabel(broken ? (anon ? "ANON_BROKEN" : epLabel) : blocked ? "ACCESS_BLOCKED" : "NO_CONFIRMED_BYPASS");
            f.setMutationType(anon ? "A1" : "B1");
            f.setMutationDescription((anon ? "Anonymous (no session)" : "Session swap → " + pr.actorName) + " — " + verdict);
            f.setOwnerActorName(owner != null ? owner.getName() : "Owner");
            f.setReplayerActorName(anon ? "Anonymous" : pr.actorName);
            f.setReplayed(true);
            f.setMethod(endpoint.getMethod());
            f.setUrl(endpoint.getOriginalUrl());
            f.setEndpointPattern(endpoint.getNormalizedPath());
            if (baseline != null) {
                f.setBaseRequest(baseline.request);
                f.setBaseResponse(baseline.response);
                f.setBaseStatus(baseline.statusCode);
                f.setBaseLength(baseline.responseLength);
            }
            // Populate the Anonymous detail tab (the anon probe for this endpoint).
            if (anonProbe != null) {
                f.setAnonymousRequest(anonProbe.request);
                f.setAnonymousResponse(anonProbe.response);
                f.setAnonymousStatus(anonProbe.statusCode);
                f.setAnonymousLength(anonProbe.responseLength);
            }
            f.setMutatedRequest(pr.request);
            f.setMutatedResponse(pr.response);
            f.setMutatedStatus(pr.statusCode);
            f.setMutatedLength(pr.responseLength);
            f.setConfidenceScore(broken ? 75 : (accessible ? 30 : 10));
            f.setAnalysisNote("Swap/Anon result. baseline=" + baseStatus + ", result=" + pr.statusCode + ", verdict=" + verdict
                + (!broken ? ". No cross-user data exposure confirmed; successful access alone is not a bypass." : ""));

            sev.addFindingIfUnique(f);
        }
    }

    private void promoteStrongProbeSignal(CapturedEndpoint endpoint, List<ActorProfile> allActors) {
        SeverityClassifier sev = this.severityClassifier;
        if (sev == null || endpoint == null || endpoint.getProbes() == null || endpoint.getProbes().isEmpty()) {
            return;
        }

        CapturedEndpoint.ProbeResult baseline = endpoint.getProbes().stream()
            .filter(p -> p != null && p.isBaseline)
            .findFirst().orElse(null);
        CapturedEndpoint.ProbeResult anonymous = endpoint.getProbes().stream()
            .filter(p -> p != null && !p.isBaseline && p.identityType==CapturedEndpoint.ProbeIdentity.ANONYMOUS)
            .findFirst().orElse(null);

        if (baseline == null || baseline.response == null || anonymous == null) {
            return;
        }

        CapturedEndpoint.ProbeResult bestSwap = null;
        ResponseComparator.AccessPatternSignal bestSignal = null;

        for (CapturedEndpoint.ProbeResult pr : endpoint.getProbes()) {
            if (pr == null || pr.isBaseline) continue;
            if (pr.identityType==CapturedEndpoint.ProbeIdentity.ANONYMOUS) continue;
            if (pr.statusCode < 200 || pr.statusCode >= 300) continue;
            if (pr.response == null) continue;

            ResponseComparator.AccessPatternSignal signal = responseComparator.analyzeAccessPattern(
                baseline.statusCode,
                extractResponseBody(baseline.response),
                anonymous.statusCode,
                extractResponseBody(anonymous.response),
                pr.statusCode,
                extractResponseBody(pr.response),
                endpoint.getMethod(),
                endpoint.getNormalizedPath()
            );

            if (bestSignal == null || signal.score > bestSignal.score) {
                bestSignal = signal;
                bestSwap = pr;
            }
        }

        if (bestSwap == null || bestSignal == null || !bestSignal.shouldPromote) {
            return;
        }

        AcasFinding finding = new AcasFinding();
        finding.setSource("Passive Probe");
        finding.setSeverity(bestSignal.score >= 80 || bestSignal.autoPromote ? "CRITICAL" : "HIGH");
        finding.setLabel("IDOR_AUTH_BYPASS");
        finding.setMutationType("PX1");
        finding.setMutationDescription("Probe matrix signal: owner 2xx / anonymous denied / swapped 2xx");

        ActorProfile owner = store.getActor(endpoint.getActorId());
        finding.setOwnerActorName(owner != null ? owner.getName() : "Owner");
        finding.setReplayerActorName(bestSwap.actorName);
        finding.setReplayed(true);

        finding.setMethod(endpoint.getMethod());
        finding.setUrl(endpoint.getOriginalUrl());
        finding.setEndpointPattern(endpoint.getNormalizedPath());

        finding.setBaseRequest(baseline.request);
        finding.setBaseResponse(baseline.response);
        finding.setBaseStatus(baseline.statusCode);
        finding.setBaseLength(baseline.responseLength);

        finding.setAnonymousRequest(anonymous.request);
        finding.setAnonymousResponse(anonymous.response);
        finding.setAnonymousStatus(anonymous.statusCode);
        finding.setAnonymousLength(anonymous.responseLength);

        finding.setMutatedRequest(bestSwap.request);
        finding.setMutatedResponse(bestSwap.response);
        finding.setMutatedStatus(bestSwap.statusCode);
        finding.setMutatedLength(bestSwap.responseLength);

        String baselineBody = extractResponseBody(baseline.response);
        String swapBody = extractResponseBody(bestSwap.response);
        String anonBody = extractResponseBody(anonymous.response);

        finding.setSizeSimilarity(responseComparator.textSimilarity(baselineBody, swapBody));
        finding.setConfidenceScore(bestSignal.score);
        finding.setFpReason(bestSignal.reason);
        finding.setConfirmedByDiff(bestSignal.autoPromote || bestSignal.score >= 80);
        finding.setContainsOwnerData(bestSignal.semanticSimilarity >= 0.85);
        finding.setSimilarityToOwner(bestSignal.semanticSimilarity);
        finding.setSimilarityToAnon(responseComparator.textSimilarity(swapBody, anonBody));
        finding.setSimilarityToInvalid(0.0);
        finding.setAnalysisNote(
            "Auto-promoted from Probe/Captured flow. " +
            "Pattern: baseline=" + baseline.statusCode + ", anonymous=" + anonymous.statusCode + ", swapped=" + bestSwap.statusCode +
            ", score=" + bestSignal.score + ", semantic=" + String.format(java.util.Locale.ROOT, "%.2f", bestSignal.semanticSimilarity)
        );

        if (sev.addFindingIfUnique(finding)) {
            api.logging().logToOutput("ACAS: Promoted strong probe signal to Result Matrix for " + endpoint.getMethod() + " " + endpoint.getNormalizedPath());
        }
    }

    private String extractResponseBody(byte[] rawResponse) {
        if (rawResponse == null || rawResponse.length == 0) {
            return "";
        }
        String text = new String(rawResponse, java.nio.charset.StandardCharsets.ISO_8859_1);
        int sep = text.indexOf("\r\n\r\n");
        if (sep >= 0 && sep + 4 <= text.length()) {
            return text.substring(sep + 4);
        }
        int sep2 = text.indexOf("\n\n");
        if (sep2 >= 0 && sep2 + 2 <= text.length()) {
            return text.substring(sep2 + 2);
        }
        return text;
    }

    public void shutdown() {
        automaticExecutor.shutdown();
        executor.shutdown();
    }
}
