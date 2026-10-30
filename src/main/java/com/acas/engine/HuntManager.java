package com.acas.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.acas.harvest.ResourceRegistry;
import com.acas.model.ActorProfile;
import com.acas.model.AcasFinding;
import com.acas.model.CapturedEndpoint;
import com.acas.model.CapturedEndpoint.HuntStatus;
import com.acas.store.ActorStore;
import com.acas.util.HttpUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

public class HuntManager {
    public enum State { IDLE, RUNNING, PAUSED, STOPPED }
    public enum ReevaluateRoute { DISCARD, REVIEW, CONFIRMED }

    private static final String PREF_THRESHOLD_DISCARD = "acas.threshold.discard";
    private static final String PREF_THRESHOLD_REVIEW = "acas.threshold.review";
    private static final String PREF_THRESHOLD_AUTOCONFIRM = "acas.threshold.autoconfirm";
    private static final String PREF_BASELINE_TTL_MINUTES = "acas.baseline.ttl";
    private static final int REQUEST_TIMEOUT_SECONDS = 15;
    private static final int MAX_VECTORS_PER_ENDPOINT = 600;

    public static class QueueEnqueueResult {
        public final int addedCount;
        public final int duplicateCount;

        public QueueEnqueueResult(int addedCount, int duplicateCount) {
            this.addedCount = addedCount;
            this.duplicateCount = duplicateCount;
        }
    }

    public static class MutationEvent {
        public final long timestamp;
        public final String endpointPath;
        public final String endpointMethod;
        public final String endpointOwnerActorId;
        public final String actorName;
        public final String mutationType;
        public final String mutationDescription;
        public final int statusCode;
        public final int responseLength;
        public final String verdict;
        public final byte[] requestBytes;
        public final byte[] responseBytes;

        public MutationEvent(String endpointPath, String endpointMethod, String endpointOwnerActorId,
                             String actorName, String mutationType, String mutationDescription,
                             int statusCode, int responseLength, String verdict, byte[] requestBytes, byte[] responseBytes) {
            this.timestamp = System.currentTimeMillis();
            this.endpointPath = endpointPath;
            this.endpointMethod = endpointMethod;
            this.endpointOwnerActorId = endpointOwnerActorId;
            this.actorName = actorName;
            this.mutationType = mutationType;
            this.mutationDescription = mutationDescription;
            this.statusCode = statusCode;
            this.responseLength = responseLength;
            this.verdict = verdict;
            this.requestBytes = requestBytes;
            this.responseBytes = responseBytes;
        }
    }

    private final MontoyaApi api;
    private final ActorStore store;
    private final MutationEngine mutationEngine;
    private final ReplayEngine replayEngine;
    private final ComparisonEngine comparisonEngine;
    private final SeverityClassifier severityClassifier;
    private final ObjectManager objectManager;
    private final BaselineManager baselineManager;
    private final ResponseComparator responseComparator;
    private final DifferentialAnalyzer differentialAnalyzer;
    private final ConfidenceScorer confidenceScorer;
    private final ResponseChainEngine chainEngine;
    private final SessionHealthMonitor healthMonitor;
    private final AdminHandler adminHandler;
    private final RateLimiter rateLimiter;
    private final ResourceRegistry resourceRegistry;

    private volatile int discardThreshold = 30;
    private volatile int reviewThreshold = 60;
    private volatile int autoConfirmThreshold = 90;
    private volatile int baselineTtlMinutes = 5;
    
    private volatile State currentState = State.IDLE;
    private final AtomicBoolean isPaused = new AtomicBoolean(false);
    private final AtomicBoolean isStopped = new AtomicBoolean(false);
    private volatile Thread activeHuntThread = null;
    private volatile long lastProgressAtMs = 0L;
    
    private final AtomicInteger tasksCompleted = new AtomicInteger(0);
    private volatile int totalTasks = 0;

    // Queued endpoints for drag-reorder support
    private final List<CapturedEndpoint> huntQueue = new ArrayList<>();
    private final Map<String, HuntStatus> queuedPreviousStatus = new HashMap<>();
    private final Map<String, Set<String>> endpointMutationOverrides = new HashMap<>();
    private volatile int harvestRehuntRecommendedCount = 0;
    private volatile long lastHarvestRefreshAtMs = 0L;

    public interface AuditListener {
        void onMutationEvent(MutationEvent event);
    }
    private final List<AuditListener> auditListeners = new java.util.concurrent.CopyOnWriteArrayList<>();

    public void addAuditListener(AuditListener listener) {
        if (!auditListeners.contains(listener)) {
            auditListeners.add(listener);
        }
    }

    public HuntManager(MontoyaApi api, ActorStore store, MutationEngine mutationEngine, ReplayEngine replayEngine, ComparisonEngine comparisonEngine, SeverityClassifier severityClassifier, ObjectManager objectManager) {
        this(api, store, mutationEngine, replayEngine, comparisonEngine, severityClassifier, objectManager, null);
    }

    public HuntManager(MontoyaApi api,
                       ActorStore store,
                       MutationEngine mutationEngine,
                       ReplayEngine replayEngine,
                       ComparisonEngine comparisonEngine,
                       SeverityClassifier severityClassifier,
                       ObjectManager objectManager,
                       ResourceRegistry resourceRegistry) {
        this.api = api;
        this.store = store;
        this.mutationEngine = mutationEngine;
        this.replayEngine = replayEngine;
        this.comparisonEngine = comparisonEngine;
        this.severityClassifier = severityClassifier;
        this.objectManager = objectManager;
        this.baselineManager = new BaselineManager();
        this.responseComparator = new ResponseComparator();
        this.differentialAnalyzer = new DifferentialAnalyzer();
        this.confidenceScorer = new ConfidenceScorer();
        this.chainEngine = new ResponseChainEngine(objectManager);
        this.healthMonitor = new SessionHealthMonitor();
        this.adminHandler = new AdminHandler(api, replayEngine);
        this.rateLimiter = new RateLimiter();
        this.resourceRegistry = resourceRegistry;
        loadThresholdSettings();
    }

    /**
     * Builds and injects a fresh Aho-Corasick searcher into the ComparisonEngine.
     * Call this at the start of every hunt after all actor objects have been loaded.
     * The automaton compiles all actor values (≥5 chars) into a single multi-pattern
     * automaton that scans response bodies in O(N+M) instead of O(N*M) per response.
     */
    private void rebuildAhoCorasickSearcher(List<ActorProfile> actors) {
        Map<String, List<String>> actorValues = new java.util.HashMap<>();
        for (ActorProfile actor : actors) {
            List<ObjectManager.ObjectEntry> objects = objectManager.getObjectsForActor(actor.getId());
            List<String> values = new java.util.ArrayList<>();
            for (ObjectManager.ObjectEntry obj : objects) {
                if (obj.value != null && obj.value.length() >= 5) {
                    values.add(obj.value);
                }
            }
            if (!values.isEmpty()) {
                actorValues.put(actor.getId(), values);
            }
        }
        AhoCorasickSearcher searcher = AhoCorasickSearcher.build(actorValues);
        comparisonEngine.setAhoCorasickSearcher(searcher);
    }

    /**
     * Expose the health monitor so HuntHubPanel can call clearExpiredActor
     * when the user updates a session and clicks Resume.
     */
    public SessionHealthMonitor getHealthMonitor() {
        return healthMonitor;
    }

    /**
     * Clears the expired state for the actor currently pending refresh,
     * then resumes the hunt. Called by the "Resume" button in HuntHubPanel
     * after the user has updated the session in the Actors tab.
     */
    public void resumeAfterSessionRefresh() {
        String actorId = healthMonitor.getPendingRefreshActorId();
        if (actorId != null) {
            healthMonitor.clearExpired(actorId);
        }
        // Resume the normal pause/resume flow
        if (currentState == State.PAUSED) {
            isPaused.set(false);
            currentState = State.RUNNING;
        }
    }

    public List<CapturedEndpoint> getHuntQueue() {
        synchronized (huntQueue) {
            return new ArrayList<>(huntQueue);
        }
    }

    /**
     * Reorder the hunt queue. Must be called BEFORE startHunt or while PAUSED.
     */
    public void reorderQueue(List<CapturedEndpoint> newOrder) {
        synchronized (huntQueue) {
            huntQueue.clear();
            huntQueue.addAll(newOrder);
        }
    }

    /**
     * Add endpoints to hunt queue without starting execution.
     * De-duplicates using strict signature: actor/method/url/path/request-bytes/response-bytes.
     */
    public QueueEnqueueResult enqueueEndpoints(List<CapturedEndpoint> endpoints) {
        if (endpoints == null || endpoints.isEmpty()) return new QueueEnqueueResult(0, 0);
        int added = 0;
        int duplicates = 0;
        synchronized (huntQueue) {
            Set<String> seenInInput = new HashSet<>();
            for (CapturedEndpoint ep : endpoints) {
                if (ep == null || ep.getHuntStatus() == CapturedEndpoint.HuntStatus.RUNNING) {
                    continue;
                }
                String sig = endpointSignature(ep);
                if (!seenInInput.add(sig)) {
                    duplicates++;
                    continue;
                }
                if (!containsInQueueBySignature(sig)) {
                    queuedPreviousStatus.put(sig, ep.getHuntStatus() == HuntStatus.QUEUED ? HuntStatus.NEVER : ep.getHuntStatus());
                    ep.setHuntStatus(HuntStatus.QUEUED);
                    huntQueue.add(ep);
                    added++;
                } else {
                    duplicates++;
                }
            }
        }
        if (added > 0) {
            store.saveEndpointsToPersistence();
        }
        return new QueueEnqueueResult(added, duplicates);
    }

    public QueueEnqueueResult enqueueEndpointsWithMutationOverride(List<CapturedEndpoint> endpoints, Set<String> allowedMutationCodes) {
        QueueEnqueueResult result = enqueueEndpoints(endpoints);
        if (endpoints == null || endpoints.isEmpty()) {
            return result;
        }
        Set<String> normalized = normalizeMutationCodes(allowedMutationCodes);
        synchronized (huntQueue) {
            for (CapturedEndpoint ep : endpoints) {
                if (ep == null) {
                    continue;
                }
                String signature = endpointSignature(ep);
                if (normalized.isEmpty()) {
                    endpointMutationOverrides.remove(signature);
                } else {
                    endpointMutationOverrides.put(signature, new HashSet<>(normalized));
                }
            }
        }
        return result;
    }

    public void clearMutationOverride(CapturedEndpoint endpoint) {
        if (endpoint == null) {
            return;
        }
        synchronized (huntQueue) {
            endpointMutationOverrides.remove(endpointSignature(endpoint));
        }
    }

    public void clearAllMutationOverrides() {
        synchronized (huntQueue) {
            endpointMutationOverrides.clear();
        }
    }

    private Set<String> getMutationOverride(CapturedEndpoint endpoint) {
        if (endpoint == null) {
            return java.util.Collections.emptySet();
        }
        synchronized (huntQueue) {
            Set<String> override = endpointMutationOverrides.get(endpointSignature(endpoint));
            return override == null ? java.util.Collections.emptySet() : new HashSet<>(override);
        }
    }

    private Set<String> normalizeMutationCodes(Set<String> allowedMutationCodes) {
        if (allowedMutationCodes == null || allowedMutationCodes.isEmpty()) {
            return java.util.Collections.emptySet();
        }
        Set<String> normalized = new HashSet<>();
        for (String code : allowedMutationCodes) {
            if (code == null) {
                continue;
            }
            String trimmed = code.trim();
            if (!trimmed.isEmpty()) {
                normalized.add(trimmed.toUpperCase());
            }
        }
        return normalized;
    }

    /**
     * Start hunt using current queued endpoints.
     * Returns true if hunt started, false when queue is empty or already running.
     */
    public boolean startQueuedHunt(Consumer<String> onLog, Consumer<MutationEvent> onMutation, Consumer<Integer> onProgress, Runnable onComplete) {
        recoverStaleRunIfNeeded(onLog);
        if (currentState == State.RUNNING) return false;
        List<CapturedEndpoint> queued;
        synchronized (huntQueue) {
            queued = new ArrayList<>(huntQueue);
        }
        if (queued.isEmpty()) return false;
        startHunt(queued, onLog, onMutation, onProgress, onComplete);
        return true;
    }

    public synchronized void restoreQueuedEndpoints(List<CapturedEndpoint> queuedEndpoints) {
        huntQueue.clear();
        queuedPreviousStatus.clear();
        if (queuedEndpoints == null) return;
        for (CapturedEndpoint ep : queuedEndpoints) {
            if (ep == null || ep.getHuntStatus() == HuntStatus.RUNNING) continue;
            String sig = endpointSignature(ep);
            if (!containsInQueueBySignature(sig)) {
                queuedPreviousStatus.put(sig, ep.getHuntStatus() == HuntStatus.QUEUED ? HuntStatus.NEVER : ep.getHuntStatus());
                ep.setHuntStatus(HuntStatus.QUEUED);
                huntQueue.add(ep);
            }
        }
        store.saveEndpointsToPersistence();
    }

    public boolean removeFromQueue(CapturedEndpoint endpoint) {
        if (endpoint == null) return false;
        String sig = endpointSignature(endpoint);
        synchronized (huntQueue) {
            for (int i = 0; i < huntQueue.size(); i++) {
                if (endpointSignature(huntQueue.get(i)).equals(sig)) {
                    restoreStatusFromQueue(endpoint, sig);
                    endpointMutationOverrides.remove(sig);
                    huntQueue.remove(i);
                    store.saveEndpointsToPersistence();
                    return true;
                }
            }
        }
        return false;
    }

    public int clearQueue() {
        synchronized (huntQueue) {
            int count = huntQueue.size();
            for (CapturedEndpoint ep : huntQueue) {
                String sig = endpointSignature(ep);
                restoreStatusFromQueue(ep, sig);
            }
            huntQueue.clear();
            queuedPreviousStatus.clear();
            endpointMutationOverrides.clear();
            if (count > 0) {
                store.saveEndpointsToPersistence();
            }
            return count;
        }
    }

    public int getHarvestRehuntRecommendedCount() {
        return harvestRehuntRecommendedCount;
    }

    public QueueEnqueueResult enqueueHarvestAffectedEndpoints() {
        List<CapturedEndpoint> affected = new ArrayList<>();
        for (CapturedEndpoint ep : store.getCapturedEndpoints()) {
            if (ep != null && ep.getHarvestDeltaCount() > 0 && ep.getHuntStatus() != CapturedEndpoint.HuntStatus.RUNNING) {
                affected.add(ep);
            }
        }
        return enqueueEndpoints(affected);
    }

    private void restoreStatusFromQueue(CapturedEndpoint endpoint, String signature) {
        if (endpoint.getHuntStatus() != HuntStatus.QUEUED) return;
        HuntStatus previous = queuedPreviousStatus.remove(signature);
        endpoint.setHuntStatus(previous != null ? previous : HuntStatus.NEVER);
    }

    private boolean containsInQueueBySignature(String candidateSignature) {
        for (CapturedEndpoint ep : huntQueue) {
            if (endpointSignature(ep).equals(candidateSignature)) {
                return true;
            }
        }
        return false;
    }

    private String endpointSignature(CapturedEndpoint ep) {
        int requestHash = 0;
        int responseHash = 0;
        try {
            requestHash = ep.getOriginalRequest() != null ? java.util.Arrays.hashCode(ep.getOriginalRequest().toByteArray().getBytes()) : 0;
        } catch (Exception ignored) {
            requestHash = 0;
        }
        try {
            responseHash = ep.getOriginalResponse() != null ? java.util.Arrays.hashCode(ep.getOriginalResponse().toByteArray().getBytes()) : 0;
        } catch (Exception ignored) {
            responseHash = 0;
        }
        return (ep.getActorId() != null ? ep.getActorId() : "-") + "|"
            + (ep.getMethod() != null ? ep.getMethod() : "-") + "|"
            + (ep.getOriginalUrl() != null ? ep.getOriginalUrl() : "-") + "|"
            + (ep.getNormalizedPath() != null ? ep.getNormalizedPath() : "-") + "|"
            + requestHash + "|" + responseHash;
    }

    public void startHunt(List<CapturedEndpoint> selectedEndpoints, Consumer<String> onLog, Consumer<Integer> onProgress, Runnable onComplete) {
        startHunt(selectedEndpoints, onLog, null, onProgress, onComplete);
    }

    public void startHunt(List<CapturedEndpoint> selectedEndpoints, Consumer<String> onLog, Consumer<MutationEvent> onMutation, Consumer<Integer> onProgress, Runnable onComplete) {
        startHunt(selectedEndpoints, onLog, onMutation, onProgress, onComplete, null);
    }

    public void startHunt(List<CapturedEndpoint> selectedEndpoints,
                          Consumer<String> onLog,
                          Consumer<MutationEvent> onMutation,
                          Consumer<Integer> onProgress,
                          Runnable onComplete,
                          Consumer<String> onSessionExpired) {
        recoverStaleRunIfNeeded(onLog);
        if (currentState == State.RUNNING) return;
        currentState = State.RUNNING;
        isPaused.set(false);
        isStopped.set(false);
        tasksCompleted.set(0);
        lastProgressAtMs = System.currentTimeMillis();
        final List<ActorProfile> allActors = new ArrayList<>();

        try {
            if (selectedEndpoints == null || selectedEndpoints.isEmpty()) {
                currentState = State.IDLE;
                if (onLog != null) onLog.accept("No endpoints selected for hunt.");
                if (onComplete != null) onComplete.run();
                return;
            }

            // No automatic sorting — hunt in the order provided by UI
            // (User manually selects which endpoint to hunt via UI selection)
            if (onLog != null && selectedEndpoints.size() > 1) {
                onLog.accept("📋 Hunt order (as selected by user):");
                for (int i = 0; i < selectedEndpoints.size(); i++) {
                    CapturedEndpoint ep = selectedEndpoints.get(i);
                    onLog.accept("   [" + (i + 1) + "] " + ep.getMethod() + " " + ep.getNormalizedPath());
                }
            }

            // Set up the hunt queue for display / reorder
            synchronized (huntQueue) {
                for (CapturedEndpoint ep : selectedEndpoints) {
                    if (ep == null) continue;
                    String sig = endpointSignature(ep);
                    if (!containsInQueueBySignature(sig)) {
                        queuedPreviousStatus.put(sig, ep.getHuntStatus() == HuntStatus.QUEUED ? HuntStatus.NEVER : ep.getHuntStatus());
                        ep.setHuntStatus(HuntStatus.QUEUED);
                        huntQueue.add(ep);
                    }
                }
            }

            allActors.clear();
            allActors.addAll(store.getAllActors());
            // Reset health monitor and register actor display names for UI notifications
            healthMonitor.clearAll();
            for (ActorProfile actor : allActors) {
                healthMonitor.registerActorName(actor.getId(), actor.getName());
            }
            // Build Aho-Corasick automaton from current actor object values for high-speed leak detection
            rebuildAhoCorasickSearcher(allActors);
            totalTasks = Math.max(1, selectedEndpoints.size());
            if (onLog != null) {
                onLog.accept("▶ Starting hunt for " + selectedEndpoints.size() + " endpoint(s)...");
            }

            // Mark all selected endpoints as RUNNING
            for (CapturedEndpoint ep : selectedEndpoints) {
                if (ep == null) continue;
                boolean resumeFromProgress = ep.getHuntProbesCompleted() > 0
                    && ep.getHuntProbesCompleted() < ep.getHuntProbesTotal();

                if (!resumeFromProgress) {
                    ep.resetForReHunt();
                } else if (onLog != null) {
                    onLog.accept("↩ Resuming partial hunt for " + ep.getMethod() + " " + ep.getNormalizedPath()
                        + " from probe " + (ep.getHuntProbesCompleted() + 1) + "/" + Math.max(1, ep.getHuntProbesTotal()));
                }
            }
            store.saveEndpointsToPersistence();
        } catch (Exception preflightEx) {
            currentState = State.IDLE;
            if (onLog != null) {
                onLog.accept("❌ Hunt failed to start: " + preflightEx.getMessage());
            }
            try {
                api.logging().logToError("ACAS Hunt preflight failed: " + preflightEx);
            } catch (Exception ignored) {
            }
            if (onComplete != null) {
                onComplete.run();
            }
            return;
        }

        // Start rate limiter
        rateLimiter.startHunt();
        if (onLog != null) {
            onLog.accept("🚦 " + rateLimiter.getConfigSummary());
        }

        Thread worker = new Thread(() -> {
            try {
                int queuePosition = 0;
                for (CapturedEndpoint ep : selectedEndpoints) {
                if (isStopped.get()) break;
                queuePosition++;
                boolean endpointCompleted = false;
                try {
                if (ep == null) {
                    onLog.accept("⚠️ Skipping null endpoint in queue.");
                    continue;
                }
                
                onLog.accept(queuePosition + "/" + selectedEndpoints.size() + " — " + 
                    ep.getMethod() + " " + ep.getNormalizedPath() + 
                    " (priority: " + ep.getPriorityScore() + ") [" + ep.getClassificationLabel() + "]");
                long endpointStartedAt = System.currentTimeMillis();
                
                // 1. Get Baseline (Owner)
                ActorProfile owner = store.getActor(ep.getActorId());
                if (owner == null) {
                    onLog.accept("⚠️ Owner actor not found for endpoint actorId='" + ep.getActorId() + "' — using captured request as baseline.");
                }

                ep.restoreTransientMessages();
                HttpRequest originalReq = ep.getOriginalRequest();
                if (originalReq == null && ep.getOriginalRequestBytes() != null) {
                    try {
                        originalReq = burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                            burp.api.montoya.core.ByteArray.byteArray(ep.getOriginalRequestBytes()));
                    } catch (Exception ignored) {
                    }
                }
                if (originalReq == null) {
                    ep.setHuntErrorCode("ERR_NO_BASE_REQUEST");
                    ep.finalizeHuntStatus();
                    continue;
                }
                // Ensure downstream engines using endpoint.getOriginalRequest() see a valid request instance.
                ep.setOriginalRequest(originalReq);

                HttpRequest baseReq = owner != null
                    ? replayEngine.buildActorRequest(originalReq, owner)
                    : originalReq;
                onLog.accept("   Capturing owner baseline...");
                HttpRequestResponse rrBase = safeSendRequest(baseReq, ep, onLog);
                if (rrBase.response() == null) {
                    ep.setHuntErrorCode("ERR_BASELINE_TIMEOUT_OR_FAILED");
                    ep.finalizeHuntStatus();
                    continue;
                }

                // False-positive Layer 1: capture baseline set once per endpoint pattern
                String baselineKey = ep.getMethod() + " " + ep.getNormalizedPath();
                EndpointBaseline baseline = baselineManager.get(baselineKey, baselineTtlMinutes);
                if (baseline == null) {
                    baseline = recaptureBaseline(ep, baseReq, rrBase.response());
                    baselineManager.put(baselineKey, baseline);
                }

                // SPECIAL: Phase 9 - Admin Reference Actor (AdminHandler)
                com.acas.engine.AdminHandler.AdminBaseline adminBaseline = null;
                if (owner != null && owner.getRoleLevel() < 4) {
                    ActorProfile admin = allActors.stream().filter(a -> a.getRoleLevel() == 4).findFirst().orElse(null);
                    if (admin != null) {
                        adminBaseline = adminHandler.establishBaseline(ep, admin, rrBase.response());
                        if (adminBaseline != null && !adminBaseline.isolated) {
                            onLog.accept("Established Admin Baseline for " + ep.getNormalizedPath());
                            chainEngine.discoverFromResponse(admin, adminBaseline.rr, 1);
                        }
                    }
                }

                // 2. Cross-Actor Matrix (All mutations for all actors)
                onLog.accept("   Generating mutation set...");
                List<MutationVector> vectors;
                try {
                    long vectorStart = System.currentTimeMillis();
                    Set<String> mutationOverride = getMutationOverride(ep);
                    if (!mutationOverride.isEmpty() && onLog != null) {
                        onLog.accept("   Mutation override active for this request: " + mutationOverride.size() + " code(s)");
                    }
                    vectors = mutationEngine.generateVectors(ep, allActors, store.getCapturedEndpoints(), mutationOverride);
                    long vectorElapsed = System.currentTimeMillis() - vectorStart;
                    onLog.accept("   Mutation generation completed: " + vectors.size() + " vectors in " + vectorElapsed + "ms");
                } catch (Exception vectorEx) {
                    onLog.accept("❌ Failed to generate mutations for " + ep.getNormalizedPath() + ": " + vectorEx.getMessage());
                    ep.setHuntErrorCode("ERR_MUTATION_GENERATION");
                    ep.finalizeHuntStatus();
                    continue;
                }

                if (vectors.size() > MAX_VECTORS_PER_ENDPOINT) {
                    onLog.accept("⚠️ Vector set too large (" + vectors.size() + ") — prioritizing top " + MAX_VECTORS_PER_ENDPOINT + " (IDOR-first)");
                    vectors.sort((a, b) -> Integer.compare(a.getPriority(), b.getPriority()));
                    vectors = new ArrayList<>(vectors.subList(0, MAX_VECTORS_PER_ENDPOINT));
                }

                int resumeFrom = 0;
                if (ep.getHuntStatus() == HuntStatus.RUNNING && ep.getHuntProbesCompleted() > 0) {
                    resumeFrom = Math.min(ep.getHuntProbesCompleted(), vectors.size());
                }
                ep.setHuntProbesTotal(vectors.size());
                ep.setHuntProbesCompleted(resumeFrom);
                
                boolean hadError = false;
                boolean endpointAborted = false;
                
                for (int vectorIndex = resumeFrom; vectorIndex < vectors.size(); vectorIndex++) {
                    MutationVector vector = vectors.get(vectorIndex);
                    if (isStopped.get()) {
                        endpointAborted = true;
                        break;
                    }
                    
                    ActorProfile targetActor = vector.getActor();
                    if (targetActor != null && healthMonitor.isExpired(targetActor.getId())) {
                        continue; // Phase 14: Skip expired sessions
                    }

                    // Phase 11 & Role Hierarchy Logic
                    if (targetActor != null) {
                        int targetLevel = targetActor.getRoleLevel();
                        int ownerLevel = owner != null ? owner.getRoleLevel() : 1;
                        String ownerId = owner != null ? owner.getId() : null;
                        
                        // Rule 1: Always test same-level but DIFFERENT actor (Horizontal IDOR)
                        if (targetLevel == ownerLevel && (ownerId == null || !targetActor.getId().equals(ownerId))) {
                            // Proceed
                        } 
                        // Rule 2: Skip HIGHER attacking LOWER (Vertical Downward Protection)
                        else if (targetLevel > ownerLevel && targetLevel != 4) {
                            continue;
                        }
                        // Rule 3: Skip same actor accessing own data (unless mutation is path-based?)
                        else if (ownerId != null && targetActor.getId().equals(ownerId) && vector.getTypeName().equals("B1")) {
                            continue;
                        }
                    }

                    while (isPaused.get()) {
                        try {
                            Thread.sleep(500);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            endpointAborted = true;
                            break;
                        }
                    }

                    if (endpointAborted) {
                        break;
                    }

                    // Delay for Part 12: Rate Limiting
                    try {
                        Thread.sleep(300);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        endpointAborted = true;
                        break;
                    }

                    if (endpointAborted || isStopped.get() || Thread.currentThread().isInterrupted()) {
                        endpointAborted = true;
                        break;
                    }

                    // Replay: always apply the selected actor profile to the mutation request.
                    HttpRequest mutationRequest = vector.getMutatedRequest();
                    if (targetActor != null) {
                        mutationRequest = replayEngine.buildActorRequest(mutationRequest, targetActor);
                    }

                    String actorName = targetActor != null ? targetActor.getName() : "Anonymous";
                    onLog.accept("↪ [" + (vectorIndex + 1) + "/" + vectors.size() + "] Mutation " + vector.getTypeName() + " | " + vector.getDescription() + " | actor=" + actorName);

                    HttpRequestResponse rrMut = safeSendRequest(mutationRequest, ep, onLog);
                    if (rrMut.response() != null) {
                        onLog.accept("   Response: " + rrMut.response().statusCode() + " (" + rrMut.response().body().length() + " bytes)");
                    } else {
                        onLog.accept("   Response: <timeout or failed>");
                    }

                    if (onMutation != null) {
                        String verdict = "NO_RESULT";
                        if (rrMut.response() != null) {
                            verdict = rrMut.response().statusCode() >= 200 && rrMut.response().statusCode() < 300 ? "SUCCESS" : "BLOCKED";
                        }
                        MutationEvent event = new MutationEvent(
                            ep.getNormalizedPath(),
                            ep.getMethod(),
                            ep.getActorId(),
                            actorName,
                            vector.getTypeName(),
                            vector.getDescription(),
                            rrMut.response() != null ? rrMut.response().statusCode() : 0,
                            rrMut.response() != null ? rrMut.response().body().length() : 0,
                            verdict,
                            rrMut.request() != null ? rrMut.request().toByteArray().getBytes() : null,
                            rrMut.response() != null ? rrMut.response().toByteArray().getBytes() : null
                        );
                        onMutation.accept(event);
                        
                        for (AuditListener l : auditListeners) {
                            l.onMutationEvent(event);
                        }
                    }
                    
                    // Handle 429
                    if (rrMut.response() != null && rrMut.response().statusCode() == 429) {
                        onLog.accept("⚠️ Rate limited on " + ep.getNormalizedPath() + " — backing off 5s");
                        try {
                            Thread.sleep(5000);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            endpointAborted = true;
                            break;
                        }
                        if (endpointAborted) {
                            break;
                        }
                        rrMut = safeSendRequest(mutationRequest, ep, onLog); // Retry once
                        if (rrMut.response() != null && rrMut.response().statusCode() == 429) {
                            ep.setHuntErrorCode("ERR_RATE_LIMITED");
                            hadError = true;
                        }
                    }

                    if (rrMut.response() != null) {
                        // Phase 14: Session Health Check
                        if (targetActor != null) {
                            if (!healthMonitor.checkHealth(targetActor.getId(), rrMut.response())) {
                                // ── Session Expired: PAUSE and wait for user to refresh ──────────────────
                                // We do NOT skip remaining vectors. Instead we pause the hunt loop here.
                                // The user updates the session in the Actors tab, then clicks Resume.
                                // clearExpired() is called by resumeAfterSessionRefresh() before un-pausing,
                                // so when the loop continues, isExpired() will return false and the
                                // vector executes normally — nothing is missed.
                                String expiredName = targetActor.getName();
                                onLog.accept("⏸️ SESSION EXPIRED — Actor '" + expiredName + "' — Update session in Actors tab, then click Resume");
                                isPaused.set(true);
                                currentState = State.PAUSED;
                                if (!hadError) {
                                    ep.setHuntErrorCode("ERR_SESSION_EXPIRED");
                                    hadError = true;
                                }
                                // Fire UI callback so the banner appears immediately
                                if (onSessionExpired != null) {
                                    onSessionExpired.accept(expiredName);
                                }
                                // Sit in the pause loop — will unblock when user clicks Resume
                                // (resumeAfterSessionRefresh clears the expired state first)
                                while (isPaused.get() && !isStopped.get()) {
                                    try { Thread.sleep(500); } catch (InterruptedException ex) {
                                        Thread.currentThread().interrupt();
                                        endpointAborted = true;
                                        break;
                                    }
                                }
                                if (endpointAborted || isStopped.get()) break;
                                // Session was refreshed — continue to execute this vector
                            }
                        }

                        // Phase 13: Response Chain Discovery (Discover new IDs from hunt results - Depth 2)
                        if (targetActor != null) {
                            chainEngine.discoverFromResponse(targetActor, rrMut, 2);
                        }

                        // Compare
                        // Use Admin response as reference IF admin is not isolated
                        burp.api.montoya.http.message.responses.HttpResponse referenceRes = (adminBaseline != null && !adminBaseline.isolated) ? adminBaseline.response : rrBase.response();
                        
                        com.acas.model.AcasFinding finding = comparisonEngine.compare(ep, vector, referenceRes, rrMut.response());
                        if (finding != null) {
                            // False-positive Layer 2: baseline comparator
                            ResponseComparator.ComparisonResult cmp = responseComparator.compare(
                                rrMut.response(),
                                baseline.authenticatedResponse,
                                baseline.anonymousResponse,
                                baseline.invalidIdResponse,
                                mutationRequest
                            );

                            if (cmp.verdict == ResponseComparator.Verdict.FALSE_POSITIVE
                                || cmp.verdict == ResponseComparator.Verdict.LIKELY_FALSE) {
                                continue;
                            }

                            // False-positive Layer 3: differential analysis
                            boolean confirmedByDiff = differentialAnalyzer.isGenuineDataLeak(
                                rrMut.response(),
                                baseline.authenticatedResponse,
                                baseline.nonExistentResponse,
                                targetActor,
                                objectManager
                            );

                            finding.setBaseRequest(rrBase.request().toByteArray().getBytes());
                            finding.setBaseResponse(rrBase.response().toByteArray().getBytes());

                            HttpRequest anonymousReq = HttpUtils.stripAuthHeaders(originalReq, store.getAllIdentityHeaderNames());
                            if (anonymousReq != null) {
                                finding.setAnonymousRequest(anonymousReq.toByteArray().getBytes());
                            }
                            if (baseline.anonymousResponse != null) {
                                finding.setAnonymousResponse(baseline.anonymousResponse.toByteArray().getBytes());
                                finding.setAnonymousStatus(baseline.anonymousResponse.statusCode());
                                finding.setAnonymousLength(baseline.anonymousResponse.body() != null ? baseline.anonymousResponse.body().length() : 0);
                            }

                            finding.setMutatedRequest(rrMut.request().toByteArray().getBytes());
                            finding.setMutatedResponse(rrMut.response().toByteArray().getBytes());
                            if (adminBaseline != null && !adminBaseline.isolated) finding.setReplayed(true);

                            finding.setFpReason(cmp.reason);
                            finding.setSimilarityToOwner(cmp.similarityToOwner);
                            finding.setSimilarityToAnon(cmp.similarityToAnon);
                            finding.setSimilarityToInvalid(cmp.similarityToInvalid);
                            finding.setMatchesAnonymous(cmp.similarityToAnon > 0.90);
                            finding.setMatchesInvalidId(cmp.similarityToInvalid > 0.90);
                            finding.setConfirmedByDiff(confirmedByDiff);
                            finding.setContainsOwnerData(confirmedByDiff);
                            finding.setBaselineCapturedAtEpochMs(baseline.capturedAtEpochMs);

                            // False-positive Layer 4: confidence scoring
                            int score = confidenceScorer.score(
                                finding,
                                cmp.verdict,
                                rrMut.response(),
                                baseline.authenticatedResponse,
                                baseline.anonymousResponse
                            );
                            if (confirmedByDiff) {
                                score = Math.min(100, score + 15);
                            }
                            finding.setConfidenceScore(score);
                            
                            if (adminBaseline != null && adminBaseline.isolated) {
                                finding.setAnalysisNote("⚠️ ADMIN_ISOLATED: Admin cannot access this endpoint.");
                            }
                            
                            // Phase 12: Verification logic for write operations
                            if ("WRITE_BYPASS".equals(finding.getLabel())) {
                                onLog.accept("Verifying write operation Impact...");
                                if (owner != null) {
                                    HttpRequest verifyReq = replayEngine.buildActorRequest(originalReq, owner);
                                    var rrVerify = safeSendRequest(verifyReq, ep, onLog);
                                    if (rrVerify.response() != null && rrVerify.response().statusCode() == 404) {
                                        finding.setSeverity("CRITICAL");
                                        finding.setAnalysisNote(finding.getAnalysisNote() + " VERIFIED: Resource was actually deleted/modified.");
                                    } else {
                                        finding.setSeverity("HIGH");
                                        finding.setAnalysisNote(finding.getAnalysisNote() + " UNVERIFIED: Server accepted write but resource still exists (owner 200).");
                                    }
                                } else {
                                    finding.setSeverity("HIGH");
                                    finding.setAnalysisNote((finding.getAnalysisNote() == null ? "" : finding.getAnalysisNote()) + " OWNER_UNKNOWN: write verification skipped.");
                                }
                            }

                            // False-positive Layer 7: review queue routing
                            boolean added;
                            if (score < discardThreshold) {
                                added = false;
                            } else if (score < reviewThreshold || cmp.verdict == ResponseComparator.Verdict.NEEDS_MANUAL_REVIEW) {
                                added = severityClassifier.addReviewFindingIfUnique(finding);
                            } else {
                                if (score >= autoConfirmThreshold) {
                                    finding.setConfidenceScore(Math.max(score, 95));
                                    finding.setConfirmedByDiff(true);
                                }
                                added = severityClassifier.addFindingIfUnique(finding);
                            }
                            if (added) {
                                // Track finding count on the endpoint
                                if (score >= reviewThreshold) {
                                    ep.addHuntFinding(finding.getSeverity());
                                }
                                
                                // Phase 15: Critical Fast-Path alert
                                if ("CRITICAL".equals(finding.getSeverity())) {
                                    onLog.accept("🔥 CRITICAL FINDING: " + finding.getLabel() + " on " + finding.getEndpointPattern());
                                }
                            }
                        }
                    }
                    
                    // Update live probe progress for this endpoint
                    ep.setHuntProbesCompleted(Math.min(vectors.size(), ep.getHuntProbesCompleted() + 1));
                    lastProgressAtMs = System.currentTimeMillis();
                    store.saveEndpointsToPersistence();
                }

                // Finalize this endpoint's hunt status
                if (!endpointAborted && !isStopped.get() && !Thread.currentThread().isInterrupted()) {
                    if (!hadError) {
                        ep.setHuntErrorCode(""); // Clear any inherited error
                    }
                    ep.finalizeHuntStatus();
                    ep.setHarvestIdCountAtLastHunt(computeHarvestIdCount(ep));
                    ep.setHarvestDeltaCount(0);
                    store.saveEndpointsToPersistence();
                    endpointCompleted = true;
                    long endpointElapsed = System.currentTimeMillis() - endpointStartedAt;
                    onLog.accept("✅ Endpoint complete: " + ep.getMethod() + " " + ep.getNormalizedPath() + " in " + endpointElapsed + "ms, probes=" + ep.getHuntProbesCompleted());
                } else if (endpointAborted) {
                    ep.setHuntStatus(HuntStatus.QUEUED);
                    if (!hadError) {
                        ep.setHuntErrorCode("ERR_STALE_RETRY");
                    }
                    store.saveEndpointsToPersistence();
                }
                } catch (Exception endpointEx) {
                    try {
                        ep.setHuntErrorCode("ERR_ENDPOINT_EXCEPTION");
                        ep.finalizeHuntStatus();
                        store.saveEndpointsToPersistence();
                        endpointCompleted = true;
                    } catch (Exception ignored) {
                    }
                    onLog.accept("❌ Endpoint failed: " + (ep != null ? ep.getMethod() + " " + ep.getNormalizedPath() : "<unknown>") + " — " + endpointEx.getMessage());
                    try {
                        api.logging().logToError("ACAS endpoint failed: " + endpointEx);
                    } catch (Exception ignored) {
                    }
                } finally {
                    if (endpointCompleted) {
                        tasksCompleted.incrementAndGet();
                    }
                    lastProgressAtMs = System.currentTimeMillis();
                    onProgress.accept(tasksCompleted.get());
                }
            }

                currentState = State.IDLE;
            } catch (Exception ex) {
                currentState = State.IDLE;
                try {
                    if (onLog != null) {
                        onLog.accept("❌ Hunt failed: " + ex.getMessage());
                    }
                } catch (Exception ignored) {
                }
                try {
                    api.logging().logToError("ACAS Hunt failed: " + ex);
                } catch (Exception ignored) {
                }
            } finally {
                if (onComplete != null) {
                    try {
                        onComplete.run();
                    } catch (Exception ignored) {
                    }
                }
                activeHuntThread = null;
            }
        }, "AcasHuntThread");
        activeHuntThread = worker;
        worker.start();
    }

    private synchronized void recoverStaleRunIfNeeded(Consumer<String> onLog) {
        Thread worker = activeHuntThread;
        boolean threadDead = worker == null || !worker.isAlive();
        boolean stateStale = currentState == State.RUNNING && threadDead;
        // Increase timeout to 15 minutes (900000ms) to prevent false positives
        boolean noProgressTooLong = currentState == State.RUNNING && !threadDead && lastProgressAtMs > 0
            && (System.currentTimeMillis() - lastProgressAtMs) > 900000;

        if (!stateStale && !noProgressTooLong) {
            return;
        }

        if (onLog != null) {
            onLog.accept("⚠️ Recovering stale hunt state (threadDead=" + threadDead + ", noProgressTooLong=" + noProgressTooLong + ")");
        }

        try {
            if (worker != null) {
                worker.interrupt();
            }
        } catch (Exception ignored) {
        }

        isPaused.set(false);
        isStopped.set(false);
        activeHuntThread = null;
        currentState = State.IDLE;
    }

    private HttpRequestResponse safeSendRequest(HttpRequest request, CapturedEndpoint ep, Consumer<String> onLog) {
        lastProgressAtMs = System.currentTimeMillis();
        if (request.httpService() == null) {
            String url = ep.getOriginalUrl();
            if (url != null) {
                try {
                    java.net.URI uri = java.net.URI.create(url);
                    java.net.URL u = uri.toURL();
                    request = request.withService(burp.api.montoya.http.HttpService.httpService(u.getHost(), u.getPort() == -1 ? u.getDefaultPort() : u.getPort(), u.getProtocol().equalsIgnoreCase("https")));
                } catch (Exception e) {
                    api.logging().logToError("ACAS: Failed to reconstruct HttpService from " + url);
                }
            }
        }

        // Apply rate limiting
        try {
            if (!rateLimiter.acquirePermit()) {
                if (onLog != null) {
                    onLog.accept("⏹️ Hunt stopped by rate limiter (time limit reached)");
                }
                isStopped.set(true);
                return burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(request, null);
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            rateLimiter.releasePermit();
            return burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(request, null);
        }

        final HttpRequest requestToSend = request;

        try {
            return CompletableFuture
            .supplyAsync(() -> com.acas.engine.ReplayGate.send(api,requestToSend))
                .get(REQUEST_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException timeout) {
            if (onLog != null) {
                onLog.accept("⚠️ Request timeout after " + REQUEST_TIMEOUT_SECONDS + "s for " + ep.getMethod() + " " + ep.getNormalizedPath());
            }
            try {
                api.logging().logToError("ACAS: Request timeout for " + ep.getMethod() + " " + ep.getNormalizedPath());
            } catch (Exception ignored) {
            }
            return burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(request, null);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(request, null);
        } catch (ExecutionException ex) {
            if (onLog != null) {
                onLog.accept("❌ Request failed: " + ex.getCause());
            }
            return burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(request, null);
        } catch (Exception ex) {
            if (onLog != null) {
                onLog.accept("❌ Request failed: " + ex.getMessage());
            }
            return burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(request, null);
        } finally {
            rateLimiter.releasePermit();
        }
    }

    public void pause() { isPaused.set(true); currentState = State.PAUSED; }
    public void resume() { 
        lastProgressAtMs = System.currentTimeMillis();
        isPaused.set(false); 
        currentState = State.RUNNING; 
    }
    public void stop() {
        isStopped.set(true);
        isPaused.set(false);
        currentState = State.STOPPED;
        Thread worker = activeHuntThread;
        if (worker != null) {
            worker.interrupt();
        }

        synchronized (huntQueue) {
            for (CapturedEndpoint ep : huntQueue) {
                if (ep.getHuntStatus() == HuntStatus.RUNNING) {
                    ep.setHuntErrorCode("ERR_STOPPED_BY_USER");
                    ep.finalizeHuntStatus();
                }
            }
            endpointMutationOverrides.clear();
        }
        store.saveEndpointsToPersistence();
        activeHuntThread = null;
    }

    public State getCurrentState() { return currentState; }
    public int getProgress() { return tasksCompleted.get(); }
    public int getTotalTasks() { return totalTasks; }

    public void refreshRuntimeState(Consumer<String> onLog) {
        recoverStaleRunIfNeeded(onLog);
        refreshHarvestDeltaState();
    }

    private void refreshHarvestDeltaState() {
        if (resourceRegistry == null) {
            harvestRehuntRecommendedCount = 0;
            return;
        }
        long now = System.currentTimeMillis();
        if ((now - lastHarvestRefreshAtMs) < 2500) {
            return;
        }
        lastHarvestRefreshAtMs = now;

        int affected = 0;
        boolean changed = false;
        for (CapturedEndpoint ep : store.getCapturedEndpoints()) {
            if (ep == null) {
                continue;
            }
            int currentCount = computeHarvestIdCount(ep);
            int baseline = ep.getHarvestIdCountAtLastHunt();
            int delta = Math.max(0, currentCount - baseline);
            if (delta != ep.getHarvestDeltaCount()) {
                ep.setHarvestDeltaCount(delta);
                changed = true;
            }
            if (delta > 0 && ep.getLastHuntTime() > 0 && ep.getHuntStatus() != CapturedEndpoint.HuntStatus.RUNNING && ep.getHuntStatus() != CapturedEndpoint.HuntStatus.QUEUED) {
                ep.setHuntStatus(CapturedEndpoint.HuntStatus.STALE);
                changed = true;
            }
            if (delta > 0 && ep.getLastHuntTime() > 0) {
                affected++;
            }
        }
        harvestRehuntRecommendedCount = affected;
        if (changed) {
            store.saveEndpointsToPersistence();
        }
    }

    private int computeHarvestIdCount(CapturedEndpoint ep) {
        if (ep == null || resourceRegistry == null) {
            return 0;
        }
        String pattern = (ep.getMethod() != null ? ep.getMethod() : "GET") + " " + (ep.getNormalizedPath() != null ? ep.getNormalizedPath() : "/");
        java.util.LinkedHashSet<String> ids = new java.util.LinkedHashSet<>();

        ActorProfile owner = store.getActor(ep.getActorId());
        if (owner != null) {
            ids.addAll(resourceRegistry.getIdsByPatternAndActor(pattern, owner.getName()));
        }
        for (String actorName : resourceRegistry.getActorsForPattern(pattern)) {
            ids.addAll(resourceRegistry.getIdsByPatternAndActor(pattern, actorName));
        }
        return ids.size();
    }

    public synchronized void setConfidenceThresholds(int discard, int review, int autoConfirm) {
        int d = clamp(discard, 0, 100);
        int r = clamp(review, 0, 100);
        int a = clamp(autoConfirm, 0, 100);
        if (d >= r) r = Math.min(100, d + 10);
        if (r >= a) a = Math.min(100, r + 10);

        this.discardThreshold = d;
        this.reviewThreshold = r;
        this.autoConfirmThreshold = a;
        saveThresholdSettings();
    }

    public int getDiscardThreshold() { return discardThreshold; }
    public int getReviewThreshold() { return reviewThreshold; }
    public int getAutoConfirmThreshold() { return autoConfirmThreshold; }

    public synchronized void setBaselineTtlMinutes(int minutes) {
        this.baselineTtlMinutes = clamp(minutes, 1, 60);
        saveThresholdSettings();
    }

    public int getBaselineTtlMinutes() { return baselineTtlMinutes; }

    /**
     * Configure rate limiting for hunts.
     */
    public void setRateLimitConfig(int requestsPerSec, int requestsPerMin, int maxConcurrent, int stopAfterMinutes, boolean enabled) {
        rateLimiter.configure(requestsPerSec, requestsPerMin, maxConcurrent, stopAfterMinutes, enabled);
    }

    public void invalidateBaselines() {
        baselineManager.invalidateAll();
    }

    public ReevaluateRoute reevaluateReviewFinding(AcasFinding finding) {
        if (finding == null) return ReevaluateRoute.REVIEW;
        try {
            String baselineKey = finding.getMethod() + " " + finding.getEndpointPattern();
            baselineManager.invalidate(baselineKey);

            HttpRequest baseReq = finding.getBaseRequest() != null
                ? burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                    burp.api.montoya.core.ByteArray.byteArray(finding.getBaseRequest()))
                : null;
            if (baseReq == null) return ReevaluateRoute.REVIEW;

            baseReq = HttpUtils.ensureRequestService(baseReq, finding.getUrl());
            HttpRequestResponse rrBase = com.acas.engine.ReplayGate.send(api,baseReq);
            if (rrBase == null || rrBase.response() == null) return ReevaluateRoute.REVIEW;

            CapturedEndpoint pseudo = new CapturedEndpoint();
            pseudo.setOriginalUrl(finding.getUrl());
            EndpointBaseline baseline = recaptureBaseline(pseudo, baseReq, rrBase.response());
            baselineManager.put(baselineKey, baseline);

            burp.api.montoya.http.message.responses.HttpResponse probeResp = finding.getMutatedResponse() != null
                ? burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                    burp.api.montoya.core.ByteArray.byteArray(finding.getMutatedResponse()))
                : null;
            burp.api.montoya.http.message.requests.HttpRequest probeReq = finding.getMutatedRequest() != null
                ? burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                    burp.api.montoya.core.ByteArray.byteArray(finding.getMutatedRequest()))
                : baseReq;

            if (probeResp == null) return ReevaluateRoute.REVIEW;

            ResponseComparator.ComparisonResult cmp = responseComparator.compare(
                probeResp,
                baseline.authenticatedResponse,
                baseline.anonymousResponse,
                baseline.invalidIdResponse,
                probeReq
            );

            finding.setFpReason(cmp.reason);
            finding.setSimilarityToOwner(cmp.similarityToOwner);
            finding.setSimilarityToAnon(cmp.similarityToAnon);
            finding.setSimilarityToInvalid(cmp.similarityToInvalid);
            finding.setMatchesAnonymous(cmp.similarityToAnon > 0.90);
            finding.setMatchesInvalidId(cmp.similarityToInvalid > 0.90);
            finding.setBaselineCapturedAtEpochMs(baseline.capturedAtEpochMs);

            int score = confidenceScorer.score(
                finding,
                cmp.verdict,
                probeResp,
                baseline.authenticatedResponse,
                baseline.anonymousResponse
            );
            finding.setConfidenceScore(score);

            if (score < discardThreshold || cmp.verdict == ResponseComparator.Verdict.FALSE_POSITIVE || cmp.verdict == ResponseComparator.Verdict.LIKELY_FALSE) {
                severityClassifier.removeReviewFinding(finding.getId());
                return ReevaluateRoute.DISCARD;
            }

            if (score > reviewThreshold) {
                severityClassifier.removeReviewFinding(finding.getId());
                severityClassifier.addFindingIfUnique(finding);
                return ReevaluateRoute.CONFIRMED;
            }

            return ReevaluateRoute.REVIEW;
        } catch (Exception ex) {
            return ReevaluateRoute.REVIEW;
        }
    }

    private EndpointBaseline recaptureBaseline(CapturedEndpoint ep, HttpRequest baseReq, burp.api.montoya.http.message.responses.HttpResponse baseResponse) {
        EndpointBaseline baseline = new EndpointBaseline();
        baseline.authenticatedResponse = baseResponse;

        HttpRequest anonReq = baselineManager.buildAnonymous(baseReq, store.getAllIdentityHeaderNames());
        HttpRequestResponse rrAnon = safeSendRequest(anonReq, ep, null);
        baseline.anonymousResponse = rrAnon != null ? rrAnon.response() : null;

        HttpRequest invalidReq = baselineManager.replaceIdWith(baseReq, "0");
        HttpRequestResponse rrInvalid = safeSendRequest(invalidReq, ep, null);
        baseline.invalidIdResponse = rrInvalid != null ? rrInvalid.response() : null;

        HttpRequest nonExistentReq = baselineManager.replaceIdWith(baseReq, "999999999");
        HttpRequestResponse rrNonExistent = safeSendRequest(nonExistentReq, ep, null);
        baseline.nonExistentResponse = rrNonExistent != null ? rrNonExistent.response() : null;
        baseline.capturedAtEpochMs = System.currentTimeMillis();
        return baseline;
    }

    private void loadThresholdSettings() {
        discardThreshold = loadPrefInt(PREF_THRESHOLD_DISCARD, 30);
        reviewThreshold = loadPrefInt(PREF_THRESHOLD_REVIEW, 60);
        autoConfirmThreshold = loadPrefInt(PREF_THRESHOLD_AUTOCONFIRM, 90);
        baselineTtlMinutes = loadPrefInt(PREF_BASELINE_TTL_MINUTES, 5);
        setConfidenceThresholds(discardThreshold, reviewThreshold, autoConfirmThreshold);
        setBaselineTtlMinutes(baselineTtlMinutes);
    }

    private void saveThresholdSettings() {
        try {
            api.persistence().preferences().setString(PREF_THRESHOLD_DISCARD, String.valueOf(discardThreshold));
            api.persistence().preferences().setString(PREF_THRESHOLD_REVIEW, String.valueOf(reviewThreshold));
            api.persistence().preferences().setString(PREF_THRESHOLD_AUTOCONFIRM, String.valueOf(autoConfirmThreshold));
            api.persistence().preferences().setString(PREF_BASELINE_TTL_MINUTES, String.valueOf(baselineTtlMinutes));
        } catch (Exception ignored) {
        }
    }

    private int loadPrefInt(String key, int fallback) {
        try {
            String v = api.persistence().preferences().getString(key);
            if (v == null || v.isBlank()) return fallback;
            return Integer.parseInt(v.trim());
        } catch (Exception ignored) {
            return fallback;
        }
    }

    private int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }
}
