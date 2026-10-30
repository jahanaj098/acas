package com.acas;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.acas.engine.ObjectManager;
import com.acas.engine.ReplayEngine;
import com.acas.harvest.IdHarvester;
import com.acas.harvest.ResourceRegistry;
import com.acas.menu.AcasContextMenu;
import com.acas.notification.NotificationService;
import com.acas.store.ActorStore;
import com.acas.store.PayloadStore;
import com.acas.store.PersistenceManager;
import com.acas.store.WorkspaceState;
import com.acas.ui.AcasPanel;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;

/**
 * ACAS — Authorization Consistency Testing
 * 
 * @author jahanaj098 (https://github.com/jahanaj098)
 */
public class AcasExtension implements BurpExtension {

    public static final String AUTHOR = "jahanaj098";
    public static final String AUTHOR_GITHUB = "https://github.com/jahanaj098";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("ACAS — Authorization Consistency Testing (by jahanaj098)");
        api.logging().logToOutput("ACAS extension loaded. Author: " + AUTHOR + " (" + AUTHOR_GITHUB + ")");

        // Initialize persistence manager
        PersistenceManager persistence = null;
        try {
            persistence = new PersistenceManager(System.getProperty("user.home"));
        } catch (Exception e) {
            api.logging().logToError("ACAS: Failed to initialize persistence manager: " + e.getMessage());
        }

        // Core components
        ActorStore store = new ActorStore(api);
        ObjectManager objectManager = new ObjectManager(api);
        ReplayEngine replayEngine = new ReplayEngine(api, store);
        PayloadStore payloadStore = new PayloadStore(api);
        ResourceRegistry resourceRegistry = new ResourceRegistry();
        IdHarvester idHarvester = new IdHarvester(resourceRegistry, store);
        com.acas.engine.MutationRegistry mutationRegistry = new com.acas.engine.MutationRegistry(api);
        com.acas.engine.MutationEngine mutationEngine = new com.acas.engine.MutationEngine(store, objectManager, mutationRegistry, payloadStore, resourceRegistry);
        com.acas.engine.DiscoveryEngine discoveryEngine = new com.acas.engine.DiscoveryEngine(objectManager);
        com.acas.engine.ClassifierEngine classifierEngine = new com.acas.engine.ClassifierEngine(api);
        com.acas.engine.ProbeEngine probeEngine = new com.acas.engine.ProbeEngine(api, store, replayEngine, discoveryEngine, classifierEngine);
        NotificationService notifier = new NotificationService(api);

        // Load persisted workspace state
        WorkspaceState savedState = null;
        if (persistence != null) {
            try {
                savedState = persistence.loadWorkspaceState();
                api.logging().logToOutput("ACAS: Loaded persisted state - " + savedState);
                
                // Restore actors
                if (savedState.actors != null && !savedState.actors.isEmpty()) {
                    for (com.acas.model.ActorProfile actor : savedState.actors) {
                        store.addActor(actor);
                    }
                    api.logging().logToOutput("ACAS: Restored " + savedState.actors.size() + " actor(s)");
                }
            } catch (Exception e) {
                api.logging().logToError("ACAS: Error loading persisted state: " + e.getMessage());
            }
        }

        // Register after workspace restoration: loading a project must not initiate requests.
        com.acas.export.ActorIdentityLookup identityLookup = new com.acas.export.ActorIdentityLookup(api, store);
        store.setIdentityLookup(identityLookup::schedule);
        store.setIdentityTester(identityLookup::test);
        store.setCaptureWorkListener(probeEngine::scheduleMissingProbes);

        // Build UI on EDT
        AcasPanel[] panelRef = new AcasPanel[1];
        try {
            SwingUtilities.invokeAndWait(() -> {
                panelRef[0] = new AcasPanel(api, store, objectManager, replayEngine, mutationEngine, mutationRegistry, payloadStore, resourceRegistry, probeEngine, classifierEngine, notifier);
                api.userInterface().registerSuiteTab("ACAS", panelRef[0]);
            });
        } catch (Exception e) {
            String errorMsg = e.getMessage();
            if (e.getCause() != null) {
                errorMsg = e.getCause().getClass().getSimpleName() + ": " + e.getCause().getMessage();
                // Log full stack trace for debugging
                java.io.StringWriter sw = new java.io.StringWriter();
                e.getCause().printStackTrace(new java.io.PrintWriter(sw));
                api.logging().logToError("ACAS UI Init StackTrace:\n" + sw.toString());
            }
            api.logging().logToError("ACAS: UI init error: " + errorMsg);
            return;
        }

        // Register context menu
        api.userInterface().registerContextMenuItemsProvider(
            new AcasContextMenu(api, store, panelRef[0], probeEngine, mutationRegistry,
                                panelRef[0].getHuntManager())
        );

        // Passive Observation Handler
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
                return RequestToBeSentAction.continueWith(req);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
                HttpRequest req = resp.initiatingRequest();
                
                // FILTER: Ignore requests generated by ACAS internal engines
                if (req.hasHeader(com.acas.engine.ReplayEngine.ACAS_INTERNAL_HEADER)) {
                    return ResponseReceivedAction.continueWith(resp);
                }

                if (req.httpService() == null) {
                    api.logging().logToError("ACAS Capture: Request is missing HttpService! Path: " + req.path());
                }
                boolean requireBurpScope = store.getScopeConfig() == null || store.getScopeConfig().isUseBurpScope();
                if (!requireBurpScope || api.scope().isInScope(req.url())) {
                    // BLACKLIST: skip auto-testing of unwanted requests (static assets,
                    // preflight, analytics, …). The list is editable in Settings.
                    String blacklist = store.getGlobalSetting("capture_blacklist");
                    if (blacklist == null || blacklist.trim().isEmpty()) {
                        blacklist = store.getSetting("capture_blacklist");
                    }
                    if (blacklist == null || blacklist.trim().isEmpty()) {
                        blacklist = com.acas.util.CaptureFilter.DEFAULT_BLACKLIST;
                    }
                    if (com.acas.util.CaptureFilter.isBlacklisted(
                            req.method(), req.url(), req.path(), resp.headerValue("Content-Type"), blacklist)) {
                        return ResponseReceivedAction.continueWith(resp);
                    }

                    String ownerId=store.getActorIdByRequest(req);
                    var captureSession=store.captureSession(ownerId);
                    // Unknown or ambiguous credentials are never assigned to a selected actor.
                    store.whileCaptureCurrent(captureSession,()->{
                        var actor=store.getActor(ownerId);
                        String color=com.acas.util.PwnFoxColors.name(req.headerValue("X-PwnFox-Color"));
                        String hex=com.acas.util.PwnFoxColors.hex(color);
                        if(hex!=null && !hex.equalsIgnoreCase(actor.getColor())) {
                            actor.setPwnfoxColor(color);store.updateActor(actor);
                        }
                        store.addHistoryEntry(ownerId,req,resp);
                        probeEngine.recordObserved(ownerId,req,resp);
                        probeEngine.runProbes(captureSession,req,store::addCapturedEndpoint);
                    });

                    // 2. Background Discovery: Map objects for any identified actor
                }
                return ResponseReceivedAction.continueWith(resp);
            }
        });

        // Shutdown hook
        var freezeDiagnostics=new com.acas.util.UiFreezeDiagnostics(api.logging()::logToError);
        freezeDiagnostics.start();
        PersistenceManager finalPersistence = persistence;
        api.extension().registerUnloadingHandler(() -> {
            freezeDiagnostics.close();
            store.stopAllCapture();
            replayEngine.shutdown();
            probeEngine.shutdown();
            notifier.shutdown();
            identityLookup.close();
            store.close();
            if (finalPersistence != null) {
                finalPersistence.shutdown();
            }
        });

        String version = "1.0.0";
        try {
            Package p = AcasExtension.class.getPackage();
            if (p != null && p.getImplementationVersion() != null && !p.getImplementationVersion().isBlank()) {
                version = p.getImplementationVersion();
            }
        } catch (Exception ignored) {
        }

        api.logging().logToOutput("ACAS Extension loaded. Version " + version);
        api.logging().logToOutput("ACAS Build Fingerprint: " + runtimeFingerprint());
        api.logging().logToOutput("Right-click any request -> Save as Actor Profile (ACAS) to get started.");
    }

    private String runtimeFingerprint() {
        try {
            java.net.URL codeSource = AcasExtension.class
                .getProtectionDomain()
                .getCodeSource()
                .getLocation();

            java.nio.file.Path path = java.nio.file.Paths.get(codeSource.toURI());
            String fileName = path.getFileName() != null ? path.getFileName().toString() : "unknown";

            String modified = "unknown";
            long size = -1L;
            if (java.nio.file.Files.exists(path)) {
                java.nio.file.attribute.FileTime ft = java.nio.file.Files.getLastModifiedTime(path);
                modified = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                    .withZone(java.time.ZoneId.systemDefault())
                    .format(ft.toInstant());
                size = java.nio.file.Files.size(path);
            }

            return fileName + " | modified=" + modified + " | size=" + size;
        } catch (Exception e) {
            return "unavailable (" + e.getClass().getSimpleName() + ")";
        }
    }

}
