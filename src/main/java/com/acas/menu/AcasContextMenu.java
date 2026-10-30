package com.acas.menu;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import com.acas.model.ActorProfile;
import com.acas.model.CapturedEndpoint;
import com.acas.store.ActorStore;
import com.acas.ui.AcasPanel;
import com.acas.ui.SaveActorDialog;
import com.acas.ui.SaveActorManualDialog;
import com.acas.util.HttpUtils;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

public class AcasContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final ActorStore store;
    private final AcasPanel acasPanel;
    private final com.acas.engine.ProbeEngine probeEngine;
    private final com.acas.engine.MutationRegistry mutationRegistry;
    private final com.acas.engine.HuntManager huntManager;

    public AcasContextMenu(MontoyaApi api,
                           ActorStore store,
                           AcasPanel acasPanel,
                           com.acas.engine.ProbeEngine probeEngine,
                           com.acas.engine.MutationRegistry mutationRegistry,
                           com.acas.engine.HuntManager huntManager) {
        this.api = api;
        this.store = store;
        this.acasPanel = acasPanel;
        this.probeEngine = probeEngine;
        this.mutationRegistry = mutationRegistry;
        this.huntManager = huntManager;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        java.util.Optional<burp.api.montoya.http.message.HttpRequestResponse> rrOpt = extractRR(event);
        if (rrOpt.isEmpty()) return items;

        burp.api.montoya.http.message.HttpRequestResponse rr = rrOpt.get();

        // Separator label
        JLabel label = new JLabel(" ACAS ");
        label.setFont(new Font("SansSerif", Font.BOLD, 11));
        label.setForeground(new Color(99, 102, 241));
        items.add(label);

        // Save as Actor
        JMenuItem saveActor = new JMenuItem("Save as Actor Profile (ACAS)");
        saveActor.setFont(new Font("SansSerif", Font.PLAIN, 12));
        saveActor.addActionListener(e -> SwingUtilities.invokeLater(() -> openSaveDialog(event, rr, false)));
        items.add(saveActor);

        JMenuItem saveActorManual = new JMenuItem("Save as Actor Profile - Manual (ACAS)");
        saveActorManual.setFont(new Font("SansSerif", Font.PLAIN, 12));
        saveActorManual.addActionListener(e -> SwingUtilities.invokeLater(() -> openSaveDialog(event, rr, true)));
        items.add(saveActorManual);

        // Update Actor Session — fully inline, same pattern as other working menu items
        JMenuItem updateSession = new JMenuItem("Update Actor Session (ACAS)");
        updateSession.setFont(new Font("SansSerif", Font.PLAIN, 12));
        updateSession.addActionListener(e -> {
            try {
                api.logging().logToOutput("ACAS: Update Actor Session clicked");

                // --- get request (same direct access as openSaveDialog) ---
                HttpRequest req = rr.request();
                if (req == null) {
                    JOptionPane.showMessageDialog(null, "No request available.", "ACAS", JOptionPane.WARNING_MESSAGE);
                    return;
                }

                // --- check actors ---
                List<ActorProfile> allActors = store.getAllActors();
                if (allActors.isEmpty()) {
                    JOptionPane.showMessageDialog(null,
                        "No actor profiles found.\nSave an actor first via \"Save as Actor Profile (ACAS)\".",
                        "ACAS - Update Session", JOptionPane.WARNING_MESSAGE);
                    return;
                }

                // --- collect identity headers for preview ---
                List<String> identityLines = new ArrayList<>();
                for (HttpHeader h : req.headers()) {
                    String n = h.name().toLowerCase();
                    if (n.equals("cookie") || n.equals("authorization") || n.contains("token")
                            || n.contains("api-key") || n.contains("apikey")
                            || n.contains("session") || n.contains("auth")) {
                        String val = h.value();
                        identityLines.add(h.name() + ": " + (val.length() > 80 ? val.substring(0, 77) + "..." : val));
                    }
                }

                if (identityLines.isEmpty()) {
                    JOptionPane.showMessageDialog(null,
                        "No identity headers (Cookie, Authorization, X-Api-Key…) found.\n"
                        + "Right-click an authenticated request.",
                        "ACAS - Update Session", JOptionPane.WARNING_MESSAGE);
                    return;
                }

                // --- pre-select actor pending refresh if hunt is paused ---
                String pendingActorId = huntManager != null
                    ? huntManager.getHealthMonitor().getPendingRefreshActorId() : null;
                ActorProfile[] actorArray = allActors.toArray(new ActorProfile[0]);
                ActorProfile preSelected = actorArray[0];
                for (ActorProfile a : actorArray) {
                    if (a.getId().equals(pendingActorId)) { preSelected = a; break; }
                }

                JComboBox<ActorProfile> combo = new JComboBox<>(actorArray);
                combo.setSelectedItem(preSelected);
                combo.setRenderer(new javax.swing.DefaultListCellRenderer() {
                    @Override public java.awt.Component getListCellRendererComponent(
                            JList<?> l, Object v, int i, boolean s, boolean f) {
                        super.getListCellRendererComponent(l, v, i, s, f);
                        if (v instanceof ActorProfile) setText(((ActorProfile) v).getName() + "  [" + ((ActorProfile) v).getRole() + "]");
                        return this;
                    }
                });

                JTextArea previewArea = new JTextArea(String.join("\n", identityLines));
                previewArea.setEditable(false);
                previewArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
                previewArea.setRows(Math.min(identityLines.size() + 1, 8));

                Object[] msg = {
                    "Select actor to update session for:", combo,
                    " ",
                    "Identity headers that will be updated:", new JScrollPane(previewArea)
                };

                int confirm = JOptionPane.showConfirmDialog(
                    null, msg, "Update Actor Session (ACAS)",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
                if (confirm != JOptionPane.OK_OPTION) return;

                ActorProfile chosen = (ActorProfile) combo.getSelectedItem();
                if (chosen == null) return;

                // --- apply the session update ---
                boolean updated = store.updateActorSession(chosen.getId(), req);
                if (!updated) {
                    JOptionPane.showMessageDialog(null, "Failed — actor not found in store.", "ACAS", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                api.logging().logToOutput("ACAS: Session updated for '" + chosen.getName() + "'");

                // --- clear expiry + auto-resume hunt if waiting ---
                if (huntManager != null) {
                    huntManager.getHealthMonitor().clearExpired(chosen.getId());
                    if (huntManager.getCurrentState() == com.acas.engine.HuntManager.State.PAUSED
                            && chosen.getId().equals(pendingActorId)) {
                        huntManager.resumeAfterSessionRefresh();
                        SwingUtilities.invokeLater(() -> {
                            if (acasPanel != null) acasPanel.getHuntHubPanel().onSessionResumeClicked();
                        });
                        JOptionPane.showMessageDialog(null,
                            "Session updated for '" + chosen.getName() + "'.\nHunt auto-resumed.",
                            "ACAS - Session Updated", JOptionPane.INFORMATION_MESSAGE);
                        return;
                    }
                }

                JOptionPane.showMessageDialog(null,
                    "Session updated for '" + chosen.getName() + "'.\nNew credentials will be used in all future mutations.",
                    "ACAS - Session Updated", JOptionPane.INFORMATION_MESSAGE);

            } catch (Throwable ex) {
                java.io.StringWriter sw = new java.io.StringWriter();
                ex.printStackTrace(new java.io.PrintWriter(sw));
                api.logging().logToError("ACAS: Update Session failed:\n" + sw);
                JOptionPane.showMessageDialog(null,
                    "ACAS Update Session error: " + ex.getMessage()
                    + "\nSee Burp > Extensions > ACAS > Output for details.",
                    "ACAS", JOptionPane.ERROR_MESSAGE);
            }
        });
        items.add(updateSession);


        items.add(new JSeparator());
        return items;
    }
    /**
     * "Update Actor Session (ACAS)" handler.
     * Receives a pre-snapshotted copy of the request (taken eagerly in the action
     * listener before the context menu RR object could become stale).
     */
    private void openUpdateSessionDialog(RequestResponseSnapshot snapshot) {
        try {
            api.logging().logToOutput("ACAS: openUpdateSessionDialog — entered");

            HttpRequest request = snapshot != null ? snapshot.request : null;
            if (request == null) {
                api.logging().logToOutput("ACAS: openUpdateSessionDialog — snapshot.request is null");
                JOptionPane.showMessageDialog(findParentFrame(),
                    "No request found in this context.\nTry right-clicking from Proxy History or Repeater.",
                    "ACAS - Update Session", JOptionPane.WARNING_MESSAGE);
                return;
            }
            api.logging().logToOutput("ACAS: openUpdateSessionDialog — request: " + request.method() + " " + request.path());

            List<ActorProfile> actors = store.getAllActors();
            if (actors.isEmpty()) {
                api.logging().logToOutput("ACAS: openUpdateSessionDialog — no actors in store");
                JOptionPane.showMessageDialog(findParentFrame(),
                    "No actor profiles found.\nSave an actor first via \"Save as Actor Profile (ACAS)\".",
                    "ACAS - Update Session", JOptionPane.WARNING_MESSAGE);
                return;
            }
            api.logging().logToOutput("ACAS: openUpdateSessionDialog — actors: " + actors.size());

            // Collect identity headers for preview
            List<String> identityHeadersFound = new ArrayList<>();
            for (burp.api.montoya.http.message.HttpHeader h : request.headers()) {
                String n = h.name().toLowerCase();
                if (n.equals("cookie") || n.equals("authorization")
                        || n.contains("token") || n.contains("api-key") || n.contains("apikey")
                        || n.contains("session") || n.contains("auth") || n.contains("bearer")) {
                    String val = h.value();
                    String preview = val.length() > 80 ? val.substring(0, 77) + "..." : val;
                    identityHeadersFound.add(h.name() + ": " + preview);
                }
            }
            api.logging().logToOutput("ACAS: openUpdateSessionDialog — identity headers found: " + identityHeadersFound.size());

            if (identityHeadersFound.isEmpty()) {
                JOptionPane.showMessageDialog(findParentFrame(),
                    "No identity headers (Cookie, Authorization, X-Api-Key, etc.) found in this request.\n"
                    + "Make sure you are right-clicking an authenticated request.",
                    "ACAS - Update Session", JOptionPane.WARNING_MESSAGE);
                return;
            }

            // Pre-select the actor pending a session refresh (if hunt is paused)
            String pendingActorId = huntManager != null
                ? huntManager.getHealthMonitor().getPendingRefreshActorId() : null;

            ActorProfile[] actorArray = actors.toArray(new ActorProfile[0]);
            ActorProfile preSelected = actorArray[0];
            for (ActorProfile a : actorArray) {
                if (a.getId().equals(pendingActorId)) { preSelected = a; break; }
            }

            JComboBox<ActorProfile> actorCombo = new JComboBox<>(actorArray);
            actorCombo.setSelectedItem(preSelected);
            actorCombo.setRenderer(new javax.swing.DefaultListCellRenderer() {
                @Override
                public java.awt.Component getListCellRendererComponent(JList<?> list, Object value,
                        int index, boolean isSelected, boolean cellHasFocus) {
                    super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                    if (value instanceof ActorProfile) {
                        ActorProfile a = (ActorProfile) value;
                        setText(a.getName() + "  [" + a.getRole() + "]");
                    }
                    return this;
                }
            });

            JTextArea previewArea = new JTextArea(String.join("\n", identityHeadersFound));
            previewArea.setEditable(false);
            previewArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
            previewArea.setRows(Math.min(identityHeadersFound.size() + 1, 8));

            JPanel panel = new JPanel();
            panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
            panel.add(new JLabel("Select actor to update session for:"));
            panel.add(Box.createVerticalStrut(4));
            panel.add(actorCombo);
            panel.add(Box.createVerticalStrut(10));
            panel.add(new JLabel("Identity headers from this request (will replace stored values):"));
            panel.add(Box.createVerticalStrut(4));
            panel.add(new JScrollPane(previewArea));

            api.logging().logToOutput("ACAS: openUpdateSessionDialog — showing confirm dialog");
            int result = JOptionPane.showConfirmDialog(
                findParentFrame(), panel,
                "Update Actor Session (ACAS)",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE
            );
            if (result != JOptionPane.OK_OPTION) {
                api.logging().logToOutput("ACAS: openUpdateSessionDialog — user cancelled");
                return;
            }

            ActorProfile chosen = (ActorProfile) actorCombo.getSelectedItem();
            if (chosen == null) return;
            api.logging().logToOutput("ACAS: openUpdateSessionDialog — updating actor: " + chosen.getName());

            boolean updated = store.updateActorSession(chosen.getId(), request);
            if (!updated) {
                JOptionPane.showMessageDialog(findParentFrame(),
                    "Failed to update session — actor not found.", "ACAS", JOptionPane.ERROR_MESSAGE);
                return;
            }

            api.logging().logToOutput("ACAS: Session headers updated for actor '" + chosen.getName() + "'.");

            // Clear health monitor + auto-resume if hunt was waiting for this actor
            if (huntManager != null) {
                huntManager.getHealthMonitor().clearExpired(chosen.getId());
                if (huntManager.getCurrentState() == com.acas.engine.HuntManager.State.PAUSED
                        && chosen.getId().equals(pendingActorId)) {
                    huntManager.resumeAfterSessionRefresh();
                    SwingUtilities.invokeLater(() -> {
                        if (acasPanel != null) acasPanel.getHuntHubPanel().onSessionResumeClicked();
                    });
                    JOptionPane.showMessageDialog(findParentFrame(),
                        "Session updated for '" + chosen.getName() + "'.\nHunt has been automatically resumed.",
                        "ACAS - Session Updated", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
            }

            JOptionPane.showMessageDialog(findParentFrame(),
                "Session headers updated for actor '" + chosen.getName() + "'.\n"
                + "The new credentials will be used in all future mutations.",
                "ACAS - Session Updated", JOptionPane.INFORMATION_MESSAGE);

        } catch (Throwable t) {
            java.io.StringWriter sw = new java.io.StringWriter();
            t.printStackTrace(new java.io.PrintWriter(sw));
            api.logging().logToError("ACAS: openUpdateSessionDialog FAILED:\n" + sw);
            try {
                JOptionPane.showMessageDialog(findParentFrame(),
                    "ACAS Update Session failed.\nError: " + t.getClass().getSimpleName() + ": " + t.getMessage()
                    + "\nSee Burp > Extensions > ACAS > Output tab for full stack trace.",
                    "ACAS", JOptionPane.ERROR_MESSAGE);
            } catch (Throwable ignored) { /* absolute last resort */ }
        }
    }


    private void openSaveDialog(ContextMenuEvent event, burp.api.montoya.http.message.HttpRequestResponse rr, boolean manualMode) {

        HttpRequest request = rr.request();
        int status = rr.response() != null ? rr.response().statusCode() : 0;
        String suggestedActorName = extractSuggestedActorName(event, request);

        // Collect all headers from the request
        List<String[]> headers = new ArrayList<>();
        for (HttpHeader h : request.headers()) {
            headers.add(new String[]{h.name(), h.value()});
        }

        Frame parent = findParentFrame();
        String fullRequest = new String(request.toByteArray().getBytes(), StandardCharsets.UTF_8);
        ActorProfile actor = null;

        if (manualMode) {
            SaveActorManualDialog dialog = new SaveActorManualDialog(parent, headers, request.url(), fullRequest, status, suggestedActorName);
            dialog.setVisible(true);
            if (dialog.isConfirmed()) {
                actor = dialog.getResult();
            }
        } else {
            SaveActorDialog dialog = new SaveActorDialog(parent, headers, request.url(), fullRequest, status, suggestedActorName);
            dialog.setVisible(true);
            if (dialog.isConfirmed()) {
                actor = dialog.getResult();
            }
        }

        if (actor != null) {
            store.addActor(actor);
            
            // AUTO-SEEDING: Mark as active and record the source request
            store.startCaptureAfterActorSave(actor.getId());
            store.addHistoryEntry(actor.getId(), rr.request(), rr.response());
            probeEngine.recordObserved(actor.getId(),rr.request(),rr.response());
            
            // Trigger probes so it appears in Probe Classification instantly
            probeEngine.runProbes(actor.getId(), rr.request(), endpoint -> {
                store.addCapturedEndpoint(endpoint);
            });

            api.logging().logToOutput("ACAS: Saved actor '" + actor.getName() + "' [" + actor.getRole() + "] and seeded history." + (manualMode ? " (manual identity headers)" : ""));
            JOptionPane.showMessageDialog(null,
                "Actor '" + actor.getName() + "' saved successfully!\n" +
                "Source request has been added to History & Probes.",
                "ACAS", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private java.util.Optional<burp.api.montoya.http.message.HttpRequestResponse> extractRR(ContextMenuEvent event) {
        // From Repeater/Editor
        if (event.messageEditorRequestResponse().isPresent()) {
            MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();
            return java.util.Optional.of(editor.requestResponse());
        }
        // From Proxy history / Target / multi-select
        if (!event.selectedRequestResponses().isEmpty()) {
            return java.util.Optional.of(event.selectedRequestResponses().get(0));
        }
        return java.util.Optional.empty();
    }

    private RequestResponseSnapshot snapshotRequestResponse(burp.api.montoya.http.message.HttpRequestResponse rr) {
        if (rr == null) {
            return new RequestResponseSnapshot(null, null);
        }
        try {
            HttpRequest req = rr.request();
            burp.api.montoya.http.message.responses.HttpResponse resp = rr.response();

            HttpRequest reqCopy = null;
            burp.api.montoya.http.message.responses.HttpResponse respCopy = null;

            if (req != null) {
                byte[] reqBytes = req.toByteArray().getBytes();
                reqCopy = HttpRequest.httpRequest(burp.api.montoya.core.ByteArray.byteArray(reqBytes));
                try {
                    if (req.httpService() != null) {
                        reqCopy = reqCopy.withService(req.httpService());
                    }
                } catch (Exception ignored) {
                }
                reqCopy = HttpUtils.ensureRequestService(reqCopy, safeUrl(req));
            }

            if (resp != null) {
                byte[] respBytes = resp.toByteArray().getBytes();
                respCopy = burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                    burp.api.montoya.core.ByteArray.byteArray(respBytes));
            }

            return new RequestResponseSnapshot(reqCopy, respCopy);
        } catch (Throwable t) {
            api.logging().logToError("ACAS: Failed to snapshot request/response for context menu: " + t.getMessage());
            return new RequestResponseSnapshot(null, null);
        }
    }

    private static final class RequestResponseSnapshot {
        private final HttpRequest request;
        private final burp.api.montoya.http.message.responses.HttpResponse response;

        private RequestResponseSnapshot(HttpRequest request,
                                        burp.api.montoya.http.message.responses.HttpResponse response) {
            this.request = request;
            this.response = response;
        }
    }

    private Frame findParentFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible()) return f;
        }
        return null;
    }

    private String safeUrl(HttpRequest request) {
        if (request == null) {
            return null;
        }
        try {
            return request.url();
        } catch (Exception ignored) {
            return null;
        }
    }

    private String extractSuggestedActorName(ContextMenuEvent event, HttpRequest request) {
        // Actor name auto-fill disabled globally by request.
        return null;
    }

    private String deriveActorNameFromRequest(HttpRequest request) {
        if (request == null) {
            return "Actor";
        }
        try {
            String url = request.url();
            java.net.URI uri = java.net.URI.create(url);
            String host = sanitizeNamePart(uri.getHost());
            String firstPathSegment = null;
            String path = uri.getPath();
            if (path != null && !path.isBlank()) {
                for (String part : path.split("/")) {
                    if (part != null && !part.isBlank()) {
                        firstPathSegment = sanitizeNamePart(part);
                        if (firstPathSegment != null && !firstPathSegment.isBlank()) {
                            break;
                        }
                    }
                }
            }

            String derived;
            if (host != null && !host.isBlank() && firstPathSegment != null && !firstPathSegment.isBlank()) {
                derived = host + "-" + firstPathSegment;
            } else if (host != null && !host.isBlank()) {
                derived = host;
            } else if (firstPathSegment != null && !firstPathSegment.isBlank()) {
                derived = firstPathSegment;
            } else {
                derived = "Actor";
            }

            if (isUsableRepeaterCaption(derived)) {
                api.logging().logToOutput("[ACAS DEBUG] Using request-derived actor name: " + derived);
                return derived;
            }
        } catch (Exception ignored) {
        }
        return "Actor";
    }

    private String sanitizeNamePart(String text) {
        if (text == null) {
            return null;
        }
        String s = text.trim().toLowerCase();
        if (s.isEmpty()) {
            return null;
        }
        s = s.replaceAll("[^a-z0-9._-]+", "-");
        s = s.replaceAll("-+", "-");
        s = s.replaceAll("(^-|-$)", "");
        return s;
    }

    private String extractCaptionFromObjectGraph(Object root) {
        try {
            java.util.Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<>());
            java.util.ArrayDeque<Object> queue = new java.util.ArrayDeque<>();
            java.util.ArrayDeque<Integer> depth = new java.util.ArrayDeque<>();
            queue.add(root);
            depth.add(0);

            while (!queue.isEmpty()) {
                Object current = queue.poll();
                int d = depth.poll();
                if (current == null || visited.contains(current) || d > 3) {
                    continue;
                }
                visited.add(current);

                if (current instanceof String) {
                    String s = ((String) current).trim();
                    if (isLikelyTabCaptionCandidate(s)) {
                        return s;
                    }
                    continue;
                }

                if (current instanceof java.util.Optional) {
                    java.util.Optional<?> optional = (java.util.Optional<?>) current;
                    optional.ifPresent(v -> {
                        if (!visited.contains(v) && d + 1 <= 3) {
                            queue.add(v);
                            depth.add(d + 1);
                        }
                    });
                    continue;
                }

                Class<?> type = current.getClass();

                // Probe no-arg String-returning methods, including obfuscated names.
                for (java.lang.reflect.Method m : type.getDeclaredMethods()) {
                    if (m.getParameterCount() != 0 || m.getReturnType() == Void.TYPE) {
                        continue;
                    }
                    try {
                        m.setAccessible(true);
                        Object value = m.invoke(current);
                        enqueueForCaptionScan(value, queue, depth, visited, d + 1);
                    } catch (Exception ignored) {
                    }
                }

                // Probe fields recursively, including obfuscated members.
                for (java.lang.reflect.Field f : type.getDeclaredFields()) {
                    try {
                        f.setAccessible(true);
                        Object value = f.get(current);
                        enqueueForCaptionScan(value, queue, depth, visited, d + 1);
                    } catch (Exception ignored) {
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private void enqueueForCaptionScan(Object value,
                                       java.util.ArrayDeque<Object> queue,
                                       java.util.ArrayDeque<Integer> depth,
                                       java.util.Set<Object> visited,
                                       int nextDepth) {
        if (value == null || nextDepth > 3) {
            return;
        }
        Object unwrapped = unwrapOptional(value);
        if (unwrapped == null || visited.contains(unwrapped)) {
            return;
        }

        if (unwrapped instanceof Iterable) {
            for (Object item : (Iterable<?>) unwrapped) {
                if (item != null && !visited.contains(item)) {
                    queue.add(item);
                    depth.add(nextDepth);
                }
            }
            return;
        }

        if (unwrapped.getClass().isArray()) {
            int len = java.lang.reflect.Array.getLength(unwrapped);
            for (int i = 0; i < len; i++) {
                Object item = java.lang.reflect.Array.get(unwrapped, i);
                if (item != null && !visited.contains(item)) {
                    queue.add(item);
                    depth.add(nextDepth);
                }
            }
            return;
        }

        queue.add(unwrapped);
        depth.add(nextDepth);
    }

    private boolean isLikelyTabCaptionCandidate(String text) {
        if (!isUsableRepeaterCaption(text)) {
            return false;
        }
        String t = text.trim();
        if (t.length() > 48) {
            return false;
        }
        String lower = t.toLowerCase();
        if (lower.startsWith("http") || lower.contains("/") || lower.contains("\\") || lower.contains("://")) {
            return false;
        }
        // Accept simple labels like "Alice", "Admin-User", "api-tab".
        return t.matches("[A-Za-z0-9._\\- ]+");
    }

    private String extractCaptionFromObject(Object source, String sourceLabel) {
        if (source == null) {
            return null;
        }

        String[] captionMethods = new String[]{
            "caption", "tabCaption", "tabName", "displayName", "name", "title",
            "getCaption", "getTabCaption", "getTabName", "getDisplayName", "getName", "getTitle"
        };

        String direct = invokeStringMethodCandidates(source, captionMethods, false, sourceLabel);
        if (direct != null) {
            return direct;
        }

        String declared = invokeStringMethodCandidates(source, captionMethods, true, sourceLabel);
        if (declared != null) {
            return declared;
        }

        String[] bridgeMethods = new String[]{
            "messageEditor", "editor", "requestEditor", "responseEditor", "component", "getComponent",
            "view", "ui", "uiComponent", "tab", "owner", "parent", "source"
        };

        for (String bridge : bridgeMethods) {
            Object child = invokeAnyNoArgMethod(source, bridge, false);
            if (child == null) {
                child = invokeAnyNoArgMethod(source, bridge, true);
            }

            Object unwrapped = unwrapOptional(child);
            if (unwrapped == null || unwrapped == source) {
                continue;
            }

            String viaChild = invokeStringMethodCandidates(unwrapped, captionMethods, false, sourceLabel + "." + bridge);
            if (viaChild != null) {
                return viaChild;
            }

            viaChild = invokeStringMethodCandidates(unwrapped, captionMethods, true, sourceLabel + "." + bridge);
            if (viaChild != null) {
                return viaChild;
            }

            if (unwrapped instanceof java.awt.Component) {
                String fromTab = findSelectedTabName((java.awt.Component) unwrapped);
                if (fromTab != null) {
                    return fromTab;
                }
            }
        }

        return null;
    }

    private String invokeStringMethodCandidates(Object source, String[] methodNames, boolean declaredOnly, String sourceLabel) {
        for (String methodName : methodNames) {
            Object value = invokeMethodIfExists(source, methodName, declaredOnly);
            Object unwrapped = unwrapOptional(value);
            if (unwrapped instanceof String) {
                String text = ((String) unwrapped).trim();
                if (isUsableRepeaterCaption(text)) {
                    api.logging().logToOutput("[ACAS DEBUG] Found caption via " + sourceLabel + "." + methodName + ": " + text);
                    return text;
                }
            }
        }
        return null;
    }

    private Object invokeAnyNoArgMethod(Object source, String methodName, boolean declaredOnly) {
        Object value = invokeMethodIfExists(source, methodName, declaredOnly);
        return unwrapOptional(value);
    }

    private Object invokeMethodIfExists(Object source, String methodName, boolean declaredOnly) {
        if (source == null) {
            return null;
        }

        try {
            java.lang.reflect.Method m;
            if (declaredOnly) {
                m = source.getClass().getDeclaredMethod(methodName);
                m.setAccessible(true);
            } else {
                m = source.getClass().getMethod(methodName);
            }
            if (m.getParameterCount() != 0) {
                return null;
            }
            return m.invoke(source);
        } catch (Exception ignored) {
            return null;
        }
    }

    private Object unwrapOptional(Object value) {
        if (value instanceof java.util.Optional) {
            java.util.Optional<?> optional = (java.util.Optional<?>) value;
            return optional.orElse(null);
        }
        return value;
    }
    
    private String extractTabNameFromComponentHierarchy(Object editor) {
        try {
            // Try to get component from editor via reflection
            java.lang.reflect.Method getComponentMethod = null;
            try {
                getComponentMethod = editor.getClass().getMethod("getComponent");
            } catch (Exception e) {
                try {
                    getComponentMethod = editor.getClass().getMethod("component");
                } catch (Exception e2) {
                    // Try other common names
                }
            }
            
            if (getComponentMethod != null) {
                Object component = getComponentMethod.invoke(editor);
                if (component instanceof java.awt.Component) {
                    String tabName = findSelectedTabName((java.awt.Component) component);
                    if (tabName != null) {
                        return tabName;
                    }
                }
            }
            
            // If editor is a Component itself, search it directly
            if (editor instanceof java.awt.Component) {
                String tabName = findSelectedTabName((java.awt.Component) editor);
                if (tabName != null) {
                    return tabName;
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }
    
    private String findSelectedTabName(java.awt.Component comp) {
        // Traverse up the component hierarchy looking for a JTabbedPane
        java.awt.Component current = comp;
        while (current != null) {
            if (current instanceof JTabbedPane) {
                JTabbedPane tabPane = (JTabbedPane) current;
                int selectedIndex = tabPane.getSelectedIndex();
                if (selectedIndex >= 0 && selectedIndex < tabPane.getTabCount()) {
                    String tabTitle = tabPane.getTitleAt(selectedIndex);
                    if (isUsableRepeaterCaption(tabTitle)) {
                        return tabTitle;
                    }
                }
                return null;
            }
            current = current.getParent();
        }
        return null;
    }

    private boolean isUsableRepeaterCaption(String text) {
        if (text == null) return false;
        String t = text.trim();
        if (t.isEmpty()) return false;
        // Ignore default numeric tab names like 1, 2, 3.
        if (t.matches("\\d+")) return false;
        return true;
    }
}


