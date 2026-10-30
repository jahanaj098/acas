package com.acas.engine;

import burp.api.montoya.http.message.responses.HttpResponse;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class SessionHealthMonitor {

    // Keywords in response bodies that indicate a session has silently expired (200 OK, but dead session)
    private static final String[] BODY_EXPIRY_KEYWORDS = {
        "token_expired", "token expired", "session_expired", "session expired",
        "session invalid", "invalid session", "please login", "please log in",
        "unauthenticated", "not authenticated", "authentication required",
        "jwt expired", "access token expired", "your session has expired",
        "login required", "signin required"
    };

    // Keywords that distinguish a session-error 403 from a WAF block 403
    private static final String[] SESSION_ERROR_403_KEYWORDS = {
        "session", "token", "expired", "authenticate", "login", "unauthorized"
    };

    private final Set<String> expiredActors = Collections.newSetFromMap(new ConcurrentHashMap<>());

    // Maps actorId → actor display name for the UI notification
    private final Map<String, String> actorNames = new ConcurrentHashMap<>();

    // The actor currently waiting for session refresh (shown in UI banner)
    private volatile String pendingRefreshActorId   = null;
    private volatile String pendingRefreshActorName = null;

    public boolean isExpired(String actorId) {
        return expiredActors.contains(actorId);
    }

    /**
     * Registers the display name for an actor so we can show it in the UI notification.
     * Call this at hunt start for every actor.
     */
    public void registerActorName(String actorId, String name) {
        if (actorId != null && name != null) {
            actorNames.put(actorId, name);
        }
    }

    /**
     * Checks whether the given response indicates the actor's session has expired.
     *
     * Detection signals (in order of reliability):
     *   1. HTTP 401 — unambiguous "you are not authenticated"
     *   2. 302 redirect to a login/auth URL
     *   3. HTTP 200 with a body keyword indicating silent expiry (most apps do this)
     *   4. HTTP 403 with a body keyword indicating session error (vs WAF block)
     *
     * @return true if the session is healthy, false if it has expired
     */
    public boolean checkHealth(String actorId, HttpResponse response) {
        if (response == null) return true;

        int status = response.statusCode();

        // Signal 1: 401 — clear session expiry
        if (status == 401) {
            markExpiredWithName(actorId);
            return false;
        }

        // Signal 2: 302 redirect to login page
        String location = response.headerValue("Location");
        if (status == 302 && location != null) {
            String loc = location.toLowerCase();
            if (loc.contains("login") || loc.contains("signin") || loc.contains("auth")) {
                markExpiredWithName(actorId);
                return false;
            }
        }

        // Get body once for the remaining checks
        String body = null;
        try {
            body = response.bodyToString();
        } catch (Exception ignored) {}
        String lowerBody = body != null ? body.toLowerCase() : "";

        // Signal 3: 200 OK but body contains silent expiry keywords
        if (status >= 200 && status < 300 && !lowerBody.isEmpty()) {
            for (String keyword : BODY_EXPIRY_KEYWORDS) {
                if (lowerBody.contains(keyword)) {
                    markExpiredWithName(actorId);
                    return false;
                }
            }
        }

        // Signal 4: 403 with session-related body (vs a WAF block which has generic body)
        if (status == 403 && !lowerBody.isEmpty()) {
            for (String keyword : SESSION_ERROR_403_KEYWORDS) {
                if (lowerBody.contains(keyword)) {
                    markExpiredWithName(actorId);
                    return false;
                }
            }
        }

        return true;
    }

    public void markExpired(String actorId) {
        markExpiredWithName(actorId);
    }

    private void markExpiredWithName(String actorId) {
        if (actorId == null) return;
        expiredActors.add(actorId);
        // Set the pending refresh info for the UI banner
        if (pendingRefreshActorId == null) {
            pendingRefreshActorId   = actorId;
            pendingRefreshActorName = actorNames.getOrDefault(actorId, actorId);
        }
    }

    /**
     * Clears the expired state for a specific actor — call this after the user
     * has updated the session in the Actors tab, just before clicking Resume.
     */
    public void clearExpired(String actorId) {
        if (actorId != null) {
            expiredActors.remove(actorId);
            if (actorId.equals(pendingRefreshActorId)) {
                pendingRefreshActorId   = null;
                pendingRefreshActorName = null;
            }
        }
    }

    /** Clears ALL expired actors — call on hunt start/stop to reset state. */
    public void clearAll() {
        expiredActors.clear();
        pendingRefreshActorId   = null;
        pendingRefreshActorName = null;
    }

    public Set<String> getExpiredActors() {
        return Collections.unmodifiableSet(expiredActors);
    }

    /**
     * Returns the display name of the actor currently waiting for a session refresh,
     * or null if no actor is pending. Used by HuntHubPanel to render the banner.
     */
    public String getPendingRefreshActorName() {
        return pendingRefreshActorName;
    }

    /** Returns the actor ID pending refresh, or null. */
    public String getPendingRefreshActorId() {
        return pendingRefreshActorId;
    }

    /** True if any actor is currently waiting for the user to refresh their session. */
    public boolean hasPendingRefresh() {
        return pendingRefreshActorId != null;
    }
}
