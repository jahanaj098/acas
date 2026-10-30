package com.acas.util;

/**
 * Decides whether a captured request should be SKIPPED by ACAS auto-testing
 * (swap + anonymous), based on a user-editable blacklist held in Settings.
 *
 * Rule syntax (one rule per line):
 *   #...          comment / blank — ignored
 *   .ext          skip when the request path ends with this extension
 *   METHOD:XXX    skip when the HTTP method equals XXX (e.g. OPTIONS, HEAD)
 *   ct:TEXT       skip when the RESPONSE content-type contains TEXT
 *   TEXT          skip when the URL or path contains TEXT (case-insensitive)
 */
public final class CaptureFilter {

    private CaptureFilter() {}

    public static final String DEFAULT_BLACKLIST = String.join("\n",
        "# ACAS capture blacklist — requests matching any rule are NOT auto-tested.",
        "# One rule per line. Lines starting with # are comments.",
        "#   .ext         path ends with this extension",
        "#   METHOD:GET   skip this HTTP method",
        "#   ct:image/    skip when the response content-type contains this",
        "#   anything else = case-insensitive substring match on the URL",
        "",
        "# --- static assets ---",
        ".js",
        ".mjs",
        ".css",
        ".map",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".avif",
        ".bmp",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".mp4",
        ".webm",
        ".mp3",
        ".wav",
        ".ogg",
        ".zip",
        ".gz",
        ".scss",
        ".less",
        "",
        "# --- preflight / non-testable methods ---",
        "METHOD:OPTIONS",
        "METHOD:HEAD",
        "",
        "# --- response content-types that are never IDOR targets ---",
        "ct:image/",
        "ct:font/",
        "ct:text/css",
        "ct:javascript",
        "ct:video/",
        "ct:audio/",
        "",
        "# --- common noise paths ---",
        "/static/",
        "/assets/",
        "/favicon",
        ".well-known",
        "google-analytics",
        "googletagmanager",
        "gtag/",
        "/collect",
        "hot-update",
        "sockjs",
        "__webpack"
    );

    /** @return true if this request should be SKIPPED (not auto-tested). */
    public static boolean isBlacklisted(String method, String url, String path, String contentType, String blacklistText) {
        if (blacklistText == null || blacklistText.trim().isEmpty()) return false;

        String m = method == null ? "" : method.trim().toUpperCase();
        String u = url == null ? "" : url.toLowerCase();
        String p = path == null ? "" : path.toLowerCase();
        int q = p.indexOf('?');
        String pathNoQuery = q >= 0 ? p.substring(0, q) : p;
        String ct = contentType == null ? "" : contentType.toLowerCase();

        for (String raw : blacklistText.split("\\r?\\n")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String rule = line.toLowerCase();

            if (rule.startsWith("method:")) {
                String wanted = rule.substring("method:".length()).trim().toUpperCase();
                if (!wanted.isEmpty() && m.equals(wanted)) return true;
            } else if (rule.startsWith("ct:")) {
                String wanted = rule.substring("ct:".length()).trim();
                if (!wanted.isEmpty() && !ct.isEmpty() && ct.contains(wanted)) return true;
            } else if (rule.startsWith(".")) {
                if (pathNoQuery.endsWith(rule)) return true;
            } else {
                if (u.contains(rule) || p.contains(rule)) return true;
            }
        }
        return false;
    }
}
