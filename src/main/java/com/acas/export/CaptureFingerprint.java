package com.acas.export;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Content identity for captured evidence. It deliberately ignores managed
 * credentials and volatile transport fields while retaining the exact target,
 * query/body bytes and meaningful application headers.
 */
public final class CaptureFingerprint {
    private CaptureFingerprint() {}

    private static final Set<String> REQUEST_TRANSPORT = Set.of(
        "cookie", "authorization", "proxy-authorization", "x-pwnfox-color",
        "content-length", "connection", "accept-encoding", "x-request-id",
        "traceparent", "tracestate", "x-correlation-id");
    private static final Set<String> RESPONSE_TRANSPORT = Set.of(
        "date", "set-cookie", "content-length", "connection", "transfer-encoding",
        "x-request-id", "traceparent", "tracestate", "x-correlation-id");

    public static String request(byte[] raw, Set<String> identityHeaders) {
        return semantic(raw, true, identityHeaders);
    }

    public static String response(byte[] raw, Set<String> identityHeaders) {
        return semantic(raw, false, identityHeaders);
    }

    private static String semantic(byte[] raw, boolean request, Set<String> identityHeaders) {
        if (raw == null) return "<missing>";
        String text = new String(raw, StandardCharsets.ISO_8859_1);
        int split = text.indexOf("\r\n\r\n");
        int skip = 4;
        if (split < 0) { split = text.indexOf("\n\n"); skip = 2; }
        if (split < 0) return text;
        String[] lines = text.substring(0, split).split("\r?\n", -1);
        String start = request ? canonicalRequestLine(lines[0]) : lines[0].trim();
        List<String> headers = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            int colon = line.indexOf(':');
            String name = colon < 0 ? line.trim().toLowerCase(Locale.ROOT) : line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            if (colon < 0 || name.isEmpty()) continue;
            if (request && (REQUEST_TRANSPORT.contains(name) || identityHeaders != null && identityHeaders.contains(name))) continue;
            if (!request && RESPONSE_TRANSPORT.contains(name)) continue;
            String value = line.substring(colon + 1).trim().replaceAll("[ \\t]+", " ");
            headers.add(name + ":" + value);
        }
        Collections.sort(headers);
        return start + "\n" + String.join("\n", headers) + "\n\n"
            + text.substring(split + skip);
    }

    private static String canonicalRequestLine(String line) {
        String[] parts = line.trim().split("\\s+");
        return parts.length < 2 ? line.trim()
            : parts[0].toUpperCase(Locale.ROOT) + " " + parts[1];
    }

    public static String originOf(byte[] requestBytes) {
        if (requestBytes == null) return null;
        String text = new String(requestBytes, StandardCharsets.ISO_8859_1);
        String[] lines = text.split("\r?\n", -1);
        for (String line : lines) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase("Host")) {
                return line.substring(colon + 1).trim().toLowerCase(Locale.ROOT);
            }
        }
        return null;
    }
}
