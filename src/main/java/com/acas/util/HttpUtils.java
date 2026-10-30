package com.acas.util;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URI;

public class HttpUtils {
    private static final java.util.Set<String> DEFAULT_AUTH_HEADERS = java.util.Set.of(
        "authorization", "cookie", "x-api-key", "x-auth-token", "token", "x-access-token", "jwt", "session"
    );

    public static HttpRequest stripAuthHeaders(HttpRequest request) {
        return stripAuthHeaders(request, DEFAULT_AUTH_HEADERS);
    }

    public static HttpRequest stripAuthHeaders(HttpRequest request, java.util.Set<String> dynamicHeaders) {
        return new CredentialPolicy().anonymous(request,dynamicHeaders==null?DEFAULT_AUTH_HEADERS:dynamicHeaders);
    }

    public static double calculateSimilarity(int len1, int len2) {
        if (len1 == 0 && len2 == 0) return 1.0;
        if (len1 == 0 || len2 == 0) return 0.0;
        return 1.0 - (Math.abs(len1 - len2) / (double) Math.max(len1, len2));
    }

    public static HttpRequest ensureRequestService(HttpRequest request, String fallbackUrl) {
        if (request == null) {
            return request;
        }

        if (hasUsableService(request)) {
            return request;
        }

        HttpService fromUrl = serviceFromUrl(safeUrl(request, fallbackUrl));
        if (fromUrl != null) {
            return request.withService(fromUrl);
        }

        HttpService fromHost = serviceFromHostHeader(request, fallbackUrl);
        if (fromHost != null) {
            return request.withService(fromHost);
        }

        return request;
    }

    public static String buildRepeaterTabName(String prefix, HttpRequest request, String fallbackUrl, String suffix) {
        HttpRequest prepared = ensureRequestService(request, fallbackUrl);

        String method = "REQ";
        String path = "/";
        String host = "target";

        if (prepared != null) {
            try {
                if (prepared.method() != null && !prepared.method().isBlank()) {
                    method = prepared.method().trim().toUpperCase();
                }
            } catch (Exception ignored) {
            }

            try {
                if (prepared.path() != null && !prepared.path().isBlank()) {
                    path = prepared.path().trim();
                }
            } catch (Exception ignored) {
            }

            try {
                if (prepared.httpService() != null && prepared.httpService().host() != null && !prepared.httpService().host().isBlank()) {
                    host = prepared.httpService().host().trim();
                }
            } catch (Exception ignored) {
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append(safeLabel(prefix, "ACAS"));
        sb.append(": ").append(method).append(" ").append(host).append(path);

        String extra = safeLabel(suffix, "");
        if (!extra.isEmpty()) {
            sb.append(" | ").append(extra);
        }

        String title = sb.toString().replaceAll("[\\r\\n\\t]+", " ").trim();
        return title.length() > 120 ? title.substring(0, 120) : title;
    }

    private static String safeLabel(String value, String fallback) {
        if (value == null) {
            return fallback;
        }
        String cleaned = value.trim();
        return cleaned.isEmpty() ? fallback : cleaned;
    }

    private static boolean hasUsableService(HttpRequest request) {
        try {
            HttpService svc = request.httpService();
            if (svc == null) {
                return false;
            }
            String host = svc.host();
            int port = svc.port();
            return host != null && !host.isBlank() && port > 0;
        } catch (Exception ignored) {
            return false;
        }
    }

    private static String safeUrl(HttpRequest request, String fallbackUrl) {
        try {
            String u = request.url();
            if (u != null && !u.isBlank()) {
                return u;
            }
        } catch (Exception ignored) {
        }
        return fallbackUrl;
    }

    private static HttpService serviceFromUrl(String url) {
        if (url == null || url.isBlank()) {
            return null;
        }
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            if (host == null || host.isBlank()) {
                return null;
            }
            int port = uri.getPort();
            String scheme = uri.getScheme() != null ? uri.getScheme() : "https";
            boolean secure = "https".equalsIgnoreCase(scheme);
            if (port <= 0) {
                port = secure ? 443 : 80;
            }
            return HttpService.httpService(host, port, secure);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static HttpService serviceFromHostHeader(HttpRequest request, String fallbackUrl) {
        String hostHeader = null;
        for (HttpHeader h : request.headers()) {
            if ("host".equalsIgnoreCase(h.name())) {
                hostHeader = h.value();
                break;
            }
        }
        if (hostHeader == null || hostHeader.isBlank()) {
            return null;
        }

        String host = hostHeader.trim();
        int port = -1;
        int colon = host.lastIndexOf(':');
        if (colon > 0 && colon < host.length() - 1) {
            try {
                port = Integer.parseInt(host.substring(colon + 1));
                host = host.substring(0, colon);
            } catch (NumberFormatException ignored) {
                port = -1;
            }
        }

        boolean secure = true;
        HttpService fallback = serviceFromUrl(fallbackUrl);
        if (fallback != null) {
            secure = fallback.secure();
            if (port <= 0) {
                port = fallback.port();
            }
        }
        if (port <= 0) {
            port = secure ? 443 : 80;
        }
        return HttpService.httpService(host, port, secure);
    }
}
