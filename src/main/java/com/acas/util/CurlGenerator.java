package com.acas.util;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class CurlGenerator {
    private CurlGenerator() {
    }

    public static String generateCurl(HttpRequest request, String scheme, String host) {
        if (request == null) {
            return "curl -v";
        }

        String raw = new String(request.toByteArray().getBytes(), StandardCharsets.ISO_8859_1);
        String[] lines = raw.split("\\r?\\n", -1);
        if (lines.length == 0) {
            return "curl -v";
        }

        String[] requestLine = lines[0].split(" ", 3);
        String method = requestLine.length > 0 ? requestLine[0] : "GET";
        String target = requestLine.length > 1 ? requestLine[1] : "/";

        List<String> headerFlags = new ArrayList<>();
        String cookie = null;
        int i = 1;
        for (; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) {
                i++;
                break;
            }
            int sep = line.indexOf(':');
            if (sep <= 0) {
                continue;
            }

            String name = line.substring(0, sep).trim();
            String value = line.substring(sep + 1).trim();
            String nameLower = name.toLowerCase();

            if (nameLower.startsWith("x-burp-")) {
                continue;
            }
            if ("host".equals(nameLower)) {
                continue;
            }
            if ("cookie".equals(nameLower)) {
                cookie = value;
                continue;
            }
            headerFlags.add("-H '" + escapeSingleQuotes(name + ": " + value) + "'");
        }

        String body = "";
        if (i < lines.length) {
            StringBuilder bodyBuilder = new StringBuilder();
            for (int j = i; j < lines.length; j++) {
                bodyBuilder.append(lines[j]);
                if (j < lines.length - 1) {
                    bodyBuilder.append("\n");
                }
            }
            body = bodyBuilder.toString();
        }

        String finalUrl = buildUrl(target, scheme, host);
        StringBuilder curl = new StringBuilder();
        curl.append("curl -v -X ").append(method).append(" \\\n");
        curl.append("  '").append(escapeSingleQuotes(finalUrl)).append("'");

        for (String headerFlag : headerFlags) {
            curl.append(" \\\n  ").append(headerFlag);
        }

        if (cookie != null && !cookie.isBlank()) {
            curl.append(" \\\n  --cookie '").append(escapeSingleQuotes(cookie)).append("'");
        }

        if (!body.isBlank() && allowsBody(method)) {
            curl.append(" \\\n  --data-raw '").append(escapeSingleQuotes(body)).append("'");
        }

        return curl.toString();
    }

    private static String buildUrl(String target, String scheme, String host) {
        if (target.startsWith("http://") || target.startsWith("https://")) {
            return target;
        }
        String effectiveScheme = (scheme == null || scheme.isBlank()) ? "https" : scheme;
        String effectiveHost = host == null ? "" : host;
        if (!target.startsWith("/")) {
            target = "/" + target;
        }
        return effectiveScheme + "://" + effectiveHost + target;
    }

    private static boolean allowsBody(String method) {
        String m = method == null ? "" : method.toUpperCase();
        return "POST".equals(m) || "PUT".equals(m) || "PATCH".equals(m) || "DELETE".equals(m);
    }

    private static String escapeSingleQuotes(String text) {
        return text.replace("'", "'\"'\"'");
    }
}
