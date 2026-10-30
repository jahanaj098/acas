package com.acas.util;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class IdParameterDetector {

    private static final List<String> HIGH_SIGNAL_PARAMS = Arrays.asList(
        "id", "user_id", "account_id", "order_id", "uid", "userid", "accountid",
        "orderid", "profile_id", "customer_id", "doc_id", "file_id", "invoice_id",
        "product_id", "record_id", "item_id", "object_id", "resource_id",
        "ticket_id", "post_id", "comment_id", "message_id", "thread_id",
        "owner_id", "creator_id", "target_id", "entity_id", "entry_id"
    );

    private static final List<String> SKIP_HEADERS = Arrays.asList(
        "host", "content-length", "content-type", "accept", "accept-language",
        "accept-encoding", "connection", "cache-control", "user-agent",
        "upgrade-insecure-requests", "sec-fetch-site", "sec-fetch-mode",
        "sec-fetch-dest", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
        "referer", "origin", "pragma", "te", "dnt"
    );

    private static final Pattern PATH_ID_PATTERN = Pattern.compile("/\\d{1,20}(/|$|\\?|#)");
    private static final Pattern UUID_PATTERN = Pattern.compile(
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    );

    public static boolean hasIdParameters(HttpRequest request) {
        String url = request.url();

        if (PATH_ID_PATTERN.matcher(url).find()) return true;
        if (UUID_PATTERN.matcher(url).find()) return true;

        String queryString = extractQueryString(url);
        if (queryString != null) {
            for (String param : queryString.split("&")) {
                String[] parts = param.split("=", 2);
                if (parts.length >= 1) {
                    String name = parts[0].toLowerCase();
                    if (HIGH_SIGNAL_PARAMS.contains(name)) return true;
                    if (name.endsWith("_id") || name.endsWith("id")) return true;
                }
            }
        }

        String body = request.bodyToString();
        if (body != null && !body.isEmpty()) {
            for (String param : HIGH_SIGNAL_PARAMS) {
                if (body.contains("\"" + param + "\"") || body.contains(param + "=")) return true;
            }
        }
        return false;
    }

    public static boolean isAuthHeader(String headerName) {
        if (headerName == null) return false;
        String lower = headerName.toLowerCase();
        return lower.equals("cookie") ||
               lower.equals("authorization") ||
               lower.startsWith("x-auth") ||
               lower.startsWith("x-token") ||
               lower.startsWith("x-session") ||
               lower.startsWith("x-api-key") ||
               lower.startsWith("x-access-token") ||
               lower.startsWith("x-refresh-token") ||
               lower.equals("x-user-token") ||
               lower.equals("x-csrf-token") ||
               lower.equals("bearer");
    }

    public static boolean isSkippableHeader(String headerName) {
        if (headerName == null) return true;
        return SKIP_HEADERS.contains(headerName.toLowerCase());
    }

    private static String extractQueryString(String url) {
        int qIndex = url.indexOf('?');
        return qIndex >= 0 ? url.substring(qIndex + 1) : null;
    }
}
