package com.acas.engine;

import com.acas.model.ActorProfile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ResponseChainEngine {

    private final ObjectManager objectManager;
    private static final Pattern UUID_PATTERN = Pattern.compile("\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b");
    private static final Pattern ID_VALUE_PATTERN = Pattern.compile("\\b(id|uuid|uid|key)[\": ]+([a-zA-Z0-9_-]{4,64})\\b");

    public ResponseChainEngine(ObjectManager objectManager) {
        this.objectManager = objectManager;
    }

    public void discoverFromResponse(ActorProfile actor, burp.api.montoya.http.message.HttpRequestResponse rr, int currentDepth) {
        if (rr == null || rr.response() == null || actor == null || currentDepth >= 3) return;
        String body = rr.response().bodyToString();
        if (body == null || body.isEmpty()) return;

        // 1. UUID Scanning
        Matcher m1 = UUID_PATTERN.matcher(body);
        while (m1.find()) {
            objectManager.registerOwnership(actor.getId(), "discovered_uuid", m1.group(), 0.7, "Chain (Depth " + currentDepth + "): UUID in response");
        }

        // 2. Key-Value Scanning
        Matcher m2 = ID_VALUE_PATTERN.matcher(body);
        while (m2.find()) {
            String key = m2.group(1);
            String val = m2.group(2);
            if (!isNoise(val)) {
                objectManager.registerOwnership(actor.getId(), key, val, 0.8, "Chain (Depth " + currentDepth + "): Key-Value in response (" + key + ")");
                
                // 3. Base64 Detection
                checkBase64(actor, key, val, currentDepth);
            }
        }
    }

    private void checkBase64(ActorProfile actor, String key, String val, int depth) {
        try {
            // Very simple check: if looks like base64, try decoding
            if (val.length() > 4 && val.matches("^[a-zA-Z0-9+/]*={0,2}$")) {
                byte[] decoded = java.util.Base64.getDecoder().decode(val);
                String decodedStr = new String(decoded);
                if (decodedStr.matches("^[a-zA-Z0-9_-]{1,64}$")) {
                    objectManager.registerOwnership(actor.getId(), "b64_" + key, decodedStr, 0.6, "Chain (Depth " + depth + "): Base64 decoded ID");
                }
            }
        } catch (Exception ignored) {}
    }

    private boolean isNoise(String val) {
        return val.equals("null") || val.equals("true") || val.equals("false") || val.equals("undefined") || val.isEmpty();
    }
}
