package com.acas.notification;

import burp.api.montoya.MontoyaApi;
import com.acas.model.TestResult;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import com.google.gson.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class NotificationService {

    private final MontoyaApi api;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private volatile String telegramBotToken = "";
    private volatile String telegramChatId = "";
    private volatile String hermesTelegramBotToken = "";
    private volatile String hermesTelegramChatId = "";
    public void setHermesTelegramBotToken(String value) { hermesTelegramBotToken = value == null ? "" : value.trim(); }
    public void setHermesTelegramChatId(String value) { hermesTelegramChatId = value == null ? "" : value.trim(); }
    public CompletableFuture<SendResult> testHermesTelegram() { return sendHermesTelegram(null,null); }
    public CompletableFuture<SendResult> sendHermesTextMessage(boolean telegram, String message) {
        if (telegram) {
            String token = hermesTelegramBotToken, chat = hermesTelegramChatId;
            if (token.isBlank() || chat.isBlank()) return CompletableFuture.completedFuture(new SendResult(false,"Set Bot Token and Chat ID under Telegram — Hermes exports in Settings."));
            try { return CompletableFuture.supplyAsync(() -> {
                try {
                    JsonObject bodyJson = new JsonObject(); bodyJson.addProperty("chat_id", chat); bodyJson.addProperty("text", message);
                    Reply reply = transport.post("https://api.telegram.org/bot" + token + "/sendMessage", "application/json; charset=UTF-8", bodyJson.toString().getBytes(StandardCharsets.UTF_8));
                    JsonObject receipt = JsonParser.parseString(reply.body()).getAsJsonObject();
                    if (reply.status() >= 200 && reply.status() < 300 && receipt.has("ok") && receipt.get("ok").getAsBoolean())
                        return new SendResult(true, "Intro message delivered to Hermes Telegram.");
                    return new SendResult(false, "Hermes Telegram rejected text message (HTTP " + reply.status() + ").");
                } catch (Exception e) { return new SendResult(false, "Failed to send intro to Telegram: " + e.getMessage()); }
            }, executor); } catch (java.util.concurrent.RejectedExecutionException e) { return CompletableFuture.completedFuture(new SendResult(false, "Sender stopped")); }
        } else {
            String webhook = discordWebhookUrl;
            if (webhook.isBlank()) return CompletableFuture.completedFuture(new SendResult(false,"Set the Discord webhook URL in Settings."));
            try { return CompletableFuture.supplyAsync(() -> {
                try {
                    JsonObject payload = new JsonObject(); payload.addProperty("content", message);
                    JsonObject mentions = new JsonObject(); mentions.add("parse", new JsonArray()); payload.add("allowed_mentions", mentions);
                    Reply reply = transport.post(discordEndpoint(webhook), "application/json; charset=UTF-8", payload.toString().getBytes(StandardCharsets.UTF_8));
                    if (reply.status() >= 200 && reply.status() < 300) return new SendResult(true, "Intro message delivered to Hermes Discord.");
                    return new SendResult(false, "Discord rejected message (HTTP " + reply.status() + ").");
                } catch (Exception e) { return new SendResult(false, "Failed to send intro to Discord: " + e.getMessage()); }
            }, executor); } catch (java.util.concurrent.RejectedExecutionException e) { return CompletableFuture.completedFuture(new SendResult(false, "Sender stopped")); }
        }
    }
    public CompletableFuture<SendResult> sendHermesTelegramAttachment(String name, byte[] data) {
        if (name == null || !name.matches("[a-zA-Z0-9._-]+") || data == null || data.length > com.acas.export.HermesUploadLimits.TELEGRAM_PART_BYTES)
            return CompletableFuture.completedFuture(new SendResult(false,"Invalid attachment or attachment exceeds Telegram's configured file budget."));
        return sendHermesTelegram(name,data);
    }
    private CompletableFuture<SendResult> sendHermesTelegram(String name, byte[] data) {
        String token = hermesTelegramBotToken, chat = hermesTelegramChatId;
        if (token.isBlank() || chat.isBlank()) return CompletableFuture.completedFuture(new SendResult(false,"Set Bot Token and Chat ID under Telegram — Hermes exports in Settings."));
        try { return CompletableFuture.supplyAsync(() -> {
            try {
                String type="application/json; charset=UTF-8"; byte[] body;
                if (name==null) {
                    JsonObject message=new JsonObject(); message.addProperty("chat_id",chat); message.addProperty("text","Hello group! ACAS Hermes export connection test.");
                    body=message.toString().getBytes(StandardCharsets.UTF_8);
                } else {
                    String boundary="ACAS-"+java.util.UUID.randomUUID(); type="multipart/form-data; boundary="+boundary;
                    StringBuilder prefix=new StringBuilder();part(prefix,boundary,"chat_id",chat);part(prefix,boundary,"caption","ACAS Hermes export: "+name);
                    prefix.append("--").append(boundary).append("\r\nContent-Disposition: form-data; name=\"document\"; filename=\"").append(name)
                        .append("\"\r\nContent-Type: ").append(name.endsWith(".json")?"application/json":"application/octet-stream").append("\r\n\r\n");
                    java.io.ByteArrayOutputStream bytes=new java.io.ByteArrayOutputStream();bytes.write(prefix.toString().getBytes(StandardCharsets.UTF_8));bytes.write(data);
                    bytes.write(("\r\n--"+boundary+"--\r\n").getBytes(StandardCharsets.UTF_8));body=bytes.toByteArray();
                }
                Reply reply=transport.post("https://api.telegram.org/bot"+token+(name==null?"/sendMessage":"/sendDocument"),type,body);
                JsonObject receipt=JsonParser.parseString(reply.body()).getAsJsonObject();
                if(reply.status()>=200 && reply.status()<300 && receipt.has("ok") && receipt.get("ok").getAsBoolean()
                    && receipt.has("result") && receipt.get("result").isJsonObject() && receipt.getAsJsonObject("result").has("message_id"))
                    return new SendResult(true,name==null?"Hermes Telegram connection test delivered.":"Attachment accepted by Hermes Telegram destination.");
                return new SendResult(false,"Hermes Telegram rejected the send (HTTP "+reply.status()+"). "+(reply.status()==429?"Wait before retrying.":"Check the export bot token, chat ID and bot permissions."));
            }catch(Exception error){return new SendResult(false,"Hermes Telegram delivery could not be confirmed ("+error.getClass().getSimpleName()+"). Check connection and settings; retry may duplicate the last message.");}
        },executor); }catch(java.util.concurrent.RejectedExecutionException stopped){return CompletableFuture.completedFuture(new SendResult(false,"Notification sender is stopped. Reload ACAS."));}
    }
    private volatile String discordWebhookUrl = "";
    private String alertTrigger = "status_diff"; // status_diff, any_diff, manual

    public NotificationService(MontoyaApi api) {
        this(api, NotificationService::post);
    }
    NotificationService(MontoyaApi api, Transport transport) {
        this.api = api;
        this.transport = transport;
    }

    public void sendAlert(String requestInfo, List<com.acas.model.TestResult> results, String flagReason) {
        String message = buildMessage(requestInfo, results, flagReason);
        if (!telegramBotToken.isEmpty() && !telegramChatId.isEmpty())
            sendTelegram(message);
        if (!discordWebhookUrl.isEmpty())
            sendDiscord(message);
    }

    public void sendFinding(String method, String url, String verdict, String leakedFields) {
        String message = String.format("🚨 ACAS: Confirmed Bypass!\n\n" +
                "Method: %s\n" +
                "URL: %s\n" +
                "Verdict: %s\n" +
                "Leaked: %s\n", method, url, verdict, leakedFields);
                
        if (!telegramBotToken.isEmpty() && !telegramChatId.isEmpty())
            sendTelegram(message);
        if (!discordWebhookUrl.isEmpty())
            sendDiscord(message);
    }

    public CompletableFuture<SendResult> sendDiscordReport(String content) { return send(false, content); }
    public CompletableFuture<SendResult> sendTelegramReport(String content) { return send(true, content); }
    public record SendResult(boolean success, String message) {}
    /** A single bounded binary attachment. Caller sequences parts and persists progress. */
    public CompletableFuture<SendResult> sendDiscordAttachment(String filename, byte[] data) {
        String webhook = discordWebhookUrl;
        if (webhook.isBlank()) return CompletableFuture.completedFuture(new SendResult(false,"Set the Discord webhook URL in Settings."));
        if (filename == null || !filename.matches("[a-zA-Z0-9._-]+") || data == null || data.length > com.acas.export.HermesUploadLimits.DISCORD_PART_BYTES)
            return CompletableFuture.completedFuture(new SendResult(false,"Invalid attachment or attachment exceeds Discord's configured file budget."));
        return CompletableFuture.supplyAsync(() -> {
            try {
                String boundary = "ACAS-" + java.util.UUID.randomUUID();
                JsonObject payload = new JsonObject(); payload.addProperty("content","ACAS Hermes export: " + filename);
                JsonObject mentions = new JsonObject(); mentions.add("parse",new JsonArray()); payload.add("allowed_mentions",mentions);
                StringBuilder prefix = new StringBuilder(); part(prefix,boundary,"payload_json",payload.toString());
                prefix.append("--").append(boundary).append("\r\nContent-Disposition: form-data; name=\"files[0]\"; filename=\"")
                    .append(filename).append("\"\r\nContent-Type: ").append(filename.endsWith(".json")?"application/json":"application/octet-stream").append("\r\n\r\n");
                java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
                body.write(prefix.toString().getBytes(StandardCharsets.UTF_8)); body.write(data);
                body.write(("\r\n--"+boundary+"--\r\n").getBytes(StandardCharsets.UTF_8));
                Reply reply = transport.post(discordEndpoint(webhook),"multipart/form-data; boundary="+boundary,body.toByteArray());
                if (reply.status() >= 200 && reply.status() < 300) {
                    JsonObject receipt = JsonParser.parseString(reply.body()).getAsJsonObject();
                    if (receipt.has("id") && !receipt.get("id").getAsString().isBlank())
                        return new SendResult(true,"Attachment accepted by Discord.");
                    return new SendResult(false,"Discord did not return a message receipt; delivery is unconfirmed.");
                }
                return new SendResult(false,"Discord rejected attachment (HTTP " + reply.status() + "). "
                    + (reply.status()==429 ? "Wait before retrying." : "Check destination permissions and upload limits."));
            } catch (Exception error) {
                return new SendResult(false,"Attachment delivery could not be confirmed ("+error.getClass().getSimpleName()+"). Retry may duplicate the last attachment.");
            }
        },executor);
    }
    record Reply(int status, String body) {}
    interface Transport { Reply post(String url, String type, byte[] body) throws Exception; }
    private final Transport transport;
    private String buildMessage(String requestInfo, List<TestResult> results, String flagReason) {
        StringBuilder sb = new StringBuilder();
        sb.append("🚨 ACAS — Authorization Inconsistency Detected\n\n");
        sb.append("Request: ").append(requestInfo).append("\n\n");
        sb.append("Results:\n");
        for (TestResult r : results) {
            sb.append(String.format("  %-15s → %d  (%d bytes, %dms)%s%n",
                    r.getActorName(), r.getStatusCode(), r.getResponseLength(),
                    r.getResponseTime(), r.isFlagged() ? " ⚠" : ""));
        }
        sb.append("\nFlag: ").append(flagReason);
        return sb.toString();
    }

    private void sendTelegram(String message) { sendTelegramReport(message); }
    private void sendDiscord(String message) { sendDiscordReport(message); }

    private CompletableFuture<SendResult> send(boolean telegram, String message) {
        // Snapshot configuration on click, before the worker is queued.
        String token = telegramBotToken, chat = telegramChatId, webhook = discordWebhookUrl;
        String service = telegram ? "Telegram" : "Discord";
        if (telegram && (token.isBlank() || chat.isBlank()))
            return CompletableFuture.completedFuture(new SendResult(false, "Set both the Telegram bot token and Chat ID in Settings."));
        if (!telegram && webhook.isBlank())
            return CompletableFuture.completedFuture(new SendResult(false, "Set the Discord webhook URL in Settings."));
        if (message == null || message.isBlank())
            return CompletableFuture.completedFuture(new SendResult(false, "The report is empty."));
        if (message.getBytes(StandardCharsets.UTF_8).length > 8 * 1024 * 1024)
            return CompletableFuture.completedFuture(new SendResult(false, "Report exceeds the 8 MB upload limit. Export it locally instead."));
        try {
            return CompletableFuture.supplyAsync(() -> {
                SendResult result;
                try {
                    boolean attachment = message.length() > (telegram ? 4096 : 2000);
                    String endpoint = telegram ? "https://api.telegram.org/bot" + token + (attachment ? "/sendDocument" : "/sendMessage")
                        : discordEndpoint(webhook);
                    JsonObject payload = new JsonObject();
                    if (telegram) {
                        payload.addProperty("chat_id", chat);
                        payload.addProperty(attachment ? "caption" : "text", attachment ? "ACAS finding report attached." : message);
                    } else {
                        payload.addProperty("content", attachment ? "ACAS finding report attached." : message);
                        JsonObject mentions = new JsonObject(); mentions.add("parse", new JsonArray());
                        payload.add("allowed_mentions", mentions);
                    }
                    String type = "application/json; charset=UTF-8";
                    byte[] body = payload.toString().getBytes(StandardCharsets.UTF_8);
                    if (attachment) {
                        String boundary = "ACAS-" + java.util.UUID.randomUUID();
                        type = "multipart/form-data; boundary=" + boundary;
                        StringBuilder multipart = new StringBuilder();
                        if (telegram) {
                            part(multipart, boundary, "chat_id", chat);
                            part(multipart, boundary, "caption", "ACAS finding report attached.");
                        } else part(multipart, boundary, "payload_json", payload.toString());
                        multipart.append("--").append(boundary).append("\r\nContent-Disposition: form-data; name=\"")
                            .append(telegram ? "document" : "files[0]")
                            .append("\"; filename=\"acas-finding.md\"\r\nContent-Type: text/markdown; charset=UTF-8\r\n\r\n")
                            .append(message).append("\r\n--").append(boundary).append("--\r\n");
                        body = multipart.toString().getBytes(StandardCharsets.UTF_8);
                    }
                    Reply reply = transport.post(endpoint, type, body);
                    JsonObject response = null;
                    try { response = JsonParser.parseString(reply.body()).getAsJsonObject(); } catch (Exception ignored) {}
                    boolean accepted = reply.status() >= 200 && reply.status() < 300;
                    if (telegram) accepted = accepted && response != null && response.has("ok") && response.get("ok").getAsBoolean();
                    if (accepted) result = new SendResult(true, service + ": " + (attachment ? "report attachment delivered." : "message delivered."));
                    else {
                        String detail = "";
                        String key = telegram ? "description" : "message";
                        if (response != null && response.has(key) && response.get(key).isJsonPrimitive()) detail = response.get(key).getAsString();
                        if (!token.isEmpty()) detail = detail.replace(token, "[redacted]");
                        if (!webhook.isEmpty()) detail = detail.replace(webhook, "[redacted]");
                        detail = detail.replaceAll("https?://\\S+", "[URL]");
                        if (detail.length() > 300) detail = detail.substring(0,300);
                        result = new SendResult(false, service + " rejected the send (HTTP " + reply.status() + "). " + detail
                            + (reply.status() == 429 ? " Wait before retrying." : " Check Settings and destination permissions."));
                    }
                } catch (Exception error) {
                    // Exception messages may contain the credential-bearing request URL.
                    result = new SendResult(false, service + " delivery could not be confirmed (" + error.getClass().getSimpleName()
                        + "). Check the destination, connection and proxy settings before retrying.");
                }
                if (api != null) {
                    if (result.success()) api.logging().logToOutput("ACAS: " + result.message());
                    else api.logging().logToError("ACAS: " + result.message());
                }
                return result;
            }, executor);
        } catch (java.util.concurrent.RejectedExecutionException stopped) {
            return CompletableFuture.completedFuture(new SendResult(false, "Notification sender is stopped. Reload ACAS."));
        }
    }

    private static String discordEndpoint(String webhook) {
        String base = com.acas.export.HermesDestinationSettings.validateDiscordWebhook(webhook);
        if (base.isBlank()) throw new IllegalArgumentException("Invalid webhook URL");
        return base + (base.contains("?") ? "&" : "?") + "wait=true";
    }

    private static void part(StringBuilder out, String boundary, String name, String value) {
        out.append("--").append(boundary).append("\r\nContent-Disposition: form-data; name=\"").append(name)
            .append("\"\r\n\r\n").append(value).append("\r\n");
    }

    public boolean testTelegram() { return sendTelegramReport("ACAS connected successfully!").join().success(); }
    public boolean testDiscord() { return sendDiscordReport("ACAS connected successfully!").join().success(); }

    private static Reply post(String url, String type, byte[] body) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) java.net.URI.create(url).toURL().openConnection();
        try {
            conn.setInstanceFollowRedirects(false);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", type);
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(15000);
            conn.setFixedLengthStreamingMode(body.length);
            try (OutputStream os = conn.getOutputStream()) { os.write(body); }
            int status = conn.getResponseCode();
            java.io.InputStream stream = status >= 400 ? conn.getErrorStream() : conn.getInputStream();
            String response = "";
            if (stream != null) try (stream) { response = new String(stream.readNBytes(65536), StandardCharsets.UTF_8); }
            return new Reply(status, response);
        } finally { conn.disconnect(); }
    }
    public String getTelegramBotToken() {
        return telegramBotToken;
    }

    public void setTelegramBotToken(String v) {
        this.telegramBotToken = v == null ? "" : v.trim();
    }

    public String getTelegramChatId() {
        return telegramChatId;
    }

    public void setTelegramChatId(String v) {
        this.telegramChatId = v == null ? "" : v.trim();
    }

    public String getDiscordWebhookUrl() {
        return discordWebhookUrl;
    }

    public void setDiscordWebhookUrl(String v) {
        this.discordWebhookUrl = v == null ? "" : v.trim();
    }

    public String getAlertTrigger() {
        return alertTrigger;
    }

    public void setAlertTrigger(String v) {
        this.alertTrigger = v;
    }

    public void shutdown() {
        executor.shutdown();
    }
}
