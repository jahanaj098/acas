package com.acas.export;

import java.net.URI;
import java.util.Locale;
import java.util.Set;

/** Resolve older installations that saved Telegram as an implicit default. */
public final class HermesDestinationSettings {
    private HermesDestinationSettings() {}
    private static final Set<String> DISCORD_HOSTS = Set.of("discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com");

    public static String resolve(String saved,boolean explicit,boolean telegramConfigured,boolean discordConfigured) {
        boolean valid="telegram".equals(saved) || "discord".equals(saved) || "both".equals(saved);
        if(valid && (explicit || !"telegram".equals(saved)))return saved;
        if(!telegramConfigured && discordConfigured)return "discord";
        return "telegram";
    }

    /** Accept only a Discord webhook endpoint; never generic user-supplied SSRF targets. */
    public static String validateDiscordWebhook(String value) {
        if (value == null || value.isBlank()) return "";
        URI uri;
        try { uri = URI.create(value.trim()); }
        catch (IllegalArgumentException invalid) { throw invalid(); }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        if (!"https".equals(scheme) || !DISCORD_HOSTS.contains(host) || uri.getRawUserInfo() != null
            || uri.getPort() != -1 && uri.getPort() != 443 || uri.getRawFragment() != null) throw invalid();
        String[] segments = uri.getRawPath().split("/", -1);
        if (segments.length != 5 || !segments[0].isEmpty() || !segments[1].equals("api")
            || !segments[2].equals("webhooks") || !segments[3].matches("[0-9]{1,32}")
            || !segments[4].matches("[A-Za-z0-9._-]{1,200}")) throw invalid();
        String thread = null;
        if (uri.getRawQuery() != null) {
            for (String pair : uri.getRawQuery().split("&")) {
                if (pair.equals("wait=true") || pair.equals("wait=false")) continue;
                if (pair.startsWith("thread_id=") && pair.substring(10).matches("[0-9]{1,32}") && thread == null)
                    thread = pair.substring(10);
                else throw invalid();
            }
        }
        return "https://discord.com/api/webhooks/" + segments[3] + "/" + segments[4]
            + (thread == null ? "" : "?thread_id=" + thread);
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("A Discord webhook URL must be https://discord.com/api/webhooks/<id>/<token>");
    }
}
