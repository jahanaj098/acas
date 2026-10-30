package com.acas.export;

/** Conservative per-file budgets, checked against provider documentation on 2026-10-19. */
public final class HermesUploadLimits {
    private HermesUploadLimits() {}
    // Telegram hosted Bot API sendDocument: 50 MB; Discord default attachment: 20 MiB.
    // Leave margin for multipart overhead and avoid depending on paid server boosts.
    public static final int TELEGRAM_PART_BYTES = 45_000_000;
    public static final int DISCORD_PART_BYTES = 19 * 1024 * 1024;
    public static int partBytes(boolean telegram) { return telegram ? TELEGRAM_PART_BYTES : DISCORD_PART_BYTES; }
    public static void validate(java.util.List<HermesArchive.FileData> files, boolean telegram) {
        for(var file:files)if(file.bytes().length>partBytes(telegram))
            throw new IllegalArgumentException("Export attachment exceeds the configured upload budget: "+file.name());
    }
}
