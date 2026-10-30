package com.acas.util;

import java.util.Locale;
import java.util.Map;

/** Palette from yeswehack/PwnFox firefox/src/popup/{popup,colors}.css. */
public final class PwnFoxColors {
    public static final String HEADER = "X-PwnFox-Color";
    public static final Map<String, String> PALETTE = Map.of(
        "blue", "#0a84ff", "turquoise", "#00feff", "green", "#30e60b", "yellow", "#ffe900",
        "orange", "#ff9400", "red", "#ff0039", "pink", "#ff1ad9", "purple", "#9400ff");
    private PwnFoxColors() {}

    public static String name(String value) {
        if (value == null) return null;
        String name = value.trim().toLowerCase(Locale.ROOT);
        // PwnFox's wire header translates Firefox turquoise/purple to cyan/magenta.
        if (name.equals("cyan")) name = "turquoise";
        if (name.equals("magenta")) name = "purple";
        return PALETTE.containsKey(name) ? name : null;
    }

    public static String hex(String value) { return PALETTE.get(name(value) == null ? "" : name(value)); }

    public static String headerValue(String value) {
        String name = name(value);
        if ("turquoise".equals(name)) return "cyan";
        if ("purple".equals(name)) return "magenta";
        return name;
    }

    public static String fromRequest(String raw) {
        if (raw == null) return null;
        for (String line : raw.split("\\r?\\n")) {
            if (line.isEmpty()) break; // never interpret the request body as headers
            int colon = line.indexOf(':');
            if (colon > 0 && HEADER.equalsIgnoreCase(line.substring(0, colon).trim())) {
                return name(line.substring(colon + 1));
            }
        }
        return null;
    }
}
