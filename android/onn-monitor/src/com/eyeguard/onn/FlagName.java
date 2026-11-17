package com.eyeguard.onn;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/** Names and sanitising for one flagged frame. The object name must match what the server's eg_onn_flag accepts
 *  (supabase/onn_monitor_phase3.sql) and what the dashboard viewer reads (its timestamp is the flag's time):
 *  onn/<UTC time with ':' written '-'>_flagged_d1.jpg.enc, exactly like the Mac's uploader names its frames. Pure JDK. */
final class FlagName {
    private FlagName() {}

    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH-mm-ss.SSS'000+00-00'").withZone(ZoneOffset.UTC);

    static String objectName(long epochMillis) {
        return "onn/" + FMT.format(Instant.ofEpochMilli(epochMillis)) + "_flagged_d1.jpg.enc";
    }

    /** Foreground package text for the alert email: letters, digits and . _ - only, at most 120 characters (the server refuses anything else). */
    static String safeForeground(String pkg) {
        if (pkg == null) return "";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < pkg.length() && b.length() < 120; i++) {
            char c = pkg.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') b.append(c);
        }
        return b.toString();
    }
}
