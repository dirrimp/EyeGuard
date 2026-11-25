package com.eyeguard.onn;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/** The rules of the YouTube TV black-frame exemption, with NO Android and NO network in it so they can be tested on a plain JVM.
 *  Design: docs/ONN-MEDIA-SESSION-ADDENDUM.md. Server side: supabase/onn_media_exempt.sql.
 *
 *  A black frame is excused ONLY when all three hold: the frame is black, the foreground app is exactly YouTube TV (the only
 *  copy-protected player on this TV), and YouTube TV's own media session says it is playing. Every other app (SmartTube, Jellyfin, the
 *  browser, the home screen) is never excused. The title of what is playing is captured content: it is only ever turned into bytes
 *  here, then ENCRYPTED by Egf2 before anything holds it elsewhere. */
final class MediaFacts {
    private MediaFacts() {}

    static final String YOUTUBE_TV = "com.google.android.youtube.tvunplugged";
    static final int MAX_TITLE = 200;
    static final long MIN_GAP_MS = 60_000L;   // at most one title record a minute (the server also refuses more than 120 an hour)

    /** The one place the exemption is decided. */
    static boolean exempt(boolean frameBlack, String foregroundPackage, boolean youtubeTvPlaying) {
        return frameBlack && youtubeTvPlaying && YOUTUBE_TV.equals(foregroundPackage);
    }

    /** A title as short plain text: control characters dropped, runs of white space collapsed, at most MAX_TITLE characters.
     *  null when nothing is left. */
    static String cleanTitle(CharSequence raw) {
        if (raw == null) return null;
        StringBuilder b = new StringBuilder();
        boolean space = false;
        for (int i = 0; i < raw.length() && b.length() < MAX_TITLE; i++) {
            char c = raw.charAt(i);
            if (Character.isISOControl(c) || Character.isWhitespace(c) || Character.isSpaceChar(c)) { space = b.length() > 0; continue; }
            if (space) { b.append(' '); space = false; if (b.length() >= MAX_TITLE) break; }
            b.append(c);
        }
        // never end on half of a surrogate pair
        if (b.length() > 0 && Character.isHighSurrogate(b.charAt(b.length() - 1))) b.setLength(b.length() - 1);
        return b.length() == 0 ? null : b.toString();
    }

    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'000+00:00'").withZone(ZoneOffset.UTC);

    /** Must match eg_onn_title in supabase/onn_media_exempt.sql: onn-title/<UTC time>+00:00_title.enc. The name is the AES-GCM
     *  additional data, so a record renamed on the server cannot be decrypted. */
    static String titleObjectName(long epochMillis) {
        return "onn-title/" + FMT.format(Instant.ofEpochMilli(epochMillis)) + "_title.enc";
    }

    /** The plaintext that is encrypted: a tiny JSON object the viewer shows as text. Hand-built so this class stays pure JDK. */
    static byte[] titlePlain(String title, long epochMillis) {
        StringBuilder s = new StringBuilder("{\"v\":1,\"pkg\":\"").append(YOUTUBE_TV).append("\",\"at\":").append(epochMillis).append(",\"title\":\"");
        for (int i = 0; i < title.length(); i++) {
            char c = title.charAt(i);
            if (c == '"' || c == '\\') s.append('\\').append(c);
            else if (c < 0x20) s.append(' ');
            else s.append(c);
        }
        s.append("\"}");
        return s.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** When to upload a title record. A record is sent when the title changed, or once per heartbeat window while exempt frames occur
     *  (the server only honours the exemption if a record arrived in the window), never more than once a minute. Not thread safe: io thread only. */
    static final class TitleGate {
        private String last = "";
        private long lastSendMs = Long.MIN_VALUE / 2;
        private int sentThisWindow;

        boolean shouldSend(String title, long nowMs) {
            if (title == null) return false;
            if (nowMs - lastSendMs < MIN_GAP_MS) return false;
            return !title.equals(last) || sentThisWindow == 0;
        }
        void sent(String title, long nowMs) { last = title; lastSendMs = nowMs; sentThisWindow++; }
        void newWindow() { sentThisWindow = 0; }
    }
}
