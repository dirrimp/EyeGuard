package com.eyeguard.onn;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** Phase 5a, FACTS ONLY: does a media app expose a usable title to this service? Counts per heartbeat window, over an allowlist of
 *  media apps. The text of an event exists only inside {@link #event}; what is kept is four integers (events, events with text, events
 *  with text that is more than a generic name, and the number of DISTINCT such texts, counted by a hash salted per process start and
 *  held only in memory). No text, no hash and no package name is logged, stored or sent. Touched only from the single "io" thread. */
final class TitleFacts {
    /** Only these apps are looked at (YouTube TV, YouTube, Jellyfin for Android TV). Anything else is ignored before its text is read. */
    static final Set<String> WATCHED = Set.of("com.google.android.youtube.tvunplugged", "com.google.android.youtube.tv", "org.jellyfin.androidtv");
    /** Longest text considered (a title is short; anything longer is a page of content, not a title) and the cap on distinct values kept. */
    static final int MAX_TEXT = 200, MAX_DISTINCT = 5000;

    private final byte[] salt = new byte[16];
    private final Set<Long> seen = new HashSet<>();
    int events, withText, specific;

    TitleFacts() { new SecureRandom().nextBytes(salt); }

    static boolean watched(String pkg) { return pkg != null && WATCHED.contains(pkg); }

    /** True when the text carries no information beyond the app or screen name. */
    static boolean generic(String text, String pkg, String cls) {
        String t = text.trim().toLowerCase(Locale.ROOT);
        if (t.length() <= 3) return true;
        if (pkg != null && t.contains(pkg.toLowerCase(Locale.ROOT))) return true;
        if (cls != null && !cls.isEmpty() && t.startsWith(cls.toLowerCase(Locale.ROOT))) return true;
        return t.equals("youtube tv") || t.equals("youtube") || t.equals("jellyfin") || t.equals("home") || t.equals("search");
    }

    void event(String pkg, String cls, String text) {
        if (!watched(pkg)) return;
        events++;
        if (text == null || text.trim().isEmpty() || text.length() > MAX_TEXT) return;
        withText++;
        if (generic(text, pkg, cls)) return;
        specific++;
        if (seen.size() < MAX_DISTINCT) seen.add(hash(text));
    }

    int distinct() { return seen.size(); }

    void reset() { events = withText = specific = 0; seen.clear(); }

    private long hash(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
            long h = 0; for (int i = 0; i < 8; i++) h = (h << 8) | (d[i] & 0xff);
            return h;
        } catch (Exception e) { return 0L; }
    }
}
