package com.eyeguard.onn;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Plain-JVM test for MediaFacts (NOT part of the APK):
 *    javac --release 11 -d /tmp/c android/onn-monitor/src/com/eyeguard/onn/MediaFacts.java android/onn-monitor/test/com/eyeguard/onn/MediaFactsTest.java
 *    java -cp /tmp/c com.eyeguard.onn.MediaFactsTest
 *  Synthetic strings only. */
public class MediaFactsTest {
    static int fails = 0;
    static void check(String name, boolean ok) { System.out.println("  [" + (ok ? "ok  " : "FAIL") + "] " + name); if (!ok) fails++; }

    public static void main(String[] a) {
        String yt = MediaFacts.YOUTUBE_TV;
        System.out.println("the exemption rule");
        check("YouTube TV is the only package ever named", yt.equals("com.google.android.youtube.tvunplugged"));
        check("black + YouTube TV in front + session PLAYING -> excused", MediaFacts.exempt(true, yt, true));
        check("not black -> nothing to excuse", !MediaFacts.exempt(false, yt, true));
        check("YouTube TV not playing (paused, stopped, no session) -> NOT excused", !MediaFacts.exempt(true, yt, false));
        for (String other : new String[] {"org.smarttube.stable", "org.jellyfin.androidtv", "com.google.android.youtube.tv", "me.efesser.flauncher",
                                          "com.android.chrome", "", null, "com.google.android.youtube.tvunplugged.fake", " com.google.android.youtube.tvunplugged"})
            check("black + playing but foreground is " + other + " -> NOT excused", !MediaFacts.exempt(true, other, true));

        System.out.println("titles");
        check("plain title is kept", "Some Show S2 E4".equals(MediaFacts.cleanTitle("Some Show S2 E4")));
        check("control characters and runs of white space collapse", "A B C".equals(MediaFacts.cleanTitle("  A\t\tB\n\u0000 C  ")));
        check("empty, blank or null -> null", MediaFacts.cleanTitle("") == null && MediaFacts.cleanTitle("   \n") == null && MediaFacts.cleanTitle(null) == null);
        String longT = "x".repeat(500);
        check("a long title is cut to " + MediaFacts.MAX_TITLE, MediaFacts.cleanTitle(longT).length() == MediaFacts.MAX_TITLE);
        StringBuilder emoji = new StringBuilder(); for (int i = 0; i < 150; i++) emoji.append("😀");
        String cut = MediaFacts.cleanTitle(emoji);
        check("never ends on half a surrogate pair", cut != null && !Character.isHighSurrogate(cut.charAt(cut.length() - 1)));
        String json = new String(MediaFacts.titlePlain("He said \"hi\" \\ ok", 1700000000000L), StandardCharsets.UTF_8);
        check("the plaintext is JSON with the package and escaped quotes", json.equals("{\"v\":1,\"pkg\":\"" + yt + "\",\"at\":1700000000000,\"title\":\"He said \\\"hi\\\" \\\\ ok\"}"));
        check("non-ASCII survives as UTF-8", new String(MediaFacts.titlePlain("Café 日本", 1L), StandardCharsets.UTF_8).contains("Café 日本"));

        System.out.println("object name (must match eg_onn_title)");
        String n = MediaFacts.titleObjectName(1700000000123L);
        check("name pattern onn-title/<UTC>+00:00_title.enc", n.equals("onn-title/2023-11-14T22:13:20.123000+00:00_title.enc"));
        check("name matches the server's regex", n.matches("^onn-title/(\\d{4}-\\d\\d-\\d\\d)T(\\d\\d):(\\d\\d):(\\d\\d)(\\.\\d{1,6})?\\+00:00_title\\.enc$"));
        check("name is within the table's check (length <= 80, allowed characters)", n.length() <= 80 && n.matches("^onn-title/[0-9T:.+-]+_title\\.enc$"));
        check("an Egf2 blob always starts with the base64 prefix the server requires", Base64.getEncoder().encodeToString(new byte[] {'E', 'G', 'F', '2', 2, 0}).startsWith("RUdGM"));

        System.out.println("the upload gate");
        MediaFacts.TitleGate g = new MediaFacts.TitleGate();
        long t0 = 1_000_000_000L;
        check("nothing to send without a title", !g.shouldSend(null, t0));
        check("first title is sent", g.shouldSend("A", t0));
        g.sent("A", t0);
        check("never twice within a minute", !g.shouldSend("B", t0 + 30_000));
        check("same title, same window, a minute later: not repeated", !g.shouldSend("A", t0 + 61_000));
        check("a changed title is sent", g.shouldSend("B", t0 + 61_000));
        g.newWindow();
        check("a new heartbeat window with the same title: one record again (the server wants one per window)", g.shouldSend("A", t0 + 120_000));
        g.sent("A", t0 + 120_000);
        check("and only one per window", !g.shouldSend("A", t0 + 200_000));

        System.out.println("no title text is ever stored beyond one record");
        check("the gate keeps only the last title in memory", java.util.Arrays.stream(MediaFacts.TitleGate.class.getDeclaredFields()).filter(f -> f.getType() == String.class).count() == 1);
        System.out.println(fails == 0 ? "ALL OK" : "FAILED: " + fails);
        System.exit(fails == 0 ? 0 : 1);
    }
}
