package com.eyeguard.onn;

/** Plain-JVM test for TitleFacts (NOT part of the APK):
 *    javac --release 11 -d /tmp/c android/onn-monitor/src/com/eyeguard/onn/TitleFacts.java android/onn-monitor/test/com/eyeguard/onn/TitleFactsTest.java
 *    java -cp /tmp/c com.eyeguard.onn.TitleFactsTest */
public class TitleFactsTest {
    static int fails = 0;
    static void check(String name, boolean ok) { System.out.println("  [" + (ok ? "ok  " : "FAIL") + "] " + name); if (!ok) fails++; }

    public static void main(String[] a) {
        String yt = "com.google.android.youtube.tvunplugged", jf = "org.jellyfin.androidtv";
        TitleFacts t = new TitleFacts();
        t.event("com.android.chrome", "x.Y", "Some Page Title");
        t.event(null, "x.Y", "Some Page Title");
        check("an app outside the allowlist is ignored completely (not even counted)", t.events == 0 && t.withText == 0 && t.specific == 0);
        t.event(yt, "android.widget.FrameLayout", "");
        t.event(yt, "android.widget.FrameLayout", null);
        t.event(yt, "android.widget.FrameLayout", "   ");
        check("events with no text count as events only", t.events == 3 && t.withText == 0);
        t.event(yt, "android.widget.FrameLayout", "YouTube TV");
        t.event(yt, "com.google.Foo", "com.google.Foo");
        t.event(yt, "x", "ok");
        t.event(yt, "x", yt);
        check("generic names are text but not specific", t.withText == 4 && t.specific == 0);
        t.event(yt, "x.Y", "Some Show S2 E4");
        t.event(yt, "x.Y", "Some Show S2 E4");
        t.event(jf, "x.Y", "Another Film (2019)");
        check("a real-looking title is specific, repeats are not distinct", t.specific == 3 && t.distinct() == 2 && t.events == 10);
        t.event(yt, "x.Y", "x".repeat(TitleFacts.MAX_TEXT + 1));
        check("a very long text is not a title: counted as an event only", t.withText == 7 && t.events == 11);
        t.reset();
        check("reset clears everything", t.events == 0 && t.withText == 0 && t.specific == 0 && t.distinct() == 0);
        TitleFacts u = new TitleFacts();
        for (int i = 0; i < TitleFacts.MAX_DISTINCT + 100; i++) u.event(jf, "x.Y", "Title number " + i);
        check("distinct values are capped in memory", u.distinct() == TitleFacts.MAX_DISTINCT && u.specific == TitleFacts.MAX_DISTINCT + 100);
        check("the only members that carry data are four counts and a set of hashes (no String field)",
              java.util.Arrays.stream(TitleFacts.class.getDeclaredFields())
                  .noneMatch(f -> f.getType() == String.class && !java.lang.reflect.Modifier.isStatic(f.getModifiers())));
        System.out.println(fails == 0 ? "ALL OK" : "FAILED: " + fails);
        System.exit(fails == 0 ? 0 : 1);
    }
}
