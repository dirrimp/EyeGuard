package com.eyeguard.onn;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.regex.Pattern;

/** Plain-JVM test for Blur, Postprocess and FlagName (NOT part of the APK). Vectors come from tools/onn_frameprep_vectors.py:
 *    javac --release 11 -d /tmp/c src/com/eyeguard/onn/{Blur,Postprocess,FlagName}.java test/com/eyeguard/onn/FramePrepTest.java
 *    java -cp /tmp/c com.eyeguard.onn.FramePrepTest <vectors dir>
 *  The expectations were computed by the Mac's own code (PIL GaussianBlur; nudenet's _postprocess with cv2.dnn.NMSBoxes). */
public class FramePrepTest {
    static int fails = 0;
    static void check(String name, boolean ok) { System.out.println("  [" + (ok ? "ok  " : "FAIL") + "] " + name); if (!ok) fails++; }

    public static void main(String[] a) throws Exception {
        Path d = Paths.get(a[0]);

        System.out.println("Blur vs the Mac's PIL GaussianBlur");
        int w = 1280, h = 720;
        ByteBuffer in = ByteBuffer.wrap(Files.readAllBytes(d.resolve("blur_in.rgb")));
        byte[] exp = Files.readAllBytes(d.resolve("blur_expected.rgb"));
        int[] px = new int[w * h];
        for (int i = 0; i < px.length; i++) px[i] = 0xff000000 | ((in.get() & 0xff) << 16) | ((in.get() & 0xff) << 8) | (in.get() & 0xff);
        check("radius for a 1280-wide frame is 17 (width // 75), and never below 6", Blur.radiusFor(1280) == 17 && Blur.radiusFor(100) == 6);
        int[] sz = Blur.boxSizes(17);
        check("box sizes for sigma 17 are 33, 33, 35 (the model the numbers below were tuned with)", sz[0] == 33 && sz[1] == 33 && sz[2] == 35);
        long t0 = System.nanoTime();
        Blur.gaussian(px, w, h, Blur.radiusFor(w));
        long ms = (System.nanoTime() - t0) / 1_000_000;
        long sum = 0; int max = 0; boolean alphaOk = true;
        for (int i = 0; i < px.length; i++) {
            int p = px[i];
            alphaOk &= (p >>> 24) == 0xff;
            int dr = Math.abs(((p >> 16) & 0xff) - (exp[3 * i] & 0xff)), dg = Math.abs(((p >> 8) & 0xff) - (exp[3 * i + 1] & 0xff)), db = Math.abs((p & 0xff) - (exp[3 * i + 2] & 0xff));
            sum += dr + dg + db; max = Math.max(max, Math.max(dr, Math.max(dg, db)));
        }
        double mean = sum / (3.0 * px.length);
        System.out.println("    (blur took " + ms + " ms on this JVM; mean abs diff " + mean + ", max " + max + ")");
        check("mean difference from PIL under 0.5 of 255", mean < 0.5);
        check("no pixel differs from PIL by more than 4", max <= 4);
        check("alpha is untouched", alphaOk);
        check("a flat image stays flat", flat());
        check("bad arguments are refused", throwsIae());

        System.out.println("Postprocess vs nudenet's _postprocess + detector rule");
        List<String> lines = Files.readAllLines(d.resolve("pp_expected.txt"), StandardCharsets.UTF_8);
        ByteBuffer t = ByteBuffer.wrap(Files.readAllBytes(d.resolve("pp_tensors.bin"))).order(ByteOrder.LITTLE_ENDIAN);
        int anchors = 2100, bad = 0, flags = 0, none = 0;
        for (int n = 0; n < lines.size(); n++) {
            String[] f = lines.get(n).trim().split(" ");
            int ow = Integer.parseInt(f[0]), oh = Integer.parseInt(f[1]);
            float[] out = new float[Postprocess.CHANNELS * anchors];
            for (int i = 0; i < out.length; i++) out[i] = t.getFloat();
            Postprocess.Hit hit = Postprocess.analyze(out, anchors, ow, oh);
            boolean same = hit.labelName().equals(f[2]) && Math.abs(hit.score - Float.parseFloat(f[3])) <= 1e-6f;
            if (!same) { bad++; System.out.println("    case " + n + ": Java " + hit.labelName() + " " + hit.score + " vs Mac " + f[2] + " " + f[3]); }
            if (hit.isFlag()) flags++;
            if (hit.label < 0) none++;
        }
        check("all " + lines.size() + " tensors give the Mac's label and score (" + flags + " are flags, " + none + " have no explicit hit)", bad == 0);
        check("the set really exercises flags and non-flags", flags >= 10 && none >= 5);
        check("a wrong-sized output is refused", throwsAnalyze());

        System.out.println("FlagName");
        Pattern server = Pattern.compile(new String(Files.readAllBytes(d.resolve("server_pattern.txt")), StandardCharsets.UTF_8).trim());
        String name = FlagName.objectName(1794940000123L);
        check("the object name matches the pattern eg_onn_flag enforces: " + name, server.matcher(name).matches());
        check("it is 2026-11-17T18-26-40 UTC (epoch 1794940000123 ms) with a micro-style fraction", name.equals("onn/2026-11-17T18-26-40.123000+00-00_flagged_d1.jpg.enc"));
        check("a name with no fraction digits still matches the pattern", server.matcher("onn/2026-11-17T19-06-40+00-00_flagged_d1.jpg.enc").matches());
        check("foreground text keeps only letters, digits . _ -", FlagName.safeForeground("com.x/<b>y z!").equals("com.xbyz"));
        check("foreground text is capped at 120 characters and null is empty", FlagName.safeForeground("a".repeat(300)).length() == 120 && FlagName.safeForeground(null).isEmpty());

        System.out.println(fails == 0 ? "\nALL OK" : "\nFAILED: " + fails);
        System.exit(fails == 0 ? 0 : 1);
    }

    static boolean flat() {
        int[] p = new int[200 * 100]; java.util.Arrays.fill(p, 0xff336699);
        Blur.gaussian(p, 200, 100, 9);
        for (int v : p) if (v != 0xff336699) return false;
        return true;
    }
    static boolean throwsIae() { try { Blur.gaussian(new int[3], 2, 2, 5); return false; } catch (IllegalArgumentException e) { return true; } }
    static boolean throwsAnalyze() { try { Postprocess.analyze(new float[10], 2100, 100, 100); return false; } catch (IllegalArgumentException e) { return true; } }
}
