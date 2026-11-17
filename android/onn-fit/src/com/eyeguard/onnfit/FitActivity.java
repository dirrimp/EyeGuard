package com.eyeguard.onnfit;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtSession;
import android.app.Activity;
import android.app.ActivityManager;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.os.Build;
import android.os.Bundle;
import android.widget.TextView;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.FloatBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import org.json.JSONArray;
import org.json.JSONObject;

/** Phase 3 gate 1: can the Mac's NudeNet model (320n.onnx) run on THIS box, and how fast / how big?
 *  Benign synthetic input only. Writes fit-result.json next to the model (adb pull); never uses the network.
 *  Start: adb shell am start -n com.eyeguard.onnfit/.FitActivity [--ei runs 40]
 *  Model: adb push 320n.onnx /sdcard/Android/data/com.eyeguard.onnfit/files/ (verified against the pinned hash below). */
public class FitActivity extends Activity {
    static final String MODEL_SHA256 = "c15d8273adad2d0a92f014cc69ab2d6c311a06777a55545f2c4eb46f51911f0f";
    static final int SIDE = 320;
    static final int[] EXPLICIT = {2, 3, 4, 6};   // BUTTOCKS_EXPOSED, FEMALE_BREAST_EXPOSED, FEMALE_GENITALIA_EXPOSED, ANUS_EXPOSED
    static final int[] THREADS = {1, 2, 4};

    private TextView view;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        view = new TextView(this);
        view.setTextSize(28);
        view.setText("EyeGuard fit test running. Do not touch the remote.");
        setContentView(view);
        final int runs = getIntent().getIntExtra("runs", 40);
        new Thread(() -> run(runs), "fit").start();
    }

    private void say(String s) { runOnUiThread(() -> view.setText(s)); }

    private void run(int runs) {
        JSONObject out = new JSONObject();
        File dir = getExternalFilesDir(null);
        File model = new File(dir, "320n.onnx");
        try {
            out.put("device", deviceInfo());
            String sha = sha256(model);
            out.put("model_sha256", sha);
            if (!MODEL_SHA256.equals(sha)) throw new IllegalStateException("model hash does not match the pin");
            out.put("memory_before_load", memory());

            OrtEnvironment env = OrtEnvironment.getEnvironment();
            JSONArray perThreads = new JSONArray();
            for (int th : THREADS) {
                JSONObject r = new JSONObject();
                r.put("threads", th);
                OrtSession.SessionOptions so = new OrtSession.SessionOptions();
                so.setIntraOpNumThreads(th);
                long t0 = System.nanoTime();
                OrtSession session = env.createSession(model.getAbsolutePath(), so);
                r.put("load_ms", (System.nanoTime() - t0) / 1e6);
                String inName = session.getInputNames().iterator().next();
                r.put("memory_after_load", memory());

                if (th == THREADS[0]) out.put("parity", parity(env, session, inName));

                Bitmap frame = syntheticFrame();                 // 1920x1080, like a TV screenshot
                ArrayList<Double> pre = new ArrayList<>(), inf = new ArrayList<>();
                for (int i = 0; i < 3 + runs; i++) {              // 3 warm-up runs are not counted
                    long a = System.nanoTime();
                    float[] x = preprocess(frame);
                    long b2 = System.nanoTime();
                    float top = infer(env, session, inName, x);
                    long c = System.nanoTime();
                    if (i >= 3) { pre.add((b2 - a) / 1e6); inf.add((c - b2) / 1e6); }
                    if (top < 0) throw new IllegalStateException("bad output");
                }
                frame.recycle();
                r.put("preprocess_ms", stats(pre));
                r.put("inference_ms", stats(inf));
                r.put("memory_after_runs", memory());
                session.close(); so.close();
                perThreads.put(r);
                say("fit test: finished " + th + " thread(s)");
            }
            out.put("runs_each", runs);
            out.put("by_threads", perThreads);
            out.put("ok", true);
        } catch (Throwable t) {
            try { out.put("ok", false); out.put("error", t.getClass().getName() + ": " + t.getMessage()); } catch (Exception ignored) { }
        }
        try (FileOutputStream fo = new FileOutputStream(new File(dir, "fit-result.json"))) {
            fo.write(out.toString(2).getBytes("UTF-8"));
        } catch (Exception ignored) { }
        say("fit test finished: " + (out.optBoolean("ok") ? "OK" : "FAILED") + ". You can leave this screen.");
    }

    /** The same deterministic input the Mac computes in tools/onn_fit_reference.py (LCG; identical float32 maths). */
    static float[] parityInput() {
        float[] in = new float[3 * SIDE * SIDE];
        long s = 12345;
        for (int i = 0; i < in.length; i++) {
            s = (s * 1103515245L + 12345L) & 0x7fffffffL;
            in[i] = ((s >> 8) & 0xFFFF) / 65535f;
        }
        return in;
    }

    private JSONObject parity(OrtEnvironment env, OrtSession session, String inName) throws Exception {
        JSONObject p = new JSONObject();
        float[] flat = new float[0];
        try (OnnxTensor t = OnnxTensor.createTensor(env, FloatBuffer.wrap(parityInput()), new long[] {1, 3, SIDE, SIDE});
             OrtSession.Result res = session.run(Collections.singletonMap(inName, t))) {
            OnnxTensor o = (OnnxTensor) res.get(0);
            long[] shape = o.getInfo().getShape();
            FloatBuffer fb = o.getFloatBuffer();
            flat = new float[fb.remaining()];
            fb.get(flat);
            JSONArray sh = new JSONArray(); for (long v : shape) sh.put(v);
            p.put("shape", sh);
        }
        double sum = 0; float max = -Float.MAX_VALUE; int arg = 0;
        for (int i = 0; i < flat.length; i++) { sum += flat[i]; if (flat[i] > max) { max = flat[i]; arg = i; } }
        p.put("count", flat.length); p.put("sum", sum); p.put("max", max); p.put("argmax", arg);
        JSONArray first = new JSONArray(); for (int i = 0; i < 16 && i < flat.length; i++) first.put(flat[i]);
        p.put("first16", first);
        int anchors = flat.length / 22;                     // output is [1, 22, anchors]: 4 box values then 18 class scores
        float top = 0;
        for (int c : EXPLICIT) for (int a = 0; a < anchors; a++) top = Math.max(top, flat[(4 + c) * anchors + a]);
        p.put("top_explicit_score", top);
        return p;
    }

    /** One inference; returns the top score over the four explicit classes (>= 0). */
    private float infer(OrtEnvironment env, OrtSession session, String inName, float[] x) throws Exception {
        try (OnnxTensor t = OnnxTensor.createTensor(env, FloatBuffer.wrap(x), new long[] {1, 3, SIDE, SIDE});
             OrtSession.Result res = session.run(Collections.singletonMap(inName, t))) {
            OnnxTensor o = (OnnxTensor) res.get(0);
            FloatBuffer fb = o.getFloatBuffer();
            int anchors = fb.remaining() / 22;
            float top = 0;
            for (int c : EXPLICIT) for (int a = 0; a < anchors; a++) top = Math.max(top, fb.get((4 + c) * anchors + a));
            return top;
        }
    }

    /** Letterbox like NudeNet: pad to a square at the bottom/right, scale to 320x320, RGB planar float 0..1. */
    private static float[] preprocess(Bitmap src) {
        int w = src.getWidth(), h = src.getHeight(), sq = Math.max(w, h);
        Bitmap scaled = Bitmap.createScaledBitmap(src, Math.round(w * (float) SIDE / sq), Math.round(h * (float) SIDE / sq), true);
        Bitmap sqr = Bitmap.createBitmap(SIDE, SIDE, Bitmap.Config.ARGB_8888);
        new Canvas(sqr).drawBitmap(scaled, 0, 0, null);
        int[] px = new int[SIDE * SIDE];
        sqr.getPixels(px, 0, SIDE, 0, 0, SIDE, SIDE);
        float[] x = new float[3 * SIDE * SIDE];
        int n = SIDE * SIDE;
        for (int i = 0; i < n; i++) {
            int p = px[i];
            x[i] = ((p >> 16) & 0xff) / 255f;
            x[n + i] = ((p >> 8) & 0xff) / 255f;
            x[2 * n + i] = (p & 0xff) / 255f;
        }
        scaled.recycle(); sqr.recycle();
        return x;
    }

    /** A benign synthetic 1080p frame (gradients and bars). Nothing here depicts anything. */
    private static Bitmap syntheticFrame() {
        int w = 1920, h = 1080;
        int[] px = new int[w * h];
        for (int y = 0; y < h; y++) for (int x = 0; x < w; x++) {
            int r = (x * 255) / w, g = (y * 255) / h, b = ((x / 120) % 2 == 0) ? 200 : 40;
            px[y * w + x] = 0xff000000 | (r << 16) | (g << 8) | b;
        }
        Bitmap bm = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888);
        bm.setPixels(px, 0, w, 0, 0, w, h);
        return bm;
    }

    private static JSONObject stats(ArrayList<Double> v) throws Exception {
        Collections.sort(v);
        JSONObject o = new JSONObject();
        double sum = 0; for (double d : v) sum += d;
        o.put("n", v.size());
        o.put("min", v.get(0)); o.put("median", v.get(v.size() / 2));
        o.put("p95", v.get(Math.min(v.size() - 1, (int) Math.ceil(v.size() * 0.95) - 1)));
        o.put("max", v.get(v.size() - 1)); o.put("mean", sum / v.size());
        return o;
    }

    private JSONObject memory() throws Exception {
        JSONObject o = new JSONObject();
        try (java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader("/proc/self/status"))) {
            String l;
            while ((l = br.readLine()) != null) {
                if (l.startsWith("VmRSS:") || l.startsWith("VmHWM:")) {
                    String[] p = l.split("\\s+");
                    o.put(p[0].replace(":", "").toLowerCase(), Long.parseLong(p[1]));   // kB
                }
            }
        }
        return o;
    }

    private JSONObject deviceInfo() throws Exception {
        JSONObject o = new JSONObject();
        o.put("sdk", Build.VERSION.SDK_INT);
        o.put("abis", new JSONArray(Build.SUPPORTED_ABIS));
        o.put("model", Build.MODEL);
        o.put("cpu_cores", Runtime.getRuntime().availableProcessors());
        ActivityManager am = (ActivityManager) getSystemService(ACTIVITY_SERVICE);
        ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
        am.getMemoryInfo(mi);
        o.put("total_mem_mb", mi.totalMem / 1048576L);
        o.put("avail_mem_mb", mi.availMem / 1048576L);
        return o;
    }

    private static String sha256(File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (FileInputStream in = new FileInputStream(f)) {
            byte[] buf = new byte[65536]; int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
        }
        StringBuilder sb = new StringBuilder();
        for (byte x : md.digest()) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }
}
