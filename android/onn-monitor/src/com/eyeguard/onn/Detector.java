package com.eyeguard.onn;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtSession;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.system.Os;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.FloatBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;

/** The on-box exposure detector: the Mac's NudeNet 320n model, bundled in the APK and checked against its pinned hash, run on ONNX
 *  Runtime with 2 threads (the fit test: 272 ms a frame, leaving two cores for video). Used only from the single "io" thread.
 *  ONNX Runtime's telemetry cannot run: the AAR manifest is never merged, the build STRIPS its 13 telemetry classes, and this class also
 *  sets ORT_DISABLE_TELEMETRY and calls setTelemetry(false) (best effort; each layer alone would be enough to stop the provider). */
final class Detector {
    static final String MODEL_ASSET = "320n.onnx";
    static final String MODEL_SHA256 = "c15d8273adad2d0a92f014cc69ab2d6c311a06777a55545f2c4eb46f51911f0f";   // = the Mac's model (pinned)
    static final int THREADS = 2;
    static final int SIDE = Postprocess.MODEL_SIDE;
    private static final int RING = 32;

    /** Result of the hourly self-test on the fixed synthetic input (the SERVER compares it with the Mac's golden values). */
    static final class SelfTest {
        final int argmax; final double max; final boolean ok;
        SelfTest(int argmax, double max, boolean ok) { this.argmax = argmax; this.max = max; this.ok = ok; }
    }

    private OrtEnvironment env;
    private OrtSession.SessionOptions opts;
    private OrtSession session;
    private String inputName;
    private volatile boolean ready;
    private int consecutiveErrors;
    private final long[] ms = new long[RING];
    private int msN;

    boolean ready() { return ready; }

    /** @return null on success, else a short reason (never a secret). */
    String init(Context c) {
        try {
            try { Os.setenv("ORT_DISABLE_TELEMETRY", "1", true); } catch (Throwable ignored) { }   // before the native library loads
            byte[] model = readAsset(c);
            if (!MODEL_SHA256.equals(hex(MessageDigest.getInstance("SHA-256").digest(model)))) return "model hash does not match the pin";
            env = OrtEnvironment.getEnvironment();
            try { env.setTelemetry(false); } catch (Throwable ignored) { }
            opts = new OrtSession.SessionOptions();
            opts.setIntraOpNumThreads(THREADS);
            session = env.createSession(model, opts);
            inputName = session.getInputNames().iterator().next();
            Arrays.fill(model, (byte) 0);
            consecutiveErrors = 0;
            ready = true;
            return null;
        } catch (Throwable t) {
            ready = false;
            return t.getClass().getSimpleName();
        }
    }

    void close() {
        ready = false;
        try { if (session != null) session.close(); } catch (Throwable ignored) { }
        try { if (opts != null) opts.close(); } catch (Throwable ignored) { }
    }

    /** Analyse one SOFTWARE ARGB screenshot. Three failures in a row mark the detector broken (the heartbeat then fails its self-test). */
    Postprocess.Hit detect(Bitmap sw) throws Exception {
        try {
            float[] x = preprocess(sw);
            long t0 = System.nanoTime();
            float[] out = run(x);
            record((System.nanoTime() - t0) / 1_000_000L);
            consecutiveErrors = 0;
            return Postprocess.analyze(out, out.length / Postprocess.CHANNELS, sw.getWidth(), sw.getHeight());
        } catch (Exception e) {
            if (++consecutiveErrors >= 3) ready = false;
            throw e;
        }
    }

    /** Same deterministic input as tools/onn_fit_reference.py (and the fit test): LCG, identical float32 arithmetic. */
    static float[] parityInput() {
        float[] in = new float[3 * SIDE * SIDE];
        long s = 12345;
        for (int i = 0; i < in.length; i++) {
            s = (s * 1103515245L + 12345L) & 0x7fffffffL;
            in[i] = ((s >> 8) & 0xFFFF) / 65535f;
        }
        return in;
    }

    SelfTest selfTest() {
        if (!ready) return new SelfTest(0, 0.0, false);
        try {
            long t0 = System.nanoTime();
            float[] out = run(parityInput());
            record((System.nanoTime() - t0) / 1_000_000L);
            float max = -Float.MAX_VALUE; int arg = 0;
            for (int i = 0; i < out.length; i++) if (out[i] > max) { max = out[i]; arg = i; }
            return new SelfTest(arg, max, true);
        } catch (Throwable t) {
            ready = false;
            return new SelfTest(0, 0.0, false);
        }
    }

    /** Median of the last inference times in ms, never below 1 (the server requires 1..600000). */
    long medianMs() {
        int n = Math.min(msN, RING);
        if (n == 0) return 1;
        long[] c = Arrays.copyOf(ms, n);
        Arrays.sort(c);
        return Math.max(1, c[n / 2]);
    }

    private void record(long v) { ms[msN++ % RING] = v; }

    private float[] run(float[] x) throws Exception {
        try (OnnxTensor t = OnnxTensor.createTensor(env, FloatBuffer.wrap(x), new long[] {1, 3, SIDE, SIDE});
             OrtSession.Result res = session.run(Collections.singletonMap(inputName, t))) {
            FloatBuffer fb = ((OnnxTensor) res.get(0)).getFloatBuffer();
            float[] out = new float[fb.remaining()];
            fb.get(out);
            return out;
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
        if (scaled != src) scaled.recycle();
        sqr.recycle();
        return x;
    }

    private static byte[] readAsset(Context c) throws Exception {
        try (InputStream in = c.getAssets().open(MODEL_ASSET)) {
            ByteArrayOutputStream bo = new ByteArrayOutputStream(13_000_000);
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
            return bo.toByteArray();
        }
    }

    private static String hex(byte[] d) {
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
