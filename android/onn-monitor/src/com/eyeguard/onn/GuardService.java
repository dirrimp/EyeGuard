package com.eyeguard.onn;

import android.accessibilityservice.AccessibilityService;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.hardware.HardwareBuffer;
import android.os.Handler;
import android.os.PowerManager;
import android.os.SystemClock;
import android.view.Display;
import android.view.accessibility.AccessibilityEvent;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Phase 3: while the TV is on, takes a screenshot every SHOT_MS, examines it in memory, runs the exposure detector on it and discards it.
 *  Only when the detector finds exposure (score >= 0.80) does a picture leave the frame's lifetime: BLURRED like the Mac's RED frames,
 *  encrypted for Dad's key and the approved browser keys, uploaded, and recorded through eg_onn_flag. Every 5 minutes it sends the counts
 *  and the detector's self-test result to eg_onn_heartbeat; the server decides whether the detector is healthy. */
public class GuardService extends AccessibilityService {
    static final int SHOT_MS = 15_000;
    static final long BEAT_MS = 300_000;          // 5 minutes: the server alerts after 15 minutes of silence
    static final long SELFTEST_MS = 3_600_000;    // the detector self-test, hourly
    static final long RETRY_MS = 60_000;          // retry undelivered flags

    private final ExecutorService io = Executors.newSingleThreadExecutor();   // frame callbacks, detector, stats, beat snapshots
    private final ExecutorService net = Executors.newSingleThreadExecutor();  // blocking HTTPS
    private final FrameStats stats = new FrameStats();                        // io thread only
    private final Detector detector = new Detector();                         // io thread only
    private final FlagUploader uploader = new FlagUploader();
    private List<Egf2.Recipient> recipients;                                  // io thread only
    private volatile int selfArgmax;
    private volatile double selfMax;
    private int framesFlagged;                                                // io thread only
    private Handler main;
    private volatile boolean connected;
    private volatile String lastPackage = "";
    private long lastTick, lastBeat;                                          // main thread only (elapsedRealtime)

    private final Runnable shotTask = new Runnable() {
        @Override public void run() {
            if (!connected) return;
            long now = SystemClock.elapsedRealtime();
            long dt = Math.min(now - lastTick, 2L * SHOT_MS);
            lastTick = now;
            if (screenState().equals("on")) {
                io.execute(() -> stats.screenOnMs += dt);
                shoot();
            }
            main.postDelayed(this, SHOT_MS);
        }
    };

    private final Runnable beatTask = new Runnable() {
        @Override public void run() {
            if (!connected) return;
            long now = SystemClock.elapsedRealtime();
            long windowS = Math.max(1, (now - lastBeat) / 1000);
            lastBeat = now;
            beat(true, screenState(), windowS);
            main.postDelayed(this, BEAT_MS);
        }
    };

    private final Runnable selfTestTask = new Runnable() {
        @Override public void run() {
            if (!connected) return;
            io.execute(GuardService.this::runSelfTest);
            main.postDelayed(this, SELFTEST_MS);
        }
    };

    private final Runnable retryTask = new Runnable() {
        @Override public void run() {
            if (!connected) return;
            if (uploader.size() > 0) deliverFlags();
            main.postDelayed(this, RETRY_MS);
        }
    };

    @Override protected void onServiceConnected() {
        super.onServiceConnected();
        main = new Handler(getMainLooper());
        connected = true;
        lastTick = lastBeat = SystemClock.elapsedRealtime();
        io.execute(this::initDetector);
        main.postDelayed(shotTask, SHOT_MS);
        main.postDelayed(beatTask, 60_000);           // first beat after a minute, then every 5 minutes
        main.postDelayed(selfTestTask, SELFTEST_MS);
        main.postDelayed(retryTask, RETRY_MS);
    }

    @Override public void onAccessibilityEvent(AccessibilityEvent e) {
        CharSequence p = e.getPackageName();
        if (p != null) lastPackage = p.toString();
    }

    @Override public void onInterrupt() { }

    /** The service is being switched off (Settings) or stopped: tell the server once, best effort. */
    @Override public boolean onUnbind(android.content.Intent intent) {
        connected = false;
        if (main != null) {
            main.removeCallbacks(shotTask); main.removeCallbacks(beatTask);
            main.removeCallbacks(selfTestTask); main.removeCallbacks(retryTask);
        }
        beat(false, screenState(), Math.max(1, (SystemClock.elapsedRealtime() - lastBeat) / 1000));
        return false;
    }

    @Override public void onDestroy() {
        connected = false;
        // Order matters: the final beat (queued on io by onUnbind) must reach net before net stops accepting work.
        io.execute(detector::close);
        io.execute(net::shutdown);
        io.shutdown();
        super.onDestroy();
    }

    /** io thread: load the model and the recipients, then run the first self-test. A failure leaves the detector not ready; the next beat then
     *  reports a failing self-test and the server alerts. */
    private void initDetector() {
        String err = detector.init(this);
        if (err == null) {
            try { recipients = Egf2.parseAll(Recipients.PEMS); }
            catch (Throwable t) { detector.close(); }          // Dad's key must be usable, or no flag could be delivered
        }
        runSelfTest();
    }

    private void runSelfTest() {
        Detector.SelfTest st = detector.selfTest();
        selfArgmax = st.argmax;
        selfMax = st.max;
    }

    /** "on" = interactive and not a screensaver. "saver" and "off" never count as screen-on time and are not photographed. */
    private String screenState() {
        try {
            PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            if (!pm.isInteractive()) return "off";
            String p = lastPackage.toLowerCase(Locale.ROOT);
            if (p.contains("dream") || p.contains("backdrop") || p.contains("screensaver")) return "saver";
            return "on";
        } catch (Exception e) {
            return "unknown";
        }
    }

    private void shoot() {
        try {
            takeScreenshot(Display.DEFAULT_DISPLAY, io, new TakeScreenshotCallback() {
                @Override public void onSuccess(ScreenshotResult r) {
                    HardwareBuffer hb = r.getHardwareBuffer();
                    Bitmap hw = null, sw = null, small = null;
                    try {
                        hw = Bitmap.wrapHardwareBuffer(hb, r.getColorSpace());
                        if (hw == null) { stats.failure(); return; }
                        sw = hw.copy(Bitmap.Config.ARGB_8888, false);              // a hardware bitmap cannot be read
                        small = Bitmap.createScaledBitmap(sw, FrameStats.SIDE, FrameStats.SIDE, true);
                        int[] px = new int[FrameStats.SIDE * FrameStats.SIDE];
                        small.getPixels(px, 0, FrameStats.SIDE, 0, 0, FrameStats.SIDE, FrameStats.SIDE);
                        int[] luma = new int[px.length];
                        for (int i = 0; i < px.length; i++) {
                            luma[i] = (int) (0.299 * Color.red(px[i]) + 0.587 * Color.green(px[i]) + 0.114 * Color.blue(px[i]));
                        }
                        stats.success(luma);
                        analyse(sw);
                    } catch (Throwable t) {
                        stats.failure();
                    } finally {                                                  // the frame is gone either way
                        if (small != null) small.recycle();
                        if (sw != null) sw.recycle();
                        if (hw != null) hw.recycle();
                        hb.close();
                    }
                }
                @Override public void onFailure(int errorCode) { stats.failure(); }
            });
        } catch (Throwable t) {
            io.execute(stats::failure);
        }
    }

    /** io thread, inside the screenshot callback: run the detector; on a flag, build, encrypt and queue the picture. */
    private void analyse(Bitmap sw) {
        if (!detector.ready()) return;
        try {
            Postprocess.Hit hit = detector.detect(sw);
            if (!hit.isFlag()) return;
            framesFlagged++;
            flag(sw, hit);
        } catch (Throwable t) {
            // the detector keeps counting consecutive errors and marks itself not ready after three: the self-test then fails server-side
        }
    }

    private void flag(Bitmap sw, Postprocess.Hit hit) {
        byte[] jpeg = null;
        try {
            if (recipients == null || recipients.isEmpty()) throw new IllegalStateException("no recipients");
            long now = System.currentTimeMillis();
            String name = FlagName.objectName(now);
            jpeg = FlagFrame.blurredJpeg(sw);                                    // blurred before it is encoded
            byte[] enc = Egf2.encrypt(jpeg, recipients, name);                   // and encrypted before it is held anywhere else
            if (uploader.enqueue(new FlagUploader.Pending(name, enc, hit.labelName(), hit.score, FlagName.safeForeground(lastPackage), now))) {
                deliverFlags();
            }
        } catch (Throwable t) {
            uploader.countDropped();                                             // never silent: flags_dropped in the next heartbeat
        } finally {
            if (jpeg != null) Arrays.fill(jpeg, (byte) 0);
        }
    }

    private void deliverFlags() {
        try {
            net.execute(() -> uploader.drain(Config.load(this)));
        } catch (Throwable ignored) { }
    }

    /** Snapshot-and-reset the counts on the io thread, then send on the net thread. A failed send loses that window's counts
     *  (the server sees silence if it keeps failing); counts are never queued or retried. */
    private void beat(boolean svcEnabled, String state, long windowS) {
        try {
            io.execute(() -> {
                try {
                    Config cfg = Config.load(this);
                    long onS = stats.screenOnMs / 1000;
                    Heartbeat.DetectorStatus d = new Heartbeat.DetectorStatus(Detector.MODEL_SHA256, selfArgmax, selfMax,
                            detector.medianMs(), framesFlagged, uploader.takeDropped());
                    org.json.JSONObject info = Heartbeat.info(this, svcEnabled, state, onS, windowS, SHOT_MS / 1000, stats, d);
                    stats.reset();
                    framesFlagged = 0;
                    if (cfg == null) return;                                      // not configured: report nothing
                    net.execute(() -> Heartbeat.send(cfg, info));
                } catch (Throwable t) {
                    stats.reset();
                }
            });
        } catch (Throwable ignored) { }
    }
}
