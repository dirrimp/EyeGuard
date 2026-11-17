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
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Phase 2: HEALTH ONLY. Takes a screenshot every SHOT_MS while the screen is on, examines it in memory (black? changing?)
 *  and discards it, and sends counts to the server every BEAT_MS. No image or text ever leaves the box in this phase. */
public class GuardService extends AccessibilityService {
    static final int SHOT_MS = 15_000;        // = interval_s 15
    static final long BEAT_MS = 300_000;      // 5 minutes: the server alerts after 15 minutes of silence

    private final ExecutorService io = Executors.newSingleThreadExecutor();   // frame callbacks + stats + beat snapshots
    private final ExecutorService net = Executors.newSingleThreadExecutor();  // blocking HTTPS
    private final FrameStats stats = new FrameStats();                        // io thread only
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
            String st = screenState();
            if (st.equals("on")) {
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

    @Override protected void onServiceConnected() {
        super.onServiceConnected();
        main = new Handler(getMainLooper());
        connected = true;
        lastTick = lastBeat = SystemClock.elapsedRealtime();
        main.postDelayed(shotTask, SHOT_MS);
        main.postDelayed(beatTask, 60_000);          // first beat after a minute, then every 5 minutes
    }

    @Override public void onAccessibilityEvent(AccessibilityEvent e) {
        CharSequence p = e.getPackageName();
        if (p != null) lastPackage = p.toString();
    }

    @Override public void onInterrupt() { }

    /** The service is being switched off (Settings) or the system is stopping it: tell the server once, best effort. */
    @Override public boolean onUnbind(android.content.Intent intent) {
        connected = false;
        if (main != null) { main.removeCallbacks(shotTask); main.removeCallbacks(beatTask); }
        beat(false, screenState(), Math.max(1, (SystemClock.elapsedRealtime() - lastBeat) / 1000));
        return false;
    }

    @Override public void onDestroy() {
        connected = false;
        // Order matters: the final beat (queued on io by onUnbind) must reach net before net stops accepting work.
        io.execute(net::shutdown);
        io.shutdown();
        super.onDestroy();
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

    /** Snapshot-and-reset the counts on the io thread, then send on the net thread. A failed send loses that window
     *  (the server sees it as silence if it keeps failing); counts are never queued or retried. */
    private void beat(boolean svcEnabled, String state, long windowS) {
        try {
            io.execute(() -> {
                try {
                    Config cfg = Config.load(this);
                    long onS = stats.screenOnMs / 1000;
                    org.json.JSONObject info = Heartbeat.info(this, svcEnabled, state, onS, windowS, SHOT_MS / 1000, stats);
                    stats.reset();
                    if (cfg == null) return;                                      // not configured: report nothing
                    net.execute(() -> Heartbeat.send(cfg, info));
                } catch (Throwable t) {
                    stats.reset();
                }
            });
        } catch (Throwable ignored) { }
    }
}
