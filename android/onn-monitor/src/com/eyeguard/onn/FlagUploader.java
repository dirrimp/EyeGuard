package com.eyeguard.onn;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayDeque;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONObject;

/** Delivers flagged frames, in this order: (1) the ENCRYPTED frame to the 'frames' bucket under onn/, (2) the flag record through
 *  eg_onn_flag (the server checks that the frame exists). Only ciphertext is ever held or sent. The queue lives in memory only
 *  (at most 10 items, at most 12 minutes old: the server accepts a frame name for 15 minutes), so nothing is written to the device.
 *  A flag that cannot be delivered is COUNTED (flags_dropped in the next heartbeat), never silently lost. Network calls: net thread only. */
final class FlagUploader {
    static final int MAX_QUEUE = 10;
    static final long MAX_AGE_MS = 12 * 60_000L;

    static final class Pending {
        final String name; final byte[] enc; final String label; final float score; final String fg; final long createdMs;
        boolean uploaded;
        Pending(String name, byte[] enc, String label, float score, String fg, long createdMs) {
            this.name = name; this.enc = enc; this.label = label; this.score = score; this.fg = fg; this.createdMs = createdMs;
        }
    }

    private enum Result { OK, RETRY, DROP }

    private final ArrayDeque<Pending> queue = new ArrayDeque<>();
    private final AtomicInteger dropped = new AtomicInteger();

    synchronized boolean enqueue(Pending p) {
        if (queue.size() >= MAX_QUEUE) { dropped.incrementAndGet(); return false; }
        queue.add(p);
        return true;
    }

    synchronized int size() { return queue.size(); }

    void countDropped() { dropped.incrementAndGet(); }

    /** Dropped-flag count since the last call (goes into the heartbeat). */
    int takeDropped() { return dropped.getAndSet(0); }

    /** Try to deliver everything queued; stops at the first transient failure (retried on the next call). */
    void drain(Config cfg) {
        if (cfg == null) return;
        while (true) {
            Pending p;
            synchronized (this) { p = queue.peek(); }
            if (p == null) return;
            if (System.currentTimeMillis() - p.createdMs > MAX_AGE_MS) { remove(p); dropped.incrementAndGet(); continue; }
            Result r = deliver(cfg, p);
            if (r == Result.OK) { remove(p); continue; }
            if (r == Result.DROP) { remove(p); dropped.incrementAndGet(); continue; }
            return;
        }
    }

    private synchronized void remove(Pending p) { queue.remove(p); }

    private Result deliver(Config cfg, Pending p) {
        try {
            if (!p.uploaded) {
                int s = post("/storage/v1/object/frames/" + p.name, "application/octet-stream", p.enc, cfg, 20000);
                if (s == 200 || s == 201 || s == 409) p.uploaded = true;          // 409: an earlier attempt already stored it
                else return (s == 400 || s == 401 || s == 403 || s == 413) ? Result.DROP : Result.RETRY;
            }
            JSONObject info = new JSONObject();
            info.put("label", p.label);
            info.put("score", (double) p.score);
            info.put("object", p.name);
            info.put("foreground", p.fg);
            JSONObject body = new JSONObject();
            body.put("p_token", cfg.token);
            body.put("p_info", info);
            int s = post("/rest/v1/rpc/eg_onn_flag", "application/json", body.toString().getBytes("UTF-8"), cfg, 15000);
            if (s == 200) return Result.OK;
            // 400 bad info / 401 token / 403 / 429 hourly ceiling are final; 404 (frame not visible yet), 5xx and network errors are retried
            return (s == 400 || s == 401 || s == 403 || s == 429) ? Result.DROP : Result.RETRY;
        } catch (Exception e) {
            return Result.RETRY;
        }
    }

    /** @return the HTTP status, or -1 when the request failed. */
    private static int post(String path, String contentType, byte[] body, Config cfg, int timeoutMs) {
        HttpURLConnection h = null;
        try {
            h = (HttpURLConnection) new URL("https", Config.HOST, path).openConnection();
            h.setInstanceFollowRedirects(false);
            h.setConnectTimeout(10000);
            h.setReadTimeout(timeoutMs);
            h.setRequestMethod("POST");
            h.setRequestProperty("Content-Type", contentType);
            h.setRequestProperty("apikey", cfg.anonKey);
            h.setRequestProperty("Authorization", "Bearer " + cfg.anonKey);
            h.setFixedLengthStreamingMode(body.length);
            h.setDoOutput(true);
            try (OutputStream out = h.getOutputStream()) { out.write(body); }
            return h.getResponseCode();
        } catch (Exception e) {
            return -1;
        } finally {
            if (h != null) h.disconnect();
        }
    }
}
