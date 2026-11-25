package com.eyeguard.onn;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONObject;

/** Delivers ENCRYPTED title records to eg_onn_title (supabase/onn_media_exempt.sql). Only ciphertext is ever held or sent. In memory only
 *  (at most 5 items, at most 12 minutes old: the server accepts an object time for 15 minutes). The heartbeat reports how many records
 *  were delivered (titles_sent); the server honours the exemption only if a record arrived in the beat window, so a record that cannot be
 *  delivered simply means those black frames count as black. Network calls: net thread only. */
final class TitleUploader {
    static final int MAX_QUEUE = 5;
    static final long MAX_AGE_MS = 12 * 60_000L;
    static final String PATH = "/rest/v1/rpc/eg_onn_title";

    static final class Pending {
        final String name; final byte[] enc; final long createdMs;
        Pending(String name, byte[] enc, long createdMs) { this.name = name; this.enc = enc; this.createdMs = createdMs; }
    }

    private enum Result { OK, RETRY, DROP }

    private final ArrayDeque<Pending> queue = new ArrayDeque<>();
    private final AtomicInteger sent = new AtomicInteger();

    synchronized boolean enqueue(Pending p) {
        if (queue.size() >= MAX_QUEUE) return false;
        queue.add(p);
        return true;
    }

    synchronized int size() { return queue.size(); }

    /** Records delivered since the last call (goes into the heartbeat as titles_sent). */
    int takeSent() { return sent.getAndSet(0); }

    void drain(Config cfg) {
        if (cfg == null) return;
        while (true) {
            Pending p;
            synchronized (this) { p = queue.peek(); }
            if (p == null) return;
            if (System.currentTimeMillis() - p.createdMs > MAX_AGE_MS) { remove(p); continue; }
            Result r = deliver(cfg, p);
            if (r == Result.OK) { remove(p); sent.incrementAndGet(); continue; }
            if (r == Result.DROP) { remove(p); continue; }
            return;
        }
    }

    private synchronized void remove(Pending p) { queue.remove(p); }

    private Result deliver(Config cfg, Pending p) {
        HttpURLConnection h = null;
        try {
            JSONObject info = new JSONObject();
            info.put("pkg", MediaFacts.YOUTUBE_TV);
            info.put("object", p.name);
            info.put("ct", Base64.getEncoder().encodeToString(p.enc));       // ciphertext only
            JSONObject body = new JSONObject();
            body.put("p_token", cfg.token);
            body.put("p_info", info);
            byte[] bytes = body.toString().getBytes("UTF-8");
            h = (HttpURLConnection) new URL("https", Config.HOST, PATH).openConnection();
            h.setInstanceFollowRedirects(false);
            h.setConnectTimeout(10000);
            h.setReadTimeout(15000);
            h.setRequestMethod("POST");
            h.setRequestProperty("Content-Type", "application/json");
            h.setRequestProperty("apikey", cfg.anonKey);
            h.setRequestProperty("Authorization", "Bearer " + cfg.anonKey);
            h.setFixedLengthStreamingMode(bytes.length);
            h.setDoOutput(true);
            try (OutputStream out = h.getOutputStream()) { out.write(bytes); }
            int s = h.getResponseCode();
            if (s == 200) return Result.OK;
            return (s == 400 || s == 401 || s == 403 || s == 429) ? Result.DROP : Result.RETRY;
        } catch (Exception e) {
            return Result.RETRY;
        } finally {
            if (h != null) h.disconnect();
        }
    }
}
