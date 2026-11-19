package com.eyeguard.onn;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import org.json.JSONObject;

/** Builds and sends ONE heartbeat to eg_onn_heartbeat (supabase/onn_monitor_phase1.sql). The server clock is the only
 *  clock; nothing here is trusted beyond what the server cross-checks. */
final class Heartbeat {
    private Heartbeat() {}

    /** SHA-256 of the app's own signing certificate, lowercase hex. Equals `openssl x509 -fingerprint -sha256`. */
    static String certSha256(Context c) throws Exception {
        PackageInfo pi = c.getPackageManager().getPackageInfo(c.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
        Signature[] s = pi.signingInfo.getApkContentsSigners();
        byte[] d = MessageDigest.getInstance("SHA-256").digest(s[0].toByteArray());
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    static String versionName(Context c) throws Exception {
        return c.getPackageManager().getPackageInfo(c.getPackageName(), 0).versionName;
    }

    /** What the detector reports with each beat. The SERVER decides from selftestArgmax/selftestMax whether the detector works
     *  (it compares them with the Mac's golden values); a detector that could not start sends 0 / 0.0, which fails that comparison. */
    static final class DetectorStatus {
        final String modelSha256; final int selftestArgmax; final double selftestMax; final long modelMs; final int framesFlagged; final int flagsDropped;
        DetectorStatus(String modelSha256, int selftestArgmax, double selftestMax, long modelMs, int framesFlagged, int flagsDropped) {
            this.modelSha256 = modelSha256; this.selftestArgmax = selftestArgmax; this.selftestMax = selftestMax;
            this.modelMs = modelMs; this.framesFlagged = framesFlagged; this.flagsDropped = flagsDropped;
        }
    }

    /** Field names and bounds MUST match eg_onn_heartbeat (tests/test_onn_app_static.py checks the names). */
    static JSONObject info(Context c, boolean svcEnabled, String screenState, long screenOnS, long windowS, int intervalS,
                           FrameStats s, DetectorStatus d, TitleFacts t) throws Exception {
        JSONObject o = new JSONObject();
        o.put("app_version", versionName(c));
        o.put("cert_sha256", certSha256(c));
        o.put("svc_enabled", svcEnabled);
        o.put("screen_state", screenState);
        o.put("screen_on_s", (int) Math.max(0, Math.min(3600, screenOnS)));
        o.put("window_s", (int) Math.max(1, Math.min(3600, windowS)));
        o.put("interval_s", intervalS);
        o.put("attempted", s.attempted);
        o.put("succeeded", s.succeeded);
        o.put("analysed", s.analysed);
        o.put("black", s.black);
        o.put("distinct_hashes", s.distinct());
        o.put("reenabled", 0);                    // never self-re-enables (no WRITE_SECURE_SETTINGS)
        if (d != null) {                          // phase 3: the model hash must come with its self-test, or the server refuses the beat
            o.put("model_sha256", d.modelSha256);
            o.put("selftest_argmax", d.selftestArgmax);
            o.put("selftest_max", d.selftestMax);
            o.put("model_ms", (int) Math.max(1, Math.min(600000, d.modelMs)));
            o.put("frames_flagged", d.framesFlagged);
            o.put("flags_dropped", d.flagsDropped);
        }
        if (t != null) {                          // phase 5a: four counts, never text (supabase/onn_monitor_phase5a_titlefacts.sql)
            o.put("title_events", t.events);
            o.put("title_with_text", t.withText);
            o.put("title_specific", t.specific);
            o.put("title_distinct", t.distinct());
        }
        return o;
    }

    /** @return the HTTP status, or -1 when the request failed. Blocking: call from a background thread only. */
    static int send(Config cfg, JSONObject info) {
        HttpURLConnection h = null;
        try {
            JSONObject body = new JSONObject();
            body.put("p_token", cfg.token);
            body.put("p_info", info);
            h = (HttpURLConnection) new URL("https", Config.HOST, Config.PATH).openConnection();
            h.setInstanceFollowRedirects(false);
            h.setConnectTimeout(10000);
            h.setReadTimeout(10000);
            h.setRequestMethod("POST");
            h.setRequestProperty("Content-Type", "application/json");
            h.setRequestProperty("apikey", cfg.anonKey);
            h.setRequestProperty("Authorization", "Bearer " + cfg.anonKey);
            h.setDoOutput(true);
            byte[] bytes = body.toString().getBytes("UTF-8");
            try (OutputStream out = h.getOutputStream()) { out.write(bytes); }
            return h.getResponseCode();
        } catch (Exception e) {
            return -1;
        } finally {
            if (h != null) h.disconnect();
        }
    }
}
