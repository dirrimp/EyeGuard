package com.eyeguard.onn;

import android.content.Context;
import java.io.File;
import java.io.FileInputStream;
import java.io.ByteArrayOutputStream;
import org.json.JSONObject;

/** Device credentials, read from a file pushed over ADB at install time. Never logged, never in the APK.
 *  The server host is a CONSTANT here, so a changed config file can never point the app at another host. */
final class Config {
    static final String HOST = "ucgldleacehxjjwwqomk.supabase.co";   // the one host the router allows (design condition 14)
    static final String PATH = "/rest/v1/rpc/eg_onn_heartbeat";
    static final String FILE = "onn-config.json";                    // {"token":"<64 hex>","anon_key":"<publishable key>"}

    final String token;
    final String anonKey;

    private Config(String token, String anonKey) { this.token = token; this.anonKey = anonKey; }

    /** Returns null (never throws) when the file is missing or malformed: the app then reports nothing. */
    static Config load(Context c) {
        try {
            File dir = c.getExternalFilesDir(null);
            if (dir == null) return null;
            File f = new File(dir, FILE);
            if (!f.isFile() || f.length() > 4096) return null;
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            try (FileInputStream in = new FileInputStream(f)) {
                byte[] buf = new byte[512]; int n;
                while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
            }
            JSONObject o = new JSONObject(bo.toString("UTF-8"));
            String t = o.optString("token", ""), k = o.optString("anon_key", "");
            if (t.length() < 32 || t.length() > 256 || k.length() < 20 || k.length() > 2048) return null;
            return new Config(t, k);
        } catch (Exception e) {
            return null;
        }
    }
}
