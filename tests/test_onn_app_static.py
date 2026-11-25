#!/usr/bin/env python3
"""Static checks for the phase 2 Onn app (android/onn-monitor). No JDK is needed. These prove the app's promises on paper:
one permission, two components (the monitor and the media listener), one host, no logging, heartbeat fields match the database function. They do NOT prove it
compiles or runs: that is done by Agent IT's build container and the real-box ADB session.
Run: python3 tests/test_onn_app_static.py"""
import re, sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "android/onn-monitor"
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + ("" if ok else f" -- {detail}"))
    if not ok: fails.append(name)

A = "{http://schemas.android.com/apk/res/android}"
man = ET.parse(APP / "AndroidManifest.xml").getroot()
java = {p.name: p.read_text() for p in (APP / "src/com/eyeguard/onn").glob("*.java")}
alljava = "\n".join(java.values())
def code(t): return re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", t, flags=re.S))   # source without comments (a comment may name what the code must not do)
sql = (ROOT / "supabase/onn_monitor_phase1.sql").read_text()
sql3 = (ROOT / "supabase/onn_monitor_phase5a_titlefacts.sql").read_text()   # the live heartbeat function since phase 5a (phase 3 body + 4 title counts)
sqlx = (ROOT / "supabase/onn_media_exempt.sql").read_text()                  # patches that heartbeat with black_exempt, titles_sent, listener_ok

print("manifest")
perms = [p.get(A + "name") for p in man.findall("uses-permission")]
check("INTERNET is the ONLY permission", perms == ["android.permission.INTERNET"], str(perms))
app = man.find("application")
comps = [c.tag for c in app if c.tag in ("service", "receiver", "provider", "activity")]
check("exactly two components, both services (the monitor and the media listener)", comps == ["service", "service"], str(comps))
svcs = {x.get(A + "name"): x for x in app.findall("service")}
check("they are .GuardService and .MediaListener", set(svcs) == {".GuardService", ".MediaListener"}, str(set(svcs)))
check("the monitor requires BIND_ACCESSIBILITY_SERVICE (only the system can bind it)", svcs[".GuardService"].get(A + "permission") == "android.permission.BIND_ACCESSIBILITY_SERVICE")
check("the media listener requires BIND_NOTIFICATION_LISTENER_SERVICE (only the system can bind it) and has no meta-data",
      svcs[".MediaListener"].get(A + "permission") == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" and svcs[".MediaListener"].find("meta-data") is None)
check("no third component, no receiver, provider or activity", not [c for c in app if c.tag in ("receiver", "provider", "activity", "activity-alias")])
check("backups off, cleartext off", app.get(A + "allowBackup") == "false" and app.get(A + "usesCleartextTraffic") == "false")
check("WRITE_SECURE_SETTINGS is not requested and no secure setting is ever written",
      "WRITE_SECURE_SETTINGS" not in (APP / "AndroidManifest.xml").read_text() and not re.search(r"Settings\.(Secure|Global|System)|putString|putInt", alljava))
cfg = ET.parse(APP / "res/xml/accessibility_service_config.xml").getroot()
check("can take screenshots but cannot read window content", cfg.get(A + "canTakeScreenshot") == "true" and cfg.get(A + "canRetrieveWindowContent") == "false")
check("manifest has no versionName/versionCode (build.sh sets them at link time)", man.get(A + "versionName") is None)

print("source promises")
check("one server host, a constant, equal to the Supabase host in config.yaml",
      re.search(r'HOST = "([a-z0-9.]+)"', java["Config.java"]).group(1) ==
      re.search(r"url: https://([a-z0-9.]+)", (ROOT / "config.yaml").read_text()).group(1))
nontitle = "\n".join(v for k, v in java.items() if k not in ("TitleFacts.java", "MediaFacts.java"))
check("no other URL or host literal in the source (the media-app allowlist in TitleFacts and YouTube TV's package in MediaFacts are package names, checked below)",
      not re.findall(r'"https?://', alljava) and len(re.findall(r'"[a-z0-9-]+(?:\.[a-z0-9-]+){2,}"', nontitle)) == 1)
check("TitleFacts: only the three media-app packages are read, nothing is logged or sent from it, and text never leaves the class",
      set(re.findall(r'"([a-z]+(?:\.[a-z]+){2,})"', java["TitleFacts.java"])) ==
      {"com.google.android.youtube.tvunplugged", "com.google.android.youtube.tv", "org.jellyfin.androidtv"}
      and not re.search(r"Log\.|System\.(out|err)|JSONObject|URL|Socket|File", java["TitleFacts.java"])
      and "TitleFacts.watched(pkg)" in java["GuardService.java"] and java["GuardService.java"].index("TitleFacts.watched(pkg)") < java["GuardService.java"].index("e.getText()"))
check("the four title counts are integers only (the heartbeat sends t.events/withText/specific/distinct(), never text)",
      sorted(re.findall(r'o\.put\("(title_[a-z_]+)", (t\.[A-Za-z]+(?:\(\))?)\)', java["Heartbeat.java"])) == sorted([("title_events", "t.events"), ("title_with_text", "t.withText"), ("title_specific", "t.specific"), ("title_distinct", "t.distinct()")]))
check("MediaFacts names exactly one package, YouTube TV; and has no Android, network or logging in it",
      re.findall(r'"([a-z]+(?:\.[a-z]+){2,})"', java["MediaFacts.java"]) == ["com.google.android.youtube.tvunplugged"]
      and not re.search(r"import android|java\.net|Log\.|System\.(out|err)|JSONObject|URL\b|File", java["MediaFacts.java"]))
check("MediaListener is an empty shell: it overrides no callback and never touches a notification",
      not re.search(r"onNotification|getActiveNotifications|getCurrentRanking|StatusBarNotification|cancelNotification|snooze|\bonListener|@Override", code(java["MediaListener.java"]))
      and "isNotificationListenerAccessGranted" in java["MediaListener.java"])
check("MediaProbe skips every session that is not YouTube TV BEFORE reading anything about it",
      java["MediaProbe.java"].index("MediaFacts.YOUTUBE_TV.equals(mc.getPackageName())") < java["MediaProbe.java"].index("getPlaybackState()")
      < java["MediaProbe.java"].index("getMetadata()") and java["MediaProbe.java"].count("getMetadata()") == 1 and "continue;" in java["MediaProbe.java"])
check("the title is read only while the session is PLAYING", re.search(r"if \(playing\) \{\s*MediaMetadata md = mc\.getMetadata\(\)", java["MediaProbe.java"]) is not None)
check("the exemption is decided in one place (MediaFacts.exempt) and used only straight after a black frame",
      java["GuardService.java"].count("MediaFacts.exempt(") == 1 and "if (stats.lastBlack) noteBlack();" in java["GuardService.java"]
      and "exemptLastBlack" in java["FrameStats.java"] and "lastBlack && blackExempt < black" in java["FrameStats.java"])
check("a title is encrypted BEFORE it is queued and the plaintext is wiped; nothing but ciphertext reaches TitleUploader",
      java["GuardService.java"].index("Egf2.encrypt(plain, recipients, name)") < java["GuardService.java"].index("titleUploader.enqueue(") and "Arrays.fill(plain, (byte) 0)" in java["GuardService.java"]
      and "titleUploader.enqueue(new TitleUploader.Pending(name, enc, now))" in java["GuardService.java"])
check("TitleUploader sends only to eg_onn_title on the one host, only the package constant, the object name and base64 CIPHERTEXT",
      'PATH = "/rest/v1/rpc/eg_onn_title"' in java["TitleUploader.java"] and 'new URL("https", Config.HOST, PATH)' in java["TitleUploader.java"]
      and "encodeToString(p.enc)" in java["TitleUploader.java"] and "setInstanceFollowRedirects(false)" in java["TitleUploader.java"])
check("the three new heartbeat fields are numbers and a flag, never text",
      all(x in java["Heartbeat.java"] for x in ('o.put("black_exempt", s.blackExempt)', 'o.put("titles_sent", titlesSent)', 'o.put("listener_ok", listenerOk)')))
check("the media listener can only be switched on from outside: the app holds no way to enable it", "allow_listener" not in code(alljava) and "enabled_notification_listeners" not in code(alljava))
check("the connection is HTTPS to Config.HOST and never follows redirects",
      'new URL("https", Config.HOST, Config.PATH)' in java["Heartbeat.java"] and "setInstanceFollowRedirects(false)" in java["Heartbeat.java"])
check("no logging at all (the token can never reach a log)", not re.search(r"android\.util\.Log|\bLog\.[a-z]\(|System\.(out|err)|printStackTrace", alljava))
check("no files written", not re.search(r"FileOutputStream|FileWriter|openFileOutput|getSharedPreferences", alljava))
check("no reflection, shell, dynamic loading or native code", not re.search(r"Runtime\.getRuntime|ProcessBuilder|Class\.forName|DexClassLoader|System\.load", alljava))
check("the frame bitmap is recycled and the buffer closed in a finally block", "finally" in java["GuardService.java"] and "hb.close()" in java["GuardService.java"] and "recycle()" in java["GuardService.java"])
check("only FlagFrame encodes an image (JPEG), and it BLURS before it encodes; Egf2 may use Base64 only to read a public-key PEM",
      not re.search(r"compress\(|JPEG|encodeToString", "\n".join(re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", v, flags=re.S)) for k, v in java.items() if k not in ("FlagFrame.java", "TitleUploader.java")))
      and "Base64.getEncoder" not in java.get("Egf2.java", "")
      and java["FlagFrame.java"].index("Blur.gaussian(") < java["FlagFrame.java"].index(".compress("))
check("reenabled is always 0 in phase 2", 'put("reenabled", 0)' in java["Heartbeat.java"])
check("the token is read only from the config file, never hard-coded", not re.search(r'token\s*=\s*"[0-9a-f]{16,}"', alljava))

print("heartbeat matches the database function")
fn = sql3[sql3.index("create or replace function public.eg_onn_heartbeat"):sql3.index("revoke execute on function public.eg_onn_heartbeat")]
sql_fields = set(re.findall(r"p_info->>'([a-z_0-9]+)'", fn)) | set(re.findall(r"p_info->>''([a-z_0-9]+)''", sqlx))
java_fields = set(re.findall(r'o\.put\("([a-z_0-9]+)"', java["Heartbeat.java"]))
check("the three media fields are the ones the media-exempt SQL reads", {"black_exempt", "titles_sent", "listener_ok"} <= sql_fields)
check("every field the phase 3 heartbeat function reads is sent (the model fields are required together)",
      sql_fields <= java_fields, str(sql_fields - java_fields))
check("nothing is sent that the database does not read", java_fields <= sql_fields, str(java_fields - sql_fields))
check("the screen states the app can send are exactly the ones the database accepts",
      set(re.findall(r'return "([a-z]+)"', java["GuardService.java"])) == {"on", "off", "saver", "unknown"}
      and "('on','off','saver','unknown')" in sql)
check("interval and window bounds fit the database's limits", "Math.min(3600" in java["Heartbeat.java"] and "SHOT_MS = 15_000" in java["GuardService.java"])
check("beat period 5 min is below the server's 15 min silence limit", "BEAT_MS = 300_000" in java["GuardService.java"])
check("counts keep the server's invariants (attempted counted when a result arrives)",
      re.search(r"void failure\(\) \{ attempted\+\+; \}", java["FrameStats.java"]) and "attempted++; succeeded++;" in java["FrameStats.java"])

print("build script")
b = (APP / "build.sh").read_text()
check("build.sh stops on any error", "set -eu" in b)
check("build.sh uses no network tool and no keystore", not re.search(r"\bcurl\b|\bwget\b|keystore|apksigner|--key", b.replace("# No keystore", "").replace("No keystore", "")))
check("build.sh fails the release on an extra permission or a native library", 'PERMS" = "1"' in b and "native libraries present" in b)
check("build.sh cannot pass the native-library check silently (lists with jar, fails if listing fails) and pins the zip date",
      "jar tf" in b and "cannot list the APK" in b and "unzip" not in b.replace("unzip is not", "") and "--date 2026-01-01T00:00:00Z" in b)
check("minSdk 30 (takeScreenshot) and targetSdk 34", "--min-sdk-version 30" in b and "--target-sdk-version 34" in b)
if fails: print("\nFAILED:", *fails, sep="\n  "); sys.exit(1)
print("\nALL OK")
