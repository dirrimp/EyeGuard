#!/usr/bin/env python3
"""Static checks for the phase 2 Onn app (android/onn-monitor). No JDK is needed. These prove the app's promises on paper:
one permission, one component, one host, no logging, heartbeat fields match the database function. They do NOT prove it
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
sql = (ROOT / "supabase/onn_monitor_phase1.sql").read_text()

print("manifest")
perms = [p.get(A + "name") for p in man.findall("uses-permission")]
check("INTERNET is the ONLY permission", perms == ["android.permission.INTERNET"], str(perms))
app = man.find("application")
comps = [c.tag for c in app if c.tag in ("service", "receiver", "provider", "activity")]
check("exactly one component, a service", comps == ["service"], str(comps))
svc = app.find("service")
check("the service requires BIND_ACCESSIBILITY_SERVICE (only the system can bind it)", svc.get(A + "permission") == "android.permission.BIND_ACCESSIBILITY_SERVICE")
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
check("no other URL or host literal in the source", not re.findall(r'"https?://', alljava) and len(re.findall(r'"[a-z0-9-]+(?:\.[a-z0-9-]+){2,}"', alljava)) == 1)
check("the connection is HTTPS to Config.HOST and never follows redirects",
      'new URL("https", Config.HOST, Config.PATH)' in java["Heartbeat.java"] and "setInstanceFollowRedirects(false)" in java["Heartbeat.java"])
check("no logging at all (the token can never reach a log)", not re.search(r"android\.util\.Log|\bLog\.[a-z]\(|System\.(out|err)|printStackTrace", alljava))
check("no files written", not re.search(r"FileOutputStream|FileWriter|openFileOutput|getSharedPreferences", alljava))
check("no reflection, shell, dynamic loading or native code", not re.search(r"Runtime\.getRuntime|ProcessBuilder|Class\.forName|DexClassLoader|System\.load", alljava))
check("the frame bitmap is recycled and the buffer closed in a finally block", "finally" in java["GuardService.java"] and "hb.close()" in java["GuardService.java"] and "recycle()" in java["GuardService.java"])
check("the image is never encoded, saved or sent (no compress/encode/JPEG)", not re.search(r"compress\(|Base64|JPEG|encodeToString|ByteArrayOutputStream.*Bitmap", alljava.replace("ByteArrayOutputStream bo", "")))
check("reenabled is always 0 in phase 2", 'put("reenabled", 0)' in java["Heartbeat.java"])
check("the token is read only from the config file, never hard-coded", not re.search(r'token\s*=\s*"[0-9a-f]{16,}"', alljava))

print("heartbeat matches the database function")
fn = sql[sql.index("create or replace function public.eg_onn_heartbeat"):sql.index("-- ---- 5. the check")]
sql_fields = set(re.findall(r"p_info->>'([a-z_0-9]+)'", fn))
java_fields = set(re.findall(r'o\.put\("([a-z_0-9]+)"', java["Heartbeat.java"]))
check("every required field the database reads is sent (model_sha256 is optional until phase 3)",
      (sql_fields - {"model_sha256"}) <= java_fields, str(sql_fields - java_fields))
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
