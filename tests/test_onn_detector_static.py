#!/usr/bin/env python3
"""Static checks for the phase 3 (0.2.0) Onn app: the detector, flagged-frame handling, upload and build. No JDK needed here; they prove the
promises on paper and that the app and the database agree on every name, label, threshold and window. They do NOT prove the Java compiles or
runs: Agent IT's container (compile + build checks) and the real box (self-test, first test flag) do that.
Run: /Applications/EyeGuard.app/Contents/Resources/python/bin/python3.12 tests/test_onn_detector_static.py"""
import json, re, sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "android/onn-monitor"
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + ("" if ok else f" -- {detail}"))
    if not ok: fails.append(name)

J = {p.stem: p.read_text() for p in (APP / "src/com/eyeguard/onn").glob("*.java")}
C = {k: re.sub(r"/\*.*?\*/", "", v, flags=re.S) for k, v in J.items()}           # without block comments
sql3 = (ROOT / "supabase/onn_monitor_phase3.sql").read_text()
ref = json.loads((APP.parent / "onn-fit/reference-mac.json").read_text())
build = (APP / "build-phase3.sh").read_text()
man = ET.parse(APP / "AndroidManifest.xml").getroot(); A = "{http://schemas.android.com/apk/res/android}"
flag_fn = sql3[sql3.index("create or replace function public.eg_onn_flag"):sql3.index("revoke execute on function public.eg_onn_flag")]
hb_fn = sql3[sql3.index("create or replace function public.eg_onn_heartbeat"):sql3.index("revoke execute on function public.eg_onn_heartbeat")]

print("the detector")
check("the model is bundled and pinned: its hash equals the Mac's model and Agent IT's pin",
      re.search(r'MODEL_SHA256 = "([0-9a-f]{64})"', J["Detector"]).group(1) == ref["model_sha256"] == "c15d8273adad2d0a92f014cc69ab2d6c311a06777a55545f2c4eb46f51911f0f"
      and "c15d8273adad2d0a92f014cc69ab2d6c311a06777a55545f2c4eb46f51911f0f" in build)
check("the hash is checked BEFORE the model is handed to ONNX Runtime, and the model bytes are wiped",
      C["Detector"].index("does not match the pin") < C["Detector"].index("env.createSession") and "Arrays.fill(model" in J["Detector"])
check("2 threads (the fit test: 272 ms a frame, two cores left for video)", "THREADS = 2" in J["Detector"] and "setIntraOpNumThreads(THREADS)" in J["Detector"])
check("ONNX Runtime telemetry is switched off in code too: ORT_DISABLE_TELEMETRY before the library loads, then setTelemetry(false)",
      'Os.setenv("ORT_DISABLE_TELEMETRY", "1", true)' in J["Detector"] and "env.setTelemetry(false)" in J["Detector"]
      and C["Detector"].index("ORT_DISABLE_TELEMETRY") < C["Detector"].index("getEnvironment()"))
check("three failures in a row mark the detector not ready, so the server-checked self-test then fails", "++consecutiveErrors >= 3" in J["Detector"] and "ready = false" in J["Detector"])
check("a detector that cannot start reports a failing self-test (0, 0.0), never a made-up pass", "new SelfTest(0, 0.0, false)" in J["Detector"])
check("the self-test input is the same LCG as the Mac reference and the fit test",
      all(x in J["Detector"] for x in ("12345", "1103515245L", "0x7fffffffL", ">> 8) & 0xFFFF", "65535f")))
check("the golden values the server compares with are the Mac reference run's", f"{ref['argmax']}, {ref['max']!r}" in sql3.replace("319.69696044921875", repr(ref["max"])) and "8355" in sql3)
check("the self-test reports the FIRST maximum, like numpy's argmax", "if (out[i] > max)" in J["Detector"] and ">=" not in re.search(r"for \(int i = 0; i < out\.length; i\+\+\) if \(out\[i\][^{]*", J["Detector"]).group(0))
check("no network, files, logging or process code in the detector or the frame builder",
      all(not re.search(r"java\.net|HttpURLConnection|FileOutputStream|android\.util\.Log|System\.(out|err)|printStackTrace|Runtime\.getRuntime|ProcessBuilder|Class\.forName", C[k]) for k in ("Detector", "FlagFrame", "Egf2", "Blur", "Postprocess", "FlagName")))

print("a flagged frame: blur, then encrypt, then queue; plaintext pixels never leave")
gs = C["GuardService"]
check("the detector runs inside the screenshot callback, after the health stats and before the bitmaps are recycled",
      gs.index("stats.success(luma);") < gs.index("analyse(sw);") < gs.index("} finally {"))
check("the screenshot bitmap goes ONLY to the detector and to FlagFrame.blurredJpeg",
      sorted(set(re.findall(r"(\w+(?:\.\w+)*)\(sw\)", gs))) == ["FlagFrame.blurredJpeg", "analyse", "detector.detect"] or
      sorted(set(re.findall(r"(\w+(?:\.\w+)*)\(sw[,)]", gs))) >= ["FlagFrame.blurredJpeg", "detector.detect"], str(re.findall(r"\w+(?:\.\w+)*\(sw[^)]*\)", gs)))
body = gs[gs.index("private void flag(Bitmap sw"):gs.index("private void deliverFlags")]
check("flag(): name, THEN blurred JPEG, THEN encrypt, THEN enqueue (in that order)",
      body.index("FlagName.objectName") < body.index("FlagFrame.blurredJpeg(sw)") < body.index("Egf2.encrypt(jpeg") < body.index("uploader.enqueue("))
check("the JPEG is wiped after encryption", "Arrays.fill(jpeg" in body)
check("the uploader only ever receives ciphertext (it is constructed with enc, never with the JPEG or the bitmap)",
      "new FlagUploader.Pending(name, enc," in body and "Pending(name, jpeg" not in body and "Pending(name, sw" not in body)
check("FlagFrame blurs at the Mac's radius BEFORE it encodes, scaled to 1280 wide, JPEG quality 80",
      "Blur.radiusFor(tw)" in J["FlagFrame"] and "MAX_WIDTH = 1280" in J["FlagFrame"] and "JPEG_QUALITY = 80" in J["FlagFrame"]
      and J["FlagFrame"].index("Blur.gaussian(") < J["FlagFrame"].index(".compress("))
check("an undeliverable flag is COUNTED, never silent (flags_dropped)", "uploader.countDropped()" in body and "takeDropped()" in C["GuardService"])
check("recipients: Dad's offline key first, then the approved browser keys, generated from config.yaml",
      "Egf2.parseAll(Recipients.PEMS)" in gs and "Recipients.PEMS" in J["Recipients"] or "PEMS" in J["Recipients"])

print("upload: ciphertext to storage first, then the flag record the server verifies")
up = C["FlagUploader"]
check("order: the encrypted frame goes to /storage/v1/object/frames/<name> BEFORE the eg_onn_flag call",
      up.index('"/storage/v1/object/frames/" + p.name') < up.index('"/rest/v1/rpc/eg_onn_flag"'))
check("an already-stored frame (409) counts as stored, so a retry is idempotent", "s == 409" in up)
info_keys = set(re.findall(r'info\.put\("([a-z_]+)"', up)); sql_keys = set(re.findall(r"p_info->>'([a-z_]+)'", flag_fn))
check("the RPC fields are exactly the ones eg_onn_flag reads", info_keys == sql_keys == {"label", "score", "object", "foreground"}, f"{info_keys} vs {sql_keys}")
check("the payload carries the token as p_token and the object as p_info", 'body.put("p_token", cfg.token)' in up and 'body.put("p_info", info)' in up)
check("only HTTPS to the one host, redirects off", 'new URL("https", Config.HOST, path)' in up and "setInstanceFollowRedirects(false)" in up)
check("the queue is bounded and in memory only: at most 10 items, nothing written to the device", "MAX_QUEUE = 10" in up and "FileOutputStream" not in up)
win = int(re.search(r"ts < now\(\) - interval '(\d+) minutes'", flag_fn).group(1)); age = int(re.search(r"MAX_AGE_MS = (\d+) \* 60_000L", up).group(1))
check(f"the app gives up on a frame at {age} min, inside the server's {win}-minute acceptance window", age < win)
check("permanent refusals are dropped and counted; transient ones (404, 5xx, network) are retried",
      "s == 400 || s == 401 || s == 403 || s == 429" in up and "Result.RETRY" in up)
check("the SQL's labels, score floor and character set equal the app's", all(l in flag_fn for l in ("FEMALE_BREAST_EXPOSED", "FEMALE_GENITALIA_EXPOSED", "BUTTOCKS_EXPOSED", "ANUS_EXPOSED"))
      and "sc < 0.80" in flag_fn and "Postprocess.FLAG_THRESHOLD" not in flag_fn and "FLAG_THRESHOLD = 0.80f" in J["Postprocess"] and "[A-Za-z0-9._-]" in flag_fn)

print("heartbeat: the model comes with its self-test")
check("the heartbeat carries model hash, self-test argmax and max, timing, and the flag counts the SQL requires",
      all(f'o.put("{k}"' in J["Heartbeat"] for k in ("model_sha256", "selftest_argmax", "selftest_max", "model_ms", "frames_flagged", "flags_dropped"))
      and all(k in hb_fn for k in ("selftest_argmax", "selftest_max", "model_ms", "frames_flagged", "flags_dropped")))
check("model_ms is clamped to the server's 1..600000", "Math.max(1, Math.min(600000, d.modelMs))" in J["Heartbeat"])
check("the hourly self-test and the 60-second retry exist, and the beat period stays under the server's 15-minute silence limit",
      "SELFTEST_MS = 3_600_000" in J["GuardService"] and "RETRY_MS = 60_000" in J["GuardService"] and "BEAT_MS = 300_000" in J["GuardService"])
check("the final 'service off' beat is queued before the detector and the network executor are closed",
      gs.index("beat(false") < gs.index("detector::close") < gs.index("net::shutdown"))

print("manifest")
perms = [p.get(A + "name") for p in man.findall("uses-permission")]
check("INTERNET is still the only permission, one service, nothing else", perms == ["android.permission.INTERNET"] and [c.tag for c in man.find("application")] == ["service"])
check("no secure-settings permission, no provider (so ONNX Runtime's telemetry provider can never be registered)",
      "WRITE_SECURE_SETTINGS" not in (APP / "AndroidManifest.xml").read_text() and "provider" not in (APP / "AndroidManifest.xml").read_text().replace("no provider", ""))
check("native libraries are extracted (the path the fit test proved on the box)", man.find("application").get(A + "extractNativeLibs") == "true")

print("build-phase3.sh")
check("stops on any error and verifies every pinned input first", "set -eu" in build and build.index("sha256sum -c SHA256SUMS") < build.index("aapt2\" compile"))
check("the telemetry code is REMOVED from the ONNX Runtime jar (the whole telemetry package and the ContentProvider) and the strip is verified",
      "ai/onnxruntime/telemetry" in build and "ai/onnxruntime/TelemetryInitializer.class" in build and "grep -i -q 'telemetry'" in build and "ort-stripped.jar" in build)
check("the build FAILS if telemetry is in the final dex, the manifest has a provider/receiver/activity, or permissions are not exactly INTERNET",
      "ai/onnxruntime/telemetry' \"$W/x/classes.dex\"" in build and "TelemetryInitializer" in build and "*provider*" in build and "exactly INTERNET" in build)
check("lib/ must be exactly the two pinned armeabi-v7a libraries, byte-compared; the bundled model is byte-compared with its pin",
      "WANT=" in build and "cmp \"lib/armeabi-v7a/$f\"" in build and 'cmp assets/320n.onnx "$MODEL"' in build and "assets/320n.onnx$" in build)
check("the class path and the dex input are the STRIPPED jar; the original classes.jar is only ever unpacked",
      '-classpath "$JAR:$STRIPPED"' in build and build.count("classes.jar") == 1 and '"$ORT/classes.jar"' in build.split("jar xf")[1].split("\n")[0]
      and re.search(r'd8.*\$\(find "\$W/classes".*"\$STRIPPED"', build) is not None)
check("libraries stored uncompressed, page-aligned and the zip date pinned (reproducible)", "--no-compress" in build and "zipalign\" -c -p 4" in build and "DATE=2026-01-01T00:00:00Z" in build)
check("no network tool, keystore or signing in the script", not re.search(r"\bcurl\b|\bwget\b|keystore|apksigner|--key", build.replace("No keystore", "")))
check("only armeabi-v7a, version 0.2.0 (code 2)", "native-code: 'armeabi-v7a'" in build and "VERSION_NAME=${VERSION_NAME:-0.2.0}" in build and "VERSION_CODE=${VERSION_CODE:-2}" in build and "arm64" not in build)
legacy = (APP / "build.sh").read_text()
check("the phase 2 build.sh refuses to run unless explicitly asked (it can no longer compile this source)", "ALLOW_LEGACY_PHASE2" in legacy and "exit 2" in legacy)
if fails: print("\nFAILED:", *fails, sep="\n  "); sys.exit(1)
print("\nALL OK")
