#!/usr/bin/env python3
"""Static checks for the Onn fit test (android/onn-fit) and its Mac reference. No JDK or device needed. They prove the throwaway app's
promises on paper (no permission, no network, an activity adb can start, pinned model, same input as the Mac reference, explicit labels match config.yaml).
They do NOT prove it compiles or runs on the box: Agent IT's container and the ADB session do that.
Run: python3 tests/test_onn_fit_static.py"""
import json, re, sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "android/onn-fit"
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + ("" if ok else f" -- {detail}"))
    if not ok: fails.append(name)

A = "{http://schemas.android.com/apk/res/android}"
man = ET.parse(APP / "AndroidManifest.xml").getroot()
app = man.find("application")
java = (APP / "src/com/eyeguard/onnfit/FitActivity.java").read_text()
build = (APP / "build-fit.sh").read_text()
ref = json.loads((APP / "reference-mac.json").read_text())
refpy = (ROOT / "tools/onn_fit_reference.py").read_text()

print("manifest")
check("no permission at all", man.findall("uses-permission") == [])
check("one activity, EXPORTED (adb's shell uid cannot start a non-exported one), no intent filter, no service/receiver/provider",
      [c.tag for c in app] == ["activity"] and app.find("activity").get(A + "exported") == "true"
      and app.find("activity").find("intent-filter") is None)
check("backups and cleartext off", app.get(A + "allowBackup") == "false" and app.get(A + "usesCleartextTraffic") == "false")

print("source promises")
check("no network, no logging, no shell, no reflection",
      not re.search(r"java\.net|HttpURLConnection|Socket|android\.util\.Log|System\.(out|err)|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Class\.forName", java))
check("the only file written is fit-result.json (next to the model)", java.count("FileOutputStream") >= 2 and '"fit-result.json"' in java)
check("the model hash pin equals the Mac model, the reference and IT's pin",
      re.search(r'MODEL_SHA256 = "([0-9a-f]{64})"', java).group(1) == ref["model_sha256"] == "c15d8273adad2d0a92f014cc69ab2d6c311a06777a55545f2c4eb46f51911f0f")
check("a model that does not match the pin aborts before it is loaded", java.index("does not match the pin") < java.index("createSession"))
check("the app never touches the screen of other apps (no accessibility, no screenshots)", "AccessibilityService" not in java and "takeScreenshot" not in java)

check("build-fit.sh refuses an app whose activity is not exported or has an intent filter",
      "exported(0x01010010)=true" in build and "intent-filter" in build)
print("same input and labels as the Mac")
lcg = lambda t: [int(v) for v in re.findall(r"\d+", t)]
check("the pseudo-random input is identical in Java and in the Mac reference",
      all(x in java for x in ("12345", "1103515245L", "0x7fffffffL", ">> 8) & 0xFFFF", "65535f"))
      and all(x in refpy for x in ("12345", "1103515245", "0x7fffffff", ">> 8) & 0xFFFF", "65535")))
nn = Path("/Applications/EyeGuard.app/Contents/Resources/python/lib/python3.12/site-packages/nudenet/nudenet.py")
cfg = (ROOT / "config.yaml").read_text()
want = set(re.findall(r"^\s+- ([A-Z_]+_EXPOSED)\s*$", cfg[cfg.index("explicit_labels:"):cfg.index("arbiter:")], re.M))
exp = [int(x) for x in re.search(r"EXPLICIT = \{([0-9, ]+)\}", java).group(1).split(",")]
check("the explicit class indices are the same in Java and the reference", list(exp) == list(re.search(r"EXPLICIT = \(([0-9, ]+)\)", refpy).group(1).replace(" ", "").split(",")) or
      [int(x) for x in re.search(r"EXPLICIT = \(([0-9, ]+)\)", refpy).group(1).split(",")] == exp)
if nn.exists():
    labels = re.findall(r'"([A-Z_]+)"', nn.read_text().split("__labels = [")[1].split("]")[0])
    check("those indices are exactly config.yaml's explicit_labels (the Mac's flag set)", {labels[i] for i in exp} == want, str(({labels[i] for i in exp}, want)))
else:
    print("  [skip] nudenet package not found: label indices not checked against it")
check("reference output has the expected shape [1,22,2100]", ref["shape"] == [1, 22, 2100] and ref["count"] == 46200)

print("build-fit.sh")
check("stops on any error and verifies the pinned inputs first", "set -eu" in build and build.index("sha256sum -c SHA256SUMS") < build.index("aapt2\" compile"))
check("fails on any permission, provider, receiver, service or telemetry in the manifest",
      '"$PERMS" = "0"' in build and "TelemetryInitializer" in build and "*provider*" in build)
check("lib/ must be exactly the two pinned libraries, byte-compared with the pins",
      "libonnxruntime.so" in build and "libonnxruntime4j_jni.so" in build and "cmp " in build and "WANT=" in build)
check("libraries are stored uncompressed and page-aligned, and the zip date is pinned",
      "--no-compress" in build and "zipalign\" -c -p 4" in build and "--date 2026-01-01T00:00:00Z" in build)
check("no network tool, keystore or signing in the script", not re.search(r"\bcurl\b|\bwget\b|keystore|apksigner|--key", build.replace("# No keystore", "").replace("No keystore", "")))
check("only the armeabi-v7a ABI is built", "arm64" not in build and "x86" not in build and "native-code: 'armeabi-v7a'" in build)
check("the ORT AAR manifest is never merged (the raw link uses only our manifest)", "--manifest \"$SRC/AndroidManifest.xml\"" in build and "AndroidManifest.xml\" \"$W" not in build)
if fails: print("\nFAILED:", *fails, sep="\n  "); sys.exit(1)
print("\nALL OK")
