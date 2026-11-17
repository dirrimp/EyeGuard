#!/usr/bin/env python3
"""Static + Python-side checks for the Onn's Java EGF2 encryption (android/onn-monitor). No JDK needed here. They prove the promises on
paper and that the Python side of the interop exchange works. The REAL proof is Egf2Test on a JVM (Agent IT's container) against vectors from
tools/onn_egf2_interop.py: see the PR. Run with the app's Python:
  /Applications/EyeGuard.app/Contents/Resources/python/bin/python3.12 tests/test_onn_egf2_static.py"""
import importlib.util, re, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eyeguard import frame_crypto as fc
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + ("" if ok else f" -- {detail}"))
    if not ok: fails.append(name)

APP = ROOT / "android/onn-monitor"
java = (APP / "src/com/eyeguard/onn/Egf2.java").read_text()
code = re.sub(r"/\*.*?\*/", "", java, flags=re.S)
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

print("Egf2.java matches eyeguard/frame_crypto.py")
check("magic EGF2, AAD prefix 'EGF2|', 12-byte nonce, 256-bit AES, 128-bit tag",
      "{'E', 'G', 'F', '2'}" in java and '"EGF2|"' in java and "new byte[12]" in java and "new byte[32]" in java and "GCMParameterSpec(128" in java)
check("RSA-OAEP with SHA-256 and MGF1-SHA-256 (not the SHA-1 default some providers use)",
      'new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256' in java and '"RSA/ECB/OAEPPadding"' in java)
check("key id = first 8 bytes of SHA-256 over the DER the PEM carries", 'copyOf(MessageDigest.getInstance("SHA-256").digest(der), 8)' in java)
check("header per recipient: 8-byte id, u16 length, wrapped key", "out.write(r.kid, 0, 8)" in java and "wrapped.length >> 8" in java and "wrapped.length & 0xff" in java)
check("limits equal the Python side (max 8 recipients, RSA >= 2048)", f"MAX_RECIPIENTS = {fc.MAX_RECIPIENTS}" in java and f"MIN_RSA_BITS = {fc.MIN_RSA_BITS}" in java)
check("a fresh random key and nonce per frame, and the key is wiped", "SecureRandom" in java and "Arrays.fill(aes" in java)
check("pure JDK: no Android classes, so a plain JVM can test it", not re.search(r"^import android\.", java, re.M))
check("no logging, files, network, reflection or printing (the plaintext and keys can never reach them)",
      not re.search(r"android\.util\.Log|System\.(out|err)|printStackTrace|FileOutputStream|java\.net|Class\.forName|Runtime", code))
check("no private-key handling at all in the app (public keys only)", not re.search(r"PrivateKey|PKCS8|DECRYPT_MODE", code))
check("the JVM test is NOT in the APK (build.sh compiles only src/)", "src" in (APP / "build.sh").read_text() and (APP / "test/com/eyeguard/onn/Egf2Test.java").exists()
      and "/test" not in (APP / "build.sh").read_text())

print("Recipients.java is exactly what config.yaml produces")
gen = load("tools/gen_onn_recipients.py", "genrec")
rec = (APP / "src/com/eyeguard/onn/Recipients.java").read_text()
check("the committed file equals the generator's output (config changed? run tools/gen_onn_recipients.py)", rec == gen.build())
ids = re.findall(r'^\s+"([0-9a-f]{16})",$', rec, re.M)
check("Dad's offline key is first, and the four approved keys are all present (ids from the dashboard enrolments)",
      len(ids) == 4 and ids[0] == "feb89164d43dcce4" and set(ids[1:]) == {"4368ae66028c0707", "2bb544e53f97ace2", "1c0f206b977392b5"}, str(ids))
check("at most 8 recipients", len(ids) <= fc.MAX_RECIPIENTS)
check("only PUBLIC keys are in the file", "PRIVATE KEY" not in rec and rec.count("BEGIN PUBLIC KEY") == len(ids))

print("interop tool: the Python side works")
with tempfile.TemporaryDirectory() as t:
    r = subprocess.run([sys.executable, str(ROOT / "tools/onn_egf2_interop.py"), "selftest", t], capture_output=True, text=True)
    check("tools/onn_egf2_interop.py selftest passes (Python encrypts v2 and decrypts it with all three throwaway keys)", r.returncode == 0, r.stdout[-300:] + r.stderr[-300:])
tool = (ROOT / "tools/onn_egf2_interop.py").read_text()
check("the interop vectors use throwaway keys generated at run time (none committed)", "generate_private_key" in tool and not list(ROOT.rglob("*.pk8")))
if fails: print("\nFAILED:", *fails, sep="\n  "); sys.exit(1)
print("\nALL OK")
