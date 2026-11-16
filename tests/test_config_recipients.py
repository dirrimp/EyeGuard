#!/usr/bin/env python3
"""Guard for config.yaml encryption.recipients (who may open review frames in the dashboard).
Adding a recipient widens who can see images, so every entry must be a well-formed, distinct, PUBLIC RSA key with a label,
and Dad's offline key must stay first. Run with the bundled python (needs cryptography, pyyaml):
  /Applications/EyeGuard.app/Contents/Resources/python/bin/python3.12 tests/test_config_recipients.py"""
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import yaml
from eyeguard import frame_crypto as fc

fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

text = (ROOT / "config.yaml").read_text()
enc = yaml.safe_load(text)["encryption"]
dad = enc["public_key_pem"]; rec = enc.get("recipients") or []
check("encryption stays enabled", enc["enabled"] is True)
check("Dad's offline key is still configured and valid", bool(fc.load_recipient(dad)))
check(f"at most {fc.MAX_RECIPIENTS - 1} extra recipients (Dad's key is the first)", len(rec) <= fc.MAX_RECIPIENTS - 1, str(len(rec)))
ids = [fc.key_id(fc.load_recipient(dad))]
for i, r in enumerate(rec, 1):
    check(f"recipient #{i} has a non-empty label and a public_key_pem", isinstance(r, dict) and str(r.get("label", "")).strip() and r.get("public_key_pem"))
    try: pk = fc.load_recipient(r["public_key_pem"]); ok = True
    except Exception as e: pk, ok = None, False
    check(f"recipient #{i} is a valid RSA public key of at least {fc.MIN_RSA_BITS} bits", ok)
    if pk: ids.append(fc.key_id(pk))
check("no recipient repeats another or Dad's key", len(ids) == len(set(ids)))
check("no private key material anywhere in config.yaml", not re.search(r"BEGIN [A-Z ]*PRIVATE KEY", text))
# what the Mac will actually do with it
import inspect
from eyeguard import menubar
src = inspect.getsource(menubar)
check("the Mac passes these recipients to the uploader", "encryption_extra_public_keys=extra" in src)
if rec:
    blob = fc.encrypt_frame_v2(b"\xff\xd8\xff synthetic", [dad] + [r["public_key_pem"] for r in rec], "x_alert_d1.jpg.enc")
    check(f"a synthetic frame is encrypted for Dad's key plus all {len(rec)} recipients", blob[4] == 1 + len(rec))

print("\nFAILED: " + ", ".join(fails) if fails else "\nALL OK")
sys.exit(1 if fails else 0)
