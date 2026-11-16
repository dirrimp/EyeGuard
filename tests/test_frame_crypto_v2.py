#!/usr/bin/env python3
"""Offline test: multi-recipient review-frame encryption (format v2) and its uploader wiring.
Synthetic bytes and throwaway keys only: no real frame, no real key. Run with the bundled python (needs cryptography):
  /Applications/EyeGuard.app/Contents/Resources/python/bin/python3.12 tests/test_frame_crypto_v2.py"""
import subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from eyeguard import frame_crypto as fc

fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

def newkey(bits=2048):
    k = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub.decode()

dad_priv, dad_pub = newkey(2048)
jada_priv, jada_pub = newkey(3072)
pat_priv, pat_pub = newkey(2048)
out_priv, out_pub = newkey(2048)             # NOT a recipient
frame = b"\xff\xd8synthetic-frame-bytes" * 500
NAME = "2026-11-16T12-00-00.000000+00-00_alert_d1.jpg.enc"

# ---- v1 is untouched ----
v1 = fc.encrypt_frame(frame, dad_pub)
check("v1 still round-trips", fc.decrypt_frame(v1, dad_priv) == frame)
check("v1 layout unchanged (4-byte length prefix = 256 for RSA-2048)", int.from_bytes(v1[:4], "big") == 256 and not fc.is_v2(v1))
v1_3072 = fc.encrypt_frame(frame, jada_pub)
check("no v1 blob can start with the v2 magic (lengths 256/384/512 vs 'EGF2')",
      all(int.from_bytes(b[:4], "big") < 1000 for b in (v1, v1_3072)) and int.from_bytes(fc.MAGIC_V2, "big") > 10**9)
check("decrypt_any reads a v1 blob", fc.decrypt_any(v1, dad_priv, NAME) == frame)

# ---- v2 ----
blob = fc.encrypt_frame_v2(frame, [dad_pub, jada_pub, pat_pub], NAME)
check("v2 blob carries the magic and 3 recipients", fc.is_v2(blob) and blob[4] == 3)
for who, priv in (("Dad", dad_priv), ("Jada's phone (3072)", jada_priv), ("second partner device", pat_priv)):
    check(f"{who} decrypts", fc.decrypt_any(blob, priv, NAME) == frame)
try: fc.decrypt_any(blob, out_priv, NAME); r = "decrypted"
except KeyError: r = "refused"
check("a key that is not a recipient is refused", r == "refused", r)
try: fc.decrypt_any(blob, dad_priv, "other-name.jpg.enc"); r = "decrypted"
except InvalidTag: r = "refused"
check("a frame moved/renamed on the server fails to decrypt (object-name binding)", r == "refused", r)
t = bytearray(blob); t[-5] ^= 1
try: fc.decrypt_any(bytes(t), dad_priv, NAME); r = "decrypted"
except InvalidTag: r = "refused"
check("a flipped ciphertext bit fails (GCM tag)", r == "refused", r)
check("same frame twice gives different bytes (fresh AES key + nonce)", fc.encrypt_frame_v2(frame, [dad_pub], NAME) != fc.encrypt_frame_v2(frame, [dad_pub], NAME))
d = fc.encrypt_frame_v2(frame, [dad_pub, dad_pub, jada_pub, dad_pub], NAME)
check("duplicate keys collapse to one entry", d[4] == 2)
many = [newkey(2048)[1] for _ in range(fc.MAX_RECIPIENTS + 1)]
try: fc.encrypt_frame_v2(frame, many, NAME); r = "encrypted"
except ValueError: r = "refused"
check(f"more than {fc.MAX_RECIPIENTS} recipients is refused", r == "refused", r)
for label, pem in (("EC key", ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
                        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()),
                   ("RSA-1024 key", newkey(1024)[1]), ("garbage", "not a key")):
    try: fc.encrypt_frame_v2(frame, [dad_pub, pem], NAME); r = "accepted"
    except Exception: r = "refused"
    check(f"{label} is rejected as a recipient", r == "refused", r)

# ---- uploader wiring: what is actually uploaded ----
from eyeguard.uploader import SupabaseUploader
tmp = Path(tempfile.mkdtemp())
(tmp / "f.jpg").write_bytes(frame)
rec = {"saved_frame": str(tmp / "f.jpg"), "verdict": "alert", "timestamp": "2026-11-16T12:00:00+00:00", "reason": "x", "display": 1}
def run(extra):
    up = SupabaseUploader(url="https://x.invalid", api_key="k", pending_path=str(tmp / "pending.jsonl"),
                          encryption_public_key_pem=dad_pub, encryption_extra_public_keys=extra)
    got = {}
    up._put_image = lambda name, data: got.update(name=name, data=data)
    up._post_row = lambda row: got.update(row=row)
    assert up._upload(dict(rec)) is True
    return got
g = run([])
check("no extra recipients: uploaded frame is v1, byte-for-byte the old format", not fc.is_v2(g["data"]) and g["name"].endswith(".jpg.enc")
      and fc.decrypt_frame(g["data"], dad_priv) == frame)
g = run([jada_pub, pat_pub])
check("with extra recipients: v2, all three can decrypt, name matches the stored object",
      fc.is_v2(g["data"]) and all(fc.decrypt_any(g["data"], k, g["name"]) == frame for k in (dad_priv, jada_priv, pat_priv))
      and g["row"]["image_path"] == g["name"])
g = run(["garbage", newkey(1024)[1], jada_pub])
check("bad extra keys are skipped; Dad and the good partner can still decrypt",
      fc.decrypt_any(g["data"], dad_priv, g["name"]) == frame and fc.decrypt_any(g["data"], jada_priv, g["name"]) == frame
      and g["data"][4] == 2)
g = run(["garbage"])
check("only bad extra keys: falls back to plain v1 for Dad (never stops encrypting)", not fc.is_v2(g["data"]) and fc.decrypt_frame(g["data"], dad_priv) == frame)
g = run([dad_pub])
check("Dad's own key repeated as an extra is ignored (still v1)", not fc.is_v2(g["data"]))

# ---- CLI ----
(tmp / "dad.pem").write_bytes(dad_priv)
(tmp / NAME).write_bytes(blob)
r = subprocess.run([sys.executable, str(ROOT / "deploy" / "decrypt_frame.py"), str(tmp / NAME), str(tmp / "dad.pem")], capture_output=True)
check("decrypt_frame.py decrypts a v2 file named like the stored object", r.returncode == 0 and r.stdout == frame, r.stderr.decode()[-120:])
(tmp / "renamed.enc").write_bytes(blob)
r = subprocess.run([sys.executable, str(ROOT / "deploy" / "decrypt_frame.py"), str(tmp / "renamed.enc"), str(tmp / "dad.pem"), "--name", NAME], capture_output=True)
check("decrypt_frame.py --name restores a renamed download", r.returncode == 0 and r.stdout == frame, r.stderr.decode()[-120:])
(tmp / "v1.enc").write_bytes(v1)
r = subprocess.run([sys.executable, str(ROOT / "deploy" / "decrypt_frame.py"), str(tmp / "v1.enc"), str(tmp / "dad.pem")], capture_output=True)
check("decrypt_frame.py still decrypts old v1 files", r.returncode == 0 and r.stdout == frame)

# ---- config + wiring ----
import yaml
cfg = yaml.safe_load((ROOT / "config.yaml").read_text())
check("config.yaml has an encryption.recipients list (its entries are validated by tests/test_config_recipients.py)", cfg["encryption"]["enabled"] is True and isinstance(cfg["encryption"]["recipients"], list))
mb = (ROOT / "eyeguard" / "menubar.py").read_text()
check("menubar passes the recipients through", "encryption_extra_public_keys=extra" in mb)

print("\nFAILED: " + ", ".join(fails) if fails else "\nALL OK")
sys.exit(1 if fails else 0)
