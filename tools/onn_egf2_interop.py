#!/usr/bin/env python3
"""Interop vectors for the Onn's Java EGF2 encryption (android/onn-monitor/src/.../Egf2.java).
The Mac has no JDK, so the proof is a two-step exchange through a plain-JVM test (Agent IT's container):
  1. python3 tools/onn_egf2_interop.py gen DIR       makes THROWAWAY keys, a synthetic plaintext, and py.enc (Python-encrypted EGF2)
  2. (IT)  java -cp <classes> com.eyeguard.onn.Egf2Test DIR   decrypts py.enc, attacks it, and writes java.enc
  3. python3 tools/onn_egf2_interop.py verify DIR    decrypts java.enc with the real eyeguard/frame_crypto.py
`selftest` does step 1 and checks the Python side alone. Everything is synthetic: nothing here is a real key or a real frame.
Run with the app's Python (it has `cryptography`)."""
import hashlib, os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from eyeguard import frame_crypto as fc

NAME = "onn/2026-11-17T14-06-30.123456+00-00_flagged_d1.jpg.enc"
COUNT = 3

def pem(pub): return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

def gen(d: Path):
    d.mkdir(parents=True, exist_ok=True)
    keys = [rsa.generate_private_key(public_exponent=65537, key_size=3072 if i else 2048) for i in range(COUNT)]
    for i, k in enumerate(keys):
        (d / f"pub{i}.pem").write_bytes(pem(k.public_key()))
        (d / f"priv{i}.pk8").write_bytes(k.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (d / "small.pem").write_bytes(pem(rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()))
    for i in range(9):
        (d / f"extra{i}.pem").write_bytes(pem(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()))
    plain = b"\xff\xd8\xff\xe0" + os.urandom(6000)          # JPEG-looking synthetic bytes, not an image
    (d / "plain.bin").write_bytes(plain)
    (d / "name.txt").write_text(NAME)
    (d / "count.txt").write_text(str(COUNT))
    (d / "py.enc").write_bytes(fc.encrypt_frame_v2(plain, [(d / f"pub{i}.pem").read_text() for i in range(COUNT)], NAME))
    (d / "kids.txt").write_text("\n".join(fc.key_id(k.public_key()).hex() for k in keys))

def load_privs(d: Path):
    return [serialization.load_der_private_key((d / f"priv{i}.pk8").read_bytes(), None) for i in range(COUNT)]

def verify(d: Path):
    plain = (d / "plain.bin").read_bytes(); name = (d / "name.txt").read_text().strip()
    blob = (d / "java.enc").read_bytes()
    ok = True
    def check(msg, cond):
        nonlocal ok
        print(f"  [{'ok  ' if cond else 'FAIL'}] {msg}"); ok = ok and cond
    check("Java output is EGF2 with 3 recipients", fc.is_v2(blob) and blob[4] == COUNT)
    kids = (d / "kids.txt").read_text().split()
    pos, got = 5, []
    for _ in range(blob[4]):
        got.append(blob[pos:pos + 8].hex()); pos += 10 + int.from_bytes(blob[pos + 8:pos + 10], "big")
    check("the key ids Java wrote equal Python's key_id() of each recipient, in order", got == kids)
    for i, k in enumerate(load_privs(d)):
        pk = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        check(f"Python decrypts Java's frame with recipient {i}", fc.decrypt_frame_v2(blob, pk, name) == plain)
    try:
        fc.decrypt_frame_v2(blob, load_privs(d)[0].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), "x" + name)
        check("a different object name fails in Python too", False)
    except Exception:
        check("a different object name fails in Python too", True)
    print("\nALL OK" if ok else "\nFAILED"); sys.exit(0 if ok else 1)

if __name__ == "__main__":
    mode, d = sys.argv[1], Path(sys.argv[2])
    if mode == "gen": gen(d); print("vectors written to", d)
    elif mode == "verify": verify(d)
    elif mode == "selftest":
        gen(d); plain = (d / "plain.bin").read_bytes()
        for i, k in enumerate(load_privs(d)):
            pk = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            assert fc.decrypt_frame_v2((d / "py.enc").read_bytes(), pk, NAME) == plain
        print("selftest ok: Python decrypts its own vectors with all", COUNT, "keys")
    else: sys.exit(__doc__)
