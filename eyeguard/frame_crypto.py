"""Client-side encryption of review-frame images before upload.

Even with managed (not self-hosted) Supabase, this closes the remaining gap
in "what does the vendor actually see": without this, a Supabase data
breach, an overreaching staff member, or anyone who otherwise obtained the
anon key could pull every uploaded review frame straight out of Storage and
view it directly -- the images are real JPEGs sitting in a bucket. With
this enabled, what actually lands in Storage is opaque ciphertext; only
whoever holds the PRIVATE key (never present on the monitored Mac, never
committed to this repo, kept only on Dad's own separate device) can ever
turn it back into a viewable image, via deploy/decrypt_frame.py.

Hybrid envelope encryption (standard shape, not a custom scheme): a fresh
random AES-256-GCM key encrypts the actual image bytes; that one-time AES
key is itself wrapped with RSA-OAEP under the recipient's public key. Only
the public key needs to exist on the monitored Mac (safe -- it's public by
definition, same as api_key already being fine to commit) and only in
config.yaml, never as a runtime secret file.

Wire format v1 (single recipient, what every frame uploaded so far uses):
[4-byte big-endian wrapped-key length][wrapped AES key][12-byte GCM nonce]
[ciphertext (includes the 16-byte GCM tag)].

Wire format v2 (several approved recipients, e.g. Dad's offline key plus partners' browser keys):
"EGF2" | u8 n | n x [8-byte key id | u16 wrapped length | wrapped AES key] | 12-byte nonce | ciphertext+tag
  key id = first 8 bytes of SHA-256(DER SubjectPublicKeyInfo of the recipient's public key)
  AES-GCM additional data = b"EGF2|" + the stored object name, so a frame moved or renamed on the server
  fails to decrypt instead of being shown under another name.
A v1 blob starts with a big-endian length (256/384/512), never the bytes "EGF2", so readers tell them apart.
"""
from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                      algorithm=hashes.SHA256(), label=None)

MAGIC_V2 = b"EGF2"
MAX_RECIPIENTS = 8          # config limit: keeps the header small and the approval list reviewable
MIN_RSA_BITS = 2048


def encrypt_frame(plaintext: bytes, public_key_pem: str | bytes) -> bytes:
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode()
    public_key = serialization.load_pem_public_key(public_key_pem)

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    wrapped_key = public_key.encrypt(aes_key, _OAEP)

    return len(wrapped_key).to_bytes(4, "big") + wrapped_key + nonce + ciphertext


def decrypt_frame(blob: bytes, private_key_pem: bytes,
                   password: bytes | None = None) -> bytes:
    """Only ever meant to run on Dad's own separate device, using a private
    key that has never touched the monitored Mac or this repo."""
    private_key = serialization.load_pem_private_key(private_key_pem, password)
    n = int.from_bytes(blob[:4], "big")
    wrapped_key = blob[4:4 + n]
    nonce = blob[4 + n:4 + n + 12]
    ciphertext = blob[4 + n + 12:]
    aes_key = private_key.decrypt(wrapped_key, _OAEP)
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)


# ---- v2: several recipients ---------------------------------------------------------------

def key_id(public_key) -> bytes:
    """8-byte id of a public key: first 8 bytes of SHA-256 over its DER SubjectPublicKeyInfo."""
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).digest()[:8]


def load_recipient(public_key_pem: str | bytes):
    """Parse one recipient PEM; raise ValueError unless it is an RSA key of at least 2048 bits."""
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode()
    pk = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(pk, rsa.RSAPublicKey) or pk.key_size < MIN_RSA_BITS:
        raise ValueError("recipient key must be RSA >= 2048 bits")
    return pk


def encrypt_frame_v2(plaintext: bytes, public_key_pems: list, object_name: str) -> bytes:
    """Encrypt once, wrap the AES key for every recipient. `public_key_pems` must be non-empty and have
    at most MAX_RECIPIENTS distinct keys; the first one is Dad's offline key (see uploader)."""
    keys, seen = [], set()
    for pem in public_key_pems:
        pk = load_recipient(pem)
        kid = key_id(pk)
        if kid not in seen:
            seen.add(kid)
            keys.append((kid, pk))
    if not keys or len(keys) > MAX_RECIPIENTS:
        raise ValueError(f"need 1..{MAX_RECIPIENTS} distinct recipients, got {len(keys)}")
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, MAGIC_V2 + b"|" + object_name.encode())
    header = MAGIC_V2 + bytes([len(keys)])
    for kid, pk in keys:
        wrapped = pk.encrypt(aes_key, _OAEP)
        header += kid + len(wrapped).to_bytes(2, "big") + wrapped
    return header + nonce + ciphertext


def is_v2(blob: bytes) -> bool:
    return blob[:4] == MAGIC_V2


def decrypt_frame_v2(blob: bytes, private_key_pem: bytes, object_name: str,
                     password: bytes | None = None) -> bytes:
    private_key = serialization.load_pem_private_key(private_key_pem, password)
    mine = key_id(private_key.public_key())
    n, pos, wrapped = blob[4], 5, None
    for _ in range(n):
        kid, ln = blob[pos:pos + 8], int.from_bytes(blob[pos + 8:pos + 10], "big")
        if kid == mine:
            wrapped = blob[pos + 10:pos + 10 + ln]
        pos += 10 + ln
    if wrapped is None:
        raise KeyError("this key is not a recipient of this frame")
    nonce, ciphertext = blob[pos:pos + 12], blob[pos + 12:]
    aes_key = private_key.decrypt(wrapped, _OAEP)
    return AESGCM(aes_key).decrypt(nonce, ciphertext, MAGIC_V2 + b"|" + object_name.encode())


def decrypt_any(blob: bytes, private_key_pem: bytes, object_name: str,
                password: bytes | None = None) -> bytes:
    """v2 or v1, whichever the blob is. (v1 ignores object_name.)"""
    if is_v2(blob):
        return decrypt_frame_v2(blob, private_key_pem, object_name, password)
    return decrypt_frame(blob, private_key_pem, password)
