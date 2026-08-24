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

Wire format: [4-byte big-endian wrapped-key length][wrapped AES key][12-byte
GCM nonce][ciphertext (includes the 16-byte GCM tag)].
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                      algorithm=hashes.SHA256(), label=None)


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
