#!/usr/bin/env python3
"""Decrypt a review-frame image downloaded from Storage. Run this ONLY on
your own device -- it needs the private key, which must never exist on the
monitored Mac or be committed to this repo.

Usage:
  1. Download the encrypted object from the Supabase Storage dashboard (or
     via the API with your own credentials) to a local file, e.g. frame.enc.
  2. python3 deploy/decrypt_frame.py frame.enc private_key.pem > frame.jpg
     (add a third arg for the key's passphrase if you encrypted it with one)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from eyeguard.frame_crypto import decrypt_frame  # noqa: E402


def main():
    if len(sys.argv) not in (3, 4):
        print(f"usage: {sys.argv[0]} <encrypted-file> <private-key.pem> "
              f"[key-passphrase]", file=sys.stderr)
        sys.exit(1)
    blob = Path(sys.argv[1]).read_bytes()
    key_pem = Path(sys.argv[2]).read_bytes()
    password = sys.argv[3].encode() if len(sys.argv) == 4 else None
    sys.stdout.buffer.write(decrypt_frame(blob, key_pem, password))


if __name__ == "__main__":
    main()
