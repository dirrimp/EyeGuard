#!/usr/bin/env python3
"""Decrypt a review-frame image downloaded from Storage. Run this ONLY on
your own device -- it needs the private key, which must never exist on the
monitored Mac or be committed to this repo.

Usage:
  1. Download the encrypted object from the Supabase Storage dashboard (or
     via the API with your own credentials) to a local file, e.g. frame.enc.
  2. python3 deploy/decrypt_frame.py frame.enc private_key.pem > frame.jpg
     (add a third arg for the key's passphrase if you encrypted it with one)
  Frames with several recipients (format v2, "EGF2") are bound to their object name in Storage. If you
  renamed the downloaded file, pass the original name:  --name <object name>.jpg.enc
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from eyeguard.frame_crypto import decrypt_any  # noqa: E402


def main():
    args = sys.argv[1:]
    name = None
    if "--name" in args:
        i = args.index("--name")
        name = args[i + 1] if i + 1 < len(args) else None
        args = args[:i] + args[i + 2:]
    if len(args) not in (2, 3) or (name is None and "--name" in sys.argv):
        print(f"usage: {sys.argv[0]} <encrypted-file> <private-key.pem> "
              f"[key-passphrase] [--name <object name>]", file=sys.stderr)
        sys.exit(1)
    blob = Path(args[0]).read_bytes()
    key_pem = Path(args[1]).read_bytes()
    password = args[2].encode() if len(args) == 3 else None
    sys.stdout.buffer.write(decrypt_any(blob, key_pem, name or Path(args[0]).name, password))


if __name__ == "__main__":
    main()
