#!/usr/bin/env python3
"""Generate a release manifest for the router's file-integrity check
(router/eyeguard-router-watcher.py) -- {"version": ..., "files":
{"eyeguard-phone.py": "sha256:.."}}.

Run this on the BUILD machine (never on the router itself) right after
router/eyeguard-phone.py is finalized for a release, before it's manually
scp'd to the router (there is no auto-deploy on OpenWrt -- no git binary
exists there). Output is meant to be piped into
deploy/publish_router_manifest.sh, which is the only thing that actually
writes to the router_manifests table (using the maintainer's own
service_role key -- never present on the router, never in this script).

Only eyeguard-phone.py is covered -- the router watcher's own code isn't
self-checked, same reasoning the Mac's file-integrity watcher doesn't check
itself either: a check verifying its own integrity is a tautology once an
attacker can edit both files together anyway. What this catches is the
CHEAPER, more likely attack -- editing the monitored script alone.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <version>", file=sys.stderr)
        sys.exit(1)
    version = sys.argv[1]

    script = REPO_ROOT / "router" / "eyeguard-phone.py"
    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    files = {"eyeguard-phone.py": f"sha256:{digest}"}

    print(json.dumps({"version": version, "files": files}, indent=2))


if __name__ == "__main__":
    main()
