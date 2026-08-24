#!/usr/bin/env python3
"""Generate a release manifest for the file-integrity check
(eyeguard/integrity.py) -- {"version": ..., "files": {rel_path: "sha256:.."}}.

Run this on the BUILD machine (never on a monitored Mac) right after
building a release, before deploy_bundle.sh/update.sh ships it. Output is
meant to be piped into deploy/publish_manifest.sh, which is the only thing
that actually writes to the release_manifests table (using the
maintainer's own service_role key -- never present on a monitored Mac,
never in this script).

Paths are recorded relative to the deployed CODE tree
("/Library/Application Support/EyeGuard"), matching exactly what
IntegrityWatcher's base_dir already is (see eyeguard/menubar.py's
_build_uploader wiring) -- NOT the .app bundle root. The embedded Python
interpreter binary is deliberately NOT included here: its integrity is
already covered separately, at load time, by deploy/harden_codesign.sh's
codesign verification, and it lives outside this tree entirely (under
EyeGuard.app/Contents/Resources/python/), so a path relative to CODE could
never resolve to it -- including it here would misreport it as missing on
every single check, a guaranteed false positive rather than a real one.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _covered_files() -> list[str]:
    """Relative paths (from REPO_ROOT / the deployed CODE tree) to hash."""
    rel_paths = [f"eyeguard/{p.name}" for p in sorted((REPO_ROOT / "eyeguard").glob("*.py"))]
    rel_paths.append("run_agent.py")
    return rel_paths


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <version>", file=sys.stderr)
        sys.exit(1)
    version = sys.argv[1]

    files = {}
    for rel_path in _covered_files():
        abs_path = REPO_ROOT / rel_path
        try:
            digest = hashlib.sha256(abs_path.read_bytes()).hexdigest()
        except OSError as e:
            print(f"warning: could not read {abs_path} ({e}) -- omitted "
                  f"from manifest", file=sys.stderr)
            continue
        files[rel_path] = f"sha256:{digest}"

    print(json.dumps({"version": version, "files": files}, indent=2))


if __name__ == "__main__":
    main()
