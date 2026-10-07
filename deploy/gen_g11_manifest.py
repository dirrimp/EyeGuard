#!/usr/bin/env python3
"""Expected-state manifest for the G11's EyeGuard code, published by CI on every merge to
main (.github/workflows/publish-g11-manifest.yml, using Dad's service-role secret) into
public.g11_manifests. The G11 reports what it actually has; the SERVER compares.

  python3 deploy/gen_g11_manifest.py <git-sha>   ->  {"version": ..., "items": {...}}

Items are keyed `file:<installed name>` / `cron:poller` and valued `sha256:<hex>`. The names
and the installed paths match deploy/g11_install.sh. The cron line is hashed exactly as the
installer writes it for the default MDM_DIR (/opt/kev/mdm), from the same template file.
"""
import hashlib, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = {"eg_report.py": "g11/eg_report.py", "eg-report.sh": "g11/eg-report.sh",
         "poll.py": "g11/mdm/poll.py", "hook.py": "g11/mdm/hook.py"}
DEFAULT_MDM_DIR = "/opt/kev/mdm"


def sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def cron_line() -> str:
    t = (ROOT / "deploy" / "g11-poller.cron").read_text().replace("@MDM_DIR@", DEFAULT_MDM_DIR)
    return [l for l in t.splitlines() if l.strip()][0].strip()


def build(version: str) -> dict:
    items = {f"file:{name}": sha((ROOT / rel).read_bytes()) for name, rel in FILES.items()}
    items["cron:poller"] = sha(cron_line().encode())
    return {"version": version, "items": items}


if __name__ == "__main__":
    if len(sys.argv) != 2 or not sys.argv[1].strip():
        sys.exit("usage: gen_g11_manifest.py <git-sha>")
    print(json.dumps(build(sys.argv[1].strip()), sort_keys=True))
