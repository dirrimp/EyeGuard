#!/usr/bin/env python3
"""Router integrity/liveness watcher -- a SEPARATE process from
eyeguard-phone.py, admin-trust pivot (2026-08-24).

Why this can't just be another check inside eyeguard-phone.py: a check
running INSIDE the process being checked can be disabled by the exact same
edit that disables everything else it's supposed to catch. Jonah getting
root SSH means he can edit eyeguard-phone.py directly -- comment out
_router_tamper_flag's call, or the whole check thread, and the script would
keep running, keep heartbeating, and nothing would ever know. This is the
same reasoning that made the Mac's session_watcher a separate LaunchDaemon
rather than a thread inside the main app.

Two independent checks, every `check_seconds`:
  1. Does /usr/bin/eyeguard-phone.py's on-disk hash match the published,
     known-good manifest (public.router_manifests, anon SELECT-only --
     populated only by deploy/publish_router_manifest.sh using the
     maintainer's own service_role key, from a machine that is never the
     router itself)? A mismatch means the script was edited after deploy.
  2. Is the eyeguard-phone.py PROCESS actually running right now, checked
     via `ps` -- independent of whether IT thinks it's still heartbeating.
     procd's `respawn` should keep it alive on a crash, but this catches
     the case where it's been stopped/disabled at the init-script level
     too (`/etc/init.d/eyeguard-phone stop`), which respawn doesn't cover.

Reports both via eg_router_watcher_heartbeat() (supabase/
router_admin_trust.sql), server-stamped -- no timestamp this script could
forge. Disabling THIS watcher is just as visible as disabling the phone
monitor: eg_check_phone() alerts independently on watcher_last_heartbeat
staleness.

Tamper-EVIDENT, not tamper-proof, same standing philosophy as the rest of
this project: OpenWrt has no code-signing/hardened-runtime equivalent to
what protects the Mac's own interpreter binary, so this watcher's own code
is exactly as editable as eyeguard-phone.py's was -- it just makes that
one additional edit necessary, and a compromise of BOTH scripts together
is a materially bigger, noisier action than editing one file.

Uses curl for HTTPS, same as eyeguard-phone.py and for the same reason:
this router's python3-light build has no _ssl module at all, so urllib
can't make an HTTPS request here -- confirmed live (`python3 -c 'import
ssl'` fails with ModuleNotFoundError) after an initial version of this
script tried urllib.request directly and every heartbeat failed with
"unknown url type: https".
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
import urllib.parse

CONF_PATH = os.environ.get("EG_PHONE_CONF", "/etc/eyeguard/phone.json")
CONF = json.load(open(CONF_PATH))
API_KEY = CONF["api_key"]
SB = CONF["supabase_url"].rstrip("/")

WATCHED_SCRIPT = "/usr/bin/eyeguard-phone.py"
VERSION = CONF.get("router_script_version", "unknown")
CHECK_SECONDS = int(CONF.get("router_watcher_check_seconds", 300))


def _curl(args, timeout=15):
    try:
        return subprocess.run(["curl", "-s", "--max-time", str(timeout)] + args,
                              capture_output=True, text=True).stdout
    except Exception:
        return ""


def _sb_headers():
    return ["-H", f"apikey: {API_KEY}", "-H", f"Authorization: Bearer {API_KEY}",
            "-H", "Content-Type: application/json"]


def _rpc(name: str, params: dict):
    _curl([f"{SB}/rest/v1/rpc/{name}"] + _sb_headers()
          + ["-X", "POST", "-d", json.dumps(params)])


def _fetch_manifest() -> dict | None:
    """{"eyeguard-phone.py": "sha256:..."} for VERSION, or None if the
    server has confirmed no manifest is published, or on any network
    failure. Never raises -- a network hiccup should skip this cycle, not
    be treated as tamper."""
    url = (f"{SB}/rest/v1/router_manifests"
           f"?version=eq.{urllib.parse.quote(VERSION, safe='')}"
           f"&select=manifest")
    out = _curl([url] + _sb_headers())
    try:
        rows = json.loads(out)
    except Exception:
        return None
    if not rows:
        return None
    return (rows[0].get("manifest") or {}).get("files")


def _script_hash() -> str | None:
    try:
        return "sha256:" + hashlib.sha256(
            open(WATCHED_SCRIPT, "rb").read()).hexdigest()
    except OSError:
        return None


def _phone_process_running() -> bool | None:
    """None on a lookup failure (never treated as a signal -- a transient ps
    hiccup shouldn't read as the process being down)."""
    try:
        out = subprocess.run(["ps", "w"], capture_output=True, text=True,
                             timeout=10).stdout
    except Exception:
        return None
    return "eyeguard-phone.py" in out


def _check_once() -> tuple[bool, bool]:
    """Returns (script_tampered, process_down)."""
    manifest = _fetch_manifest()
    live_hash = _script_hash()
    script_tampered = False
    if manifest is not None and live_hash is not None:
        expected = manifest.get("eyeguard-phone.py")
        if expected is not None and expected != live_hash:
            script_tampered = True
            print(f"[router-watcher] script hash mismatch: expected "
                  f"{expected}, got {live_hash}", flush=True)
    # manifest is None (unpublished/unreachable) or live_hash is None
    # (unreadable) -- neither is itself treated as tamper, matching the
    # Mac integrity.py's "unknown/unreachable is not the same as tampered"
    # reasoning, EXCEPT unlike the Mac, an unpublished version here is not
    # separately escalated -- the router's release process is manual
    # (scp), not auto-deployed, so "no manifest yet" is an expected state
    # right after a fresh install, not a signal worth a false alarm over.

    running = _phone_process_running()
    process_down = running is False
    if process_down:
        print("[router-watcher] eyeguard-phone.py is not running", flush=True)

    return script_tampered, process_down


def run():
    print(f"[router-watcher] active, checking every {CHECK_SECONDS}s "
          f"(watched script version: {VERSION})", flush=True)
    while True:
        try:
            script_tampered, process_down = _check_once()
            _rpc("eg_router_watcher_heartbeat",
                 {"p_script_tampered": script_tampered,
                  "p_process_down": process_down})
        except Exception as e:
            # A bad check must never kill this daemon -- same rule as
            # every other background watcher in this project.
            print(f"[router-watcher] check raised {e!r} -- continuing",
                  flush=True)
        time.sleep(CHECK_SECONDS)


if __name__ == "__main__":
    run()
