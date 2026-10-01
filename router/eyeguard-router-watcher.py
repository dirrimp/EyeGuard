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

import glob
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
# Router connection log (2026-10-01). Required ONLY if the published manifest
# lists "connlog.sh" -- the requirement lives server-side (Dad's manifest), so
# it can't be switched off by editing a local config file. This watcher reads
# only file mtimes + `ps` for it, never log lines (Jada's phone traffic is in
# that file and must never be read).
CONNLOG_FILES = {"connlog.sh": "/usr/bin/connlog.sh",
                 "connlog.init": "/etc/init.d/connlog"}
# Second phone instance (2026-10-01, Jada's phone) -- see phone_instances().
JADA_CONF = "/etc/eyeguard/phone-jada.json"
JADA_INIT_NAME = "eyeguard-phone-jada.init"
JADA_INIT_PATH = "/etc/init.d/eyeguard-phone-jada"
CONNLOG_DIR = CONF.get("connlog_dir", "/tmp/connlog")
CONNLOG_STALE_SECONDS = int(CONF.get("connlog_stale_seconds", 300))
CONNLOG_CONSECUTIVE = 2          # checks in a row before alerting (~10 min)
BOOT_GRACE_SECONDS = 600
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


# Matches eyeguard-phone.py's _SB_RETRY_BACKOFF and the Mac's
# uploader._FAST_RETRY_BACKOFF -- ~32s across 4 attempts.
_SB_RETRY_BACKOFF = (3, 9, 20)
_SB_FAILING = [False]


def _curl_code(args, timeout=15):
    """Like _curl(), but also returns the HTTP status. -> (body, code|None).
    code is None if curl couldn't run, 0 if it got no response at all."""
    try:
        p = subprocess.run(["curl", "-s", "--max-time", str(timeout),
                            "-w", "\n%{http_code}"] + args,
                           capture_output=True, text=True)
    except Exception:
        return "", None
    body, _, code = p.stdout.rpartition("\n")
    code = code.strip()
    return body, (int(code) if code.isdigit() else None)


def _rpc(name: str, params: dict):
    """Report to Supabase, retrying transient failures. -> bool sent.

    Added 2026-09-14. This watcher checks in every 300s against
    eg_check_phone()'s 10-minute threshold, so it tolerates ONE missed
    check-in and alerts on the second. With no retry and no status check at
    all -- _curl()'s output was discarded -- two unlucky writes during the
    Supabase degradation of 2026-09-10..14 emailed "router integrity watcher
    stopped reporting" while this process was running normally.

    4xx is never retried: that's a permanent fault (missing RPC signature,
    bad key) that must stay visible rather than be buried under retries.
    """
    code = None
    for delay in (0,) + _SB_RETRY_BACKOFF:
        if delay:
            time.sleep(delay)
        _, code = _curl_code([f"{SB}/rest/v1/rpc/{name}"] + _sb_headers()
                             + ["-X", "POST", "-d", json.dumps(params)])
        if code is not None and 200 <= code < 300:
            if _SB_FAILING[0]:
                print("[router-watcher] supabase writes recovered", flush=True)
                _SB_FAILING[0] = False
            return True
        if code is not None and 400 <= code < 500:
            break
    if not _SB_FAILING[0]:
        print(f"[router-watcher] supabase write FAILING ({name}, last "
              f"http={code}) -- next line is on recovery", flush=True)
        _SB_FAILING[0] = True
    return False


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


def _file_hash(path: str) -> str | None:
    try:
        return "sha256:" + hashlib.sha256(open(path, "rb").read()).hexdigest()
    except OSError:
        return None


def evaluate_connlog(running, newest_age, init_enabled, uptime):
    """Pure. -> list of problem strings (empty = healthy). Inputs: running
    (bool|None), newest_age = seconds since the newest log file was written
    (None = no files), init_enabled (bool), uptime seconds (None unknown).
    None for `running` = lookup failure, never a signal. Skips entirely right
    after a (weekly) reboot while the log is still spinning up."""
    if uptime is not None and uptime < BOOT_GRACE_SECONDS:
        return []
    problems = []
    if running is False:
        problems.append("the connection logger is not running")
    if newest_age is None:
        problems.append("the connection log has no files")
    elif newest_age > CONNLOG_STALE_SECONDS:
        problems.append(f"the connection log hasn't been written for {int(newest_age)}s")
    if not init_enabled:
        problems.append("the connection logger is not enabled at boot")
    return problems


def _connlog_inputs():
    running = None
    try:
        out = subprocess.run(["ps", "w"], capture_output=True, text=True,
                             timeout=10).stdout
        running = "conntrack -E" in out and "connlog.sh" in out
    except Exception:
        pass
    mt = []
    for f in glob.glob(os.path.join(CONNLOG_DIR, "log.*")):
        try:
            mt.append(os.stat(f).st_mtime)
        except OSError:
            pass
    newest_age = (time.time() - max(mt)) if mt else None
    init_enabled = bool(glob.glob("/etc/rc.d/S*connlog"))
    try:
        uptime = float(open("/proc/uptime").read().split()[0])
    except Exception:
        uptime = None
    return running, newest_age, init_enabled, uptime


_CONNLOG_BAD = [0]
_CONNLOG_ALERTED = [False]


def _post_flag(detail: str, what: str = "router connection log",
               title: str = "Router connection log"):
    """Red tamper flag through the existing anon insert-only flags path (same
    shape as eyeguard-phone.py's _router_tamper_flag). No SQL needed."""
    from datetime import datetime, timezone
    body = {"flagged_at": datetime.now(timezone.utc).isoformat(),
            "verdict": "flagged", "reason": f"tamper: {what} -- {detail}",
            "app": "Router", "url": None, "window_title": title,
            "grade": "Likely", "risk": "high", "is_nudity": False}
    _, code = _curl_code([f"{SB}/rest/v1/flags"] + _sb_headers()
                         + ["-X", "POST", "-d", json.dumps(body)])
    return code is not None and 200 <= code < 300


def _check_connlog(manifest) -> bool:
    """-> True if a connlog file hash mismatched the manifest (reported through
    the existing script_tampered boolean). Also raises the no-SQL flag for
    not-running / stale / not-enabled, debounced and once per outage."""
    if not manifest or "connlog.sh" not in manifest:
        return False          # not (yet) required by the published manifest
    tampered = False
    problems = []
    for name, path in CONNLOG_FILES.items():
        expected = manifest.get(name)
        if expected is None:
            continue
        live = _file_hash(path)
        if live is None:
            problems.append(f"{path} is missing")
        elif live != expected:
            tampered = True
            print(f"[router-watcher] {name} hash mismatch: expected {expected}, "
                  f"got {live}", flush=True)
    problems += evaluate_connlog(*_connlog_inputs())
    if problems:
        _CONNLOG_BAD[0] += 1
        print(f"[router-watcher] connlog problems ({_CONNLOG_BAD[0]}): {problems}",
              flush=True)
        if _CONNLOG_BAD[0] >= CONNLOG_CONSECUTIVE and not _CONNLOG_ALERTED[0]:
            if _post_flag("; ".join(problems)):
                _CONNLOG_ALERTED[0] = True
    else:
        _CONNLOG_BAD[0] = 0
        _CONNLOG_ALERTED[0] = False
    return tampered


def phone_instances(ps_out: str) -> tuple[bool, bool]:
    """Pure. -> (primary_running, jada_running) from `ps w` output.

    Since 2026-10-01 eyeguard-phone.py can run twice: the primary (Jonah's
    phone, no arguments) and a secondary for Jada's phone, started with
    `--conf /etc/eyeguard/phone-jada.json`. The old check ("is the script name
    anywhere in ps") would have let a live secondary hide a dead primary, so
    the two are matched separately: primary = a line with the script and NO
    --conf; secondary = a line with the script and its own config path."""
    primary = jada = False
    for line in ps_out.splitlines():
        if "eyeguard-phone.py" not in line:
            continue
        if JADA_CONF in line:
            jada = True
        elif "--conf" not in line:
            primary = True
    return primary, jada


def _ps() -> str | None:
    try:
        return subprocess.run(["ps", "w"], capture_output=True, text=True,
                              timeout=10).stdout
    except Exception:
        return None


def _phone_process_running() -> bool | None:
    """The PRIMARY instance. None on a lookup failure (never treated as a
    signal -- a transient ps hiccup shouldn't read as the process being down)."""
    out = _ps()
    if out is None:
        return None
    return phone_instances(out)[0]


def evaluate_jada(running, init_enabled, uptime):
    """Pure. -> list of problem strings for the second instance (empty =
    healthy). running None = lookup failure, never a signal."""
    if uptime is not None and uptime < BOOT_GRACE_SECONDS:
        return []
    problems = []
    if running is False:
        problems.append("the monitor for Jada's phone is not running")
    if not init_enabled:
        problems.append("the monitor for Jada's phone is not enabled at boot")
    return problems


_JADA_BAD = [0]
_JADA_ALERTED = [False]


def _check_jada(manifest) -> bool:
    """Second instance (Jada's phone). Required ONLY if the published manifest
    lists its init script -- same server-side rule as connlog, so the
    requirement can't be dropped by editing a local file. -> True if the init
    script's hash mismatches the manifest (reported through script_tampered).
    Not-running / not-enabled raise the no-SQL tamper flag, debounced (2 checks
    in a row) and once per outage."""
    if not manifest or JADA_INIT_NAME not in manifest:
        return False
    tampered = False
    problems = []
    live = _file_hash(JADA_INIT_PATH)
    if live is None:
        problems.append(f"{JADA_INIT_PATH} is missing")
    elif live != manifest[JADA_INIT_NAME]:
        tampered = True
        print(f"[router-watcher] {JADA_INIT_NAME} hash mismatch: expected "
              f"{manifest[JADA_INIT_NAME]}, got {live}", flush=True)
    out = _ps()
    running = None if out is None else phone_instances(out)[1]
    try:
        uptime = float(open("/proc/uptime").read().split()[0])
    except Exception:
        uptime = None
    problems += evaluate_jada(running, bool(glob.glob("/etc/rc.d/S*eyeguard-phone-jada")),
                              uptime)
    if problems:
        _JADA_BAD[0] += 1
        print(f"[router-watcher] jada-phone problems ({_JADA_BAD[0]}): {problems}",
              flush=True)
        if _JADA_BAD[0] >= CONNLOG_CONSECUTIVE and not _JADA_ALERTED[0]:
            if _post_flag("; ".join(problems), what="Jada's phone monitor",
                          title="Jada's phone monitor"):
                _JADA_ALERTED[0] = True
    else:
        _JADA_BAD[0] = 0
        _JADA_ALERTED[0] = False
    return tampered


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

    if _check_connlog(manifest):
        script_tampered = True
    if _check_jada(manifest):
        script_tampered = True

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
