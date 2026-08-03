#!/usr/bin/env python3
"""EyeGuard phone connector — runs on the GL.iNet Flint 2 (OpenWRT).

The phone tunnels through WireGuard -> this router -> AdGuard Home, so AdGuard
already logs every domain the phone's browser + apps touch. This reads AdGuard's
query log and mirrors it into EyeGuard's Supabase as the SAME red / yellow /
green feed the Mac produces, so the partner sees the iPhone next to the Mac in
one dashboard. It also heartbeats a phone_status row and fires a "phone went
dark" flag when the phone stops routing through AdGuard (tunnel off / phone off).

Uses curl for HTTPS (avoids the python-ssl-on-OpenWRT headache) + python3-light
for logic. Config: /etc/eyeguard/phone.json (see phone.config.example).
"""
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

CONF_PATH = os.environ.get("EG_PHONE_CONF", "/etc/eyeguard/phone.json")
CONF = json.load(open(CONF_PATH))
SECRET = Path(CONF["secret_file"]).read_text().strip()
STATE = Path(CONF.get("state_file", "/tmp/eyeguard-phone.state.json"))

SB = CONF["supabase_url"].rstrip("/")
AG = CONF["adguard_url"].rstrip("/")
PHONE_CLIENTS = [c.lower() for c in CONF.get("phone_clients", [])]
TERMS = [t.lower() for t in CONF.get("explicit_terms", [])]
NOISE = [n.lower() for n in CONF.get("noise_domains", [])]
APP_MAP = {k.lower(): v for k, v in CONF.get("app_map", {}).items()}
POLL = int(CONF.get("poll_seconds", 15))
DARK = int(CONF.get("dark_buffer_seconds", 30))
GREEN_THROTTLE = int(CONF.get("green_repeat_seconds", 900))


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---- HTTP via curl -------------------------------------------------------

def _curl(args, timeout=15):
    try:
        return subprocess.run(["curl", "-s", "--max-time", str(timeout)] + args,
                              capture_output=True, text=True).stdout
    except Exception:
        return ""


def _sb_headers():
    return ["-H", f"apikey: {SECRET}", "-H", f"Authorization: Bearer {SECRET}",
            "-H", "Content-Type: application/json"]


def sb_post(path, row, prefer="return=minimal"):
    _curl([f"{SB}{path}"] + _sb_headers()
          + ["-H", f"Prefer: {prefer}", "-X", "POST", "-d", json.dumps(row)])


def sb_upsert_phone(row):
    sb_post("/rest/v1/phone_status", row,
            prefer="resolution=merge-duplicates,return=minimal")


def wg_rx_bytes():
    """Total received-bytes for the phone's WireGuard peer, or None if WG isn't
    being used as the liveness signal. Climbs every keepalive interval while the
    tunnel is up (even with the phone asleep) -> lets us parse out sleep the way
    the Mac parses out its own sleep. Requires Persistent Keepalive on the peer."""
    iface = CONF.get("wg_interface")
    if not iface:
        return None
    try:
        out = subprocess.run(["wg", "show", iface, "transfer"],
                             capture_output=True, text=True).stdout
    except Exception:
        return None
    peer = (CONF.get("wg_peer") or "").strip()
    total, found = 0, False
    for line in out.splitlines():
        cols = line.split("\t")
        if len(cols) >= 3:
            pk, rx = cols[0].strip(), cols[1].strip()
            if peer and pk != peer:
                continue
            try:
                total += int(rx)
                found = True
            except ValueError:
                pass
    return total if found else None


def adguard_log():
    """Recent query-log entries (newest first). Adjust for your AdGuard auth."""
    args = [f"{AG}/control/querylog?limit=200"]
    if CONF.get("adguard_user"):
        args += ["-u", f"{CONF['adguard_user']}:{CONF['adguard_pass']}"]
    try:
        return json.loads(_curl(args)).get("data", [])
    except Exception:
        return []


# ---- classification ------------------------------------------------------

def base_domain(name):
    d = (name or "").rstrip(".").lower()
    parts = d.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


def is_noise(domain):
    return any(n in domain for n in NOISE)


def app_name(domain):
    for key, app in APP_MAP.items():
        if key in domain:
            return app
    return None


def classify(entry):
    """-> (verdict, reason, label) or None to skip. verdict flagged/alert/clear."""
    domain = base_domain((entry.get("question") or {}).get("name"))
    if not domain or is_noise(domain):
        return None
    hits = [t for t in TERMS if re.search(r"\b" + re.escape(t) + r"\b", domain)]
    blocked = str(entry.get("reason", "")).lower().startswith("filtered")
    app = app_name(domain)
    label = app or domain
    if hits and blocked:
        # tried to reach an explicit domain and AdGuard blocked it -> RED
        return ("flagged", f"phone-blocked: attempted NSFW site {domain}", label)
    if hits:
        return ("alert", f"phone-signal: explicit domain {domain}", label)
    if blocked:
        return None  # ad/tracker block -> noise, skip
    return ("clear", f"phone: {label}", label)


# ---- state ---------------------------------------------------------------

def load_state():
    try:
        return json.loads(STATE.read_text())
    except Exception:
        return {"cursor": "", "green_seen": {}, "dark_alerted": False}


def save_state(s):
    try:
        STATE.write_text(json.dumps(s))
    except Exception:
        pass


# ---- main loop -----------------------------------------------------------

def cycle(state):
    entries = adguard_log()
    # phone entries only, oldest-first, newer than the cursor
    mine = [e for e in entries
            if str(e.get("client", "")).lower() in PHONE_CLIENTS
            or str(e.get("client_id", "")).lower() in PHONE_CLIENTS]
    mine = [e for e in mine if str(e.get("time", "")) > state["cursor"]]
    mine.sort(key=lambda e: str(e.get("time", "")))

    last_seen = None
    for e in mine:
        state["cursor"] = max(state["cursor"], str(e.get("time", "")))
        last_seen = str(e.get("time", ""))
        c = classify(e)
        if not c:
            continue
        verdict, reason, label = c
        if verdict == "clear":  # throttle repeated greens per domain
            now = time.time()
            if now - state["green_seen"].get(label, 0) < GREEN_THROTTLE:
                continue
            state["green_seen"][label] = now
        sb_post("/rest/v1/flags", {
            "flagged_at": now_iso(), "verdict": verdict, "reason": reason,
            "app": "iPhone", "url": None, "window_title": label,
            "grade": "Likely" if verdict == "flagged" else "Possible",
            "risk": "high" if verdict == "flagged" else "neutral",
            "no_image": True, "is_nudity": False},
            prefer="resolution=merge-duplicates,return=minimal")

    # phone liveness. Preferred signal = WireGuard rx-byte counter: it climbs on
    # every keepalive while the tunnel is up, so a SLEEPING-but-tethered phone
    # still reads alive (this is how we "parse out sleep" like the Mac does).
    # Only a tunnel that's actually down (VPN off / phone off / no signal) makes
    # it flatline. Falls back to DNS activity if wg_interface isn't configured.
    rx = wg_rx_bytes()
    if rx is not None:
        if rx > state.get("last_rx", -1):
            state["last_activity"] = time.time()
        state["last_rx"] = rx
    elif mine:  # no WG signal available -> old DNS-activity heuristic
        state["last_activity"] = time.time()
    dark_secs = time.time() - state.get("last_activity", 0)
    if dark_secs > DARK and not state.get("dark_alerted"):
        sb_post("/rest/v1/flags", {
            "flagged_at": now_iso(), "verdict": "flagged",
            "reason": f"phone-dark: tunnel silent for {int(dark_secs)}s (VPN off / phone off / no signal)",
            "app": "iPhone", "url": None, "window_title": "phone went dark",
            "grade": "Likely", "risk": "high", "no_image": True,
            "is_nudity": False},
            prefer="resolution=merge-duplicates,return=minimal")
        state["dark_alerted"] = True
    elif dark_secs <= DARK and state.get("dark_alerted"):
        state["dark_alerted"] = False  # recovered

    # heartbeat: prove the router script itself is alive (router-down alert)
    sb_upsert_phone({"id": 1, "monitor_beat": now_iso(),
                     "last_seen": now_iso() if mine else None,
                     "phone_active": not state.get("dark_alerted", False)})
    save_state(state)


def main():
    state = load_state()
    state.setdefault("last_activity", time.time())
    while True:
        try:
            cycle(state)
        except Exception as ex:
            print(f"[eyeguard-phone] {type(ex).__name__}: {ex}", flush=True)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
