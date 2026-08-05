#!/usr/bin/env python3
"""EyeGuard phone connector — runs on the GL.iNet Flint 2 (OpenWRT).

AdGuard Home's own query-log API is unusable here: GL.iNet's --glinet flag
hijacks AdGuard's auth, so no credentials (native or added) can read it, and
its on-disk query log only flushes on shutdown (unusably stale). Instead this
watches the phone's DNS traffic directly off the wire with tcpdump -- the
router's firewall already forces plaintext DNS (DoT/DoH blocked), so every
lookup crosses the LAN or the WireGuard tunnel in the clear. That also means
bypass attempts (e.g. querying 8.8.8.8 directly) are seen too, not just
whatever AdGuard chose to log.

Two capture streams run concurrently: one on the home LAN interface (the
phone's reserved IP), one on the WireGuard interface (the phone's tunnel IP),
so both "home" and "away" traffic are covered. Mirrors classified events into
EyeGuard's Supabase as the same red/yellow/green feed the Mac produces, plus a
phone_status heartbeat and a "phone went dark" flag.

Uses curl for HTTPS (avoids the python-ssl-on-OpenWRT headache) + python3-light
for logic. Config: /etc/eyeguard/phone.json (see phone.config.example).
"""
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

CONF_PATH = os.environ.get("EG_PHONE_CONF", "/etc/eyeguard/phone.json")
CONF = json.load(open(CONF_PATH))
SECRET = Path(CONF["secret_file"]).read_text().strip()

SB = CONF["supabase_url"].rstrip("/")
HOME_IP = CONF.get("home_ip", "")
HOME_IFACE = CONF.get("home_interface", "br-lan")
WG_IFACE = CONF.get("wg_interface", "")
WG_IP = CONF.get("wg_ip", "")
WG_PEER = CONF.get("wg_peer", "")
TERMS = [t.lower() for t in CONF.get("explicit_terms", [])]
NOISE = [n.lower() for n in CONF.get("noise_domains", [])]
APP_MAP = {k.lower(): v for k, v in CONF.get("app_map", {}).items()}
DARK = int(CONF.get("dark_buffer_seconds", 30))
GREEN_THROTTLE = int(CONF.get("green_repeat_seconds", 900))
HEARTBEAT_SECONDS = int(CONF.get("heartbeat_seconds", 20))

# tcpdump's default -nn text output, e.g. "...: 36802+ Type65? ocsp2.apple.com. (33)"
# -- works for any query type (A/AAAA/PTR/Type65/...) without enumerating them.
QUERY_RE = re.compile(r"\d+\+\s+\S+\?\s+(\S+)\.\s+\(\d+\)")

_LOCK = threading.Lock()
_STATE = {"last_activity": time.time(), "last_rx": -1, "dark_alerted": False,
          "green_seen": {}}


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


def home_ping_alive():
    """ARP/L2 reachability probe for the phone's home-LAN IP -- NOT ICMP.
    Confirmed empirically on this network: a locked/idle iPhone stays
    associated to the AP and answers ARP, but silently drops ICMP echo
    requests (100% ping loss) the same moment `ip neigh` shows it
    REACHABLE. So ICMP alone reads a normal idle phone as gone. Instead:
    issue a ping only to *force* a fresh ARP probe as a side effect (its own
    ICMP result is ignored), then read the kernel neighbor-cache state,
    which the kernel only (re)confirms to REACHABLE/DELAY on an actual ARP
    reply -- i.e. real L2 presence, not app-layer cooperation."""
    if not HOME_IP:
        return False
    try:
        subprocess.run(["ping", "-c", "1", "-W", "1", HOME_IP],
                       capture_output=True, text=True, timeout=3)
        out = subprocess.run(["ip", "neigh", "show", HOME_IP],
                             capture_output=True, text=True, timeout=3).stdout
        return "REACHABLE" in out or "DELAY" in out
    except Exception:
        return False


def wg_rx_bytes():
    """Total received-bytes for the phone's WireGuard peer, or None if WG isn't
    configured. Climbs every keepalive interval while the tunnel is up (even
    with the phone asleep) -> lets us parse out sleep the way the Mac parses
    out its own sleep. Requires Persistent Keepalive on the peer."""
    if not WG_IFACE:
        return None
    try:
        out = subprocess.run(["wg", "show", WG_IFACE, "transfer"],
                             capture_output=True, text=True).stdout
    except Exception:
        return None
    total, found = 0, False
    for line in out.splitlines():
        cols = line.split("\t")
        if len(cols) >= 3:
            pk, rx = cols[0].strip(), cols[1].strip()
            if WG_PEER and pk != WG_PEER:
                continue
            try:
                total += int(rx)
                found = True
            except ValueError:
                pass
    return total if found else None


# ---- classification ------------------------------------------------------

def base_domain(name):
    d = (name or "").rstrip(".").lower()
    parts = d.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


def is_noise(domain):
    if domain.endswith(".arpa") or domain.endswith(".local") or domain.endswith(".lan"):
        return True  # reverse-DNS / mDNS / DNS-SD service-discovery junk, not browsing
    return any(n in domain for n in NOISE)


def app_name(domain):
    for key, app in APP_MAP.items():
        if key in domain:
            return app
    return None


def classify(raw_name):
    """-> (verdict, reason, label) or None to skip. verdict flagged/clear.

    Unlike the old AdGuard-log version, wire capture only sees the outgoing
    query, not whether AdGuard's filter blocked it -- so an explicit-domain
    query is flagged red outright (the attempt itself is the signal that
    matters, independent of whether the network-level block held)."""
    domain = base_domain(raw_name)
    if not domain or is_noise(domain):
        return None
    hits = [t for t in TERMS if re.search(r"\b" + re.escape(t) + r"\b", domain)]
    app = app_name(domain)
    label = app or domain
    if hits:
        return ("flagged", f"phone-signal: explicit domain {domain}", label)
    return ("clear", f"phone: {label}", label)


# ---- capture ---------------------------------------------------------------

def _mark_alive():
    with _LOCK:
        _STATE["last_activity"] = time.time()


def _handle_query(raw_name):
    c = classify(raw_name)
    if not c:
        return
    verdict, reason, label = c
    if verdict == "clear":
        now = time.time()
        with _LOCK:
            last = _STATE["green_seen"].get(label, 0)
            if now - last < GREEN_THROTTLE:
                return
            _STATE["green_seen"][label] = now
    sb_post("/rest/v1/flags", {
        "flagged_at": now_iso(), "verdict": verdict, "reason": reason,
        "app": "iPhone", "url": None, "window_title": label,
        "grade": "Likely" if verdict == "flagged" else "Possible",
        "risk": "high" if verdict == "flagged" else "neutral",
        "is_nudity": False})


def capture_loop(iface, host_ip):
    """Runs forever: streams tcpdump for one interface, respawning it if it
    ever exits (interface flap, transient error)."""
    filt = f"udp dst port 53 and src host {host_ip}"
    while True:
        try:
            proc = subprocess.Popen(
                ["tcpdump", "-i", iface, "-l", "-nn", filt],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1)
            for line in proc.stdout:
                _mark_alive()  # any packet at all proves the phone/tunnel is up
                m = QUERY_RE.search(line)
                if m:
                    _handle_query(m.group(1))
            proc.wait()
        except Exception as ex:
            print(f"[eyeguard-phone] capture({iface}) {type(ex).__name__}: {ex}",
                  flush=True)
        time.sleep(5)


# ---- liveness / heartbeat ---------------------------------------------------

def heartbeat_loop():
    """phone liveness = ANY of three signals, whichever is fresher:
      (a) DNS packets seen on the home interface -> covers active browsing
          on home wifi.
      (b) home-LAN ping reachability -> covers the phone sitting IDLE on
          home wifi (locked, no DNS traffic) without false-firing dark.
      (c) WireGuard rx-byte counter -> covers the phone AWAY on the tunnel:
          with Persistent Keepalive the counter climbs every ~25s even while
          asleep, so sleep is parsed out and only a truly-down tunnel goes
          dark.
    OR-combining them means home browsing, home idle, and away-asleep-on-
    tunnel all read alive; only genuine silence on ALL THREE (phone off,
    off-network entirely, or VPN killed while away) trips phone-dark."""
    while True:
        rx = wg_rx_bytes()
        ping_ok = home_ping_alive()
        with _LOCK:
            if ping_ok:
                _STATE["last_activity"] = time.time()
            if rx is not None and rx > _STATE["last_rx"]:
                _STATE["last_activity"] = time.time()
            if rx is not None:
                _STATE["last_rx"] = rx
            dark_secs = time.time() - _STATE["last_activity"]
            was_alerted = _STATE["dark_alerted"]
            fire_dark = dark_secs > DARK and not was_alerted
            if fire_dark:
                _STATE["dark_alerted"] = True
            elif dark_secs <= DARK and was_alerted:
                _STATE["dark_alerted"] = False
            active = not _STATE["dark_alerted"]

        if fire_dark:
            sb_post("/rest/v1/flags", {
                "flagged_at": now_iso(), "verdict": "flagged",
                "reason": f"phone-dark: silent for {int(dark_secs)}s "
                          "(VPN off / phone off / no signal)",
                "app": "iPhone", "url": None, "window_title": "phone went dark",
                "grade": "Likely", "risk": "high", "is_nudity": False})

        sb_upsert_phone({"id": 1, "monitor_beat": now_iso(),
                         "last_seen": now_iso() if active else None,
                         "phone_active": active})
        time.sleep(HEARTBEAT_SECONDS)


def main():
    threads = []
    if HOME_IP:
        threads.append(threading.Thread(target=capture_loop,
                                        args=(HOME_IFACE, HOME_IP), daemon=True))
    if WG_IFACE and WG_IP:
        threads.append(threading.Thread(target=capture_loop,
                                        args=(WG_IFACE, WG_IP), daemon=True))
    if not threads:
        print("[eyeguard-phone] no home_ip or wg_interface+wg_ip configured "
              "-- nothing to capture", flush=True)
        sys.exit(1)
    for t in threads:
        t.start()
    heartbeat_loop()


if __name__ == "__main__":
    main()
