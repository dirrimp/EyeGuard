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
ROUTER_CHECK_SECONDS = int(CONF.get("router_check_seconds", 300))
ROUTER_BASELINE_PATH = Path(CONF.get("router_baseline_file",
                                     "/etc/eyeguard/router_baseline.json"))

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
    if domain in ("arpa", "local", "lan"):
        return True  # bare TLD-only query (single label, e.g. raw "local.")
    if domain.endswith(".arpa") or domain.endswith(".local") or domain.endswith(".lan"):
        return True  # reverse-DNS / mDNS / DNS-SD service-discovery junk, not browsing
    if domain.endswith(".invalid"):
        return True  # iOS's own randomized captive-portal/DNS-hijack probe
                     # domains (e.g. "<random-uuid>.invalid") -- always junk,
                     # the subdomain differs per check so no fixed substring
                     # in noise_domains could ever match it.
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


# ---- DNS-over-HTTPS bypass detection ---------------------------------------
#
# DoH can't be network-blocked the clean way DoT was (port 853 is its own
# protocol; DoH deliberately reuses port 443, identical to ordinary HTTPS, so
# there's no way to separate it from regular browsing without deep packet
# inspection). Layer 1 (AdGuard: NXDOMAIN for Firefox's use-application-dns.net
# canary + known DoH provider hostnames) and Layer 2 (firewall: REJECT TCP:443
# to known DoH provider IPs, both lan and wgserver sources -- see
# router/CONFIG_BACKUP.md) close the casual/default-browser-setting gap. This
# is Layer 3: even with the firewall REJECTing the connection, the initial SYN
# packet still crosses the wire before the reject happens (tcpdump on the LAN
# side sees it regardless of what the firewall does downstream), so an
# attempt is still visible even if a firewall rule ever gets removed/missed a
# provider -- same tamper-evident philosophy as everything else here. A
# technically motivated bypass (self-hosted DoH on an unlisted IP, or
# Encrypted Client Hello hiding even the destination-IP-adjacent signal) is
# NOT caught by this -- that's an accepted residual, not a gap in this layer.

# Known public DoH provider IPs -- keep in sync with the Block-DoH-Providers
# firewall rules. Adding a provider here does NOT need a firewall change to
# take effect (this layer is independent), but for it to actually be BLOCKED
# and not just flagged, add it to the firewall rule too.
DOH_IPS = [
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "9.9.9.10",
    "149.112.112.112", "149.112.112.10", "208.67.222.222", "208.67.220.220",
    "208.67.222.123", "208.67.220.123", "94.140.14.14", "94.140.15.15",
    "185.228.168.9", "185.228.169.9",
]

SYN_DST_RE = re.compile(r"IP \S+ > (\d+\.\d+\.\d+\.\d+)\.\d+:")

_DOH_THROTTLE = 300  # a rejected connection retries several SYNs in a burst;
                     # collapse those into one flag per IP per window.


def _doh_filter(host_ip):
    ips = " or ".join(f"host {ip}" for ip in DOH_IPS)
    return (f"tcp and src host {host_ip} and dst port 443 and "
            f"tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and ({ips})")


def _handle_doh_attempt(ip):
    now = time.time()
    with _LOCK:
        seen = _STATE.setdefault("doh_seen", {})
        last = seen.get(ip, 0)
        if now - last < _DOH_THROTTLE:
            return
        seen[ip] = now
    sb_post("/rest/v1/flags", {
        "flagged_at": now_iso(), "verdict": "flagged",
        "reason": f"phone-signal: DNS-over-HTTPS bypass attempt to {ip}",
        "app": "iPhone", "url": None, "window_title": f"DoH attempt: {ip}",
        "grade": "Likely", "risk": "high", "is_nudity": False})


def doh_syn_loop(iface, host_ip):
    """Same respawn-forever pattern as capture_loop, watching for the initial
    SYN of a TCP:443 connection attempt to a known DoH provider IP."""
    filt = _doh_filter(host_ip)
    while True:
        try:
            proc = subprocess.Popen(
                ["tcpdump", "-i", iface, "-l", "-nn", filt],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1)
            for line in proc.stdout:
                m = SYN_DST_RE.search(line)
                if m:
                    _handle_doh_attempt(m.group(1))
            proc.wait()
        except Exception as ex:
            print(f"[eyeguard-phone] doh_syn({iface}) {type(ex).__name__}: {ex}",
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


# ---- router config tamper-evidence -----------------------------------------
#
# Giving Jonah his own router GUI login (requested 2026-08-05) is genuinely
# useful for day-to-day network management, but GL.iNet's admin account is
# all-or-nothing -- there's no "network management only" role. The same login
# that lets you check which devices are online also lets you disable AdGuard,
# delete a WireGuard peer, remove the Block-DoT firewall rule, or re-enable
# the GoodCloud remote-management channel that was disabled during hardening.
# None of those are PREVENTABLE from inside the router (that's the same
# "can't stop a local admin" limit as everywhere else in this project) -- but
# they can be made VISIBLE, the same tamper-evident philosophy as the Mac's
# browser-extension and VM-software monitors. This snapshots the handful of
# security-relevant settings established during the 2026-08-04 hardening
# pass and flags ANY drift from the expected/hardened value as a tamper
# event, routed through the same eg_on_red "tampering detected" email as
# every other tamper signal in this project.
#
# Deliberately does NOT try to catch every possible router change (that would
# be noisy and fragile) -- only the specific things actually established as
# "this must stay this way" during hardening: AdGuard protection, the
# Block-DoT rule, WAN-facing default-deny, SSH password-auth staying off,
# GoodCloud staying disabled, the admin GUI staying HTTPS-only, and the set
# of WireGuard peers (an added OR removed peer is worth knowing about either
# way -- a removal breaks monitoring, an addition is an unknown device on
# the tunnel).

def _uci_show(pkg):
    try:
        return subprocess.run(["uci", "show", pkg],
                              capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return ""


def _parse_uci_show(text):
    """{'<pkg>.<section>': {option: value}} from `uci show <pkg>` text --
    handles both named (dropbear.main) and anonymous (firewall.@rule[21])
    sections. Values are read fresh each check, so an admin renaming/
    reordering anonymous sections doesn't matter -- sections are matched by
    their own 'name' field below, never by index."""
    sections = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, val = line.split("=", 1)
        val = val.strip().strip("'")
        parts = key.split(".")
        if len(parts) >= 3:
            sect = ".".join(parts[:2])
            opt = ".".join(parts[2:])
            sections.setdefault(sect, {})[opt] = val
        elif len(parts) == 2:
            sections.setdefault(key, {})["_type"] = val
    return sections


def _find_by_name(sections, name):
    for opts in sections.values():
        if opts.get("name") == name:
            return opts
    return {}


def _find_by_opt(sections, key, val):
    for opts in sections.values():
        if opts.get(key) == val:
            return opts
    return {}


def _adguard_protection_enabled():
    try:
        text = Path("/etc/AdGuardHome/config.yaml").read_text()
    except Exception:
        return None
    m = re.search(r"^\s*protection_enabled:\s*(true|false)", text, re.MULTILINE)
    return m.group(1) if m else None


def _wg_peer_pubkeys():
    try:
        out = subprocess.run(["wg", "show", "wgserver", "dump"],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return None
    lines = out.splitlines()
    if not lines:
        return None
    # First line is the interface's own privkey/pubkey/port/fwmark, not a
    # peer -- every subsequent line is one peer, first column = its pubkey.
    return sorted(l.split("\t")[0] for l in lines[1:] if l.strip())


def router_snapshot():
    fw = _parse_uci_show(_uci_show("firewall"))
    db = _parse_uci_show(_uci_show("dropbear"))
    cloud = _parse_uci_show(_uci_show("gl-cloud"))
    uh = _parse_uci_show(_uci_show("uhttpd"))

    block_dot = _find_by_name(fw, "Block-DoT")
    wan_zone = _find_by_opt(fw, "name", "wan")
    dropbear_main = db.get("dropbear.main", {})
    cloud_section = next(iter(cloud.values()), {})
    uh_main = uh.get("uhttpd.main", {})
    wg_peers = _wg_peer_pubkeys()

    return {
        "adguard_protection_enabled": _adguard_protection_enabled(),
        "block_dot_ok": block_dot.get("target") == "REJECT",
        "wan_input_policy": wan_zone.get("input"),
        "dropbear_password_auth": dropbear_main.get("PasswordAuth"),
        "dropbear_root_password_auth": dropbear_main.get("RootPasswordAuth"),
        "goodcloud_enabled": cloud_section.get("enable"),
        "uhttpd_has_http_listener": "listen_http" in uh_main,
        "wg_peers": wg_peers,
    }


# (key, expected, human description) for the scalar checks. wg_peers is
# handled separately below since it's a set, not a scalar.
_ROUTER_INVARIANTS = [
    ("adguard_protection_enabled", "true", "AdGuard protection was disabled"),
    ("block_dot_ok", True, "the Block-DoT firewall rule was removed/weakened "
                            "(DNS-over-TLS can now bypass filtering)"),
    ("wan_input_policy", "DROP", "the WAN firewall default-deny policy changed"),
    ("dropbear_password_auth", "off", "SSH password authentication was "
                                       "re-enabled (was key-only)"),
    ("dropbear_root_password_auth", "off", "SSH root password authentication "
                                            "was re-enabled (was key-only)"),
    ("goodcloud_enabled", "0", "GoodCloud remote management was re-enabled"),
    ("uhttpd_has_http_listener", False, "an insecure HTTP admin listener was "
                                         "added (was HTTPS-only)"),
]


def _router_tamper_flag(detail):
    sb_post("/rest/v1/flags", {
        "flagged_at": now_iso(), "verdict": "flagged",
        "reason": f"tamper: router config changed -- {detail}",
        "app": "Router", "url": None, "window_title": "Router configuration changed",
        "grade": "Likely", "risk": "high", "is_nudity": False})


def router_check_loop():
    """Baseline on first run (no flags then -- avoids flagging the router's
    own already-hardened state as if it were a change), then flag any drift
    from either the baseline OR the known-hardened expected value, whichever
    catches it: a value can drift baseline-to-baseline (a change after the
    monitor started) or start already wrong (baseline captured a value that
    was never actually hardened, e.g. this check being added later than the
    setting) -- checking against _ROUTER_INVARIANTS' expected values as well
    as the previous snapshot covers both."""
    baseline = None
    if ROUTER_BASELINE_PATH.exists():
        try:
            baseline = json.loads(ROUTER_BASELINE_PATH.read_text())
        except Exception:
            baseline = None
    while True:
        try:
            current = router_snapshot()
            if baseline is None:
                for key, expected, detail in _ROUTER_INVARIANTS:
                    if current.get(key) != expected:
                        _router_tamper_flag(f"{detail} (found at first check)")
                baseline = current
            else:
                for key, expected, detail in _ROUTER_INVARIANTS:
                    if current.get(key) != expected and baseline.get(key) == expected:
                        _router_tamper_flag(detail)
                cur_peers = current.get("wg_peers")
                base_peers = baseline.get("wg_peers")
                if cur_peers is not None and base_peers is not None:
                    added = set(cur_peers) - set(base_peers)
                    removed = set(base_peers) - set(cur_peers)
                    for pk in added:
                        _router_tamper_flag(
                            f"a new WireGuard peer was added ({pk[:12]}...)")
                    for pk in removed:
                        _router_tamper_flag(
                            f"a WireGuard peer was removed ({pk[:12]}...)")
                baseline = current
            ROUTER_BASELINE_PATH.write_text(json.dumps(baseline))
        except Exception as ex:
            print(f"[eyeguard-phone] router_check {type(ex).__name__}: {ex}",
                  flush=True)
        time.sleep(ROUTER_CHECK_SECONDS)


def main():
    threading.Thread(target=router_check_loop, daemon=True).start()
    threads = []
    if HOME_IP:
        threads.append(threading.Thread(target=capture_loop,
                                        args=(HOME_IFACE, HOME_IP), daemon=True))
    if WG_IFACE and WG_IP:
        threads.append(threading.Thread(target=capture_loop,
                                        args=(WG_IFACE, WG_IP), daemon=True))
    if HOME_IP:
        threads.append(threading.Thread(target=doh_syn_loop,
                                        args=(HOME_IFACE, HOME_IP), daemon=True))
    if WG_IFACE and WG_IP:
        threads.append(threading.Thread(target=doh_syn_loop,
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
