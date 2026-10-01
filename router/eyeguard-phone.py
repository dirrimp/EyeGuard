#!/usr/bin/env python3
"""EyeGuard phone connector — runs on the GL.iNet Flint 2 (OpenWRT).

AdGuard Home's own query-log API is unusable here: GL.iNet's --glinet flag
hijacks AdGuard's auth, so no credentials (native or added) can read it, and
its on-disk query log is flushed in batches (stale by minutes to tens of
minutes -- see the querylog section below). So the real-time path instead
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
# Second instance (2026-10-01, Jada's phone): `--conf <path>` on the command
# line wins over the env var. It has to be argv, not env, because BusyBox `ps`
# shows argv only -- that is how eyeguard-router-watcher.py tells the primary
# instance (no --conf) from a secondary one, so a live secondary can never
# mask a dead primary.
if "--conf" in sys.argv[1:-1]:
    CONF_PATH = sys.argv[sys.argv.index("--conf") + 1]
CONF = json.load(open(CONF_PATH))
# ---- per-device identity (all default to the original single-phone values,
# so the primary instance's rows are byte-for-byte what they were) ----------
# device_app:     the `app` column on this device's flags (dashboard label).
# reason_prefix:  prepended to this device's reasons. The server's eg_on_red()
#                 keys Jonah's phone logic on reasons STARTING with
#                 phone-dark/phone-blocked/phone-signal (Find My cross-check,
#                 phone_status id=1). A second device MUST carry a prefix so its
#                 events can never be evaluated against Jonah's phone state.
# heartbeat_rpc:  server RPC for this device's own status row.
# dark_verdict:   verdict on this device's phone-dark rows.
# secondary_instance: true = skip the ROUTER-level loops the primary already
#                 runs (router config tamper check, Tor list refresh, sleep
#                 relay), which would otherwise double-fire.
DEVICE_APP = CONF.get("device_app", "iPhone")
REASON_PREFIX = CONF.get("reason_prefix", "")
HEARTBEAT_RPC = CONF.get("heartbeat_rpc", "eg_phone_heartbeat")
DARK_VERDICT = CONF.get("dark_verdict", "flagged")
SECONDARY = bool(CONF.get("secondary_instance", False))
# Admin-trust pivot (2026-08-24): Jonah is getting SSH (root shell, not just
# the router GUI) for network administration -- the same reasoning that
# moved the Mac off a secret key applies here, since anyone with SSH could
# read secret_file directly. There is no secret client-side anymore -- only
# the public anon key, same one everything else in this project already
# uses. Every write goes through either flags' existing anon-scoped
# insert-only RLS policy (unchanged, predates this) or a SECURITY DEFINER
# RPC that stamps server-side (phone_status), never a raw table write.
API_KEY = CONF["api_key"]

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
# Network-transition grace (2026-09-28) -- see heartbeat_loop()'s own comment
# block for the full false-alarm evidence and reasoning. Extra tolerance
# granted ONLY while the most recent confirmed-alive signal was a HOME one
# (ping/DNS on HOME_IFACE) and nothing has confirmed either home or away
# since -- i.e. only during the specific transition-away-from-home window,
# never for a phone that was already away and then goes dark.
TRANSITION_GRACE = int(CONF.get("transition_grace_seconds", 40))
GREEN_THROTTLE = int(CONF.get("green_repeat_seconds", 900))
# LAN sleep-signal relay (2026-09-04) -- see sleep_relay_loop()'s own
# docstring below and eyeguard/session_watcher.py's SleepWatcher for the
# Mac side. Optional: the listener never starts if unset.
SLEEP_RELAY_TOKEN = CONF.get("sleep_relay_token", "")
SLEEP_RELAY_PORT = int(CONF.get("sleep_relay_port", 51900))
HEARTBEAT_SECONDS = int(CONF.get("heartbeat_seconds", 20))
# How often the LOCAL 20s poll above actually REPORTS to Supabase (2026-09-14).
# These were the same number until an audit found phone_status had taken
# 152,773 single-row UPDATEs -- 180/hour, the single largest source of traffic
# against the project, more than every other client combined. The 20s cadence
# is tuned for the LOCAL dark-detection math (it beats against the 25s
# WireGuard Persistent Keepalive -- see phone.config.example's _dark_buffer
# note), but the SERVER never needed that granularity: eg_check_phone() only
# ever asks "is monitor_beat older than 5 minutes". Decoupling the two keeps
# every bit of local detection fidelity while cutting reports ~3x. State
# CHANGES (alive<->dark) still report instantly, so alerting is actually more
# responsive than a fixed 20s tick, not less.
REPORT_SECONDS = int(CONF.get("report_seconds", 60))
ROUTER_CHECK_SECONDS = int(CONF.get("router_check_seconds", 300))
ROUTER_BASELINE_PATH = Path(CONF.get("router_baseline_file",
                                     "/etc/eyeguard/router_baseline.json"))
TOR_RELAY_CACHE_PATH = Path(CONF.get("tor_relay_cache_file",
                                     "/etc/eyeguard/tor_relays.json"))
TOR_REFRESH_SECONDS = int(CONF.get("tor_refresh_seconds", 21600))  # 6h
# AdGuard query-log reader + health watcher (2026-09-30) -- see the section
# above querylog_loop(). MAX_LAG is how far behind real time the on-disk log
# may legitimately run: AdGuard buffers `size_memory` entries (1000 at time
# of writing, ~40 min at this router's volume) before each flush, so the
# default is generous; tighten it together with size_memory.
QUERYLOG_PATH = Path(CONF.get("adguard_querylog_file",
                              "/etc/AdGuardHome/data/querylog.json"))
QUERYLOG_MAX_LAG = int(CONF.get("querylog_max_lag_seconds", 14400))
QUERYLOG_CHECK_SECONDS = int(CONF.get("querylog_check_seconds", 120))
QUERYLOG_MISSING_THRESHOLD = int(CONF.get("querylog_missing_threshold", 5))
# The "wire saw it, log didn't" check can only be trusted after it has been
# watched on the live router; until then it logs but doesn't email.
QUERYLOG_MISSING_ALERTS = bool(CONF.get("querylog_missing_alerts", False))
# Router connection-log watcher (2026-10-01) -- see the connlog section. LOG-ONLY:
# nothing in it posts a flag. Off unless connlog_devices is set; devices are an
# explicit ALLOWLIST ({"phone": [ips], ...}) and connlog_excluded_ips (default:
# Jada's phone peer) can never be added to it, whatever the config says.
CONNLOG_DIR = Path(CONF.get("connlog_dir", "/tmp/connlog"))
CONNLOG_EXCLUDED_IPS = set(CONF.get("connlog_excluded_ips", ["10.1.0.5"]))
CONNLOG_WINDOW = int(CONF.get("connlog_answer_window_seconds", 21600))
CONNLOG_SETTLE = int(CONF.get("connlog_settle_seconds", 300))
CONNLOG_REPORT_SECONDS = int(CONF.get("connlog_report_seconds", 3600))
CONNLOG_STATS_PATH = Path(CONF.get("connlog_stats_file", "/tmp/connlog-stats.json"))

# tcpdump's default -nn text output, e.g. "...: 36802+ Type65? ocsp2.apple.com. (33)"
# -- works for any query type (A/AAAA/PTR/Type65/...) without enumerating them.
QUERY_RE = re.compile(r"\d+\+\s+\S+\?\s+(\S+)\.\s+\(\d+\)")

_LOCK = threading.Lock()
_STATE = {"last_activity": time.time(), "last_rx": -1, "dark_alerted": False,
          "green_seen": {},
          # Split out of last_activity (2026-09-28) so heartbeat_loop() can
          # tell WHICH side last confirmed alive, not just when -- see its
          # own comment block. Both start equal to last_activity at boot
          # (a tie, not "home more recent"), so a fresh start/restart grants
          # no transition grace it can't actually justify yet.
          "last_home_seen": time.time(), "last_wg_seen": time.time(),
          "transition_grace_logged": False}
# Last heartbeat actually SENT to Supabase -- see REPORT_SECONDS. active=None
# forces a report on the very first loop iteration, so a fresh start (or a
# service restart) always checks in immediately rather than waiting.
_LAST_REPORT = {"active": None, "at": 0.0}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---- throttled failure logging for the liveness signals -------------------
# Both home_ping_alive() and wg_rx_bytes() used to fail with a bare
# `except Exception: return None`/`return False` -- completely silent, no
# log line at all. Confirmed live (2026-08-25) this is exactly why a real
# phone-dark false-alarm pattern (firing every time the phone sleeps, while
# away from home with the tunnel otherwise healthy) couldn't be diagnosed
# without direct SSH access to the router. If wg_interface in phone.json is
# even slightly stale post-AmneziaWG-migration (the exact class of drift PR
# #48 already found once, for the wg->awg binary rename), `awg show
# <bad-iface> transfer` fails and this signal silently stops contributing
# -- indistinguishable, from the logs, from "everything's fine and the tunnel
# is just quiet." Logged only on the failing/recovered transition, not every
# heartbeat_seconds tick, so a sustained outage doesn't spam the log.
_LIVENESS_FAIL_STATE = {"wg": None, "ping": None}


def _log_liveness_failure(signal, detail):
    with _LOCK:
        if _LIVENESS_FAIL_STATE[signal] != detail:
            print(f"[eyeguard-phone] {now_iso()} {signal} liveness signal "
                  f"FAILING: {detail}", flush=True)
            _LIVENESS_FAIL_STATE[signal] = detail


def _log_liveness_recovered(signal):
    with _LOCK:
        if _LIVENESS_FAIL_STATE[signal] is not None:
            print(f"[eyeguard-phone] {now_iso()} {signal} liveness signal "
                  f"recovered", flush=True)
            _LIVENESS_FAIL_STATE[signal] = None


# ---- HTTP via curl -------------------------------------------------------

def _curl(args, timeout=15):
    try:
        return subprocess.run(["curl", "-s", "--max-time", str(timeout)] + args,
                              capture_output=True, text=True).stdout
    except Exception:
        return ""


def _sb_headers():
    return ["-H", f"apikey: {API_KEY}", "-H", f"Authorization: Bearer {API_KEY}",
            "-H", "Content-Type: application/json"]


# Retry schedule for Supabase writes -- see _sb_write(). Matches the Mac's
# uploader._FAST_RETRY_BACKOFF exactly; ~32s across 4 attempts.
_SB_RETRY_BACKOFF = (3, 9, 20)
_SB_FAIL_STATE = {"failing": False}


def _curl_code(args, timeout=15):
    """Like _curl(), but also returns the HTTP status. -> (body, code|None).

    code is None when curl itself couldn't be run, and 0 when curl ran but
    never got a response (timeout, connection refused, DNS) -- both are
    transient as far as _sb_write() is concerned.
    """
    try:
        p = subprocess.run(["curl", "-s", "--max-time", str(timeout),
                            "-w", "\n%{http_code}"] + args,
                           capture_output=True, text=True)
    except Exception:
        return "", None
    body, _, code = p.stdout.rpartition("\n")
    code = code.strip()
    return body, (int(code) if code.isdigit() else None)


def _sb_write(args, what):
    """Perform a Supabase write, retrying transient failures. -> bool sent.

    Added 2026-09-14, the router half of the same fix applied to the Mac's
    uploader.py and session_watcher.py. Two problems here, not one:

    1. NO RETRY. A single failed write was simply lost. During the Supabase
       platform degradation of 2026-09-10..14 ("Partially Degraded Service";
       incident "Unresponsive Projects") that was enough to blow past
       eg_check_phone()'s thresholds and email "router watcher offline" while
       this router was up and reporting normally the whole time.
    2. NO ERROR VISIBILITY AT ALL. The old sb_post/sb_rpc called _curl() and
       discarded its output, so a write failing got NOTHING -- no retry, no
       return value, no log line. The router could not distinguish "reported"
       from "silently dropped on the floor," which is why the phone-side
       outages in this project have always been so much harder to diagnose
       than the Mac's.

    That second point matters beyond heartbeats: sb_post() to /rest/v1/flags
    is how a RED phone signal reaches the server. A dropped flag insert was a
    MISSED ALERT that left no trace anywhere. Those are now retried and, if
    they still fail, logged.

    4xx is not retried -- that's a permanent schema/permission fault (a 404
    RPC signature, a 401 key) that retries would only hide, same rule as the
    Mac clients use.
    """
    # Hard wall-clock bound. heartbeat_loop() runs the LOCAL alive/dark
    # detection in the same thread that calls this, so an unbounded retry
    # sequence (4 attempts x a 15s curl timeout, plus 32s of backoff) could
    # freeze local detection for ~90s -- trading the reporting problem for a
    # detection one. Give up cleanly at 45s and let the next
    # HEARTBEAT_SECONDS tick try again.
    deadline = time.time() + 45
    code = None
    for delay in (0,) + _SB_RETRY_BACKOFF:
        if delay:
            if time.time() + delay >= deadline:
                break
            time.sleep(delay)
        remaining = deadline - time.time()
        if remaining <= 1:
            break
        _, code = _curl_code(args, timeout=min(15, int(remaining)))
        if code is not None and 200 <= code < 300:
            with _LOCK:
                if _SB_FAIL_STATE["failing"]:
                    print(f"[eyeguard-phone] {now_iso()} supabase writes "
                          f"recovered", flush=True)
                    _SB_FAIL_STATE["failing"] = False
            return True
        if code is not None and 400 <= code < 500:
            break  # permanent -- report it immediately, don't paper over it
    # Log the TRANSITION only, not every cycle -- a long outage would
    # otherwise fill the router's small log partition.
    with _LOCK:
        if not _SB_FAIL_STATE["failing"]:
            print(f"[eyeguard-phone] {now_iso()} supabase write FAILING "
                  f"({what}, last http={code}) -- next line is on recovery",
                  flush=True)
            _SB_FAIL_STATE["failing"] = True
    return False


def sb_post(path, row, prefer="return=minimal"):
    return _sb_write([f"{SB}{path}"] + _sb_headers()
                     + ["-H", f"Prefer: {prefer}", "-X", "POST",
                        "-d", json.dumps(row)], path)


def sb_rpc(name, params):
    return _sb_write([f"{SB}/rest/v1/rpc/{name}"] + _sb_headers()
                     + ["-X", "POST", "-d", json.dumps(params)], name)


def sb_phone_heartbeat(active):
    # Replaces the old raw phone_status upsert -- eg_phone_heartbeat() stamps
    # monitor_beat/last_seen with the SERVER's clock, the same reasoning as
    # the Mac's eg_heartbeat(): no timestamp parameter exists for this
    # script to submit, so it cannot forge one even if it tried.
    return sb_rpc(HEARTBEAT_RPC, {"p_active": active})


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
        _log_liveness_recovered("ping")
        return "REACHABLE" in out or "DELAY" in out
    except Exception as ex:
        _log_liveness_failure("ping", f"{type(ex).__name__}: {ex}")
        return False


def wg_rx_bytes():
    """Total received-bytes for the phone's WireGuard peer, or None if WG isn't
    configured. Climbs every keepalive interval while the tunnel is up (even
    with the phone asleep) -> lets us parse out sleep the way the Mac parses
    out its own sleep. Requires Persistent Keepalive on the peer."""
    if not WG_IFACE:
        return None
    try:
        proc = subprocess.run(["awg", "show", WG_IFACE, "transfer"],
                              capture_output=True, text=True, timeout=5)
        if proc.returncode != 0:
            # The original code never checked this -- a bad interface name
            # (e.g. stale post-migration) or a missing/renamed binary exits
            # non-zero with stderr explaining why, but stdout alone (what
            # used to be read) can come back empty and silent either way.
            raise RuntimeError(f"awg show exited {proc.returncode}: "
                               f"{proc.stderr.strip()}")
        out = proc.stdout
    except Exception as ex:
        _log_liveness_failure("wg", f"{type(ex).__name__}: {ex}")
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
    if not found:
        # The command itself succeeded (no exception above), but no peer in
        # its output matched WG_PEER -- either the interface is up but has
        # the WRONG peer set (wg_peer stale in phone.json), or WG_IFACE
        # itself is subtly wrong (exists, but isn't actually the phone's
        # tunnel). Different failure mode from the exception above, same
        # silent-by-default problem before this logging existed.
        _log_liveness_failure(
            "wg", f"no peer matching wg_peer={WG_PEER!r} in "
            f"'awg show {WG_IFACE} transfer' output")
        return None
    _log_liveness_recovered("wg")
    return total


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

def _mark_alive(source):
    """source: 'home' or 'wg' -- which capture interface saw this packet.
    Feeds both the combined last_activity (unchanged dark-detection math)
    and the per-source timestamp heartbeat_loop()'s transition grace uses to
    tell a home-departure gap apart from a genuinely-already-away outage."""
    now = time.time()
    with _LOCK:
        _STATE["last_activity"] = now
        if source == "home":
            _STATE["last_home_seen"] = now
        elif source == "wg":
            _STATE["last_wg_seen"] = now


# (client, base_domain) -> last time the live WIRE capture saw it. The AdGuard
# log reader consults this so a query both paths see is flagged once, not twice.
_WIRE_SEEN: dict = {}
_WIRE_SEEN_TTL = 3 * 3600


def _wire_seen_record(client, raw_name, now=None):
    now = now or time.time()
    with _LOCK:
        _WIRE_SEEN[(client, base_domain(raw_name))] = now
        if len(_WIRE_SEEN) > 5000:
            for k in [k for k, t in _WIRE_SEEN.items() if now - t > _WIRE_SEEN_TTL]:
                del _WIRE_SEEN[k]


def _wire_seen_recently(client, raw_name, now=None):
    now = now or time.time()
    with _LOCK:
        t = _WIRE_SEEN.get((client, base_domain(raw_name)))
    return t is not None and now - t <= _WIRE_SEEN_TTL


def _handle_query(raw_name, suffix=""):
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
        "flagged_at": now_iso(), "verdict": verdict,
        "reason": REASON_PREFIX + reason + suffix,
        "app": DEVICE_APP, "url": None, "window_title": label,
        "grade": "Likely" if verdict == "flagged" else "Possible",
        "risk": "high" if verdict == "flagged" else "neutral",
        "is_nudity": False})


def capture_loop(iface, host_ip, source):
    """Runs forever: streams tcpdump for one interface, respawning it if it
    ever exits (interface flap, transient error). `source` ('home'/'wg')
    identifies which liveness bucket this interface's packets count toward
    -- see _mark_alive()."""
    filt = f"udp dst port 53 and src host {host_ip}"
    while True:
        try:
            proc = subprocess.Popen(
                ["tcpdump", "-i", iface, "-l", "-nn", filt],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1)
            for line in proc.stdout:
                _mark_alive(source)  # any packet at all proves the phone/tunnel is up
                m = QUERY_RE.search(line)
                if m:
                    _wire_seen_record(host_ip, m.group(1))
                    QUERYLOG_XCHECK.record_wire(time.time(), host_ip, m.group(1))
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
        "reason": REASON_PREFIX + f"phone-signal: DNS-over-HTTPS bypass attempt to {ip}",
        "app": DEVICE_APP, "url": None, "window_title": f"DoH attempt: {ip}",
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


# ---- Tor bypass detection ---------------------------------------------------
#
# DNS-based detection (classify(), above) is blind to Tor by design: Tor
# resolves the sites actually visited *inside* the encrypted circuit, so a
# Tor Browser / Onion Browser session generates no plaintext DNS query for
# whatever's actually being viewed -- there's nothing for classify() to see.
# The wire capture still sees the raw TCP connection to whatever Tor guard
# relay the phone's client picks as its first hop, though, so that's the
# signal used here: match the destination of each outbound TCP:443 SYN
# against the current set of public Guard-flagged relay IPs (Tor's own
# Onionoo directory API, https://onionoo.torproject.org) -- a client's FIRST
# hop must be Guard-flagged, so this is the precise signal, not just "any
# known Tor relay" (which would also match IPs a client never connects to
# directly, e.g. middle/exit-only relays).
#
# Guard relay churn means this can't be a static list the way DOH_IPS is (a
# handful of large public DNS providers that rarely change) -- refreshed on
# TOR_REFRESH_SECONDS, ~6000 entries currently. That's also too large for a
# tcpdump BPF filter enumerating every IP the way _doh_filter() does (16
# entries is fine, thousands isn't) -- so unlike DoH, the tcpdump filter here
# is broad (every outbound TCP:443 SYN) and the actual IP match happens in
# Python against an in-memory set (O(1), trivial even at phone-browsing SYN
# volume).
#
# Known, accepted residual (not caught by this): pluggable transports
# (obfs4, meek, snowflake) and user-configured bridges are specifically
# designed to look like ordinary HTTPS to exactly this kind of IP-list
# detection -- this catches default Tor Browser / Onion Browser usage (no
# bridge configured), which is the overwhelming common case, not a
# bridge-configured evasion attempt. Same tamper-evident philosophy as the
# DoH layer's own documented residual (self-hosted DoH / ECH) -- flagged
# honestly rather than silently claimed as complete coverage.

_TOR_LOCK = threading.Lock()
_TOR_STATE = {"ips": set()}


def _load_tor_cache():
    """Best-effort local cache so a restart isn't blind until the first live
    fetch succeeds -- especially relevant right after a router reboot, when
    outbound HTTPS to onionoo.torproject.org may not be up yet."""
    try:
        data = json.loads(TOR_RELAY_CACHE_PATH.read_text())
        return set(data.get("ips", []))
    except Exception:
        return set()


def _fetch_tor_guard_ips():
    """Current public Guard-flagged relay IPv4 addresses, or None on any
    failure (network down, malformed response, etc.) -- caller must keep the
    last-known-good set rather than wiping it out on a transient fetch miss."""
    try:
        out = _curl(["https://onionoo.torproject.org/summary"
                      "?type=relay&running=true&flag=Guard"], timeout=30)
        data = json.loads(out)
        ips = set()
        for relay in data.get("relays", []):
            for addr in relay.get("a", []):
                if addr and not addr.startswith("["):  # skip bracketed IPv6
                    ips.add(addr)
        return ips if ips else None
    except Exception as ex:
        print(f"[eyeguard-phone] tor relay fetch {type(ex).__name__}: {ex}",
              flush=True)
        return None


def tor_refresh_loop():
    with _TOR_LOCK:
        _TOR_STATE["ips"] = _load_tor_cache()
    print(f"[eyeguard-phone] tor relay cache loaded: "
          f"{len(_TOR_STATE['ips'])} IPs", flush=True)
    while True:
        fresh = _fetch_tor_guard_ips()
        if fresh:
            with _TOR_LOCK:
                _TOR_STATE["ips"] = fresh
            try:
                TOR_RELAY_CACHE_PATH.write_text(json.dumps({"ips": sorted(fresh)}))
            except Exception:
                pass
            print(f"[eyeguard-phone] tor relay list refreshed: {len(fresh)} IPs",
                  flush=True)
        # else: keep whatever's already loaded (memory or the on-disk cache
        # from a prior run) -- a failed refresh must never blank the list.
        time.sleep(TOR_REFRESH_SECONDS)


_TOR_THROTTLE = 300  # same rationale as _DOH_THROTTLE -- collapse retry bursts


def _handle_tor_attempt(ip):
    now = time.time()
    with _LOCK:
        seen = _STATE.setdefault("tor_seen", {})
        last = seen.get(ip, 0)
        if now - last < _TOR_THROTTLE:
            return
        seen[ip] = now
    sb_post("/rest/v1/flags", {
        "flagged_at": now_iso(), "verdict": "flagged",
        "reason": REASON_PREFIX + f"phone-signal: Tor connection to guard relay {ip}",
        "app": DEVICE_APP, "url": None, "window_title": f"Tor guard relay: {ip}",
        "grade": "Likely", "risk": "high", "is_nudity": False})


def _tor_syn_filter(host_ip):
    # Broad on purpose (see module comment above) -- every outbound
    # TCP:443 SYN, matched against the Tor relay set in Python, not here.
    return (f"tcp and src host {host_ip} and dst port 443 and "
            f"tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn")


def tor_syn_loop(iface, host_ip):
    """Same respawn-forever pattern as capture_loop/doh_syn_loop."""
    filt = _tor_syn_filter(host_ip)
    while True:
        try:
            proc = subprocess.Popen(
                ["tcpdump", "-i", iface, "-l", "-nn", filt],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1)
            for line in proc.stdout:
                m = SYN_DST_RE.search(line)
                if not m:
                    continue
                ip = m.group(1)
                with _TOR_LOCK:
                    is_tor = ip in _TOR_STATE["ips"]
                if is_tor:
                    _handle_tor_attempt(ip)
            proc.wait()
        except Exception as ex:
            print(f"[eyeguard-phone] tor_syn({iface}) {type(ex).__name__}: {ex}",
                  flush=True)
        time.sleep(5)


# ---- liveness / heartbeat ---------------------------------------------------

def _evaluate_liveness(state, now, ping_ok, rx, dark, grace):
    """Pure decision core of heartbeat_loop() -- mutates `state` (the
    caller's _STATE dict, already under _LOCK) and returns
    (fire_dark, dark_secs, active, log_line_or_None). No I/O, no subprocess,
    no network -- kept separate from heartbeat_loop()'s actual polling and
    reporting specifically so it's unit-testable
    (tests/test_phone_dark_transition.py) without mocking tcpdump/ping/awg.
    See heartbeat_loop()'s own docstring for the full reasoning."""
    if ping_ok:
        state["last_activity"] = now
        state["last_home_seen"] = now
    if rx is not None and rx > state["last_rx"]:
        state["last_activity"] = now
        state["last_wg_seen"] = now
    if rx is not None:
        state["last_rx"] = rx
    dark_secs = now - state["last_activity"]
    recently_left_home = (
        state["last_home_seen"] > state["last_wg_seen"]
        and (now - state["last_home_seen"]) <= (dark + grace))
    threshold = dark + grace if recently_left_home else dark
    was_alerted = state["dark_alerted"]
    fire_dark = dark_secs > threshold and not was_alerted
    if fire_dark:
        state["dark_alerted"] = True
    elif dark_secs <= dark and was_alerted:
        state["dark_alerted"] = False
    active = not state["dark_alerted"]

    # Log every suppression (once per occurrence, not every
    # HEARTBEAT_SECONDS tick while it holds) so the grace is auditable, not
    # silent tolerance -- same pattern as _log_liveness_failure elsewhere in
    # this file.
    log_line = None
    in_grace_window = recently_left_home and dark < dark_secs <= threshold
    if in_grace_window and not state["transition_grace_logged"]:
        log_line = (f"[eyeguard-phone] {now_iso()} phone-dark threshold "
                     f"extended to {threshold}s (left home "
                     f"{int(now - state['last_home_seen'])}s ago, no WG "
                     f"confirmation yet) -- would have fired at the normal "
                     f"{dark}s")
        state["transition_grace_logged"] = True
    elif not in_grace_window:
        state["transition_grace_logged"] = False

    return fire_dark, dark_secs, active, log_line


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
    off-network entirely, or VPN killed while away) trips phone-dark.

    NETWORK-TRANSITION GRACE (2026-09-28). Confirmed live: 17 phone-dark
    flags 2026-09-22 through 2026-09-27 (queried directly from the flags
    table via the anon key), EVERY one reading "silent for 168s" or "silent
    for 169s" -- not a spread of durations the way a real, arbitrarily-timed
    outage would produce, but a near-fixed ~168-169s window repeating across
    6 separate days at different times of day. Matches Jonah's own lead
    (leaving home, the phone should have been online the whole time) exactly:
    when the phone leaves home Wi-Fi, ALL THREE signals above go silent
    simultaneously for the real duration of the handoff -- no more DNS/ping
    on the home interface (phone's gone), and no WG traffic yet either,
    because the on-demand tunnel hasn't associated/handshaked on the new
    network yet. That handoff (cellular acquisition + iOS's on-demand VPN
    evaluation + the WireGuard handshake itself) is genuinely invisible to
    every signal this router can observe. Checked and ruled out a simpler
    explanation first: the phone's WG peer (10.1.0.2) IS correctly
    configured with Persistent Keepalive=25 on the router side (`uci show
    wireguard_server`, confirmed live) -- once the tunnel connects it stays
    reliably alive, so the false alarm is specifically the ~168-169s BEFORE
    that first handshake, not a keepalive gap once connected.

    Fix: grant DARK + TRANSITION_GRACE (not DARK) as the firing threshold,
    but ONLY while the most recent confirmed-alive signal (of either kind)
    was specifically a HOME one and nothing has reconfirmed home OR away
    since -- i.e. only for the window immediately following a departure
    from home. The instant either side reconfirms (home ping/DNS resumes --
    it wasn't really a departure -- or WG activity/handshake lands -- the
    transition completed), last_home_seen/last_wg_seen move and this
    condition no longer holds on the next tick. A phone that was ALREADY
    away and then goes dark is completely unaffected: its last confirmed
    signal was a WG one, so this branch never engages and the original
    DARK=150s threshold applies exactly as before -- unchanged, same
    urgency as today.

    !!! REDUCES COVERAGE for one narrow case, disclosed in this PR: the
    router cannot distinguish "phone is mid-transition, will reconnect in
    ~169s" from "phone was switched off/killed at the exact moment it left
    home" -- both look identical from here (last signal was home, then
    silence). So a genuine dark event that begins WHILE AT HOME is delayed
    by up to TRANSITION_GRACE seconds (default 40s -> 190s total) versus
    before this fix. An event that begins while already away is not
    delayed at all. Every suppression is logged (see below), not silent.

    The actual decision math lives in _evaluate_liveness() -- a pure
    function of (state, now, ping_ok, rx) with no I/O -- so it can be unit
    tested directly (tests/test_phone_dark_transition.py) without mocking
    subprocess/tcpdump/ping."""
    while True:
        rx = wg_rx_bytes()
        ping_ok = home_ping_alive()
        with _LOCK:
            fire_dark, dark_secs, active, log_line = _evaluate_liveness(
                _STATE, time.time(), ping_ok, rx, DARK, TRANSITION_GRACE)

        if log_line:
            print(log_line, flush=True)

        if fire_dark:
            sb_post("/rest/v1/flags", {
                "flagged_at": now_iso(), "verdict": DARK_VERDICT,
                "reason": REASON_PREFIX + f"phone-dark: silent for {int(dark_secs)}s "
                          "(VPN off / phone off / no signal)",
                "app": DEVICE_APP, "url": None, "window_title": "phone went dark",
                "grade": "Likely", "risk": "high", "is_nudity": False})

        # Report on the SLOWER REPORT_SECONDS cadence, or immediately whenever
        # the alive/dark state flips -- the local poll above still runs every
        # HEARTBEAT_SECONDS and all dark-detection math is unchanged. See
        # REPORT_SECONDS' own comment for why these were split apart.
        now_t = time.time()
        if (active != _LAST_REPORT["active"]
                or now_t - _LAST_REPORT["at"] >= REPORT_SECONDS):
            # Only advance the throttle on a CONFIRMED send (2026-09-14).
            # Marking it reported on a failed write would hold the next
            # attempt back a further REPORT_SECONDS, turning one dropped
            # heartbeat into a 60s reporting gap -- exactly the amplification
            # this round of fixes exists to remove. On failure we simply try
            # again on the next HEARTBEAT_SECONDS tick.
            if sb_phone_heartbeat(active):
                _LAST_REPORT["active"] = active
                _LAST_REPORT["at"] = now_t
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


def parse_querylog_config(text):
    """True iff AdGuard's `querylog:` block is logging everything to file:
    enabled, file_enabled, ignored_enabled false, no `ignored` domains. None
    if the block can't be found/read (treated as drift, like protection)."""
    m = re.search(r"^querylog:\s*\n((?:[ \t]+.*\n?|\n)*)", text or "", re.MULTILINE)
    if not m:
        return None
    blk = m.group(1)

    def val(key):
        mm = re.search(r"^[ \t]+" + key + r":\s*(\S.*?)\s*$", blk, re.MULTILINE)
        return mm.group(1) if mm else None

    ignored_empty = bool(re.search(r"^[ \t]+ignored:\s*\[\s*\]\s*$", blk, re.MULTILINE))
    return (val("enabled") == "true" and val("file_enabled") == "true"
            and val("ignored_enabled") in ("false", None) and ignored_empty)


def _adguard_querylog_ok():
    try:
        return parse_querylog_config(Path("/etc/AdGuardHome/config.yaml").read_text())
    except Exception:
        return None


def _wg_peer_pubkeys():
    try:
        out = subprocess.run(["awg", "show", "wgserver", "dump"],
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
        "adguard_querylog_ok": _adguard_querylog_ok(),
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
    ("adguard_querylog_ok", True, "AdGuard query logging was disabled, "
                                    "filtered or its file log turned off "
                                    "(EyeGuard's DNS-log view is blind)"),
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
    """Admin-trust pivot (2026-08-24): the scalar invariant checks now
    compare directly against _ROUTER_INVARIANTS' fixed expected value on
    EVERY cycle, no longer gated on the local baseline file also agreeing.

    The original design required `baseline.get(key) == expected` before
    alerting -- meaning a real gap opened up the moment Jonah got SSH
    (root shell, not just the GUI): change the actual config AND
    hand-edit ROUTER_BASELINE_PATH to match in the same window, and the
    alert condition can never become true again, since baseline advances
    to `current` every cycle regardless of whether something fired. A
    locally-tamperable file gating a security alert defeats the alert.

    _ROUTER_INVARIANTS' expected values are permanently fixed (unlike
    wg_peers, which legitimately changes over time and still needs real
    diff-against-baseline semantics, kept below unchanged) -- so there's
    no reason to route the scalar checks through mutable local state at
    all. `_alerted` is purely an in-memory anti-spam dedup now, not a
    security boundary: losing it on restart just means one possible extra
    duplicate email, not a missed detection, since the fixed-value
    comparison itself is what actually catches drift."""
    baseline = None
    if ROUTER_BASELINE_PATH.exists():
        try:
            baseline = json.loads(ROUTER_BASELINE_PATH.read_text())
        except Exception:
            baseline = None
    _alerted: set[str] = set()
    while True:
        try:
            current = router_snapshot()
            for key, expected, detail in _ROUTER_INVARIANTS:
                if current.get(key) != expected:
                    if key not in _alerted:
                        _router_tamper_flag(detail)
                        _alerted.add(key)
                elif key in _alerted:
                    _alerted.discard(key)  # recovered -- a future drift re-alerts

            cur_peers = current.get("wg_peers")
            base_peers = (baseline or {}).get("wg_peers")
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


# ---- AdGuard query-log reader + health watcher (2026-09-30) ------------------
#
# tcpdump (above) stays the real-time path. This adds a SECOND view of the
# phone's DNS from AdGuard's own on-disk query log, for two jobs:
#
#  1. Catch-all after the fact: whatever AdGuard resolved for the phone is
#     classified exactly like a wire query, whatever transport the phone used
#     to reach AdGuard (plain DNS today; DoT/DoH if a listener is ever
#     enabled). A query the wire path already flagged is NOT flagged twice.
#
#  2. Tripwire: "if the logs stop, alert". The log is only trustworthy as a
#     second view if we know it's alive and complete, so:
#       - config drift (logging off / file log off / `ignored` domains added)
#         is a router invariant (adguard_querylog_ok), alerted like any other
#         router tamper;
#       - STALLED: the wire saw the phone query more than MAX_LAG ago but the
#         log has no phone entry that recent -> the log stopped;
#       - MISSING: the log is current past a wire query but never contains it
#         -> AdGuard isn't recording everything the phone asks (or the phone
#         is talking to another resolver). Logs always; emails only if
#         querylog_missing_alerts is true (shadow period on the live router).
#
# The log is flushed in batches (size_memory), so it LAGS real time by minutes
# to tens of minutes. That's why it supplements tcpdump and never replaces it.

class QueryLogTailer:
    """Follows AdGuard's querylog.json by byte offset. Starts at EOF (no replay
    of history at boot), survives rotation (keeps draining the old inode, then
    reopens the new file from 0), and holds back a partial trailing line."""

    def __init__(self, path):
        self.path = Path(path)
        self._fh = None
        self._buf = b""
        self._opened_before = False

    def _open(self, from_start):
        self._fh = open(self.path, "rb")
        if not from_start:
            self._fh.seek(0, os.SEEK_END)
        self._buf = b""
        self._opened_before = True

    def poll(self):
        """-> list of complete raw lines (bytes) appended since last poll."""
        if self._fh is None:
            try:
                # EOF only on the very first open (no replay of history at
                # boot); a file that appears later is new content, read it all.
                self._open(from_start=self._opened_before)
            except OSError:
                self._opened_before = True   # started up with no file: when it
                return []                    # appears, it is all new content
        out = []
        while True:
            chunk = self._fh.read(1 << 20)
            if not chunk:
                break
            self._buf += chunk
        *lines, self._buf = self._buf.split(b"\n")
        out.extend(l for l in lines if l.strip())
        try:
            rotated = os.stat(self.path).st_ino != os.fstat(self._fh.fileno()).st_ino
            truncated = os.stat(self.path).st_size < self._fh.tell()
        except OSError:
            return out  # file briefly absent mid-rotation; retry next poll
        if rotated or truncated:
            self._fh.close()
            try:
                self._open(from_start=True)
            except OSError:
                self._fh = None
        return out


def parse_querylog_line(raw):
    """-> (epoch_ts, client_ip, qname) or None. Tolerates junk lines."""
    try:
        d = json.loads(raw)
        qh, ip, t = d["QH"], d["IP"], d["T"]
    except Exception:
        return None
    if not qh or not ip:
        return None
    try:
        # AdGuard writes RFC3339 with 0-9 fractional digits (it trims trailing
        # zeros); normalise to exactly 6 for fromisoformat.
        t = t.replace("Z", "+00:00")
        t = re.sub(r"\.(\d+)", lambda m: "." + (m.group(1) + "000000")[:6], t, count=1)
        ts = datetime.fromisoformat(t).timestamp()
    except Exception:
        # Never drop a query over a timestamp quirk -- a dropped explicit
        # query is a blind spot. Treat it as "just read".
        ts = time.time()
    return ts, ip, qh


class QueryLogCrossCheck:
    """Pure (injected time) comparison of wire-seen queries against the log."""

    def __init__(self, max_lag, slack=120, missing_threshold=5, cap=20000):
        self.max_lag, self.slack = max_lag, slack
        self.missing_threshold, self.cap = missing_threshold, cap
        self._lock = threading.Lock()
        self._pending = []            # [(ts, client, domain)] wire queries awaiting the log
        self._log = {}                # (client, domain) -> [ts...]
        self._last_log_t = {}         # client -> newest log entry timestamp

    @staticmethod
    def _norm(raw_name):
        return (raw_name or "").rstrip(".").lower()

    def record_wire(self, ts, client, raw_name):
        d = self._norm(raw_name)   # full name, not base domain: a log that
        # drops one subdomain must not hide behind a sibling that was logged
        if not d or is_noise(base_domain(d)):
            return
        with self._lock:
            self._pending.append((ts, client, d))
            if len(self._pending) > self.cap:
                del self._pending[: len(self._pending) - self.cap]

    def record_log(self, ts, client, raw_name):
        d = self._norm(raw_name)
        if not d:
            return
        with self._lock:
            self._log.setdefault((client, d), []).append(ts)
            if ts > self._last_log_t.get(client, 0):
                self._last_log_t[client] = ts

    def evaluate(self, now):
        """-> {'stalled': [(client, age_s)], 'missing': [(client, domain)]}.
        Only wire queries older than max_lag are judged (the log may
        legitimately trail by up to that long)."""
        stalled, missing, keep = {}, [], []
        with self._lock:
            for ts, client, d in self._pending:
                if now - ts <= self.max_lag:
                    keep.append((ts, client, d))
                    continue
                last = self._last_log_t.get(client)
                if last is None or last < ts - self.slack:
                    # the log hasn't reached this (overdue) wire query: stalled.
                    stalled[client] = max(stalled.get(client, 0), now - ts)
                    keep.append((ts, client, d))
                    continue
                hits = self._log.get((client, d), ())
                if not any(abs(t - ts) <= self.slack for t in hits):
                    missing.append((client, d))
            self._pending = keep
            horizon = now - 2 * self.max_lag - self.slack
            for k in list(self._log):
                self._log[k] = [t for t in self._log[k] if t >= horizon]
                if not self._log[k]:
                    del self._log[k]
        return {"stalled": sorted(stalled.items()), "missing": missing}


QUERYLOG_XCHECK = QueryLogCrossCheck(QUERYLOG_MAX_LAG,
                                     missing_threshold=QUERYLOG_MISSING_THRESHOLD)


def _querylog_flag(detail):
    sb_post("/rest/v1/flags", {
        "flagged_at": now_iso(), "verdict": "flagged",
        "reason": f"tamper: AdGuard DNS log -- {REASON_PREFIX}{detail}",
        "app": "Router", "url": None, "window_title": "AdGuard DNS log health",
        "grade": "Likely", "risk": "high", "is_nudity": False})


def querylog_loop():
    """Reads new AdGuard log entries for the phone's IPs, classifies them like
    wire queries (skipping ones the wire already flagged), and feeds the
    cross-check. Exceptions never kill the loop."""
    clients = {ip for ip in (HOME_IP, WG_IP) if ip}
    tailer = QueryLogTailer(QUERYLOG_PATH)
    answer_only = set(CONNLOG_IPMAP) - clients
    while True:
        try:
            for raw in tailer.poll():
                parsed = parse_querylog_line(raw)
                if not parsed:
                    continue
                ts, ip, qname = parsed
                if ip in answer_only:      # connlog device that isn't the phone:
                    connlog_answers_from_querylog(ip, raw)   # answers only, no flags
                    continue
                if ip not in clients:
                    continue
                QUERYLOG_XCHECK.record_log(ts, ip, qname)
                connlog_answers_from_querylog(ip, raw)
                if not _wire_seen_recently(ip, qname):
                    _handle_query(qname, suffix=" (via AdGuard log, after the fact)")
        except Exception as ex:
            print(f"[eyeguard-phone] querylog_reader {type(ex).__name__}: {ex}",
                  flush=True)
        time.sleep(15)


def querylog_watch_loop():
    """Evaluates the cross-check; alerts once per condition until it recovers."""
    alerted = set()
    while True:
        time.sleep(QUERYLOG_CHECK_SECONDS)
        try:
            res = QUERYLOG_XCHECK.evaluate(time.time())
            if res["stalled"]:
                if "stalled" not in alerted:
                    who = ", ".join(f"{c} (oldest unlogged query {int(a)}s ago)"
                                    for c, a in res["stalled"])
                    _querylog_flag(f"the log has stopped recording the phone: {who}")
                    alerted.add("stalled")
            else:
                alerted.discard("stalled")
            n = len(res["missing"])
            if n:
                sample = ", ".join(sorted({d for _, d in res["missing"]})[:3])
                print(f"[eyeguard-phone] querylog: {n} wire quer(ies) absent from "
                      f"AdGuard's log (e.g. {sample})", flush=True)
            if n >= QUERYLOG_MISSING_THRESHOLD and QUERYLOG_MISSING_ALERTS:
                if "missing" not in alerted:
                    _querylog_flag(f"{n} phone DNS queries seen on the wire are "
                                   f"missing from AdGuard's log")
                    alerted.add("missing")
            elif n == 0:
                alerted.discard("missing")
        except Exception as ex:
            print(f"[eyeguard-phone] querylog_watch {type(ex).__name__}: {ex}",
                  flush=True)


# ---- router connection-log watcher: unexplained destinations (2026-10-01) ----
#
# The router logs every NEW/DESTROY conntrack event to non-private destinations
# (/usr/bin/connlog.sh -> /tmp/connlog/log.0-3: `<epoch> <N|D> <proto> <src>
# <dst> <dport> <bytes>`). This closes the gap DNS/DoH/Tor lists can't: a
# monitored device connecting to an IP that NOTHING it resolved explains --
# hardcoded IPs, self-hosted or unlisted DoH, VPNs.
#
# "Explained" = that device resolved the destination IP within
# connlog_answer_window_seconds, from (a) the A/AAAA records in AdGuard's
# query-log `Answer` field and (b) DNS responses seen on the wire. Devices are
# matched by DEVICE, not IP (a phone's home and tunnel IPs are one device).
#
# LOG-ONLY. It never posts a flag. It keeps aggregate counters (no domains, no
# per-connection records) so the false-positive rate can be measured before any
# alerting is proposed in a separate PR.
#
# PRIVACY SCOPE: only lines whose source IP is in the configured allowlist are
# parsed past the first field. Every other line -- including Jada's phone
# (connlog_excluded_ips, which can't be allowlisted) -- is dropped before any
# state is touched, logged or stored. The router watcher's freshness check
# reads only file mtimes, never lines.

import base64
import ipaddress
import socket
import struct
from collections import Counter


def parse_dns_answer(b64):
    """base64 DNS wire message (AdGuard querylog `Answer`) -> [(ip_str, ttl)].
    Handles name compression and CNAME chains; ignores everything but A/AAAA.
    Returns [] on any malformed input (never raises)."""
    try:
        msg = base64.b64decode(b64)
        qd, an = struct.unpack(">HH", msg[4:8])

        def skip_name(i):
            while True:
                n = msg[i]
                if n == 0:
                    return i + 1
                if n & 0xC0 == 0xC0:
                    return i + 2
                i += 1 + n

        i = 12
        for _ in range(qd):
            i = skip_name(i) + 4
        out = []
        for _ in range(an):
            i = skip_name(i)
            rtype, _cls, ttl, rdlen = struct.unpack(">HHIH", msg[i:i + 10])
            i += 10
            rdata = msg[i:i + rdlen]
            i += rdlen
            if rtype == 1 and rdlen == 4:
                out.append((socket.inet_ntop(socket.AF_INET, rdata), ttl))
            elif rtype == 28 and rdlen == 16:
                out.append((socket.inet_ntop(socket.AF_INET6, rdata), ttl))
        return out
    except Exception:
        return []


# tcpdump -nn response text: "... 3/0/1 CNAME x., A 1.2.3.4, AAAA 2001:db8::1 (80)"
_WIRE_ANSWER_RE = re.compile(r"\b(?:A|AAAA) ([0-9a-fA-F:.]+)(?=[,\s(])")


def parse_wire_answers(line):
    out = []
    for m in _WIRE_ANSWER_RE.finditer(line):
        try:
            out.append(str(ipaddress.ip_address(m.group(1))))
        except ValueError:
            pass
    return out


def build_device_map(devices, excluded):
    """{'phone': ['192.168.8.153','10.1.0.3']} -> ({ip: device}, [dropped_ips]).
    Excluded IPs are refused outright (defense in depth for Jada's peer)."""
    ipmap, dropped = {}, []
    for dev, ips in (devices or {}).items():
        for ip in ips:
            if ip in excluded:
                dropped.append(ip)
            else:
                ipmap[ip] = dev
    return ipmap, dropped


def parse_connlog_line(raw, ipmap):
    """-> (ts, ev, proto, device, dst, dport, nbytes) or None.
    The SOURCE is checked first; a line from any IP not in ipmap returns None
    before anything else is derived from it."""
    try:
        f = raw.decode("ascii", "ignore").split()
        if len(f) < 7:
            return None
        device = ipmap.get(f[3])
        if device is None:
            return None
        return (int(f[0]), f[1], f[2], device, f[4], int(f[5]), int(f[6]))
    except Exception:
        return None


class ConnExplainer:
    """Pure (injected time) explainer: is each NEW connection's destination
    something the device resolved recently? Log-only statistics out."""

    def __init__(self, window=21600, settle=300, slack=120, warmup_until=0):
        self.window, self.settle, self.slack = window, settle, slack
        self.warmup_until = warmup_until   # conns before this are not judged
        self._lock = threading.Lock()
        self._answers = {}      # (device, ip) -> newest answer ts
        self._pending = []      # [(ts, device, dst, dport, proto)]
        self._bytes = {}        # (device, dst) -> bytes from D events
        self.stats = Counter()
        self.unexplained_prefix = Counter()
        self.unexplained_port = Counter()

    def add_answer(self, device, ip, ts):
        with self._lock:
            k = (device, ip)
            if ts > self._answers.get(k, 0):
                self._answers[k] = ts

    def add_event(self, ev):
        ts, kind, proto, device, dst, dport, nbytes = ev
        with self._lock:
            if kind == "N":
                self._pending.append((ts, device, dst, dport, proto))
                if len(self._pending) > 50000:
                    del self._pending[:len(self._pending) - 50000]
            elif kind == "D" and nbytes:
                self._bytes[(device, dst)] = self._bytes.get((device, dst), 0) + nbytes

    @staticmethod
    def _prefix(dst):
        try:
            ip = ipaddress.ip_address(dst)
            return str(ipaddress.ip_network(f"{dst}/{16 if ip.version == 4 else 32}",
                                            strict=False))
        except ValueError:
            return "?"

    def evaluate(self, now):
        """Judge pending NEW events older than `settle`. Updates counters;
        returns the number judged."""
        judged, keep = 0, []
        with self._lock:
            for ev in self._pending:
                ts, device, dst, dport, proto = ev
                if now - ts < self.settle:
                    keep.append(ev)
                    continue
                if ts < self.warmup_until:
                    self.stats["skipped_warmup"] += 1
                    continue
                judged += 1
                self.stats["new_total"] += 1
                if dport in (53, 853):
                    self.stats["resolver_port"] += 1   # direct DNS/DoT to a public IP
                a = self._answers.get((device, dst))
                if a is not None and a - self.slack <= ts <= a + self.window:
                    self.stats["explained"] += 1
                else:
                    self.stats["unexplained"] += 1
                    self.unexplained_prefix[self._prefix(dst)] += 1
                    self.unexplained_port[f"{proto}/{dport}"] += 1
                    b = self._bytes.get((device, dst), 0)
                    band = "big" if b >= 1_000_000 else "medium" if b >= 50_000 else "tiny"
                    self.stats[f"unexplained_{band}"] += 1
            self._pending = keep
            horizon = now - self.window - self.slack
            for k in [k for k, t in self._answers.items() if t < horizon]:
                del self._answers[k]
            if len(self._bytes) > 20000:
                self._bytes.clear()
        return judged

    def snapshot(self, top=5):
        with self._lock:
            tot = self.stats["new_total"]
            return {"new_total": tot, "explained": self.stats["explained"],
                    "unexplained": self.stats["unexplained"],
                    "unexplained_pct": round(100.0 * self.stats["unexplained"] / tot, 1) if tot else None,
                    "unexplained_tiny": self.stats["unexplained_tiny"],
                    "unexplained_medium": self.stats["unexplained_medium"],
                    "unexplained_big": self.stats["unexplained_big"],
                    "resolver_port": self.stats["resolver_port"],
                    "skipped_warmup": self.stats["skipped_warmup"],
                    "pending": len(self._pending),
                    "top_unexplained_prefixes": self.unexplained_prefix.most_common(top),
                    "top_unexplained_ports": self.unexplained_port.most_common(top)}


def seed_answers_from_querylog(explainer, ipmap, path=QUERYLOG_PATH):
    """Warm the answer index from AdGuard's existing log (current + rotated)
    so a restart doesn't make every connection look unexplained. Only lines
    for allowlisted client IPs are decoded."""
    n = 0
    for p in (Path(str(path) + ".1"), Path(path)):
        try:
            fh = open(p, "rb")
        except OSError:
            continue
        with fh:
            for raw in fh:
                parsed = parse_querylog_line(raw)
                if not parsed or parsed[1] not in ipmap:
                    continue
                try:
                    ans = json.loads(raw).get("Answer")
                except Exception:
                    continue
                for ip, _ttl in parse_dns_answer(ans) if ans else ():
                    explainer.add_answer(ipmap[parsed[1]], ip, parsed[0])
                    n += 1
    return n


CONNLOG_IPMAP, _CONNLOG_DROPPED = build_device_map(
    CONF.get("connlog_devices", {}), CONNLOG_EXCLUDED_IPS)
CONNLOG_EXPLAINER = ConnExplainer(CONNLOG_WINDOW, CONNLOG_SETTLE,
                                  warmup_until=time.time() + 600)


def connlog_answers_from_querylog(ip, raw):
    """Feed one AdGuard log line's answers to the explainer (allowlisted IPs only)."""
    dev = CONNLOG_IPMAP.get(ip)
    if dev is None:
        return
    try:
        d = json.loads(raw)
        ts = parse_querylog_line(raw)[0]
    except Exception:
        return
    for aip, _ttl in parse_dns_answer(d.get("Answer") or ""):
        CONNLOG_EXPLAINER.add_answer(dev, aip, ts)


def wire_answers_loop(iface, host_ip):
    """Real-time DNS answers to one monitored IP, straight off the wire."""
    dev = CONNLOG_IPMAP.get(host_ip)
    filt = f"udp src port 53 and dst host {host_ip}"
    while True:
        try:
            proc = subprocess.Popen(["tcpdump", "-i", iface, "-l", "-nn", filt],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, bufsize=1)
            for line in proc.stdout:
                now = time.time()
                for aip in parse_wire_answers(line):
                    CONNLOG_EXPLAINER.add_answer(dev, aip, now)
            proc.wait()
        except Exception as ex:
            print(f"[eyeguard-phone] wire_answers({iface}) {type(ex).__name__}: {ex}",
                  flush=True)
        time.sleep(5)


def connlog_loop():
    """Tails the router connection log for allowlisted devices, judges settled
    NEW connections, and writes hourly AGGREGATE stats (log + tmpfs file)."""
    if not CONNLOG_IPMAP:
        return
    if _CONNLOG_DROPPED:
        print(f"[eyeguard-phone] connlog: REFUSED excluded IPs in connlog_devices: "
              f"{_CONNLOG_DROPPED}", flush=True)
    try:
        n = seed_answers_from_querylog(CONNLOG_EXPLAINER, CONNLOG_IPMAP)
        print(f"[eyeguard-phone] connlog: devices={sorted(set(CONNLOG_IPMAP.values()))} "
              f"seeded {n} DNS answers from AdGuard log (LOG-ONLY)", flush=True)
    except Exception as ex:
        print(f"[eyeguard-phone] connlog seed {type(ex).__name__}: {ex}", flush=True)
    tailers = [QueryLogTailer(CONNLOG_DIR / f"log.{i}") for i in range(4)]
    last_eval = last_report = time.time()
    while True:
        try:
            for t in tailers:
                for raw in t.poll():
                    ev = parse_connlog_line(raw, CONNLOG_IPMAP)
                    if ev:
                        CONNLOG_EXPLAINER.add_event(ev)
            now = time.time()
            if now - last_eval >= 60:
                CONNLOG_EXPLAINER.evaluate(now)
                last_eval = now
            if now - last_report >= CONNLOG_REPORT_SECONDS:
                snap = CONNLOG_EXPLAINER.snapshot()
                snap["at"] = now_iso()
                print(f"[eyeguard-phone] connlog stats (log-only): {json.dumps(snap)}",
                      flush=True)
                try:
                    CONNLOG_STATS_PATH.write_text(json.dumps(snap))
                except OSError:
                    pass
                last_report = now
        except Exception as ex:
            print(f"[eyeguard-phone] connlog {type(ex).__name__}: {ex}", flush=True)
        time.sleep(5)


def sleep_relay_loop():
    """LAN relay for the Mac's WillSleep signal (2026-09-04).

    The Mac's own WillSleep handler (eyeguard/session_watcher.py's
    SleepWatcher) races a tight, OS-shared deadline to call
    IOAllowPowerChange -- confirmed live (2026-09-03/04) that a WAN network
    call made from inside that handler is genuinely risky: DNS + VPN
    tunnel + internet round trip, all squeezed into a window other system
    daemons are simultaneously eating into (pmset -g log's own "PM Client
    Acks: Delays to Sleep notifications" lines). A UDP packet to THIS
    router, on the same LAN, needs none of that -- no DNS, no tunnel, no
    internet hop, just a same-subnet send that returns essentially
    instantly whether or not anything answers. This router then relays the
    signal to Supabase over its own already-reliable, non-time-pressured
    connection -- the Mac only needs to reach as far as this router, not
    all the way to Supabase, during the one moment that's hardest.

    Reuses eg_watcher_report_sleep() directly -- no new RPC, no new column.
    The relay produces IDENTICAL server-side state to the Mac calling it
    directly; this router is just a more reliable messenger for the exact
    same message.

    Security: SLEEP_RELAY_TOKEN is a plain shared string, not HMAC-signed --
    deliberately not hardened further, because the worst case a forged
    packet achieves (suppressing one "session watcher went dark" alert) is
    EXACTLY what anyone already holding the public anon key can already do
    directly via eg_report_suspend() with zero authentication at all
    (accepted residual since 2026-08-24, supabase/anon_client_pivot.sql) --
    this LAN channel adds a new PATH to an already-accepted capability, not
    a new capability. Only reachable from the LAN itself (not exposed over
    the WireGuard tunnel or WAN), so it doesn't even extend that residual's
    existing reach.

    Only runs if this router doesn't ALSO happen to be genuinely down or
    unreachable from the Mac at that exact moment (e.g. a router reboot
    mid-sleep-transition) -- in that case the Mac's own direct (WAN)
    fallback attempt still applies, same as before this existed. This is
    an additional path, not a replacement for that fallback."""
    import socket as _socket
    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", SLEEP_RELAY_PORT))
    print(f"[eyeguard-phone] sleep relay listening on UDP :{SLEEP_RELAY_PORT}",
          flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(512)
            msg = json.loads(data.decode())
            if msg.get("token") != SLEEP_RELAY_TOKEN:
                continue  # wrong/missing token -- silently ignore, no reply
            sb_rpc("eg_watcher_report_sleep", {})
            print(f"[eyeguard-phone] relayed sleep signal from {addr[0]} "
                  f"({msg.get('reason', '?')})", flush=True)
        except Exception as e:
            print(f"[eyeguard-phone] sleep relay error: {e!r}", flush=True)


def main():
    # A secondary instance (another device's config) skips the two ROUTER-level
    # loops: the primary already runs them, and running them twice would bind
    # the relay port twice and double every router-tamper alert. Everything
    # per-device below (captures, DoH, Tor, querylog, connlog, liveness) runs
    # in every instance. The Tor list refresh also stays on in every instance,
    # so a secondary is never dependent on the primary being up.
    if SECONDARY:
        print(f"[eyeguard-phone] secondary instance for {DEVICE_APP!r} "
              f"(conf {CONF_PATH}): router config check + sleep relay left to "
              f"the primary", flush=True)
    if SLEEP_RELAY_TOKEN and not SECONDARY:
        threading.Thread(target=sleep_relay_loop, daemon=True).start()
    if not SECONDARY:
        threading.Thread(target=router_check_loop, daemon=True).start()
    if CONNLOG_IPMAP:
        threading.Thread(target=connlog_loop, daemon=True).start()
        for ip in CONNLOG_IPMAP:
            iface = HOME_IFACE if not ip.startswith("10.1.") else (WG_IFACE or HOME_IFACE)
            threading.Thread(target=wire_answers_loop, args=(iface, ip), daemon=True).start()
    if HOME_IP or WG_IP:
        threading.Thread(target=querylog_loop, daemon=True).start()
        threading.Thread(target=querylog_watch_loop, daemon=True).start()
    threading.Thread(target=tor_refresh_loop, daemon=True).start()
    threads = []
    if HOME_IP:
        threads.append(threading.Thread(target=capture_loop,
                                        args=(HOME_IFACE, HOME_IP, "home"), daemon=True))
    if WG_IFACE and WG_IP:
        threads.append(threading.Thread(target=capture_loop,
                                        args=(WG_IFACE, WG_IP, "wg"), daemon=True))
    if HOME_IP:
        threads.append(threading.Thread(target=doh_syn_loop,
                                        args=(HOME_IFACE, HOME_IP), daemon=True))
    if WG_IFACE and WG_IP:
        threads.append(threading.Thread(target=doh_syn_loop,
                                        args=(WG_IFACE, WG_IP), daemon=True))
    if HOME_IP:
        threads.append(threading.Thread(target=tor_syn_loop,
                                        args=(HOME_IFACE, HOME_IP), daemon=True))
    if WG_IFACE and WG_IP:
        threads.append(threading.Thread(target=tor_syn_loop,
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
