#!/usr/bin/env python3
"""EyeGuard network monitor -- runs ONLY on the router (2026-10-20).

Watches every DNS query from every client on every router segment (br-lan,
br-guest, br-iot and the wgserver tunnel) and applies the SAME rules the phone
and Mac monitors use (explicit_terms / noise_domains / app_map, read from the
same /etc/eyeguard/phone.json), plus one extra rule:

    TRAFFIC THAT IS MASKED OR ROUTED AROUND THE ROUTER'S DNS IS ALERTED.

That means Tor, VPN apps and tunnels, iCloud Private Relay, DNS-over-TLS/QUIC,
DNS-over-HTTPS to known providers, and VPN/Tor provider lookups.

Nothing here talks to the clients, needs software on them, or reads packet
payload beyond the DNS question name. It is passive tcpdump on the router, so a
device cannot opt out by uninstalling anything. Only domain names and
destination IPs are used. No screen content exists on the router.

Design rules (same as the rest of EyeGuard):
  * Alerts are anon inserts into public.flags (no new SQL, no new secret).
    Reasons start with "net-signal:" / "net-bypass:" so the server's
    phone-specific logic (eg_on_red keys on phone-*) never sees them.
  * Overlap with the per-phone monitors is de-duplicated ONLY while the phone
    monitor for that device is actually running. If it dies, this daemon
    becomes the backstop for the same events.
  * New heuristics that could plausibly fire on innocent traffic are
    OBSERVE-ONLY (counted in /tmp/dnsnet-stats.json and the hourly log line)
    until measured; `dnsnet_alert_classes` in phone.json promotes them.
  * Excluded IPs (dnsnet_excluded_ips, default = connlog_excluded_ips, i.e.
    Jada's tunnel peer) are never evaluated at all.
  * Stdlib only; python3-light on the router has no _ssl, so HTTPS is curl.

Known, accepted residuals (documented, not claimed as covered): obfs4/meek/
snowflake bridges and AmneziaWG-style obfuscated tunnels (built to evade
exactly these signatures), a VPN running INSIDE the household's own tunnel
from outside the home (only the outer tunnel is visible), IPv6 (disabled on the
LAN; a tripwire alerts if that changes), and DoH to an unlisted private
server.
"""
from __future__ import annotations

import bisect
import json
import math
import os
import queue
import re
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

CONF_PATH = os.environ.get("EG_PHONE_CONF", "/etc/eyeguard/phone.json")
CONF = json.load(open(CONF_PATH))
API_KEY = CONF["api_key"]
SB = CONF["supabase_url"].rstrip("/")

# ---- same rules as the phone monitor (single source: phone.json) -----------
TERMS = [t.lower() for t in CONF.get("explicit_terms", [])]
NOISE = [n.lower() for n in CONF.get("noise_domains", [])]
APP_MAP = {k.lower(): v for k, v in CONF.get("app_map", {}).items()}

IFACES = CONF.get("dnsnet_interfaces", ["br-lan", "br-guest", "br-iot", "wgserver"])
# EVERY device on the network is evaluated, Jada's included (Jonah's decision
# 2026-10-20, Jada knows). Exclusion exists only as an explicit, deliberate config choice;
# the default is nobody. The connection logger's own exclusion list is NOT inherited.
EXCLUDED = set(CONF.get("dnsnet_excluded_ips", []))
EXCLUDED_MACS = {m.lower() for m in CONF.get("dnsnet_excluded_macs", [])}
THROTTLE = int(CONF.get("dnsnet_throttle_seconds", 1800))   # per client+class+target
STATS_PATH = Path(CONF.get("dnsnet_stats_file", "/tmp/dnsnet-stats.json"))
STATS_LOG_SECONDS = int(CONF.get("dnsnet_stats_log_seconds", 3600))
STATS_SECONDS = int(CONF.get("dnsnet_stats_seconds", 60))
TOR_CACHE = Path(CONF.get("tor_relay_cache_file", "/etc/eyeguard/tor_relays.json"))
TOR_REFRESH = int(CONF.get("tor_refresh_seconds", 21600))
# Public lists (curl, daily). Both are optional: a failed fetch keeps the last good copy.
VPN_RANGES_PATH = Path(CONF.get("vpn_ranges_file", "/etc/eyeguard/vpn_ranges.txt"))
VPN_RANGES_URL = CONF.get("vpn_ranges_url",
    "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt")
TOR_BRIDGES_PATH = Path(CONF.get("tor_bridges_file", "/etc/eyeguard/tor_bridges.json"))
TOR_BRIDGES_URL = CONF.get("tor_bridges_url",
    "https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/raw/main/projects/tor-expert-bundle/pt_config.json")
LISTS_REFRESH = int(CONF.get("dnsnet_lists_refresh_seconds", 86400))
LISTS_RETRY = int(CONF.get("dnsnet_lists_retry_seconds", 600))   # until the first copy exists
# Public names a site uses when it hides its real name with Encrypted Client Hello.
ECH_PUBLIC_NAMES = ("cloudflare-ech.com", "encryptedsni.com")
LEASES = CONF.get("dnsnet_leases_file", "/tmp/dhcp.leases")
DHCP_CONFIG = CONF.get("dnsnet_dhcp_config", "/etc/config/dhcp")
DEVICE_NAMES = {"10.1.0.2": "Jonahs-Mac", "10.1.0.3": "JJPWS-Phone",
                "10.1.0.4": "Jonahs-Mac-Remote", "10.1.0.5": "Jadas-Phone"}
SEGMENTS = {"192.168.8.": "home LAN", "192.168.9.": "guest Wi-Fi", "192.168.10.": "IoT network",
            "10.1.0.": "VPN tunnel"}
SEGMENTS.update(CONF.get("dnsnet_segments", {}))
DEVICE_NAMES.update(CONF.get("dnsnet_device_names", {}))
# Addresses that are NOT bypass destinations: the router itself and the G11.
TRUSTED_DESTS = set(CONF.get("dnsnet_trusted_dests", ["192.168.8.231"]))

# Attack classes. ALERT = emailed immediately (throttled). OBSERVE = counted.
ALERT_DEFAULT = ["explicit-dns", "explicit-sni", "vpn-ip", "tor-guard", "doh-ip", "dot-attempt", "vpn-domain",
                 "tor-domain", "private-relay", "vpn-port", "wg-handshake",
                 "ipv6-enabled"]
OBSERVE_ONLY = ["dns-bypass", "doh-host", "ike-ipsec", "openvpn-udp", "proxy-port",
                "tls-no-sni", "ech-hidden", "dns-tunnel"]
ALERT_CLASSES = set(CONF.get("dnsnet_alert_classes", ALERT_DEFAULT))

# ---- the same classification as eyeguard-phone.py (parity-tested) ----------

def base_domain(name):
    d = (name or "").rstrip(".").lower()
    parts = d.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


def is_noise(domain):
    if domain in ("arpa", "local", "lan"):
        return True
    if domain.endswith(".arpa") or domain.endswith(".local") or domain.endswith(".lan"):
        return True
    if domain.endswith(".invalid"):
        return True
    return any(n in domain for n in NOISE)


def app_name(domain):
    for key, app in APP_MAP.items():
        if key in domain:
            return app
    return None


def classify(raw_name):
    """-> (verdict, reason, label) or None. Identical rule to the phone's."""
    domain = base_domain(raw_name)
    if not domain or is_noise(domain):
        return None
    hits = [t for t in TERMS if re.search(r"\b" + re.escape(t) + r"\b", domain)]
    label = app_name(domain) or domain
    if hits:
        return ("flagged", f"explicit domain {domain}", label)
    return ("clear", f"{label}", label)


# ---- bypass knowledge ------------------------------------------------------

# Same list as the router's Block-DoH-Providers firewall rules.
DOH_IPS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "9.9.9.10",
    "149.112.112.112", "149.112.112.10", "208.67.222.222", "208.67.220.220",
    "208.67.222.123", "208.67.220.123", "94.140.14.14", "94.140.15.15",
    "185.228.168.9", "185.228.169.9",
}
# Hostnames of public encrypted-DNS services (observe-only: a lookup is not a use).
DOH_HOSTS = (
    "dns.google", "cloudflare-dns.com", "one.one.one.one", "dns.quad9.net",
    "doh.opendns.com", "dns.nextdns.io", "doh.dns.apple.com", "dns.adguard.com",
    "dns.adguard-dns.com", "doh.mullvad.net", "doh.libredns.gr", "dns.sb",
    "doh.cleanbrowsing.org",
)
# VPN / proxy / anti-censorship providers. Suffix match on the full name.
# proton.me itself is NOT listed (Proton Mail and Drive are in normal use);
# only Proton's VPN endpoints are.
VPN_DOMAINS = (
    "nordvpn.com", "nordcdn.com", "nordvpn.net", "expressvpn.com", "expressapisv2.net",
    "protonvpn.com", "protonvpn.ch", "protonvpn.net", "vpn-api.proton.me",
    "surfshark.com", "mullvad.net", "privateinternetaccess.com", "piaservers.net",
    "windscribe.com", "cyberghostvpn.com", "tunnelbear.com", "hotspotshield.com",
    "ipvanish.com", "vyprvpn.com", "hide.me", "ivpn.net", "purevpn.com",
    "torguard.net", "atlasvpn.com", "privatevpn.com", "zenmate.com", "psiphon.ca",
    "getlantern.org", "lantern.io", "ultrasurf.us", "freegate-sec.com",
    "betternet.co", "hola.org", "browsec.com", "urban-vpn.com", "windscribe.net",
    "vpnunlimited.com", "keepsolid.com", "x-vpn.org", "thundervpn.com", "turbovpn.com",
)
TOR_DOMAINS = ("torproject.org", "onionoo.torproject.org", "bridges.torproject.org",
               "snowflake.torproject.net", "meek.azureedge.net")
PRIVATE_RELAY = ("mask.icloud.com", "mask-h2.icloud.com", "mask-api.icloud.com",
                 "mask.apple-dns.net")
DNS_BYPASS_PORTS = {853}
VPN_TCP_PORTS = {1194: "OpenVPN", 1723: "PPTP"}
VPN_UDP_PORTS = {1194: "OpenVPN", 51820: "WireGuard (default port)", 1701: "L2TP"}
PROXY_PORTS = {1080: "SOCKS", 3128: "HTTP proxy", 8118: "Privoxy", 9050: "Tor SOCKS",
               9150: "Tor Browser SOCKS", 8388: "Shadowsocks"}


def host_matches(name: str, suffixes) -> str | None:
    """Return the matching suffix when `name` equals it or is a subdomain."""
    n = (name or "").rstrip(".").lower()
    for s in suffixes:
        if n == s or n.endswith("." + s):
            return s
    return None


# ---- parsers (pure) --------------------------------------------------------

# tcpdump 4.9.3: "IP 192.168.8.150.5353 > 192.168.8.1.53: 1234+ A? name. (30)".
# EDNS queries print "1234+ [1au] A? name." and some clients drop RD (no "+"),
# so both are accepted. Class tokens like "A?" "AAAA?" "HTTPS?" "TYPE65?" all match.
DNS_RE = re.compile(
    r"IP (\d+\.\d+\.\d+\.\d+)\.\d+ > (\d+\.\d+\.\d+\.\d+)\.53: "
    r".*?(?<![\w.])\d+\+?\s+(?:\[[^\]]*\]\s+)*([A-Za-z0-9]+)\?\s+(\S+?)\.?\s+\(\d+\)")
FLOW_RE = re.compile(
    r"IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): (\S+)")


def parse_dns_query(line: str):
    """-> (client_ip, resolver_ip, qname, qtype) or None."""
    m = DNS_RE.search(line)
    if not m:
        return None
    return m.group(1), m.group(2), m.group(4).rstrip("."), m.group(3).upper()


def parse_dns_line(line: str):
    """-> (client_ip, resolver_ip, qname) or None."""
    q = parse_dns_query(line)
    return q[:3] if q else None


def parse_flow_line(line: str):
    """-> (src, sport, dst, dport, kind) or None. kind = 'Flags' (tcp) or
    'UDP' (the token after the colon)."""
    m = FLOW_RE.search(line)
    if not m:
        return None
    return m.group(1), int(m.group(2)), m.group(3), int(m.group(4)), m.group(5)



# ---- TLS ClientHello (server name) ------------------------------------------
#
# Every HTTPS connection announces its hostname in plaintext in the first packet
# (SNI). Reading it applies the SAME explicit-site rule even when DNS was bypassed
# (DoH to an unlisted server, a hardcoded IP, cached answers). Encrypted Client Hello
# hides it; a site that hides behind a public ECH name is counted. QUIC/HTTP3 hides
# the name and is not covered (blocking UDP/443 at the firewall would force TCP).

HEXLINE_RE = re.compile(r"^\s+0x[0-9a-fA-F]+:\s+((?:[0-9a-fA-F]{2,4}\s?)+)")
SNAP_IP = 1486          # bytes of IP packet kept by `-s 1500` on an ethernet segment
_SNI_OK = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$")


def parse_client_hello(pkt: bytes):
    """Pure. Raw IPv4 packet -> {src, dst, dport, sni, ech, cut} for a TLS ClientHello, else None.
    `cut` = the extension block runs past the captured bytes (an absent SNI then means
    'not seen', not 'not present')."""
    try:
        if len(pkt) < 40 or pkt[0] >> 4 != 4 or pkt[9] != 6:
            return None
        ihl = (pkt[0] & 0x0F) * 4
        src, dst = ".".join(map(str, pkt[12:16])), ".".join(map(str, pkt[16:20]))
        tcp = pkt[ihl:]
        dport = struct.unpack(">H", tcp[2:4])[0]
        p = tcp[(tcp[12] >> 4) * 4:]
        if len(p) < 44 or p[0] != 0x16 or p[5] != 0x01:
            return None
        i = 43
        i += 1 + p[i]                                   # session id
        i += 2 + int.from_bytes(p[i:i + 2], "big")      # cipher suites
        i += 1 + p[i]                                   # compression
        ext_len = int.from_bytes(p[i:i + 2], "big")
        i += 2
        cut = i + ext_len > len(p)
        end = min(len(p), i + ext_len)
        sni, ech = None, False
        while i + 4 <= end:
            t = int.from_bytes(p[i:i + 2], "big")
            n = int.from_bytes(p[i + 2:i + 4], "big")
            body = p[i + 4:i + 4 + n]
            i += 4 + n
            if t == 0:
                j = 2
                while j + 3 <= len(body):
                    nl = int.from_bytes(body[j + 1:j + 3], "big")
                    if body[j] == 0:
                        cand = body[j + 3:j + 3 + nl].decode("ascii", "ignore").lower().rstrip(".")
                        sni = cand if _SNI_OK.match(cand) else None
                        break
                    j += 3 + nl
            elif t == 0xFE0D:
                ech = True
        return {"src": src, "dst": dst, "dport": dport, "sni": sni, "ech": ech, "cut": cut}
    except (IndexError, struct.error, ValueError):
        return None


class HexAssembler:
    """Reassembles `tcpdump -x` output (header line, then indented hex lines) into packets,
    emitting each as soon as its bytes are complete (so a quiet network is not delayed
    until the NEXT packet arrives)."""

    def __init__(self):
        self.cur = bytearray()
        self.want = None

    def feed(self, line: str):
        if line[:1] not in (" ", "\t"):             # a new packet header
            out = bytes(self.cur) if self.cur else None
            self.cur, self.want = bytearray(), None
            return out
        m = HEXLINE_RE.match(line)
        if not m:
            return None
        self.cur += bytes.fromhex(m.group(1).replace(" ", ""))
        if self.want is None and len(self.cur) >= 4:
            self.want = min(struct.unpack(">H", bytes(self.cur[2:4]))[0], SNAP_IP)
        if self.want is not None and len(self.cur) >= self.want:
            out = bytes(self.cur)
            self.cur, self.want = bytearray(), None
            return out
        return None


# ---- DNS tunnelling -----------------------------------------------------------

def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


class TunnelDetector:
    """Data smuggled through DNS (iodine, dnscat2...) looks like MANY distinct, long or
    random-looking sub-names under one domain from one device in a short window, often as
    TXT/NULL queries, or a single very long random label. Returns the base domain the
    first time a pattern trips for a (device, domain) in the window."""

    def __init__(self, window=60, min_unique=40, long_label=50):
        self.window, self.min_unique, self.long_label = window, min_unique, long_label
        self.m = {}

    def observe(self, client, qname, qtype, now):
        labels = qname.split(".")
        if len(labels) < 3:
            return None
        base, sub = base_domain(qname), ".".join(labels[:-2])
        e = self.m.get((client, base))
        if e is None or now - e["t0"] > self.window:
            if len(self.m) > 5000:
                self.m = {k: v for k, v in self.m.items() if now - v["t0"] <= self.window}
            e = self.m[(client, base)] = {"t0": now, "names": set(), "txt": 0, "flag": False}
        e["names"].add(sub)
        if qtype in ("TXT", "NULL", "CNAME", "MX"):
            e["txt"] += 1
        longest = max(labels[:-2], key=len)
        single = len(longest) >= self.long_label and entropy(longest) >= 3.5
        n = len(e["names"])
        many = n >= self.min_unique and (
            sum(len(x) for x in e["names"]) / n >= 16
            or sum(entropy(x) for x in e["names"]) / n >= 3.3
            or e["txt"] >= self.min_unique // 2)
        if (single or many) and not e["flag"]:
            e["flag"] = True
            return base
        return None


TUNNELS = TunnelDetector()
_RECENT_DNS = {}                      # (client, base domain) -> last time that device asked
_RECENT_TTL = 3600


def dns_seen_recently(client, name, now=None, ttl=_RECENT_TTL):
    now = time.time() if now is None else now
    t = _RECENT_DNS.get((client, base_domain(name)))
    return t is not None and now - t <= ttl


# ---- public lists: VPN server ranges, Tor default bridges -------------------------

def _ip2int(s):
    parts = s.split(".")
    if len(parts) != 4:
        raise ValueError("not an IPv4 address")
    a, b, c, d = (int(x) for x in parts)
    if not all(0 <= x <= 255 for x in (a, b, c, d)):
        raise ValueError("octet out of range")
    return (a << 24) | (b << 16) | (c << 8) | d


def _is_global_int(n):
    a = n >> 24
    b = (n >> 16) & 255
    if a in (0, 10, 127) or a >= 224:
        return False
    return not ((a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 169 and b == 254)
                or (a == 100 and 64 <= b <= 127))


def parse_ranges(text: str):
    """Pure. One IPv4 CIDR or address per line -> (starts, ends) of MERGED, sorted,
    global-only intervals. Private/reserved entries and junk are ignored."""
    iv = []
    for ln in text.splitlines():
        ln = ln.strip().split("#")[0].strip()
        if not ln:
            continue
        try:
            ip, _, bits = ln.partition("/")
            bits = int(bits) if bits else 32
            base = _ip2int(ip)
            if not 0 <= bits <= 32:
                continue
            size = 1 << (32 - bits)
            start = base & ~(size - 1) & 0xFFFFFFFF
            if _is_global_int(start) and _is_global_int(start + size - 1):
                iv.append((start, start + size - 1))
        except (ValueError, IndexError):
            continue
    iv.sort()
    merged = []
    for st, en in iv:
        if merged and st <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], en))
        else:
            merged.append((st, en))
    return [m[0] for m in merged], [m[1] for m in merged]


_VPN = {"starts": [], "ends": [], "mtime": 0.0}


def vpn_match(ip: str, tables=None) -> bool:
    t = tables or _VPN
    try:
        n = _ip2int(ip)
    except (ValueError, IndexError):
        return False
    i = bisect.bisect_right(t["starts"], n) - 1
    return i >= 0 and n <= t["ends"][i]


def parse_bridge_ips(text: str) -> set:
    """Pure. Tor Browser's pt_config.json -> public IPv4 addresses of its built-in bridges
    (documentation/placeholder addresses such as 192.0.2.x are ignored)."""
    ips = set()
    for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}\b", text):
        try:
            if _is_global_int(_ip2int(m.group(1))) and not m.group(1).startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
                ips.add(m.group(1))
        except ValueError:
            continue
    return ips


def _fetch_text(url, timeout=60):
    body, code = _curl(["-L", url], timeout=timeout)
    return body if code is not None and 200 <= code < 300 and body else None


def load_vpn_ranges():
    try:
        st = VPN_RANGES_PATH.stat()
        if st.st_mtime != _VPN["mtime"]:
            starts, ends = parse_ranges(VPN_RANGES_PATH.read_text())
            with _LOCK:
                _VPN.update(starts=starts, ends=ends, mtime=st.st_mtime)
    except Exception:
        pass


def _file_age(path):
    try:
        return time.time() - path.stat().st_mtime
    except Exception:
        return None


def lists_loop():
    """Daily refresh of the VPN range list and Tor's default bridges. A failed fetch keeps
    the last good copy; a copy that parses to nothing is never written."""
    while True:
        try:
            load_vpn_ranges()
            load_tor_bridges()
            if (_file_age(VPN_RANGES_PATH) or 1e12) > LISTS_REFRESH:
                txt = _fetch_text(VPN_RANGES_URL)
                if txt and len(parse_ranges(txt)[0]) > 1000:
                    VPN_RANGES_PATH.write_text(txt)
                    load_vpn_ranges()
                    print(f"[eyeguard-dnsnet] vpn ranges refreshed: {len(_VPN['starts'])} intervals", flush=True)
            if (_file_age(TOR_BRIDGES_PATH) or 1e12) > LISTS_REFRESH:
                txt = _fetch_text(TOR_BRIDGES_URL)
                ips = parse_bridge_ips(txt) if txt else set()
                if ips:
                    TOR_BRIDGES_PATH.write_text(json.dumps({"ips": sorted(ips)}))
                    load_tor_bridges()
                    print(f"[eyeguard-dnsnet] tor default bridges refreshed: {len(ips)}", flush=True)
        except Exception as ex:
            # one bad refresh (full disk, odd response) must never end the refresh loop
            print(f"[eyeguard-dnsnet] list refresh {type(ex).__name__}: {ex}", flush=True)
        time.sleep(LISTS_RETRY if _file_age(VPN_RANGES_PATH) is None else 3600)


# ---- state -----------------------------------------------------------------

_LOCK = threading.Lock()
_SEEN: dict = {}                       # (client, cls, target) -> last alert time
_STATS = {"since": time.time(), "dns_queries": 0, "dns_classified": 0,
          "alerts": {}, "observed": {}, "suppressed_covered": 0, "excluded_skipped": 0}
_TOR = {"ips": set(), "mtime": 0.0, "bridges": set(), "all": set(), "bmtime": 0.0}
_COVER = {"map": {}, "alive": {}, "checked": 0.0}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _curl(args, timeout=15):
    try:
        p = subprocess.run(["curl", "-s", "--max-time", str(timeout),
                            "-w", "\n%{http_code}"] + args,
                           capture_output=True, text=True)
    except Exception:
        return "", None
    body, _, code = p.stdout.rpartition("\n")
    code = code.strip()
    return body, (int(code) if code.isdigit() else None)


def _post_flags(row) -> bool:
    """Retry transient failures (never 4xx), bounded at 45 s. A dropped flag is
    a missed alert, so failures are logged."""
    args = [f"{SB}/rest/v1/flags", "-H", f"apikey: {API_KEY}",
            "-H", f"Authorization: Bearer {API_KEY}",
            "-H", "Content-Type: application/json", "-H", "Prefer: return=minimal",
            "-X", "POST", "-d", json.dumps(row)]
    deadline = time.time() + 45
    code = None
    for delay in (0, 3, 9, 20):
        if delay:
            if time.time() + delay >= deadline:
                break
            time.sleep(delay)
        _, code = _curl(args, timeout=max(2, min(15, int(deadline - time.time()))))
        if code is not None and 200 <= code < 300:
            return True
        if code is not None and 400 <= code < 500:
            break
    print(f"[eyeguard-dnsnet] {now_iso()} flag write FAILED http={code}", flush=True)
    return False


_OUTBOX: "queue.Queue" = queue.Queue(maxsize=500)


def _emit(row) -> bool:
    """Hand a flag to the sender thread. Never blocks packet processing: when the
    backend is down the capture keeps reading and the sender retries (bounded
    queue; a full queue is logged, never silent)."""
    try:
        _OUTBOX.put_nowait(row)
        return True
    except queue.Full:
        print(f"[eyeguard-dnsnet] {now_iso()} outbox FULL, alert dropped: "
              f"{row.get('reason', '')[:80]}", flush=True)
        return False


def sender_loop():
    while True:
        row = _OUTBOX.get()
        _post_flags(row)


_MACX = {"ips": set(), "at": 0.0}


def parse_leases(text: str) -> dict:
    """Pure. dnsmasq lease file -> {ip: mac}."""
    out = {}
    for ln in text.splitlines():
        f = ln.split()
        if len(f) >= 3 and re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", f[1]):
            out[f[2]] = f[1].lower()
    return out


def parse_neigh(text: str) -> dict:
    """Pure. `ip neigh` output -> {ip: mac}."""
    out = {}
    for ln in text.splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+) .*lladdr ((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", ln)
        if m:
            out[m.group(1)] = m.group(2).lower()
    return out


def excluded_by_mac(ttl: float = 30.0) -> set:
    """IPs that currently belong to an excluded MAC (lease file + neighbor table)."""
    now = time.time()
    if now - _MACX["at"] > ttl:
        ips = set()
        try:
            for ip, mac in parse_leases(open(LEASES).read()).items():
                if mac in EXCLUDED_MACS:
                    ips.add(ip)
        except Exception:
            pass
        try:
            out = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5).stdout
            for ip, mac in parse_neigh(out).items():
                if mac in EXCLUDED_MACS:
                    ips.add(ip)
        except Exception:
            pass
        _MACX["ips"], _MACX["at"] = ips, now
    return _MACX["ips"]


def is_excluded(ip: str) -> bool:
    return ip in EXCLUDED or ip in excluded_by_mac()


def parse_dhcp_hosts(text: str) -> tuple:
    """Pure. /etc/config/dhcp -> ({mac: name}, {ip: name}) for static `config host` entries."""
    by_mac, by_ip = {}, {}
    cur = None
    for ln in text.splitlines():
        t = ln.strip()
        if t.startswith("config "):
            if cur is not None:
                _store_host(cur, by_mac, by_ip)
            cur = {} if t.split()[1] == "host" else None
        elif cur is not None:
            m = re.match(r"option\s+(\w+)\s+['\"]?([^'\"]*)['\"]?\s*$", t)
            if m:
                cur[m.group(1)] = m.group(2)
    if cur is not None:
        _store_host(cur, by_mac, by_ip)
    return by_mac, by_ip


def _store_host(h, by_mac, by_ip):
    name = h.get("name") or h.get("tag")
    if not name:
        return
    for mac in h.get("mac", "").lower().split():
        by_mac[mac] = name
    if h.get("ip"):
        by_ip[h["ip"]] = name


def is_private_mac(mac: str) -> bool:
    """Locally administered bit set = a randomized (iOS 'Private Wi-Fi Address') MAC."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def segment_of(ip: str) -> str:
    for prefix, name in SEGMENTS.items():
        if ip.startswith(prefix):
            return name
    return "network"


_IDENT = {"at": 0.0, "mac_of": {}, "host_of": {}, "static_mac": {}, "static_ip": {}}


def _refresh_identity(ttl=30.0, now=None):
    now = time.time() if now is None else now
    if now - _IDENT["at"] <= ttl:
        return
    mac_of, host_of = {}, {}
    try:
        for ln in open(LEASES).read().splitlines():
            f = ln.split()
            if len(f) >= 4:
                mac_of[f[2]] = f[1].lower()
                if f[3] not in ("*", ""):
                    host_of[f[2]] = f[3]
    except Exception:
        pass
    try:
        out = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5).stdout
        for ip, mac in parse_neigh(out).items():
            mac_of.setdefault(ip, mac)
    except Exception:
        pass
    smac, sip = {}, {}
    try:
        smac, sip = parse_dhcp_hosts(open(DHCP_CONFIG).read())
    except Exception:
        pass
    _IDENT.update(at=now, mac_of=mac_of, host_of=host_of, static_mac=smac, static_ip=sip)


def identify(ip: str) -> dict:
    """Everything the router can say about the device behind an address."""
    _refresh_identity()
    mac = _IDENT["mac_of"].get(ip)
    name = (DEVICE_NAMES.get(ip) or (mac and _IDENT["static_mac"].get(mac))
            or _IDENT["static_ip"].get(ip) or _IDENT["host_of"].get(ip))
    return {"ip": ip, "mac": mac, "name": name, "segment": segment_of(ip),
            "private": bool(mac and is_private_mac(mac))}


def format_device(d: dict) -> str:
    """'Jonahs-iPhone: 192.168.8.153, MAC 6e:.. (randomized address), home LAN'."""
    bits = [d["ip"]]
    if d.get("mac"):
        bits.append(f"MAC {d['mac']}" + (" (randomized address)" if d.get("private") else ""))
    bits.append(d["segment"])
    return f"{d.get('name') or 'UNKNOWN device'}: " + ", ".join(bits)


def device_label(ip: str) -> str:
    return format_device(identify(ip))


# ---- overlap with the per-phone monitors -----------------------------------

def load_covered(paths=(("/etc/eyeguard/phone.json", "primary"),
                        ("/etc/eyeguard/phone-jada.json", "jada"))):
    """ip -> instance name for the devices the phone monitors already cover."""
    out = {}
    for path, name in paths:
        try:
            c = json.load(open(path))
        except Exception:
            continue
        for k in ("home_ip", "wg_ip"):
            if c.get(k):
                out[c[k]] = name
    return out


def phone_instances_alive(ps_out: str) -> dict:
    """Pure. -> {'primary': bool, 'jada': bool} from `ps w`."""
    primary = jada = False
    for line in ps_out.splitlines():
        if "eyeguard-phone.py" not in line:
            continue
        if "phone-jada.json" in line:
            jada = True
        elif "--conf" not in line:
            primary = True
    return {"primary": primary, "jada": jada}


def covered_by_live_monitor(ip: str, cls: str, now: float | None = None) -> bool:
    """True when the phone monitor for this IP is running AND would raise the
    same class itself. Only explicit-dns, doh-ip and tor-guard overlap."""
    if cls not in ("explicit-dns", "doh-ip", "tor-guard"):
        return False
    now = now or time.time()
    with _LOCK:
        stale = now - _COVER["checked"] > 30
    if stale:
        try:
            alive = phone_instances_alive(subprocess.run(
                ["ps", "w"], capture_output=True, text=True, timeout=10).stdout)
        except Exception:
            alive = {"primary": False, "jada": False}   # unknown -> alert (safe side)
        with _LOCK:
            _COVER["alive"] = alive
            _COVER["checked"] = now
            if not _COVER["map"]:
                _COVER["map"] = load_covered()
    with _LOCK:
        inst = _COVER["map"].get(ip)
        return bool(inst and _COVER["alive"].get(inst))


# ---- raising -----------------------------------------------------------------

_TITLES = {
    "explicit-dns": "explicit domain",
    "explicit-sni": "explicit site name in a TLS handshake (no DNS lookup seen: DNS was cached or bypassed)",
    "vpn-ip": "known VPN server contacted",
    "tls-no-sni": "TLS connection with no server name",
    "ech-hidden": "site name hidden by Encrypted Client Hello",
    "dns-tunnel": "possible DNS tunnelling",
    "tor-guard": "Tor entry relay or default bridge contacted",
    "tor-domain": "Tor project lookup",
    "doh-ip": "DNS-over-HTTPS provider contacted",
    "dot-attempt": "DNS-over-TLS/QUIC attempt (port 853)",
    "vpn-domain": "VPN/proxy provider lookup",
    "private-relay": "iCloud Private Relay lookup",
    "vpn-port": "VPN protocol traffic",
    "wg-handshake": "WireGuard tunnel handshake to the internet",
    "ipv6-enabled": "IPv6 enabled on a client network",
    "dns-bypass": "DNS sent to an outside resolver",
    "doh-host": "encrypted-DNS provider lookup",
    "ike-ipsec": "IPsec/IKE traffic",
    "openvpn-udp": "OpenVPN-like UDP",
    "proxy-port": "proxy port traffic",
}


def raise_event(client: str, cls: str, target: str, now: float | None = None) -> str:
    """-> 'alerted' | 'observed' | 'throttled' | 'excluded' | 'covered'.
    The single decision point for every signal."""
    now = now or time.time()
    if is_excluded(client):
        with _LOCK:
            _STATS["excluded_skipped"] += 1
        return "excluded"
    if cls not in ALERT_CLASSES:
        with _LOCK:
            d = _STATS["observed"].setdefault(cls, {})
            d[target] = d.get(target, 0) + 1
            if len(d) > 200:
                d.pop(next(iter(d)))
        return "observed"
    if covered_by_live_monitor(client, cls, now):
        with _LOCK:
            _STATS["suppressed_covered"] += 1
        return "covered"
    key = (client, cls, target)
    with _LOCK:
        if now - _SEEN.get(key, 0) < THROTTLE:
            return "throttled"
        _SEEN[key] = now
        if len(_SEEN) > 5000:
            for k in [k for k, t in _SEEN.items() if now - t > THROTTLE]:
                del _SEEN[k]
        _STATS["alerts"][cls] = _STATS["alerts"].get(cls, 0) + 1
    explicit = cls in ("explicit-dns", "explicit-sni")
    who = device_label(client)
    prefix = "net-signal" if explicit else "net-bypass"
    _emit({
        "flagged_at": now_iso(), "verdict": "flagged",
        "reason": f"{prefix}: {_TITLES.get(cls, cls)} {target} from {who}",
        "app": "Network", "url": None,
        "window_title": f"{_TITLES.get(cls, cls)}: {target} -- {identify(client).get('name') or client}",
        "grade": "Likely", "risk": "high", "is_nudity": False})
    return "alerted"


# ---- decisions for each parsed packet (pure given state) ---------------------

def on_dns(client: str, resolver: str, qname: str, local_ips: set,
           now: float | None = None, qtype: str | None = None) -> list:
    """Apply every DNS-derived rule to one query. Returns list of results."""
    out = []
    t_now = time.time() if now is None else now
    with _LOCK:
        _STATS["dns_queries"] += 1
        _RECENT_DNS[(client, base_domain(qname))] = t_now
        if len(_RECENT_DNS) > 20000:
            for k in [k for k, t in _RECENT_DNS.items() if t_now - t > _RECENT_TTL]:
                del _RECENT_DNS[k]
    tunnel = TUNNELS.observe(client, qname, qtype, t_now)
    if tunnel and not is_noise(tunnel):
        out.append(raise_event(client, "dns-tunnel", tunnel, now))
    if resolver not in local_ips and resolver not in TRUSTED_DESTS:
        out.append(raise_event(client, "dns-bypass", resolver, now))
    c = classify(qname)
    if c:
        with _LOCK:
            _STATS["dns_classified"] += 1
        if c[0] == "flagged":
            out.append(raise_event(client, "explicit-dns", base_domain(qname), now))
    if host_matches(qname, VPN_DOMAINS):
        out.append(raise_event(client, "vpn-domain", host_matches(qname, VPN_DOMAINS), now))
    if host_matches(qname, TOR_DOMAINS):
        out.append(raise_event(client, "tor-domain", host_matches(qname, TOR_DOMAINS), now))
    if host_matches(qname, PRIVATE_RELAY):
        out.append(raise_event(client, "private-relay", host_matches(qname, PRIVATE_RELAY), now))
    if host_matches(qname, DOH_HOSTS):
        out.append(raise_event(client, "doh-host", host_matches(qname, DOH_HOSTS), now))
    return out


def on_flow(src: str, dst: str, dport: int, proto: str, local_ips: set,
            tor_ips, now: float | None = None) -> list:
    """Apply every flow-start rule. proto is 'tcp' (a SYN) or 'udp'."""
    if dst in local_ips or dst in TRUSTED_DESTS:
        return []          # traffic to the router/G11 is the household's own tunnel/DNS
    out = []
    if vpn_match(dst):
        out.append(raise_event(src, "vpn-ip", dst, now))
    if proto == "tcp":
        if dst in tor_ips:
            out.append(raise_event(src, "tor-guard", dst, now))
        if dport == 853:
            out.append(raise_event(src, "dot-attempt", f"{dst}:853", now))
        if dport == 443 and dst in DOH_IPS:
            out.append(raise_event(src, "doh-ip", dst, now))
        if dport in VPN_TCP_PORTS:
            out.append(raise_event(src, "vpn-port", f"{VPN_TCP_PORTS[dport]} {dst}:{dport}", now))
        if dport in PROXY_PORTS:
            out.append(raise_event(src, "proxy-port", f"{PROXY_PORTS[dport]} {dst}:{dport}", now))
    else:
        if dport == 853:
            out.append(raise_event(src, "dot-attempt", f"{dst}:853/udp", now))
        if dport in VPN_UDP_PORTS:
            out.append(raise_event(src, "vpn-port", f"{VPN_UDP_PORTS[dport]} {dst}:{dport}", now))
        if dport in (500, 4500):
            out.append(raise_event(src, "ike-ipsec", f"{dst}:{dport}", now))
    return out


def on_sni(client: str, dst: str, sni: str | None, ech: bool, cut: bool, local_ips: set,
           now: float | None = None) -> list:
    """Rules for the server name in a TLS ClientHello. A name the device ALSO just looked up
    in DNS is skipped (the DNS rule already spoke); what is left is DNS that was cached,
    encrypted or bypassed."""
    if dst in local_ips or dst in TRUSTED_DESTS:
        return []
    t_now = time.time() if now is None else now
    with _LOCK:
        _STATS["sni_seen"] = _STATS.get("sni_seen", 0) + 1
    if sni is None:
        if cut:
            with _LOCK:
                _STATS["sni_unparsed"] = _STATS.get("sni_unparsed", 0) + 1
            return []
        return [raise_event(client, "tls-no-sni", dst, now)]
    out = []
    if host_matches(sni, ECH_PUBLIC_NAMES):
        out.append(raise_event(client, "ech-hidden", host_matches(sni, ECH_PUBLIC_NAMES), now))
    if dns_seen_recently(client, sni, t_now):
        with _LOCK:
            _STATS["sni_dns_dup"] = _STATS.get("sni_dns_dup", 0) + 1
        return out
    c = classify(sni)
    if c and c[0] == "flagged":
        out.append(raise_event(client, "explicit-sni", base_domain(sni), now))
    for suffixes, cls in ((VPN_DOMAINS, "vpn-domain"), (TOR_DOMAINS, "tor-domain"),
                          (PRIVATE_RELAY, "private-relay"), (DOH_HOSTS, "doh-host")):
        hit = host_matches(sni, suffixes)
        if hit:
            out.append(raise_event(client, cls, hit, now))
    return out


def on_wg_handshake(src: str, dst: str, dport: int, local_ips: set,
                    now: float | None = None) -> list:
    """A WireGuard handshake initiation (UDP, 148-byte payload, type 1) from a
    client to a non-household address: a tunnel on any port."""
    if dst in local_ips or dst in TRUSTED_DESTS:
        return []
    return [raise_event(src, "wg-handshake", f"{dst}:{dport}", now)]


# ---- environment -------------------------------------------------------------

_LOCAL = {"ips": set(), "at": 0.0}


def local_ips(ttl: float = 60.0) -> set:
    """The router's own IPv4 addresses (LAN gateways, tunnel, and the current WAN
    address), refreshed at most every `ttl` seconds."""
    now = time.time()
    if not _LOCAL["ips"] or now - _LOCAL["at"] > ttl:
        _LOCAL["ips"] = router_local_ips()
        _LOCAL["at"] = now
    return _LOCAL["ips"]


def router_local_ips() -> set:
    """Router addresses (+ dnsnet_local_ips from config). Uses plain
    `ip -4 addr show`, which every iproute/BusyBox build supports."""
    ips = {"127.0.0.1"} | set(CONF.get("dnsnet_local_ips", []))
    try:
        out = subprocess.run(["ip", "-4", "addr", "show"], capture_output=True,
                             text=True, timeout=10).stdout
        found = set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/", out))
        ips |= found
        if not found and not _LOCAL.get("warned"):
            _LOCAL["warned"] = True
            print("[eyeguard-dnsnet] WARNING: no router addresses found; every resolver "
                  "would look like a bypass. Set dnsnet_local_ips.", flush=True)
    except Exception as ex:
        print(f"[eyeguard-dnsnet] local address lookup failed: {ex}", flush=True)
    return ips


def load_tor():
    try:
        st = TOR_CACHE.stat()
        if st.st_mtime != _TOR["mtime"]:
            data = json.loads(TOR_CACHE.read_text())
            with _LOCK:
                _TOR["ips"] = set(data.get("ips", []))
                _TOR["mtime"] = st.st_mtime
                _TOR["all"] = _TOR["ips"] | _TOR["bridges"]
    except Exception:
        pass


def load_tor_bridges():
    try:
        st = TOR_BRIDGES_PATH.stat()
        if st.st_mtime != _TOR["bmtime"]:
            data = json.loads(TOR_BRIDGES_PATH.read_text())
            with _LOCK:
                _TOR["bridges"] = set(data.get("ips", []))
                _TOR["bmtime"] = st.st_mtime
                _TOR["all"] = _TOR["ips"] | _TOR["bridges"]
    except Exception:
        pass


def tor_all():
    with _LOCK:
        return _TOR["all"]


def tor_age() -> float | None:
    try:
        return time.time() - TOR_CACHE.stat().st_mtime
    except Exception:
        return None


def tor_refresh_loop():
    """The primary phone monitor owns the guard-list refresh and writes the
    cache. This daemon reloads it, and refreshes it ITSELF only if the cache is
    missing or older than twice the refresh period (phone monitor down)."""
    while True:
        load_tor()
        age = tor_age()
        if age is None or age > 2 * TOR_REFRESH:
            body, code = _curl(["https://onionoo.torproject.org/summary"
                                "?type=relay&running=true&flag=Guard"], timeout=30)
            try:
                ips = {a for r in json.loads(body).get("relays", [])
                       for a in r.get("a", []) if a and not a.startswith("[")}
                if ips:
                    TOR_CACHE.write_text(json.dumps({"ips": sorted(ips)}))
                    load_tor()
                    print(f"[eyeguard-dnsnet] tor guard list refreshed: {len(ips)}", flush=True)
            except Exception as ex:
                print(f"[eyeguard-dnsnet] tor refresh failed: {ex}", flush=True)
        time.sleep(600)


# ---- capture loops -----------------------------------------------------------

_CHILDREN: set = set()


def _spawn(iface: str, filt: str, snaplen: int = 256, hexdump: bool = False):
    proc = subprocess.Popen(["tcpdump", "-i", iface, "-l", "-nn"] + (["-x"] if hexdump else [])
                            + ["-s", str(snaplen), filt],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, bufsize=1)
    with _LOCK:
        _CHILDREN.add(proc)
    return proc


def _terminate(signum=None, frame=None):
    """procd stop: take the tcpdump children down WITH us so nothing is orphaned."""
    with _LOCK:
        kids = list(_CHILDREN)
    for k in kids:
        try:
            k.terminate()
        except Exception:
            pass
    os._exit(0)


# dst port 53 on EVERY resolver address, not just the router: a query sent to
# 8.8.8.8:53 is visible before the NAT redirect and is a bypass attempt.
DNS_FILTER = "(udp or tcp) and dst port 53"
# New TCP connections only (SYN, no ACK): cheap and sufficient.
SYN_FILTER = "tcp and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"


CAPTURES_PER_IFACE = 5          # dns, new-connection, wireguard, vpn/doq ports, tls hello


def dns_loop(iface: str):
    filt = DNS_FILTER
    while True:
        try:
            proc = _spawn(iface, filt)
            for line in proc.stdout:
                local = local_ips()
                p = parse_dns_query(line)
                if p and p[0] not in local:
                    on_dns(p[0], p[1], p[2], local, qtype=p[3])
            proc.wait()
        except Exception as ex:
            print(f"[eyeguard-dnsnet] dns({iface}) {type(ex).__name__}: {ex}", flush=True)
        time.sleep(5)


def flow_loop(iface: str):
    filt = SYN_FILTER
    while True:
        try:
            proc = _spawn(iface, filt)
            for line in proc.stdout:
                local = local_ips()
                f = parse_flow_line(line)
                if f and f[0] not in local:
                    tor = tor_all()
                    on_flow(f[0], f[2], f[3], "tcp", local, tor)
            proc.wait()
        except Exception as ex:
            print(f"[eyeguard-dnsnet] flow({iface}) {type(ex).__name__}: {ex}", flush=True)
        time.sleep(5)


# WireGuard initiation: UDP payload 148 bytes (IP total 176), type byte 1 then
# three zero bytes. BPF reads the UDP payload's first four bytes. Its own
# capture so a match can never be confused with the port-based view below.
WG_FILTER = "udp and ip[2:2] = 176 and udp[8:4] = 0x01000000"
UDP_FILTER = ("udp and (dst port 853 or dst port 500 or dst port 4500 "
              "or dst port 1194 or dst port 51820 or dst port 1701)")


def wg_loop(iface: str):
    while True:
        try:
            proc = _spawn(iface, WG_FILTER)
            for line in proc.stdout:
                local = local_ips()
                f = parse_flow_line(line)
                if f and f[0] not in local:
                    on_wg_handshake(f[0], f[2], f[3], local)
            proc.wait()
        except Exception as ex:
            print(f"[eyeguard-dnsnet] wg({iface}) {type(ex).__name__}: {ex}", flush=True)
        time.sleep(5)


def udp_loop(iface: str):
    """Well-known VPN / DNS-over-QUIC UDP ports."""
    while True:
        try:
            proc = _spawn(iface, UDP_FILTER)
            for line in proc.stdout:
                local = local_ips()
                f = parse_flow_line(line)
                if f and f[0] not in local:
                    tor = tor_all()
                    on_flow(f[0], f[2], f[3], "udp", local, tor)
            proc.wait()
        except Exception as ex:
            print(f"[eyeguard-dnsnet] udp({iface}) {type(ex).__name__}: {ex}", flush=True)
        time.sleep(5)


# TLS ClientHello: a TCP segment to :443 whose payload starts 0x16 (handshake), with
# handshake type 0x01 five bytes in. Handshakes only, so volume is small. Snaplen covers a
# whole ClientHello (Chrome randomises extension order, so the SNI can sit late).
SNI_SNAPLEN = 1500
SNI_FILTER = ("tcp dst port 443 and tcp[((tcp[12] & 0xf0) >> 2)] = 0x16 "
              "and tcp[((tcp[12] & 0xf0) >> 2) + 5] = 0x01")


def sni_loop(iface: str):
    while True:
        try:
            proc = _spawn(iface, SNI_FILTER, snaplen=SNI_SNAPLEN, hexdump=True)
            asm = HexAssembler()
            for line in proc.stdout:
                pkt = asm.feed(line)
                if pkt is None:
                    continue
                h = parse_client_hello(pkt)
                if h and h["src"] not in local_ips():
                    on_sni(h["src"], h["dst"], h["sni"], h["ech"], h["cut"], local_ips())
            proc.wait()
        except Exception as ex:
            print(f"[eyeguard-dnsnet] sni({iface}) {type(ex).__name__}: {ex}", flush=True)
        time.sleep(5)


def invariants_loop():
    """Tripwire: IPv6 on a client segment would let traffic skip these captures
    (they are IPv4-only). Alert once per change, as a client-less router event."""
    while True:
        time.sleep(300)
        for iface in IFACES:
            try:
                v = open(f"/proc/sys/net/ipv6/conf/{iface}/disable_ipv6").read().strip()
            except Exception:
                continue
            if v == "0":
                raise_event("router", "ipv6-enabled", iface)


def stats_loop():
    last_log = time.time()
    while True:
        time.sleep(STATS_SECONDS)
        with _LOCK:
            snap = json.loads(json.dumps(_STATS, default=str))
        snap["written_at"] = now_iso()
        snap["tor_guard_ips"] = len(_TOR["ips"])
        snap["tor_default_bridges"] = len(_TOR["bridges"])
        snap["vpn_intervals"] = len(_VPN["starts"])
        with _LOCK:
            for k in [k for k in _CHILDREN if k.poll() is not None]:
                _CHILDREN.discard(k)
            snap["captures"] = len(_CHILDREN)
        snap["expected_captures"] = len(IFACES) * CAPTURES_PER_IFACE
        try:
            STATS_PATH.write_text(json.dumps(snap))
        except Exception:
            pass
        if time.time() - last_log >= STATS_LOG_SECONDS:
            last_log = time.time()
            obs = {k: sum(v.values()) for k, v in snap.get("observed", {}).items()}
            print(f"[eyeguard-dnsnet] {now_iso()} stats: dns={snap['dns_queries']} "
                  f"alerts={snap['alerts']} observed={obs} "
                  f"covered={snap['suppressed_covered']} tor_ips={snap['tor_guard_ips']} "
                  f"captures={snap['captures']}/{snap['expected_captures']}",
                  flush=True)


def main():
    import signal
    signal.signal(signal.SIGTERM, _terminate)
    load_tor()
    load_tor_bridges()
    load_vpn_ranges()
    print(f"[eyeguard-dnsnet] active on {IFACES}; alert classes: "
          f"{sorted(ALERT_CLASSES)}; excluded: {sorted(EXCLUDED)} + macs {sorted(EXCLUDED_MACS)}", flush=True)
    for fn in (tor_refresh_loop, invariants_loop, stats_loop, sender_loop, lists_loop):
        threading.Thread(target=fn, daemon=True).start()
    for iface in IFACES:
        for fn in (dns_loop, flow_loop, wg_loop, udp_loop, sni_loop):
            threading.Thread(target=fn, args=(iface,), daemon=True).start()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
