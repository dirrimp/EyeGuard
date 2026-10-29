#!/usr/bin/env python3
"""dnsnet_expected_tunnels: the G11's Proton tunnel is silent, nothing else is.

Controls: with the config empty (default) the same packets MUST alert; a different source,
destination range, port, protocol, or a different class from the same device MUST still alert.
Run: python3 tests/test_dnsnet_expected_tunnel.py
"""
import importlib.util, json, os, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
G11, MAC, PROTON = "192.168.8.231", "192.168.8.150", "217.138.198.246"
BASE = {"api_key": "t", "supabase_url": "https://example.invalid", "explicit_terms": ["porn"],
        "noise_domains": [], "app_map": {}, "home_ip": "192.168.8.153", "wg_ip": "10.1.0.3"}
fails = []


def check(name, cond):
    print(("  [ok  ] " if cond else "  [FAIL] ") + name)
    if not cond:
        fails.append(name)


def load(extra):
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump({**BASE, **extra}, f); f.close()
    os.environ["EG_PHONE_CONF"] = f.name
    spec = importlib.util.spec_from_file_location("dn_t", ROOT / "router" / "eyeguard-dnsnet.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    os.unlink(f.name)
    sent = []
    m.raise_event = lambda client, cls, target, now=None: (sent.append((client, cls, target)) or cls)
    return m, sent


ENTRY = [{"src": G11, "dst": "217.138.198.0/24", "port": 51820}]

# control: default config -> alerts (the rule must not silence anything by default)
dn, sent = load({})
dn.on_flow(G11, PROTON, 51820, "udp", set(), set(), now=1)
dn.on_wg_handshake(G11, PROTON, 51820, set(), now=1)
classes = {c for _, c, _ in sent}
check("control: default alerts vpn-port", "vpn-port" in classes)
check("control: default alerts wg-handshake", "wg-handshake" in classes)
vpn_listed = dn.vpn_match(PROTON)
print(f"  (info) {PROTON} in loaded VPN list: {vpn_listed} (list may be empty in this sandbox)")

dn, sent = load({"dnsnet_expected_tunnels": ENTRY})
dn.on_flow(G11, PROTON, 51820, "udp", set(), set(), now=1)
dn.on_wg_handshake(G11, PROTON, 51820, set(), now=1)
check("expected G11 -> Proton:51820 is silent", sent == [])

for label, call in [
    ("other source (the Mac) same dest", lambda: dn.on_flow(MAC, PROTON, 51820, "udp", set(), set(), now=1)),
    ("other dest range", lambda: dn.on_flow(G11, "185.159.158.86", 51820, "udp", set(), set(), now=1)),
    ("other port (1194)", lambda: dn.on_flow(G11, PROTON, 1194, "udp", set(), set(), now=1)),
    ("Mac handshake to same dest", lambda: dn.on_wg_handshake(MAC, PROTON, 51820, set(), now=1)),
    ("G11 handshake to a different server", lambda: dn.on_wg_handshake(G11, "185.159.158.86", 51820, set(), now=1)),
    ("G11 DoT attempt", lambda: dn.on_flow(G11, "1.1.1.1", 853, "tcp", set(), set(), now=1)),
    ("G11 DoH IP", lambda: dn.on_flow(G11, "1.1.1.1", 443, "tcp", set(), set(), now=1)),
    ("G11 Tor guard", lambda: dn.on_flow(G11, "203.0.113.9", 443, "tcp", set(), {"203.0.113.9"}, now=1)),
]:
    del sent[:]
    call()
    check(f"still alerts: {label}", len(sent) >= 1)

# malformed / too broad entries are ignored, never widened
for bad in ({"src": G11, "dst": "217.0.0.0/8", "port": 51820}, {"src": G11, "dst": "0.0.0.0/0", "port": 51820},
            {"src": "300.1.1.1", "dst": PROTON, "port": 51820}, {"src": G11, "dst": PROTON, "port": 0},
            {"src": G11, "dst": PROTON}, "junk"):
    d2, s2 = load({"dnsnet_expected_tunnels": [bad]})
    d2.on_wg_handshake(G11, PROTON, 51820, set(), now=1)
    check(f"bad entry ignored (still alerts): {str(bad)[:44]}", len(s2) == 1)

print("ALL OK" if not fails else f"FAILED {len(fails)}")
sys.exit(1 if fails else 0)
