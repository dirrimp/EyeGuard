#!/usr/bin/env python3
"""Proton website/API visits are observed, real VPN use still alerts; bursts email once.
Controls included: with the new config empty/0 the same packets alert exactly as before; node names, other names, no
name, missing ClientHello, UDP, other ports and every non-grouped class still alert.
Run: python3 tests/test_dnsnet_proton_group.py"""
import importlib.util, json, os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
MAC, G11, PHONE = "192.168.8.150", "192.168.8.231", "192.168.8.2"
BASE = {"api_key": "t", "supabase_url": "https://example.invalid", "explicit_terms": ["porn"],
        "noise_domains": [], "app_map": {}, "home_ip": "192.168.8.153", "wg_ip": "10.1.0.3"}
fails = []
def check(name, cond, detail=""):
    print(("  [ok  ] " if cond else "  [FAIL] ") + name + (f" -- {detail}" if detail and not cond else ""))
    if not cond: fails.append(name)

def load(extra=None):
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False); json.dump({**BASE, **(extra or {})}, f); f.close()
    os.environ["EG_PHONE_CONF"] = f.name
    spec = importlib.util.spec_from_file_location("dn_pg", ROOT / "router" / "eyeguard-dnsnet.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); os.unlink(f.name)
    rows = []
    m._emit = lambda row: (rows.append(row) or True)
    m.vpn_match = lambda ip, tables=None: ip.startswith("185.159.159.")        # Proton's web/API block is in the VPN list
    m.is_excluded = lambda c: False; m.covered_by_live_monitor = lambda c, k, n: False
    m.device_label = lambda c: f"test-device {c}"; m.identify = lambda c: {"name": "test"}
    return m, rows
def kinds(rows): return [(r["verdict"], r["reason"].split(":")[1].strip().split(" ")[0:3]) for r in rows]
IP = "185.159.159.140"; T = 1000.0

# ---- the incident: a Proton account page ----
m, rows = load()
m.on_flow(MAC, IP, 443, "tcp", set(), set(), now=T)
check("a TCP/443 connection to a VPN-list address is held, not alerted at once", rows == [] and (MAC, IP) in m._PENDING)
m.on_sni(MAC, IP, "account.protonvpn.com", False, False, set(), now=T + .2)
check("its ClientHello names account.protonvpn.com -> observed only, no alert", rows == [] and (MAC, IP) not in m._PENDING)
check("...and it is counted as observed (vpn-control-plane)", "vpn-control-plane" in m._STATS["observed"])
m.sweep_pending(now=T + 60)
check("the sweeper does not alert for it afterwards", rows == [])
for name in ("vpncdn.protonweb.com", "account-api.protonvpn.com", "mail.proton.me", "www.protonvpn.ch", "protonvpn.com"):
    m2, r2 = load(); m2.on_flow(MAC, IP, 443, "tcp", set(), set(), now=T); m2.on_sni(MAC, IP, name, False, False, set(), now=T + .1)
    check(f"Proton site/API name {name} is not alerted", r2 == [])

# ---- real VPN use still alerts ----
def alerts_for(sni, cut=False, wait=None):
    m, rows = load(); m.on_flow(MAC, IP, 443, "tcp", set(), set(), now=T)
    if wait is None: m.on_sni(MAC, IP, sni, False, cut, set(), now=T + .1)
    else: m.sweep_pending(now=T + wait)
    return [r["verdict"] for r in rows]
check("a Proton NODE name (*.protonvpn.net) alerts", alerts_for("node-us-12.protonvpn.net") == ["flagged"])
check("a look-alike name (account.protonvpn.com.evil.test) alerts", alerts_for("account.protonvpn.com.evil.test") == ["flagged"])
check("a look-alike suffix (notprotonvpn.com) alerts", alerts_for("notprotonvpn.com") == ["flagged"])
check("an unrelated name on a VPN-list address alerts", alerts_for("example.com") == ["flagged"])
check("a ClientHello with no name alerts", alerts_for(None) == ["flagged"])
check("a truncated ClientHello alerts", alerts_for(None, cut=True) == ["flagged"])
check("no ClientHello at all (e.g. OpenVPN over TCP/443): alerts once PENDING_SECONDS pass, not before",
      alerts_for(None, wait=3.9) == [] and alerts_for(None, wait=4.0) == ["flagged"])
m, rows = load(); m.on_flow(MAC, IP, 443, "udp", set(), set(), now=T)
check("UDP/443 (QUIC) to the address alerts immediately, unchanged", [r["verdict"] for r in rows] == ["flagged"])
m, rows = load(); m.on_flow(MAC, IP, 51820, "udp", set(), set(), now=T)
check("a WireGuard flow (UDP 51820) alerts immediately: vpn-ip and vpn-port", len(rows) == 2 and all(r["verdict"] in ("flagged", "alert") for r in rows)
      and any("WireGuard" in r["reason"] or "port" in r["reason"] for r in rows))
m, rows = load(); m.on_flow(MAC, IP, 1194, "tcp", set(), set(), now=T)
check("OpenVPN TCP/1194 to the address alerts immediately (vpn-ip + vpn-port)", len(rows) >= 1 and (MAC, IP) not in m._PENDING)
m, rows = load({"dnsnet_vpn_control_hosts": []}); m.on_flow(MAC, IP, 443, "tcp", set(), set(), now=T)
check("control: with dnsnet_vpn_control_hosts empty the old behaviour returns (immediate alert)", [r["verdict"] for r in rows] == ["flagged"])
m, rows = load(); m.on_flow(MAC, "93.184.216.34", 443, "tcp", set(), set(), now=T)
check("an address not in the VPN list is untouched (nothing held, nothing raised)", rows == [] and not m._PENDING)

# ---- grouping ----
m, rows = load({"dnsnet_vpn_control_hosts": []})
for i in range(5): m.on_flow(MAC, f"185.159.159.{140 + i}", 443, "tcp", set(), set(), now=T + i)
v = [r["verdict"] for r in rows]
check("five VPN-server alerts in one burst: ONE email (flagged) + four yellow rows", v == ["flagged"] + ["alert"] * 4, str(v))
check("the yellow rows still carry the target, device and say they were grouped", all("185.159.159." in r["reason"] and "grouped" in r["reason"] for r in rows[1:]))
check("every row is still sent (nothing dropped)", len(rows) == 5 and all(r["app"] == "Network" for r in rows))
m.on_flow(MAC, "185.159.159.200", 443, "tcp", set(), set(), now=T + 599)
check("still inside the 10-minute window: yellow", rows[-1]["verdict"] == "alert")
m.on_flow(MAC, "185.159.159.201", 443, "tcp", set(), set(), now=T + 601)
check("10 minutes after the emailed alert: a new episode emails again", rows[-1]["verdict"] == "flagged")
m.on_flow(G11, "185.159.159.150", 443, "tcp", set(), set(), now=T + 602)
check("another device gets its own email", rows[-1]["verdict"] == "flagged")
m, rows = load({"dnsnet_vpn_control_hosts": []})
m.on_flow(MAC, "185.159.159.1", 443, "tcp", set(), set(), now=T); m.on_flow(MAC, "185.159.159.2", 51820, "udp", set(), set(), now=T + 1)
check("a different class (vpn-port) right after is NOT grouped: it emails", [r["verdict"] for r in rows if "port" in r["reason"] or "WireGuard" in r["reason"]].count("flagged") >= 1)
m, rows = load({"dnsnet_vpn_control_hosts": []})
for i, n in enumerate(("porn-a.test", "porn-b.test", "porn-c.test")): m.raise_event(MAC, "explicit-dns", n, T + i)
check("explicit-content alerts are never grouped: all three email", [r["verdict"] for r in rows] == ["flagged"] * 3)
m, rows = load({"dnsnet_vpn_control_hosts": [], "dnsnet_group_seconds": 0})
for i in range(3): m.on_flow(MAC, f"185.159.159.{10 + i}", 443, "tcp", set(), set(), now=T + i)
check("control: dnsnet_group_seconds = 0 disables grouping (three emails)", [r["verdict"] for r in rows] == ["flagged"] * 3)
m, rows = load({"dnsnet_vpn_control_hosts": []})
m.raise_event(MAC, "vpn-ip", "185.159.159.9", T); m.raise_event(MAC, "vpn-ip", "185.159.159.9", T + 5)
check("the existing per-target throttle is untouched (same target twice = one row)", len(rows) == 1)
m, rows = load({"dnsnet_vpn_control_hosts": []})
m.raise_event(MAC, "doh-ip", "1.1.1.1", T); m.raise_event(MAC, "doh-ip", "8.8.8.8", T + 1); m.raise_event(MAC, "tor-guard", "9.9.9.9", T + 2)
check("doh-ip and tor-guard group per class: first of each emails, repeats yellow", [r["verdict"] for r in rows] == ["flagged", "alert", "flagged"])

print("\nFAILED: " + ", ".join(fails) if fails else "\nALL OK"); sys.exit(1 if fails else 0)
