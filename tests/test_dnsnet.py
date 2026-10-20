#!/usr/bin/env python3
"""router/eyeguard-dnsnet.py: same rules as the phone monitor + bypass detection.

No router needed: the daemon is imported with a throwaway config, flag writes
are captured instead of sent, and the BPF filters are evaluated by the real
`tcpdump` against synthetic pcaps (skipped, loudly, if tcpdump is missing).
Run: python3 tests/test_dnsnet.py
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _pcap as P  # noqa: E402

CONF = {
    "api_key": "test", "supabase_url": "https://example.invalid",
    "explicit_terms": ["porn", "pornhub", "xxx", "nude", "onlyfans"],
    "noise_domains": ["googleapis.com", "gstatic.com", "apple-dns.net"],
    "app_map": {"instagram.com": "Instagram", "youtube.com": "YouTube"},
    "home_ip": "192.168.8.153", "wg_ip": "10.1.0.3",
}
tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
json.dump(CONF, tmp); tmp.close()
os.environ["EG_PHONE_CONF"] = tmp.name


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


dn = load("dnsnet_under_test", ROOT / "router" / "eyeguard-dnsnet.py")
ph = load("phone_under_test", ROOT / "router" / "eyeguard-phone.py")
os.unlink(tmp.name)

fails = []


def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        fails.append(name)


POSTED = []
dn._emit = lambda row: (POSTED.append(row) or True)
LOCAL = {"127.0.0.1", "192.168.8.1", "192.168.9.1", "192.168.10.1", "10.1.0.1", "73.43.190.194"}
TOR = {"185.220.101.7"}


def reset(alive=None, covered=None):
    POSTED.clear(); dn._SEEN.clear()
    dn._STATS.update({"dns_queries": 0, "dns_classified": 0, "alerts": {}, "observed": {},
                      "suppressed_covered": 0, "excluded_skipped": 0})
    dn._COVER["map"] = covered if covered is not None else {"192.168.8.153": "primary", "10.1.0.3": "primary"}
    dn._COVER["alive"] = alive if alive is not None else {"primary": False, "jada": False}
    dn._COVER["checked"] = time.time()
    dn.ALERT_CLASSES = set(dn.ALERT_DEFAULT)


print("-- same rules as the phone monitor (parity) --")
names = ["pornhub.com", "www.xxx.example.org", "nude.example.com", "cdn.onlyfans.com",
         "instagram.com", "i.instagram.com", "youtube.com", "example.com", "x.gstatic.com",
         "foo.arpa", "printer.local", "router.lan", "abc.invalid", "localhost", "",
         "a.b.c.d.example.co.uk", "apple-dns.net", "PORN.EXAMPLE.COM", "notpornography.com",
         "sub.googleapis.com", "single"]
bad = [n for n in names if ph.classify(n) is not None and dn.classify(n) is None
       or ph.classify(n) is None and dn.classify(n) is not None
       or (ph.classify(n) and dn.classify(n) and ph.classify(n)[0] != dn.classify(n)[0])]
check("verdict identical to the phone monitor on %d names" % len(names), not bad, str(bad))
check("base_domain/is_noise/app_name identical",
      all(ph.base_domain(n) == dn.base_domain(n) and ph.is_noise(ph.base_domain(n)) == dn.is_noise(dn.base_domain(n))
          and ph.app_name(n) == dn.app_name(n) for n in names))
check("DoH IP list equals the phone monitor's list", set(ph.DOH_IPS) == dn.DOH_IPS)

print("-- DNS parser (real tcpdump output) --")
check("plain", dn.parse_dns_line("IP 192.168.8.150.5000 > 192.168.8.1.53: 4660+ A? plain.example.com. (35)")
      == ("192.168.8.150", "192.168.8.1", "plain.example.com"))
check("EDNS [1au] (the phone monitor's regex misses this form)",
      dn.parse_dns_line("IP 192.168.8.150.5001 > 192.168.8.1.53: 4660+ [1au] A? edns.example.com. (45)")
      == ("192.168.8.150", "192.168.8.1", "edns.example.com"))
check("no recursion-desired bit",
      dn.parse_dns_line("IP 192.168.8.150.5002 > 8.8.8.8.53: 4660 A? nord.example.com. (34)")
      == ("192.168.8.150", "8.8.8.8", "nord.example.com"))
check("HTTPS/SVCB type", dn.parse_dns_line("IP 1.2.3.4.5 > 5.6.7.8.53: 7+ [1au] Type65? svcb.example.com. (45)")[2]
      == "svcb.example.com")
check("TCP dns line", dn.parse_dns_line("IP 10.1.0.2.5004 > 10.1.0.1.53: Flags [P.], seq 1:37, ack 1, win 1000, length 36 4660+ A? tcp.example.com. (34)")
      == ("10.1.0.2", "10.1.0.1", "tcp.example.com"))
check("answer packets are ignored",
      dn.parse_dns_line("IP 192.168.8.1.53 > 192.168.8.150.5000: 4660 1/0/0 A 1.2.3.4 (51)") is None)
check("garbage ignored", dn.parse_dns_line("ARP, Request who-has 1.2.3.4") is None)
check("flow parse tcp", dn.parse_flow_line("IP 192.168.8.150.50000 > 185.220.101.7.9001: Flags [S], seq 1")
      == ("192.168.8.150", 50000, "185.220.101.7", 9001, "Flags"))
check("flow parse udp", dn.parse_flow_line("IP 1.1.1.2.5 > 9.9.9.9.51820: UDP, length 148")[2:4] == ("9.9.9.9", 51820))

print("-- explicit domains: same rule, network wide --")
reset()
r = dn.on_dns("192.168.8.150", "192.168.8.1", "www.pornhub.com", LOCAL)
check("explicit domain from ANY client is flagged red", r == ["alerted"] and POSTED[0]["verdict"] == "flagged")
f = POSTED[0]
check("flag shape: app Network, net-signal reason, device label, grade Likely",
      f["app"] == "Network" and f["reason"].startswith("net-signal: explicit domain pornhub.com from ")
      and "192.168.8.150" in f["reason"] and f["grade"] == "Likely" and f["is_nudity"] is False)
check("reason never begins with phone-/jada- (server phone logic untouched)",
      not f["reason"].startswith(("phone", "jada")))
reset(); dn.on_dns("192.168.8.150", "192.168.8.1", "example.com", LOCAL)
check("innocent domain posts nothing", POSTED == [])
reset(); dn.on_dns("192.168.8.150", "192.168.8.1", "x.googleapis.com", LOCAL)
check("noise domain posts nothing", POSTED == [])
reset(); dn.on_dns("192.168.8.150", "192.168.8.1", "pornhub.com", LOCAL); dn.on_dns("192.168.8.150", "192.168.8.1", "pornhub.com", LOCAL)
check("repeat within the window is throttled to one alert", len(POSTED) == 1)
reset(); dn.on_dns("192.168.8.150", "192.168.8.1", "pornhub.com", LOCAL); dn.on_dns("192.168.8.77", "192.168.8.1", "pornhub.com", LOCAL)
check("a different device is NOT throttled by the first", len(POSTED) == 2)
reset(); r = dn.on_dns("192.168.8.150", "8.8.8.8", "pornhub.com", LOCAL)
check("explicit query sent to an outside resolver flags AND records the bypass", "alerted" in r and "observed" in r)
reset(); dn.on_dns("192.168.8.150", "192.168.8.1", "pornhub.com", LOCAL, now=time.time())
dn.on_dns("192.168.8.150", "192.168.8.1", "pornhub.com", LOCAL, now=time.time() + dn.THROTTLE + 5)
check("after the throttle window the same hit alerts again", len(POSTED) == 2)

print("-- every device is evaluated, Jada's included; exclusion is opt-in only --")
check("default: nobody is excluded (by IP or MAC)", dn.EXCLUDED == set() and dn.EXCLUDED_MACS == set())
for who in ("10.1.0.5", "192.168.8.113", "192.168.9.77", "192.168.10.5", "192.168.8.244"):
    reset(); dn._MACX.update({"ips": set(), "at": time.time()})
    r = dn.on_dns(who, "10.1.0.1", "pornhub.com", LOCAL)
    check(f"{who}: explicit domain alerts", r == ["alerted"] and len(POSTED) == 1, str(r))
reset(); r = dn.on_flow("192.168.9.77", "185.220.101.7", 9001, "tcp", LOCAL, TOR)
check("a guest-network device using Tor alerts", r == ["alerted"] and "guest Wi-Fi" in POSTED[0]["reason"], str(POSTED))
reset(); dn.EXCLUDED = {"10.9.9.9"}
check("opt-in exclusion by IP still works", dn.on_dns("10.9.9.9", "10.1.0.1", "pornhub.com", LOCAL) == ["excluded"] and POSTED == [])
dn.EXCLUDED = set()
lf = tempfile.NamedTemporaryFile("w", suffix=".leases", delete=False)
lf.write("1792 aa:bb:cc:00:00:01 192.168.8.77 Someones-Phone 01:aa\n"); lf.close()
old_leases, old_macs = dn.LEASES, dn.EXCLUDED_MACS
dn.LEASES = lf.name; dn.EXCLUDED_MACS = {"aa:bb:cc:00:00:01"}; dn._MACX.update({"ips": set(), "at": 0.0}); reset()
check("opt-in exclusion by MAC follows the device to whatever address it holds", dn.on_dns("192.168.8.77", "192.168.8.1", "pornhub.com", LOCAL) == ["excluded"])
dn.LEASES, dn.EXCLUDED_MACS = old_leases, old_macs; os.unlink(lf.name); dn._MACX.update({"ips": set(), "at": 0.0})
check("lease parser", dn.parse_leases("1792 84:0F:4C:65:75:6C 192.168.8.77 Jadas-iPhone 01:84\n1 bad x y") == {"192.168.8.77": "84:0f:4c:65:75:6c"})
check("neighbor parser", dn.parse_neigh("192.168.8.77 dev br-lan lladdr 84:0f:4c:65:75:6c REACHABLE\n192.168.8.9 FAILED") == {"192.168.8.77": "84:0f:4c:65:75:6c"})

print("-- every alert names the device that caused it --")
dhcp_txt = """config dnsmasq
\toption domain 'lan'
config host
\toption mac '6E:1C:30:D6:53:C7'
\toption ip '192.168.8.153'
\toption tag 'Jonahs-iPhone'
config host
\toption name 'Jadas-iPhone'
\toption mac '84:0f:4c:65:75:6c'
\toption ip '192.168.8.113'
"""
bm, bi = dn.parse_dhcp_hosts(dhcp_txt)
check("static DHCP hosts parsed (tag or name, by mac and by ip)", bm["6e:1c:30:d6:53:c7"] == "Jonahs-iPhone" and bi["192.168.8.113"] == "Jadas-iPhone" and len(bm) == 2)
check("randomized-MAC detection", dn.is_private_mac("6e:1c:30:d6:53:c7") and not dn.is_private_mac("84:0f:4c:65:75:6c") and not dn.is_private_mac("2c:7c:f2:d8:7a:0d"))
check("segments", dn.segment_of("192.168.9.5") == "guest Wi-Fi" and dn.segment_of("192.168.10.9") == "IoT network"
      and dn.segment_of("10.1.0.3") == "VPN tunnel" and dn.segment_of("192.168.8.1") == "home LAN")
td = tempfile.mkdtemp()
lf2 = Path(td) / "leases"; lf2.write_text("1792 6e:1c:30:d6:53:c7 192.168.8.153 iPhone 01:6e\n1792 de:ad:be:ef:00:01 192.168.9.50 * 01:de\n")
hf = Path(td) / "dhcp"; hf.write_text(dhcp_txt)
save = (dn.LEASES, dn.DHCP_CONFIG)
dn.LEASES, dn.DHCP_CONFIG = str(lf2), str(hf)
dn._IDENT["at"] = 0.0
i = dn.identify("192.168.8.153")
check("identify: static name beats the lease hostname, MAC and segment included",
      i["name"] == "Jonahs-iPhone" and i["mac"] == "6e:1c:30:d6:53:c7" and i["private"] and i["segment"] == "home LAN", str(i))
check("tunnel devices are named from the tunnel map", dn.identify("10.1.0.5")["name"] == "Jadas-Phone")
check("an unnamed guest is labelled UNKNOWN with its MAC",
      "UNKNOWN device: 192.168.9.50, MAC de:ad:be:ef:00:01 (randomized address), guest Wi-Fi" == dn.device_label("192.168.9.50"), dn.device_label("192.168.9.50"))
reset(); dn.on_dns("192.168.8.153", "192.168.8.1", "pornhub.com", LOCAL)
check("explicit-domain alert says which device: name, IP, MAC, segment",
      "Jonahs-iPhone: 192.168.8.153, MAC 6e:1c:30:d6:53:c7 (randomized address), home LAN" in POSTED[0]["reason"]
      and "Jonahs-iPhone" in POSTED[0]["window_title"], str(POSTED))
reset(); dn.on_flow("192.168.9.50", "185.220.101.7", 9001, "tcp", LOCAL, TOR)
check("bypass alert from an unknown guest identifies it as UNKNOWN with its MAC", "UNKNOWN device" in POSTED[0]["reason"] and "de:ad:be:ef:00:01" in POSTED[0]["reason"], str(POSTED))

print("-- a device appearing is NOT an alert by itself --")
src = (ROOT / "router" / "eyeguard-dnsnet.py").read_text()
check("no new-device alert, scan or state file exists", "new-device" not in src and "devices_loop" not in src and "dnsnet_devices" not in src)
dn.LEASES, dn.DHCP_CONFIG = save
shutil.rmtree(td, ignore_errors=True)
reset(); dn._IDENT["at"] = 0.0
check("an unknown device doing something harmless raises nothing", dn.on_dns("192.168.9.77", "192.168.8.1", "example.com", LOCAL) == [] and POSTED == [])
check("an unknown device tripping a rule alerts and is described as UNKNOWN with its address",
      dn.on_dns("192.168.9.77", "192.168.8.1", "pornhub.com", LOCAL) == ["alerted"] and "UNKNOWN device: 192.168.9.77" in POSTED[0]["reason"] and "guest Wi-Fi" in POSTED[0]["reason"], str(POSTED))

print("-- phone-monitor overlap: de-duplicated only while that monitor is alive --")
reset(alive={"primary": True, "jada": False})
r = dn.on_dns("192.168.8.153", "192.168.8.1", "pornhub.com", LOCAL)
check("phone's own explicit hit is not double-emailed while its monitor runs", r == ["covered"] and POSTED == [])
reset(alive={"primary": False, "jada": False})
r = dn.on_dns("192.168.8.153", "192.168.8.1", "pornhub.com", LOCAL)
check("monitor dead -> this daemon is the backstop and alerts", r == ["alerted"] and len(POSTED) == 1)
reset(alive={"primary": True, "jada": False})
r = dn.on_flow("192.168.8.153", "185.220.101.8", 443, "tcp", LOCAL, {"185.220.101.8"})
check("tor-guard on the phone also deduped while alive", r == ["covered"])
r = dn.on_dns("192.168.8.153", "192.168.8.1", "nordvpn.com", LOCAL)
check("a VPN-provider lookup is observed (never emailed, never reported as 'covered')", r == ["observed"])
r = dn.on_flow("192.168.8.153", "5.6.7.8", 853, "tcp", LOCAL, TOR)
check("DoT attempt from the phone is never suppressed", r == ["alerted"])
reset(alive={"primary": True, "jada": False})
r = dn.on_dns("192.168.8.77", "192.168.8.1", "pornhub.com", LOCAL)
check("another device is never covered by the phone's monitor", r == ["alerted"])
check("ps parsing: primary vs jada",
      dn.phone_instances_alive("1 /usr/bin/python3 /usr/bin/eyeguard-phone.py\n2 python3 eyeguard-phone.py --conf /etc/eyeguard/phone-jada.json")
      == {"primary": True, "jada": True}
      and dn.phone_instances_alive("2 python3 eyeguard-phone.py --conf /etc/eyeguard/phone-jada.json") == {"primary": False, "jada": True})

print("-- bypass: masked or routed around --")
reset()
check("Tor guard contact alerts", dn.on_flow("192.168.8.150", "185.220.101.7", 9001, "tcp", LOCAL, TOR) == ["alerted"]
      and "Tor entry relay" in POSTED[0]["reason"] and POSTED[0]["reason"].startswith("net-bypass:"))
reset()
check("Tor guard on a non-443 ORPort is caught (any port)", dn.on_flow("192.168.8.150", "185.220.101.7", 9030, "tcp", LOCAL, TOR) == ["alerted"])
reset(); check("ordinary HTTPS is silent", dn.on_flow("192.168.8.150", "93.184.216.34", 443, "tcp", LOCAL, TOR) == [])
reset(); check("DNS-over-TLS (853) alerts", dn.on_flow("192.168.8.150", "1.2.3.4", 853, "tcp", LOCAL, TOR) == ["alerted"])
reset(); check("DNS-over-QUIC (853/udp) alerts", dn.on_flow("192.168.8.150", "1.2.3.4", 853, "udp", LOCAL, TOR) == ["alerted"])
reset(); check("DoH to a known provider IP alerts", dn.on_flow("192.168.8.150", "8.8.8.8", 443, "tcp", LOCAL, TOR) == ["alerted"])
reset(); check("443 to a non-provider IP is silent", dn.on_flow("192.168.8.150", "8.8.8.7", 443, "tcp", LOCAL, TOR) == [])
reset(); check("OpenVPN/PPTP ports alert", dn.on_flow("192.168.8.150", "5.5.5.5", 1194, "udp", LOCAL, TOR) == ["alerted"]
               and dn.on_flow("192.168.8.150", "5.5.5.5", 1723, "tcp", LOCAL, TOR) == ["alerted"])
reset(); check("WireGuard default port alerts", dn.on_flow("192.168.8.150", "5.5.5.5", 51820, "udp", LOCAL, TOR) == ["alerted"])
reset(); check("WireGuard handshake on ANY port alerts", dn.on_wg_handshake("192.168.8.150", "5.5.5.5", 443, LOCAL) == ["alerted"])
reset()
check("traffic to the router / G11 is never bypass (household tunnel, own DoH on 8853)",
      dn.on_wg_handshake("10.1.0.2", "73.43.190.194", 51820, LOCAL) == []
      and dn.on_flow("10.1.0.2", "192.168.8.231", 853, "tcp", LOCAL, TOR) == []
      and dn.on_flow("10.1.0.2", "10.1.0.1", 8853, "tcp", LOCAL, TOR) == [])
for dom, cls in [("nordvpn.com", "vpn-domain"), ("api.protonvpn.ch", "vpn-domain"), ("vpn-api.proton.me", "vpn-domain"),
                 ("account.protonvpn.com", "vpn-domain"), ("x.mullvad.net", "vpn-domain"), ("check.torproject.org", "tor-domain"),
                 ("mask.icloud.com", "private-relay-lookup"), ("mask-h2.icloud.com", "private-relay-lookup")]:
    reset()
    r = dn.on_dns("192.168.8.150", "192.168.8.1", dom, LOCAL)
    check(f"{dom} is OBSERVED as {cls}, never emailed", r == ["observed"] and POSTED == [] and cls in dn._STATS["observed"], str((r, POSTED)))
reset()
for i in range(500):      # measured on the live network: ~1,300 lookups of mask.icloud.com in 15 h from 12 clients
    dn.on_dns("10.1.0.3", "10.1.0.1", "mask.icloud.com", LOCAL, now=1000.0 + i * 60)
    dn.on_dns("192.168.8.150", "192.168.8.1", "account.protonvpn.com", LOCAL, now=1000.0 + i * 60)
check("500 Private Relay / Proton VPN app lookups over ~8 h produce ZERO emails", POSTED == [])
for dom in ["mail.proton.me", "drive.proton.me", "account.proton.me", "icloud.com", "p01-mail.icloud.com",
            "notnordvpn.com", "nordvpn.com.example.org", "mask.icloud.com.evil.example"]:
    reset()
    r = dn.on_dns("192.168.8.150", "192.168.8.1", dom, LOCAL)
    check(f"{dom} does NOT alert", r == [] or "alerted" not in r, str(r))

print("-- persistent offenders back off; the first alert and new targets are immediate --")
reset(); dn.THROTTLE, dn.THROTTLE_BACKOFF = 1800, 4
check("defaults: 30 min first gap, x4 backoff, never more than a day between reminders", dn.THROTTLE_MAX == 86400 and dn.THROTTLE_BACKOFF == 4 and dn.THROTTLE == 1800)
n = 0; times = []
for k in range(7 * 288):                        # a device hits a DoH address every 5 minutes for a week
    r = dn.on_flow("192.168.10.20", "8.8.8.8", 443, "tcp", LOCAL, TOR, now=1000.0 + k * 300)
    if r == ["alerted"]: times.append(k * 300)
check("a week of constant DoH attempts = about 10 emails (was ~330), not one every 30 minutes", 8 <= len(times) <= 12, f"{len(times)}: {[round(t / 3600, 1) for t in times]}")
check("the very first one is immediate", times[0] == 0)
check("spacing grows 30 min -> 2 h -> 8 h -> daily", [round((b - a) / 3600, 1) for a, b in zip(times, times[1:4])] == [0.5, 2.0, 8.0])
check("it keeps reminding at least daily after that", all((b - a) <= 86400 + 300 for a, b in zip(times[3:], times[4:])))
check("repeats are marked, the first is not", "[repeat" not in POSTED[0]["reason"] and "[repeat #2]" in POSTED[1]["reason"] and "[repeat #3]" in POSTED[2]["reason"])
reset(); dn.on_flow("192.168.10.20", "8.8.8.8", 443, "tcp", LOCAL, TOR, now=0.0)
check("a different target from the same device alerts immediately", dn.on_flow("192.168.10.20", "1.1.1.1", 443, "tcp", LOCAL, TOR, now=60.0) == ["alerted"])
check("a different device alerts immediately", dn.on_flow("192.168.10.21", "8.8.8.8", 443, "tcp", LOCAL, TOR, now=61.0) == ["alerted"])
reset(); dn.on_flow("192.168.10.20", "8.8.8.8", 443, "tcp", LOCAL, TOR, now=0.0); dn.on_flow("192.168.10.20", "8.8.8.8", 443, "tcp", LOCAL, TOR, now=1900.0)
check("after two quiet days it is a new episode again (30 min gap, no repeat marker)",
      dn.on_flow("192.168.10.20", "8.8.8.8", 443, "tcp", LOCAL, TOR, now=1900.0 + 2 * 86400 + 5) == ["alerted"]
      and "[repeat" not in POSTED[-1]["reason"] and dn.on_flow("192.168.10.20", "8.8.8.8", 443, "tcp", LOCAL, TOR, now=1900.0 + 2 * 86400 + 5 + 1810) == ["alerted"])
reset(); n = 0
for k in range(48):                              # the core rule never backs off: a repeat visit is the signal
    n += dn.on_dns("192.168.8.150", "192.168.8.1", "pornhub.com", LOCAL, now=k * 1900.0) == ["alerted"]
check("explicit-domain repeats keep the flat 30-minute throttle (48 visits spaced 31 min = 48 alerts)", n == 48, str(n))

print("-- observe-only classes count but never email --")
reset()
check("DNS to an outside resolver is observed, not emailed", dn.on_dns("192.168.8.150", "8.8.4.4", "example.com", LOCAL) == ["observed"] and POSTED == [])
check("...and counted", dn._STATS["observed"]["dns-bypass"]["8.8.4.4"] == 1)
reset(); check("DNS to the router/G11 is not a bypass", dn.on_dns("192.168.8.150", "192.168.8.231", "example.com", LOCAL) == [])
reset(); check("proxy port observed only", dn.on_flow("192.168.8.150", "5.5.5.5", 1080, "tcp", LOCAL, TOR) == ["observed"] and POSTED == [])
reset(); check("IPsec/IKE observed only (Wi-Fi Calling safe)", dn.on_flow("192.168.8.150", "5.5.5.5", 500, "udp", LOCAL, TOR) == ["observed"])
reset(); check("DoH hostname lookup observed only", dn.on_dns("192.168.8.150", "192.168.8.1", "dns.google", LOCAL) == ["observed"])
reset(); dn.ALERT_CLASSES = set(dn.ALERT_DEFAULT) | {"proxy-port"}
check("config promotes an observed class to an alert", dn.on_flow("192.168.8.150", "5.5.5.5", 1080, "tcp", LOCAL, TOR) == ["alerted"])
reset()

print("-- real BPF filters evaluated by tcpdump on synthetic pcaps --")
if shutil.which("tcpdump") is None:
    print("  [SKIP] tcpdump not installed")
else:
    d = tempfile.mkdtemp()
    wg148 = b"\x01\x00\x00\x00" + b"\xaa" * 144
    pk = [
        P.udp("192.168.8.150", "5.5.5.5", 40000, 443, wg148),                       # 0 wg handshake on 443
        P.udp("192.168.8.150", "5.5.5.5", 40001, 51820, b"\x02\x00\x00\x00" + b"\xaa" * 144),  # 1 148B but type 2
        P.udp("192.168.8.150", "5.5.5.5", 40002, 443, b"\x01\x00\x00\x00" + b"\xaa" * 100),    # 2 type 1, wrong size
        P.udp("192.168.8.150", "5.5.5.5", 40003, 1194, b"\x38" + b"\x00" * 13),     # 3 openvpn port
        P.udp("192.168.8.150", "1.2.3.4", 40004, 853, b"x" * 20),                   # 4 DoQ
        P.udp("192.168.8.150", "1.2.3.4", 40005, 5353, b"x" * 20),                  # 5 irrelevant
        P.tcp("192.168.8.150", "185.220.101.7", 40006, 9001, 0x02),                 # 6 SYN
        P.tcp("192.168.8.150", "185.220.101.7", 40007, 9001, 0x12),                 # 7 SYN-ACK
        P.tcp("192.168.8.150", "185.220.101.7", 40008, 9001, 0x10),                 # 8 ACK
        P.udp("192.168.8.150", "192.168.8.1", 40009, 53, P.dns_query("a.example.com")),        # 9
        P.udp("192.168.8.150", "8.8.8.8", 40010, 53, P.dns_query("b.example.com", edns=True)), # 10
        P.udp("192.168.8.150", "8.8.8.8", 40011, 80, P.dns_query("c.example.com")),            # 11 not dns port
    ]
    pcap = os.path.join(d, "t.pcap")
    P.write_pcap(pcap, pk)

    def sports(filt):
        out = subprocess.run(["tcpdump", "-r", pcap, "-nn", filt], capture_output=True, text=True)
        ports = []
        for l in out.stdout.splitlines():
            f = dn.parse_flow_line(l)
            ports.append(f[1] - 40000 if f else -1)
        return ports, out.returncode

    p, rc = sports(dn.WG_FILTER); check("WG filter: only the type-1 148-byte packet", p == [0] and rc == 0, str(p))
    p, rc = sports(dn.UDP_FILTER); check("UDP filter: VPN/DoQ ports only", p == [1, 3, 4] and rc == 0, str(p))
    p, rc = sports(dn.SYN_FILTER); check("SYN filter: SYN only (not SYN-ACK / ACK)", p == [6] and rc == 0, str(p))
    out = subprocess.run(["tcpdump", "-r", pcap, "-nn", dn.DNS_FILTER], capture_output=True, text=True).stdout.splitlines()
    parsed = [dn.parse_dns_line(l) for l in out]
    check("DNS filter + parser: 2 queries incl. the EDNS one to 8.8.8.8, none for port 80",
          len(parsed) == 2 and all(parsed) and parsed[1] == ("192.168.8.150", "8.8.8.8", "b.example.com"), str(parsed))
    reset()
    for l in subprocess.run(["tcpdump", "-r", pcap, "-nn", dn.WG_FILTER], capture_output=True, text=True).stdout.splitlines():
        f = dn.parse_flow_line(l); dn.on_wg_handshake(f[0], f[2], f[3], LOCAL)
    check("end to end: pcap -> filter -> parser -> one WireGuard alert", len(POSTED) == 1 and "WireGuard" in POSTED[0]["reason"])
    shutil.rmtree(d, ignore_errors=True)

print("-- the monitor itself is REQUIRED once Dad's manifest lists it --")
_t2 = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
json.dump(CONF, _t2); _t2.close()
os.environ["EG_PHONE_CONF"] = _t2.name
wt = load("watcher_under_test", ROOT / "router" / "eyeguard-router-watcher.py")
os.unlink(_t2.name)
ev = wt.evaluate_dnsnet
check("healthy -> no problems", ev(True, True, 30, 16, 16, 9999) == [])
check("not running", any("not running" in x for x in ev(False, True, None, None, None, 9999)))
check("not enabled at boot", any("enabled at boot" in x for x in ev(True, False, 30, 16, 16, 9999)))
check("daemon alive but silent (wedged) -> problem", any("silent" in x for x in ev(True, True, 900, 16, 16, 9999)))
check("no status file -> problem", any("no status" in x for x in ev(True, True, None, None, None, 9999)))
check("a missing capture is a problem (a dead tcpdump blinds one view)", any("14 of 16" in x for x in ev(True, True, 30, 14, 16, 9999)))
check("grace right after a reboot", ev(False, False, None, None, None, 60) == [])
check("ps lookup failure is never a signal", ev(None, True, 30, 16, 16, 9999) == [])
posted = []
wt._post_flag = lambda detail, what="", title="": (posted.append((what, detail)) or True)
wt._file_hash = lambda path: "sha256:ok"
wt._dnsnet_inputs = lambda: (False, True, None, None, None, 9999)
man = {"eyeguard-dnsnet.init": "sha256:ok", "eyeguard-dnsnet.py": "sha256:ok"}
check("not required when the manifest does not list it", wt._check_dnsnet({"eyeguard-phone.py": "x"}) is False and not posted)
wt._check_dnsnet(man); check("first bad check is debounced", not posted)
wt._check_dnsnet(man); check("second consecutive bad check raises the tamper flag", len(posted) == 1 and "network" in posted[0][0])
wt._check_dnsnet(man); check("one flag per outage", len(posted) == 1)
wt._dnsnet_inputs = lambda: (True, True, 30, 16, 16, 9999)
wt._check_dnsnet(man); check("recovery re-arms", wt._DNSNET_BAD[0] == 0 and wt._DNSNET_ALERTED[0] is False)
wt._file_hash = lambda path: "sha256:edited"
check("an edited script/init -> tampered", wt._check_dnsnet(man) is True)
wsrc = (ROOT / "router" / "eyeguard-router-watcher.py").read_text()
seg = wsrc[wsrc.index("def _dnsnet_inputs"):wsrc.index("_DNSNET_BAD =")]
check("watcher reads only counters from the monitor's status file, never what it observed",
      '"observed"' not in seg and '"captures"' in seg and '"expected_captures"' in seg)

print("-- manifest / installer / init agree with the code --")
gm = (ROOT / "deploy" / "gen_router_manifest.py").read_text()
check("manifest lists the daemon and its init", '"eyeguard-dnsnet.py"' in gm and '"eyeguard-dnsnet.init"' in gm)
inst = (ROOT / "deploy" / "dnsnet_install.sh").read_text()
check("installer expects exactly the captures the daemon starts",
      f'"{len(dn.IFACES) * dn.CAPTURES_PER_IFACE} / {len(dn.IFACES) * dn.CAPTURES_PER_IFACE}"' in inst)
check("installer changes only router_script_version in phone.json",
      inst.count('c["') == 1 and 'c["router_script_version"]' in inst)
check("installer never restarts the phone monitors", "eyeguard-phone stop" not in inst and "eyeguard-phone restart" not in inst
      and "eyeguard-phone start" not in inst and "eyeguard-phone-jada restart" not in inst)
check("installer aborts unless the manifest lists the monitor", "does not list eyeguard-dnsnet.init" in inst)
init = (ROOT / "router" / "eyeguard-dnsnet.init").read_text()
check("init runs the daemon under procd with respawn", "eyeguard-dnsnet.py" in init and "procd_set_param respawn" in init)
check("every router interface the installer checks is a default interface",
      all(i in dn.IFACES for i in ("br-lan", "br-guest", "br-iot", "wgserver")))

print("-- backend outage can't stall packet processing --")
import queue as _q
_t3 = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
json.dump(CONF, _t3); _t3.close()
os.environ["EG_PHONE_CONF"] = _t3.name
real_emit = load("dnsnet_emit_under_test", ROOT / "router" / "eyeguard-dnsnet.py")
os.unlink(_t3.name)
slow_calls = []
real_emit._post_flags = lambda row: (time.sleep(30), slow_calls.append(row))
t0 = time.time(); ok = real_emit._emit({"reason": "x"}); dt = time.time() - t0
check("_emit returns immediately even when the backend would take 30 s", ok and dt < 0.5, f"{dt:.2f}s")
real_emit._OUTBOX = _q.Queue(maxsize=1); real_emit._OUTBOX.put({})
check("a full outbox is reported as a drop, not a hang", real_emit._emit({"reason": "y"}) is False)
check("local address set is refreshed by time, not packet count", "def local_ips" in (ROOT / "router" / "eyeguard-dnsnet.py").read_text()
      and "n % " not in (ROOT / "router" / "eyeguard-dnsnet.py").read_text())

print("-- tripwire / config --")
reset(); r = dn.raise_event("router", "ipv6-enabled", "br-lan")
check("IPv6-enabled tripwire alerts", r == "alerted" and "IPv6" in POSTED[0]["reason"])
check("daemon is stdlib-only", not any(l.startswith(("import requests", "import yaml", "from scapy")) for l in
                                      (ROOT / "router" / "eyeguard-dnsnet.py").read_text().splitlines()))
check("module has no secret literals", "service_role" not in (ROOT / "router" / "eyeguard-dnsnet.py").read_text())

print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all dnsnet checks passed")
