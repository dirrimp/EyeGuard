#!/usr/bin/env python3
"""End-to-end smoke test of the REAL eyeguard-dnsnet.py process.

A fake `tcpdump` on PATH replays realistic tcpdump lines per capture type, a local
HTTP server plays Supabase, and curl (as on the router) posts to it. Proves: the
threads start, every capture is spawned, packets become correctly shaped alert rows
through the sender thread, innocent traffic and an excluded peer produce nothing,
the status file reports every capture, and SIGTERM takes the tcpdump children down
with it (no orphans). Run: python3 tests/test_dnsnet_process.py
"""
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
fails = []


def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        fails.append(name)


got = []


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        got.append((self.path, self.headers.get("apikey"), json.loads(body)))
        self.send_response(201); self.end_headers()

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

d = Path(tempfile.mkdtemp())
(d / "bin").mkdir()
fake = d / "bin" / "tcpdump"
fake.write_text(r'''#!/usr/bin/env python3
# Fake tcpdump: the last argument is the BPF filter; replay lines for that capture type, then idle.
import sys, time
F = sys.argv[-1]
L = []
if F == "(udp or tcp) and dst port 53":
    L = ["12:00:00.1 IP 192.168.8.150.5000 > 192.168.8.1.53: 11+ A? www.pornhub.com. (35)",
         "12:00:00.2 IP 192.168.8.150.5001 > 192.168.8.1.53: 12+ [1au] A? example.com. (40)",
         "12:00:00.3 IP 192.168.8.160.5002 > 192.168.8.1.53: 13+ A? api.nordvpn.com. (36)",
         "12:00:00.4 IP 10.1.0.5.5003 > 10.1.0.1.53: 14+ A? pornhub.com. (30)",
         "12:00:00.5 IP 192.168.8.170.5004 > 8.8.4.4.53: 15 A? example.org. (30)",
         "12:00:00.6 IP 192.168.8.150.5005 > 192.168.8.1.53: 16+ A? x.googleapis.com. (35)"]
elif F.startswith("tcp and tcp"):
    L = ["12:00:01.1 IP 192.168.8.150.40000 > 185.220.101.7.9001: Flags [S], seq 1, win 64240, length 0",
         "12:00:01.2 IP 192.168.8.150.40001 > 93.184.216.34.443: Flags [S], seq 1, win 64240, length 0",
         "12:00:01.3 IP 10.1.0.5.40002 > 185.220.101.7.9001: Flags [S], seq 1, win 64240, length 0",
         "12:00:01.4 IP 192.168.8.150.40003 > 1.2.3.4.853: Flags [S], seq 1, win 64240, length 0"]
elif F.startswith("udp and (dst port 853"):
    L = ["12:00:02.3 IP 192.168.8.153.50398 > 73.43.190.194.51820: UDP, length 148",
         "12:00:02.4 IP 192.168.8.153.50399 > 73.43.190.194.51820: UDP, length 148",
         "12:00:02.5 IP 208.54.4.195.4500 > 192.168.8.153.4500: UDP, length 100"]
elif F.startswith("udp and ip[2:2]"):
    L = ["12:00:02.2 IP 192.168.8.153.50398 > 73.43.190.194.51820: UDP, length 148","12:00:02.1 IP 192.168.8.150.41000 > 5.5.5.5.443: UDP, length 148"]
for l in L:
    print(l, flush=True)
time.sleep(600)
''')
fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
(d / "tor.json").write_text(json.dumps({"ips": ["185.220.101.7"]}))
(d / "leases").write_text("1792 84:94:37:ec:d6:83 192.168.8.150 Jonahs-Mac 01:84\n")
conf = {"api_key": "ANONKEY", "supabase_url": f"http://127.0.0.1:{srv.server_port}",
        "explicit_terms": ["porn", "pornhub"], "noise_domains": ["googleapis.com"],
        "app_map": {}, "dnsnet_interfaces": ["fake0", "fake1"], "dnsnet_local_ips": ["192.168.8.1", "10.1.0.1", "73.43.190.194"], "dnsnet_stats_seconds": 1, "dnsnet_trusted_hostnames": [],
        "dnsnet_stats_file": str(d / "stats.json"), "dnsnet_leases_file": str(d / "leases"), "dnsnet_dhcp_config": str(d / "nodhcp"), "tor_relay_cache_file": str(d / "tor.json"),
        "dnsnet_stats_log_seconds": 3600}
(d / "phone.json").write_text(json.dumps(conf))
env = dict(os.environ, EG_PHONE_CONF=str(d / "phone.json"), PATH=f"{d / 'bin'}:{os.environ['PATH']}",
           PYTHONDONTWRITEBYTECODE="1")
proc = subprocess.Popen([sys.executable, str(ROOT / "router" / "eyeguard-dnsnet.py")], env=env,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
deadline = time.time() + 25
while time.time() < deadline and len(got) < 6:
    time.sleep(0.5)
time.sleep(2)

rows = [r for _, _, r in got]
reasons = [r["reason"] for r in rows]
print("  alerts received:", len(rows))
check("flags arrive at the flags endpoint with the anon key",
      got and all(p == "/rest/v1/flags" and k == "ANONKEY" for p, k, _ in got))
check("explicit domain from a LAN device -> red", any(r.startswith("net-signal: explicit domain pornhub.com from Jonahs-Mac: 192.168.8.150, MAC 84:94:37:ec:d6:83, home LAN") for r in reasons), str(reasons))
check("a VPN-provider LOOKUP is observed, not emailed", not any("nordvpn" in r for r in reasons))
check("Tor guard contact -> red", any("Tor entry relay contacted 185.220.101.7 from Jonahs-Mac: 192.168.8.150" in r for r in reasons))
check("DoT attempt -> red", any("DNS-over-TLS/QUIC attempt (port 853) 1.2.3.4:853 from Jonahs-Mac: 192.168.8.150" in r for r in reasons))
check("WireGuard handshake on 443 -> red", any("WireGuard tunnel handshake to the internet 5.5.5.5:443" in r for r in reasons))
check("every row is flagged / Network / Likely", all(r["verdict"] == "flagged" and r["app"] == "Network" and r["grade"] == "Likely" for r in rows))
check("Jada's tunnel address is evaluated like everyone else's",
      any("explicit domain pornhub.com from Jadas-Phone: 10.1.0.5" in r for r in reasons) and any("Tor entry relay contacted 185.220.101.7 from Jadas-Phone" in r for r in reasons), str(reasons))
check("the phone's tunnel to the router's own public address (at home) raises nothing", not any("73.43.190.194" in r for r in reasons), str(reasons))
check("a device that merely joins (in the lease file) raises nothing", not any("net-device" in r for r in reasons))
check("every alert names its device (a name or UNKNOWN, plus the IP and network)", all((" from " in r) and ("home LAN" in r or "VPN tunnel" in r) and ("Jonahs-Mac" in r or "Jadas-Phone" in r or "UNKNOWN device" in r) for r in reasons), str(reasons))
check("innocent, noise and EDNS-innocent queries raise nothing",
      not any("example.com" in r or "googleapis" in r for r in reasons))
check("the outside-resolver query is observed, not alerted", not any("example.org" in r or "8.8.4.4" in r for r in reasons))
check("duplicate across the two interfaces is throttled to one alert per signal",
      len([r for r in reasons if "explicit domain pornhub.com from Jonahs-Mac" in r]) == 1)
check("exactly six alerts (no extras)", len(rows) == 6, f"{len(rows)}: {reasons}")

stats = None
for _ in range(20):
    try:
        stats = json.load(open(d / "stats.json")); 
        if stats.get("captures") == 8: break
    except Exception:
        pass
    time.sleep(0.5)
check("status file reports every capture (4 per interface x 2)", stats and stats.get("captures") == 8 and stats.get("expected_captures") == 8, str(stats and (stats.get("captures"), stats.get("expected_captures"))))
check("status counts ONLY the outside resolver (router addresses are never a bypass), once per interface",
      stats and stats["observed"].get("dns-bypass") == {"8.8.4.4": 2}, str(stats and stats.get("observed")))

check("the phone's tunnel to the router's own public address (at home) is neither alerted nor even observed",
      not any("73.43.190.194" in r for r in reasons) and not any("73.43.190.194" in k for d in stats["observed"].values() for k in d), str(stats and stats["observed"]))
check("an inbound packet from the carrier (Wi-Fi Calling reply) is not treated as a device doing something",
      not any("208.54.4.195" in k for d in stats["observed"].values() for k in d) and "ike-ipsec" not in stats["observed"], str(stats["observed"]))
kids = subprocess.run(["pgrep", "-f", str(fake)], capture_output=True, text=True).stdout.split()
check("8 fake tcpdump children are running", len(kids) == 8, str(len(kids)))
proc.send_signal(signal.SIGTERM)
try:
    proc.wait(timeout=10)
except subprocess.TimeoutExpired:
    proc.kill()
time.sleep(1)
left = [p for p in subprocess.run(["pgrep", "-f", str(fake)], capture_output=True, text=True).stdout.split()]
check("SIGTERM leaves no orphaned tcpdump children", left == [], str(left))
subprocess.run(["pkill", "-f", str(fake)])
srv.shutdown()
print()
if fails:
    print(f"{len(fails)} FAILED: {fails}"); sys.exit(1)
print("process smoke test passed")
