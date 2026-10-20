#!/usr/bin/env python3
"""How often would the network monitor alert on realistic traffic? (spam / false-alarm check)

Replays N simulated days of household traffic through the REAL rule code of
router/eyeguard-dnsnet.py (on_dns / on_sni / on_flow, real throttle, real dedupe, real VPN
and Tor lists) on a simulated clock, with flag writes captured instead of sent.

Everything the households "do" is innocent by construction, so ANY alert that is not one of
the injected, known-bad events is a false alarm. Inputs are public: the Tranco top-sites list
(names), the real server IPs of those sites, the public VPN ranges, Tor's guard list, and the
rule config (terms / noise / app map). NO real household traffic is used or needed.

Usage:  python3 tests/sim_dnsnet_traffic.py [--days 7] [--seed 1] [--data DIR] [--worst-case]
Needs network on first run (downloads into --data, default /tmp/simdata). Exit 1 if a baseline
household produces any false alert or misses an injected one.
"""
import argparse, bisect, collections, concurrent.futures, importlib.util, json, math, os
import random, re, socket, subprocess, sys, tempfile, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser()
ap.add_argument("--days", type=int, default=7)
ap.add_argument("--seed", type=int, default=1)
ap.add_argument("--data", default="/tmp/simdata")
ap.add_argument("--sites", type=int, default=1500, help="top sites to resolve to real IPs")
ap.add_argument("--worst-case", action="store_true", help="add misbehaving devices (DoH-to-8.8.8.8 TV, tunnel-ish app)")
args = ap.parse_args()
D = Path(args.data); D.mkdir(parents=True, exist_ok=True)
rnd = random.Random(args.seed)


def fetch(url, dest):
    if not dest.exists() or dest.stat().st_size < 100:
        subprocess.run(["curl", "-s", "-L", "--max-time", "120", "-o", str(dest), url], check=True)


# ---------------------------------------------------------------- data
fetch("https://tranco-list.eu/top-1m.csv.zip", D / "tranco.zip")
if not (D / "top-1m.csv").exists():
    zipfile.ZipFile(D / "tranco.zip").extractall(D)
fetch("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt", D / "vpn.txt")
fetch("https://onionoo.torproject.org/summary?type=relay&running=true&flag=Guard", D / "guards.json")
conf = json.load(open(D / "conf.json"))          # explicit_terms / noise_domains / app_map (rule config only)
sites = [ln.split(",")[1].strip() for ln in open(D / "top-1m.csv").read().splitlines()[:200000]]

# ---------------------------------------------------------------- the real daemon
tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
json.dump({"api_key": "sim", "supabase_url": "https://sim.invalid", **conf}, tmp); tmp.close()
os.environ["EG_PHONE_CONF"] = tmp.name
spec = importlib.util.spec_from_file_location("dn", ROOT / "router" / "eyeguard-dnsnet.py")
dn = importlib.util.module_from_spec(spec); spec.loader.exec_module(dn)
os.unlink(tmp.name)

T0 = 1_800_000_000
SIM = [T0]
ALERTS, OBSERVED = [], collections.Counter()
dn._emit = lambda row: ALERTS.append((SIM[0], row)) or True
dn.covered_by_live_monitor = lambda *a, **k: False           # pessimistic: no de-dup against the phone monitors
dn._VPN["starts"], dn._VPN["ends"] = dn.parse_ranges(open(D / "vpn.txt").read())
guards = json.load(open(D / "guards.json"))
TOR = {a for r in guards["relays"] for a in r.get("a", []) if a and not a.startswith("[")}

DEV = {  # name: (ip, kind)
    "Jonahs-iPhone": ("192.168.8.153", "phone"), "Jonahs-Mac": ("192.168.8.150", "mac"),
    "Jadas-iPhone": ("192.168.8.113", "phone"), "g11": ("192.168.8.231", "server"),
    "Visitor-Galaxy": ("192.168.9.60", "phone"),
}
if args.worst_case:
    DEV["Living-room-TV"] = ("192.168.10.20", "tv")
leases = Path(tempfile.mkdtemp()) / "leases"
leases.write_text("".join(f"1 aa:00:00:00:00:{i:02x} {ip} {n} 01\n" for i, (n, (ip, _)) in enumerate(DEV.items())))
dn.LEASES = str(leases); dn.DHCP_CONFIG = "/nonexistent"; dn._IDENT["at"] = 0.0
LOCAL = {"127.0.0.1", "192.168.8.1", "192.168.9.1", "192.168.10.1", "10.1.0.1", "73.43.190.194"}

# ---------------------------------------------------------------- real IPs for real sites
ipfile = D / "resolved.json"
if ipfile.exists():
    resolved = json.load(open(ipfile))
else:
    def res(d):
        try:
            return d, sorted({a[4][0] for a in socket.getaddrinfo(d, 443, socket.AF_INET)})
        except Exception:
            return d, []
    with concurrent.futures.ThreadPoolExecutor(64) as ex:
        resolved = dict(ex.map(res, sites[:args.sites]))
    json.dump(resolved, open(ipfile, "w"))
def rule_hit(d):
    c = dn.classify(d)
    return bool(c and c[0] == "flagged") or any(dn.host_matches(d, x) for x in (dn.VPN_DOMAINS, dn.TOR_DOMAINS, dn.PRIVATE_RELAY, dn.DOH_HOSTS))
excluded_sites = [d for d in resolved if rule_hit(d)]
pool = [(d, ips) for d, ips in resolved.items() if ips and not rule_hit(d)]
print(f"data: {len(sites):,} top sites, {len(pool)} innocent sites with real IPs ({len(excluded_sites)} removed: they ARE explicit / VPN / DoH names), VPN intervals {len(dn._VPN['starts']):,}, Tor guards {len(TOR):,}")

# ---------------------------------------------------------------- measurements that need no traffic at all
base = lambda d: dn.base_domain(d)
term_hits = [(i + 1, d) for i, d in enumerate(sites) if (c := dn.classify(d)) and c[0] == "flagged"]
top10k = [x for x in term_hits if x[0] <= 10000]
vpn_coll = [(d, ip) for d, ips in pool for ip in ips if dn.vpn_match(ip)]
tor_coll = [(d, ip) for d, ips in pool for ip in ips if ip in TOR]
print(f"explicit-term hits among the top {len(sites):,} names: {len(term_hits)} (top 10k: {len(top10k)})")
print(f"top sites whose real server IPs fall in the VPN list: {len(vpn_coll)} of {len(pool)}; in Tor guards: {len(tor_coll)}")

rr = random.Random(99); n_rand = 200000; hit = 0
for _ in range(n_rand):
    n = (rr.randint(1, 223) << 24) | rr.getrandbits(24)
    if dn._is_global_int(n) and dn.vpn_match(".".join(str((n >> k) & 255) for k in (24, 16, 8, 0))): hit += 1
print(f"exposure: a connection to an ARBITRARY global IP lands in the VPN list {100 * hit / n_rand:.3f}% of the time "
      f"(only matters for P2P/odd hosts; real sites above: {len(vpn_coll)} collisions)")

# ---------------------------------------------------------------- traffic generator
HOST_PREFIX = ["www"] * 6 + ["api", "cdn", "static", "m", "login", "img", "edge", "assets", "ws", "mail", "app", "s", "i", "media"]
HEX = "0123456789abcdef"; AZ = "abcdefghijklmnopqrstuvwxyz0123456789"
weights = [1 / (i + 1) for i in range(len(pool))]
cum = []; s_ = 0
for w in weights:
    s_ += w; cum.append(s_)
pick_site = lambda: pool[min(bisect.bisect_left(cum, rnd.random() * s_), len(pool) - 1)]
HOUR_W = [1, 1, 1, 1, 1, 2, 4, 7, 8, 7, 6, 6, 7, 6, 6, 6, 7, 8, 9, 10, 10, 9, 6, 3]


def rl(n, alpha=AZ): return "".join(rnd.choice(alpha) for _ in range(n))


def noisy_name():
    r = rnd.random()
    if r < .25: return f"d{rl(13)}.cloudfront.net"
    if r < .45: return f"e{rnd.randint(1000, 99999)}.a.akamaiedge.net"
    if r < .60: return f"{rl(32, HEX)}.r2.cloudflarestorage.com"
    if r < .75: return f"p{rnd.randint(1, 99)}-{rl(10)}.icloud.com"
    if r < .90: return f"{rl(20, HEX)}.{rnd.choice(['fbcdn.net', 'tiktokcdn.com', 'scdn.co'])}"
    return f"{rl(7)}.{rnd.choice(['execute-api.us-east-1.amazonaws.com', 'azurewebsites.net', 'herokuapp.com'])}"


NOISE_Q = ["_dns-sd._udp.local", "1.8.168.192.in-addr.arpa", "wpad.lan", "captive.apple.com", "connectivitycheck.gstatic.com",
           "time.apple.com", "pool.ntp.org", "detectportal.firefox.com", "gateway.icloud.com", "mask.apple-dns.net"]
events = []


def add(t, kind, **kw): events.append((t, len(events), kind, kw))


def device_day(name, ip, kind, day):
    base_t = T0 + day * 86400
    n_dns = {"phone": 3500, "mac": 6000, "server": 1500, "tv": 1200}[kind]
    for _ in range(n_dns):
        hour = rnd.choices(range(24), HOUR_W if kind != "server" else [1] * 24)[0]
        t = base_t + hour * 3600 + rnd.random() * 3600
        r = rnd.random()
        if r < .06:
            name = rnd.choice(NOISE_Q); dst_ips = []
        elif r < .22:
            name = noisy_name(); dst_ips = rnd.choice(pool)[1]
        else:
            d, ips = pick_site(); name = f"{rnd.choice(HOST_PREFIX)}.{d}"; dst_ips = ips
        add(t, "dns", ip=ip, name=name, qtype=rnd.choice(["A", "AAAA", "HTTPS", "A", "AAAA"]),
            resolver="192.168.8.1" if kind != "tv" or not args.worst_case else "8.8.8.8")
        if dst_ips and rnd.random() < .75:                                   # a connection follows the lookup
            add(t + .05, "syn", ip=ip, dst=rnd.choice(dst_ips), port=rnd.choices([443, 80, 993, 5223, 8443], [80, 8, 3, 6, 3])[0])
            if rnd.random() < .85:
                add(t + .1, "sni", ip=ip, name=name, dst=dst_ips[0])
        if rnd.random() < .04 and dst_ips:                                   # connection from cached DNS: hello with NO recent lookup
            d, ips = pick_site()
            add(t + 7200 + rnd.random() * 3600, "sni", ip=ip, name=f"{rnd.choice(HOST_PREFIX)}.{d}", dst=ips[0])
    if kind in ("phone", "mac"):                                              # measured on the live network
        for k in range(int(36 * 24 if kind == "phone" else 14 * 24)):          # Apple devices retry the blocked mask.icloud.com constantly
            add(base_t + rnd.random() * 86400, "dns", ip=ip, name="mask.icloud.com", qtype="A", resolver="192.168.8.1")
    if kind == "mac":
        for _ in range(32):                                                    # the Proton VPN app polls its account API
            add(base_t + rnd.random() * 86400, "dns", ip=ip, name=rnd.choice(["account.protonvpn.com", "vpn-api.proton.me", "protonvpn.com", "account-api.protonvpn.com"]), qtype="A", resolver="192.168.8.1")
            add(base_t + rnd.random() * 86400, "sni", ip=ip, name="account.protonvpn.com", dst="185.159.157.1")
        for _ in range(6):                                                     # dev tooling reading Tor's public lists
            add(base_t + rnd.random() * 86400, "dns", ip=ip, name=rnd.choice(["onionoo.torproject.org", "gitlab.torproject.org"]), qtype="A", resolver="192.168.8.1")
        for _ in range(200):                                                   # the household's own DoH name
            add(base_t + rnd.random() * 86400, "dns", ip=ip, name="doh.orthanc.me", qtype="A", resolver="192.168.8.1")
    if kind in ("phone", "mac"):                                              # a streaming session or two a day: many googlevideo-style names
        for _ in range(rnd.randint(1, 3)):
            t0 = base_t + rnd.choice([12, 19, 20, 21]) * 3600 + rnd.random() * 3000
            for k in range(rnd.randint(30, 90)):
                add(t0 + k * rnd.uniform(2, 9), "dns", ip=ip, name=f"rr{rnd.randint(1, 9)}---sn-{rl(8)}.googlevideo.com", qtype="A", resolver="192.168.8.1")
    if kind == "phone":                                                        # Wi-Fi calling keeps an IPsec tunnel to the carrier
        for h in range(24):
            if rnd.random() < .5:
                add(base_t + h * 3600 + rnd.random() * 3600, "udp", ip=ip, dst="208.54.12.34", port=rnd.choice([500, 4500]))
    if kind == "server":                                                       # container pulls, package mirrors, mail bridge
        for _ in range(60):
            d, ips = pick_site()
            add(base_t + rnd.random() * 86400, "syn", ip=ip, dst=ips[0], port=443)
    if kind == "tv" and args.worst_case:                                       # misbehaving IoT: DoH to Google every ~5 min
        for k in range(288):
            add(base_t + k * 300 + rnd.random() * 30, "syn", ip=ip, dst="8.8.8.8", port=443)


for day in range(args.days):
    for name, (ip, kind) in DEV.items():
        device_day(name, ip, kind, day)

# injected, KNOWN-BAD events: the only alerts that should exist (per day)
EXPECT = collections.Counter()
INJ = []


def inject(t, kind, expect_cls, **kw):
    add(t, kind, **kw); EXPECT[expect_cls] += 1; INJ.append((t, expect_cls, kw.get("ip")))


for day in range(args.days):
    b = T0 + day * 86400 + 14 * 3600
    mac = DEV["Jonahs-Mac"][0]
    inject(b + 10, "dns", "explicit-dns", ip=mac, name="www.pornhub.com", qtype="A", resolver="192.168.8.1")
    inject(b + 400, "sni", "explicit-sni", ip=mac, name="www.xvideos.com", dst="93.184.216.34")
    guard = sorted(TOR)[day]
    inject(b + 800, "syn", "tor-guard", ip=mac, dst=guard, port=9001)
    inject(b + 1200, "sni", "private-relay", ip=DEV["Visitor-Galaxy"][0], name="mask.icloud.com", dst="17.253.1.1")
    inject(b + 1600, "syn", "dot-attempt", ip=DEV["Jonahs-iPhone"][0], dst="1.2.3.4", port=853)
    inject(b + 2000, "wg", "wg-handshake", ip=DEV["Jonahs-iPhone"][0], dst="5.5.5.5", port=51820)
    vi = dn._VPN["starts"][day * 7]
    inject(b + 2400, "syn", "vpn-ip", ip=mac, dst=".".join(str((vi >> s) & 255) for s in (24, 16, 8, 0)), port=443)

events.sort()
print(f"simulated {args.days} days, {len(events):,} events across {len(DEV)} devices "
      f"({'worst-case devices ON' if args.worst_case else 'baseline households'})")

# ---------------------------------------------------------------- replay
for t, _, kind, kw in events:
    SIM[0] = t
    if kind == "dns":
        dn.on_dns(kw["ip"], kw["resolver"], kw["name"], LOCAL, now=t, qtype=kw["qtype"])
    elif kind == "sni":
        dn.on_sni(kw["ip"], kw["dst"], kw["name"], False, False, LOCAL, now=t)
    elif kind == "syn":
        dn.on_flow(kw["ip"], kw["dst"], kw["port"], "tcp", LOCAL, TOR, now=t)
    elif kind == "udp":
        dn.on_flow(kw["ip"], kw["dst"], kw["port"], "udp", LOCAL, TOR, now=t)
    elif kind == "wg":
        dn.on_wg_handshake(kw["ip"], kw["dst"], kw["port"], LOCAL, now=t)

# ---------------------------------------------------------------- report
CLS = {v: k for k, v in dn._TITLES.items()}
def cls_of(row):
    for title, cls in sorted(CLS.items(), key=lambda x: -len(x[0])):
        if title in row["reason"]: return cls
    return "?"

inj_keys = collections.Counter((cls, ip) for _, cls, ip in INJ)
tp, fp = [], []
for t, row in ALERTS:
    c = cls_of(row); ip = re.search(r": (\d+\.\d+\.\d+\.\d+)", row["reason"])
    ip = ip.group(1) if ip else None
    day = int((t - T0) // 86400)
    if any(abs(t - it) < 3600 and c == ic and ip == iip for it, ic, iip in INJ):
        tp.append((day, c, ip, row))
    else:
        fp.append((day, c, ip, row))
print("\n=== RESULT ===")
print(f"injected known-bad events: {sum(EXPECT.values())}   alerts that matched them (true positives): {len(tp)}")
print(f"ALERTS THAT WERE NOT INJECTED (false alarms): {len(fp)}  = {len(fp) / args.days:.2f} emails/day")
missed = [(c, n - sum(1 for _, cc, *_ in tp if cc == c)) for c, n in EXPECT.items() if sum(1 for _, cc, *_ in tp if cc == c) < n]
print("injected events NOT alerted:", missed or "none")
if fp:
    by = collections.Counter((c, ip) for _, c, ip, _ in fp)
    print("false alarms by (class, device):")
    for (c, ip), n in by.most_common(15):
        ex = next(r for _, cc, i, r in fp if cc == c and i == ip)["reason"][:150]
        print(f"   {n:4d}  {c:14s} {ip}   e.g. {ex}")
    perday = collections.Counter((d, ip) for d, _, ip, _ in fp)
    print("worst single device-day:", perday.most_common(1)[0])
print("\nobserve-only (never emailed), per week:")
for c, d in sorted(dn._STATS["observed"].items(), key=lambda x: -sum(x[1].values())):
    print(f"   {sum(d.values()):6d}  {c:12s} ({len(d)} distinct targets) top: {sorted(d.items(), key=lambda x: -x[1])[:2]}")
print("stats:", {k: v for k, v in dn._STATS.items() if k in ("dns_queries", "sni_seen", "sni_dns_dup", "suppressed_covered")})
ok = (not fp and not missed) if not args.worst_case else True
sys.exit(0 if ok else 1)
