#!/usr/bin/env python3
"""Tests for the router connection-log watcher (2026-10-01): unexplained-
destination explainer in router/eyeguard-phone.py and the connlog invariant in
router/eyeguard-router-watcher.py. Synthetic data only. Run:
`python3 tests/test_connlog.py`."""
import base64, importlib.util, json, os, struct, sys, tempfile, socket, hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_c = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
json.dump({"api_key": "t", "supabase_url": "https://example.invalid",
           "home_ip": "192.168.8.153", "wg_ip": "10.1.0.3",
           "connlog_devices": {"phone": ["192.168.8.153", "10.1.0.3"],
                               "mac": ["10.1.0.2", "10.1.0.4", "10.1.0.5"]}}, _c)
_c.close()
os.environ["EG_PHONE_CONF"] = _c.name
def load(name, file):
    sp = importlib.util.spec_from_file_location(name, ROOT / "router" / file)
    m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m); return m
ph = load("ph", "eyeguard-phone.py")
wt = load("wt", "eyeguard-router-watcher.py")
os.unlink(_c.name)

fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

def dns_answer(records, qname=b"\x03www\x07example\x03com\x00"):
    """records: [('A','1.2.3.4',ttl) | ('AAAA',..) | ('CNAME',None,ttl)] -> b64 wire msg
    (answers use a compression pointer to the question name, as real servers do)."""
    msg = struct.pack(">HHHHHH", 1, 0x8180, 1, len(records), 0, 0) + qname + struct.pack(">HH", 1, 1)
    for t, v, ttl in records:
        msg += b"\xc0\x0c"
        if t == "A":
            msg += struct.pack(">HHIH", 1, 1, ttl, 4) + socket.inet_pton(socket.AF_INET, v)
        elif t == "AAAA":
            msg += struct.pack(">HHIH", 28, 1, ttl, 16) + socket.inet_pton(socket.AF_INET6, v)
        else:  # CNAME to a compressed name
            rd = b"\x03cdn\xc0\x0c"
            msg += struct.pack(">HHIH", 5, 1, ttl, len(rd)) + rd
    return base64.b64encode(msg).decode()

print("— DNS answer parsing —")
r = ph.parse_dns_answer(dns_answer([("CNAME", None, 60), ("A", "93.184.216.34", 300), ("AAAA", "2606:2800::1", 300)]))
check("CNAME chain skipped, A + AAAA extracted", r == [("93.184.216.34", 300), ("2606:2800::1", 300)], str(r))
check("empty / garbage / truncated -> [] (no exception)",
      ph.parse_dns_answer("") == [] and ph.parse_dns_answer("!!notb64") == [] and ph.parse_dns_answer(base64.b64encode(b"\x00\x01\x02").decode()) == [])
check("wire text answers parsed",
      ph.parse_wire_answers("12:00 IP 192.168.8.1.53 > 192.168.8.153.5555: 1234 3/0/1 CNAME x., A 17.253.1.1, AAAA 2001:db8::1 (80)") == ["17.253.1.1", "2001:db8::1"])
check("wire query lines yield no answers", ph.parse_wire_answers("IP a > b: 36802+ A? example.com. (33)") == [])

print("— privacy scope: Jada's peer and every other IP are never read —")
ipmap, dropped = ph.build_device_map(json.loads('{"phone":["192.168.8.153","10.1.0.3"],"mac":["10.1.0.2","10.1.0.5"]}'), {"10.1.0.5"})
check("excluded IP refused even if listed in connlog_devices", "10.1.0.5" not in ipmap and dropped == ["10.1.0.5"])
check("module-level map (from the test config that LISTS 10.1.0.5) excludes it", "10.1.0.5" not in ph.CONNLOG_IPMAP)
jada = b"1790000000 N tcp 10.1.0.5 1.2.3.4 443 0"
check("Jada's connlog line -> None", ph.parse_connlog_line(jada, ph.CONNLOG_IPMAP) is None)
check("unlisted LAN device -> None", ph.parse_connlog_line(b"1790000000 N tcp 192.168.8.200 1.2.3.4 443 0", ph.CONNLOG_IPMAP) is None)
check("allowlisted phone line parses",
      ph.parse_connlog_line(b"1790000000 N tcp 192.168.8.153 1.2.3.4 443 0", ph.CONNLOG_IPMAP) == (1790000000, "N", "tcp", "phone", "1.2.3.4", 443, 0))
check("garbage line -> None", ph.parse_connlog_line(b"x y", ph.CONNLOG_IPMAP) is None)
ex = ph.ConnExplainer(window=3600, settle=10)
t = ph.parse_connlog_line(jada, ph.CONNLOG_IPMAP)
if t: ex.add_event(t)
ex.evaluate(1790000999)
check("Jada's traffic leaves no state in the explainer", ex.snapshot()["new_total"] == 0 and ex.snapshot()["pending"] == 0)
check("Jada's DNS answers are not indexed",
      (ph.connlog_answers_from_querylog("10.1.0.5", json.dumps({"T": "2026-10-01T00:00:00Z", "QH": "x.com", "IP": "10.1.0.5", "Answer": dns_answer([("A", "9.9.9.9", 60)])}).encode()) is None)
      and not ph.CONNLOG_EXPLAINER._answers)

print("— explainer logic —")
W, S = 3600, 60
def N(ts, dev, dst, dport=443, proto="tcp"): return (ts, "N", proto, dev, dst, dport, 0)
ex = ph.ConnExplainer(W, S, slack=30)
ex.add_answer("phone", "1.1.1.1", 1000)
ex.add_event(N(1010, "phone", "1.1.1.1"))      # resolved just before -> explained
ex.add_event(N(1010, "phone", "2.2.2.2"))      # never resolved -> unexplained
ex.add_event(N(1010, "mac", "1.1.1.1"))        # another device resolved it, not this one -> unexplained
ex.add_event(N(1000 + W + 100, "phone", "1.1.1.1"))  # answer older than window -> unexplained
ex.add_event(N(1010, "phone", "8.8.8.8", 853))
check("nothing judged before the settle delay", ex.evaluate(1010 + S - 1) == 0)
ex.evaluate(1000 + W + 100 + S)
s = ex.snapshot()
check("1 explained, 4 unexplained of 5", (s["new_total"], s["explained"], s["unexplained"]) == (5, 1, 4), str(s))
check("resolver-port connection counted separately", s["resolver_port"] == 1)
check("unexplained /16 prefixes aggregated (no per-conn records)", ("2.2.0.0/16", 1) in s["top_unexplained_prefixes"])
ex = ph.ConnExplainer(W, S, slack=30)
ex.add_event(N(1000, "phone", "5.5.5.5")); ex.add_answer("phone", "5.5.5.5", 1010)
ex.evaluate(1000 + S + 1)
check("answer logged slightly AFTER the connection (flush ordering) still explains", ex.snapshot()["explained"] == 1)
ex = ph.ConnExplainer(W, S, warmup_until=5000)
ex.add_event(N(1000, "phone", "6.6.6.6")); ex.evaluate(1000 + S + 1)
check("connections during warm-up are skipped, not judged", ex.snapshot()["new_total"] == 0 and ex.snapshot()["skipped_warmup"] == 1)
ex = ph.ConnExplainer(W, S)
ex.add_event((1000, "D", "tcp", "phone", "7.7.7.7", 443, 2_000_000)); ex.add_event(N(1000, "phone", "7.7.7.7"))
ex.evaluate(1000 + S + 1)
check("D-event bytes band the unexplained flow (big)", ex.snapshot()["unexplained_big"] == 1)
check("nothing in this module can post a flag (log-only)",
      "sb_post" not in ph.ConnExplainer.evaluate.__code__.co_names and "sb_post" not in ph.connlog_loop.__code__.co_names)

print("— device (not IP) matching: phone home IP and tunnel IP are one device —")
ipm = ph.CONNLOG_IPMAP
check("home and wg IPs map to the same device", ipm["192.168.8.153"] == ipm["10.1.0.3"] == "phone")

print("— seeding from the AdGuard log —")
d = Path(tempfile.mkdtemp()); ql = d / "querylog.json"
ql.write_bytes(
    json.dumps({"T": "2026-10-01T00:00:00Z", "QH": "a.com", "IP": "192.168.8.153", "Answer": dns_answer([("A", "4.4.4.4", 60)])}).encode() + b"\n" +
    json.dumps({"T": "2026-10-01T00:00:01Z", "QH": "b.com", "IP": "10.1.0.5", "Answer": dns_answer([("A", "4.4.4.5", 60)])}).encode() + b"\n")
ex = ph.ConnExplainer(W, S)
n = ph.seed_answers_from_querylog(ex, ph.CONNLOG_IPMAP, ql)
check("seeds the allowlisted device's answers, not Jada's", n == 1 and ("phone", "4.4.4.4") in ex._answers and not any(k[1] == "4.4.4.5" for k in ex._answers), str(ex._answers))

print("— tailer: file that appears after start is read from its beginning (ring files) —")
f = d / "log.1"
t = ph.QueryLogTailer(f)
check("absent at first poll -> []", t.poll() == [])
f.write_bytes(b"line1\nline2\n")
check("appears later -> read from line 1 (not skipped to EOF)", t.poll() == [b"line1", b"line2"])
f2 = d / "log.2"; f2.write_bytes(b"old\n"); t2 = ph.QueryLogTailer(f2)
check("file present at boot -> EOF (no history replay)", t2.poll() == [])

print("— router watcher: connlog invariant —")
check("healthy -> no problems", wt.evaluate_connlog(True, 5, True, 99999) == [])
check("not running -> problem", any("not running" in p for p in wt.evaluate_connlog(False, 5, True, 99999)))
check("stale log -> problem", any("hasn't been written" in p for p in wt.evaluate_connlog(True, 301, True, 99999)))
check("no files -> problem", any("no files" in p for p in wt.evaluate_connlog(True, None, True, 99999)))
check("not enabled at boot -> problem", any("enabled at boot" in p for p in wt.evaluate_connlog(True, 5, False, 99999)))
check("ps lookup failure (None) is NOT a signal", wt.evaluate_connlog(None, 5, True, 99999) == [])
check("right after reboot -> skipped (grace)", wt.evaluate_connlog(False, None, False, 100) == [])
posted = []
wt._post_flag = lambda d: posted.append(d) or True
wt._connlog_inputs = lambda: (False, 5, True, 99999)
wt._file_hash = lambda p: "sha256:ok"
M = {"connlog.sh": "sha256:ok", "connlog.init": "sha256:ok"}
check("manifest WITHOUT connlog.sh -> not required, never alerts", wt._check_connlog({"eyeguard-phone.py": "x"}) is False and not posted)
wt._check_connlog(M)
check("first bad check does not alert yet (debounce)", not posted)
wt._check_connlog(M)
check("second consecutive bad check posts exactly one flag", len(posted) == 1 and "not running" in posted[0])
wt._check_connlog(M)
check("no repeat flag while the outage continues", len(posted) == 1)
wt._connlog_inputs = lambda: (True, 5, True, 99999)
wt._check_connlog(M)
wt._connlog_inputs = lambda: (False, 5, True, 99999)
wt._check_connlog(M); wt._check_connlog(M)
check("recovery re-arms: a new outage alerts again", len(posted) == 2)
wt._file_hash = lambda p: "sha256:EDITED"
check("edited connlog.sh -> reported via existing script_tampered path", wt._check_connlog(M) is True)

print("— manifest generator covers connlog files —")
import subprocess
man = json.loads(subprocess.run([sys.executable, str(ROOT / "deploy" / "gen_router_manifest.py"), "t"], capture_output=True, text=True).stdout)["files"]
check("manifest lists connlog.sh + connlog.init with real hashes",
      man["connlog.sh"] == "sha256:" + hashlib.sha256((ROOT / "router" / "connlog.sh").read_bytes()).hexdigest() and "connlog.init" in man)

print()
if fails:
    print(f"FAILED — {len(fails)}: {fails}"); sys.exit(1)
print("PASSED — connlog watcher behaves as expected.")
