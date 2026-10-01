#!/usr/bin/env python3
"""Tests for the AdGuard query-log reader + health watcher in
router/eyeguard-phone.py (2026-09-30). Synthetic fixtures only -- never the
real querylog. Runs anywhere: `python3 tests/test_adguard_querylog.py`."""
import importlib.util, json, os, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_c = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
json.dump({"api_key": "t", "supabase_url": "https://example.invalid",
           "explicit_terms": ["badterm"], "home_ip": "192.168.8.153",
           "wg_ip": "10.1.0.3"}, _c)
_c.close()
os.environ["EG_PHONE_CONF"] = _c.name
spec = importlib.util.spec_from_file_location("ph", ROOT / "router" / "eyeguard-phone.py")
ph = importlib.util.module_from_spec(spec); spec.loader.exec_module(ph)
os.unlink(_c.name)

fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

def line(t, ip, qh):
    return json.dumps({"T": t, "QH": qh, "IP": ip}).encode()

print("— config parser: every way of blinding the log is caught —")
GOOD = "dns:\n  x: 1\nquerylog:\n  dir_path: \"\"\n  ignored: []\n  interval: 24h\n  size_memory: 1000\n  enabled: true\n  ignored_enabled: false\n  file_enabled: true\nstatistics:\n  ignored: []\n  enabled: true\n"
check("healthy config -> True", ph.parse_querylog_config(GOOD) is True)
for what, bad in [("enabled off", GOOD.replace("  enabled: true\n  ignored_enabled", "  enabled: false\n  ignored_enabled")),
                  ("file_enabled off", GOOD.replace("file_enabled: true", "file_enabled: false")),
                  ("ignored domain added", GOOD.replace("  ignored: []\n  interval", "  ignored:\n    - example.com\n  interval")),
                  ("ignored_enabled on", GOOD.replace("ignored_enabled: false", "ignored_enabled: true")),
                  ("block missing", "dns:\n  x: 1\n"),
                  ("empty text", "")]:
    check(f"{what} -> not True", ph.parse_querylog_config(bad) is not True)
check("statistics.enabled=false does NOT mask a healthy querylog",
      ph.parse_querylog_config(GOOD.replace("statistics:\n  ignored: []\n  enabled: true", "statistics:\n  ignored: []\n  enabled: false")) is True)
check("invariant registered", any(k == "adguard_querylog_ok" for k, _, _ in ph._ROUTER_INVARIANTS))

print("— tailer —")
d = tempfile.mkdtemp(); f = Path(d) / "q.json"
f.write_bytes(line("2026-09-30T00:00:00Z", "10.1.0.3", "old.example") + b"\n")
t = ph.QueryLogTailer(f)
check("starts at EOF: history not replayed", t.poll() == [])
with open(f, "ab") as fh: fh.write(line("2026-09-30T00:01:00Z", "10.1.0.3", "a.example") + b"\npartial")
got = t.poll()
check("returns complete line only, holds partial", len(got) == 1 and b"a.example" in got[0])
with open(f, "ab") as fh: fh.write(b'":1}\n')
check("partial completes next poll", len(t.poll()) == 1)
# rotation: old file drains then new file read from 0
with open(f, "ab") as fh: fh.write(line("2026-09-30T00:02:00Z", "10.1.0.3", "tail-of-old.example") + b"\n")
os.rename(f, Path(d) / "q.json.1")
f.write_bytes(line("2026-09-30T00:03:00Z", "10.1.0.3", "new-file.example") + b"\n")
got = b" ".join(t.poll()) + b" " + b" ".join(t.poll())
check("rotation: tail of old file not lost", b"tail-of-old.example" in got)
check("rotation: new file read from the start", b"new-file.example" in got)
check("missing file -> [] not crash", ph.QueryLogTailer(Path(d) / "nope").poll() == [])

print("— parser —")
r = ph.parse_querylog_line(line("2026-09-30T00:01:00.123456789Z", "10.1.0.3", "x.example"))
check("parses nanosecond RFC3339", r is not None and r[1] == "10.1.0.3" and r[2] == "x.example")
for ts_s in ("2026-09-30T00:01:00Z", "2026-09-30T00:01:00.5Z", "2026-09-30T00:01:00.5473Z", "2026-09-30T00:01:00.123456789-04:00"):
    r = ph.parse_querylog_line(line(ts_s, "10.1.0.3", "x.example"))
    check(f"timestamp {ts_s} parses to a real time (not now-fallback)", r is not None and abs(r[0] - 1790726460) < 86400 * 2, str(r))
r = ph.parse_querylog_line(line("not-a-time", "10.1.0.3", "x.example"))
check("unparseable timestamp still yields the query (never dropped)", r is not None and r[2] == "x.example")
check("junk/short lines -> None", ph.parse_querylog_line(b"garbage") is None and ph.parse_querylog_line(b"{}") is None)

print("— cross-check: stalled / missing / healthy —")
LAG = 1000
def xc(): return ph.QueryLogCrossCheck(LAG, slack=60, missing_threshold=3)
C = "10.1.0.3"
x = xc(); x.record_wire(100, C, "a.example.com")
check("recent wire query is not judged yet", x.evaluate(100 + LAG - 1) == {"stalled": [], "missing": []})
check("log silent past MAX_LAG -> STALLED", [c for c, _ in x.evaluate(100 + LAG + 5)["stalled"]] == [C])
check("stall persists (not forgotten)", x.evaluate(100 + LAG + 500)["stalled"] != [])
x.record_log(100 + 5, C, "a.example.com")
r = x.evaluate(100 + LAG + 600)
check("log catches up with the query -> recovered, nothing missing", r == {"stalled": [], "missing": []}, str(r))
x = xc(); x.record_wire(100, C, "seen.example.com"); x.record_wire(101, C, "ghost.example.com")
x.record_log(103, C, "seen.example.com"); x.record_log(900, C, "later.example.com")
r = x.evaluate(100 + LAG + 5)
check("log current but lacks a wire query -> MISSING (only that one)",
      r["stalled"] == [] and r["missing"] == [(C, "ghost.example.com")], str(r))
check("matched query is not reported missing", (C, "seen.example.com") not in r["missing"])
x = xc(); x.record_wire(100, C, "x.local"); x.record_wire(100, C, "x.arpa")
check("noise domains are ignored on the wire side", x.evaluate(100 + LAG + 5) == {"stalled": [], "missing": []})
x = xc(); x.record_wire(100, "192.168.8.153", "a.example.com"); x.record_log(150, C, "z.example.com")
check("another client's log entries don't mask a stall",
      [c for c, _ in x.evaluate(100 + LAG + 5)["stalled"]] == ["192.168.8.153"])

print("— dedupe: wire + log flag a query once —")
posts = []
ph.sb_post = lambda path, body: posts.append(body)
ph._wire_seen_record(C, "badterm.com")
check("wire-seen query is recognised", ph._wire_seen_recently(C, "badterm.com"))
check("unseen query is not", not ph._wire_seen_recently(C, "badterm.org"))
ph._handle_query("badterm.org", suffix=" (via AdGuard log, after the fact)")
check("log-only explicit query IS flagged red, labelled as after-the-fact",
      len(posts) == 1 and posts[0]["verdict"] == "flagged" and "after the fact" in posts[0]["reason"], str(posts))

print("— regression: real detection untouched —")
check("explicit domain still classifies flagged", ph.classify("www.badterm.com")[0] == "flagged")

print()
if fails:
    print(f"FAILED — {len(fails)}: {fails}"); sys.exit(1)
print("PASSED — querylog reader/watcher behave as expected.")
