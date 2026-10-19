#!/usr/bin/env python3
"""Tests for the Find My session-age heads-up (2026-10-18).
No network: the flag POST and the Apple check are stubbed.
Run: python3 tests/test_findmy_session_age.py"""
import json
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eyeguard import findmy_watcher as fw  # noqa: E402

fails = []


def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        fails.append(name)


def make(warn_days=None, creds=True):
    tmp = Path(tempfile.mkdtemp())
    cfg = {"logging": {"flag_log": str(tmp / "flags.jsonl")}}
    if warn_days is not None:
        cfg["findmy"] = {"setup_warn_days": warn_days}
    if creds:
        (tmp / ".findmy_credentials.json").write_text('{"apple_id":"a@x","password":"PW"}')
    w = fw.FindMyWatcher(cfg, "http://x", "k", "iphone")
    w.posted = []
    w._post_flag = lambda row: w.posted.append(row)
    return w, cfg, tmp


T0 = datetime(2026, 10, 18, 5, 9)
day = lambda n: T0 + timedelta(days=n)

print("-- fresh --setup: no alert --")
w, cfg, tmp = make()
fw._record_setup(cfg, T0)
check("fresh", w._session_age_heads_up(T0 + timedelta(hours=1)) == "fresh" and not w.posted)
check("day 20 still quiet (threshold 21)", w._session_age_heads_up(day(20)) == "fresh" and not w.posted)

print("-- threshold crossing alerts once, yellow, distinct reason --")
check("day 21 warns", w._session_age_heads_up(day(21)) == "warned")
check("exactly one row", len(w.posted) == 1)
r = w.posted[0]
check("verdict alert (yellow), not flagged", r["verdict"] == "alert")
check("distinct reason, not session_expired",
      r["reason"].startswith("findmy: session aging") and "session_expired" not in r["reason"])
check("states 21 days", "21 days" in r["reason"])

print("-- debounce: once per 24 h --")
check("10 min later debounced", w._session_age_heads_up(day(21) + timedelta(minutes=10)) == "debounced")
check("23h debounced", w._session_age_heads_up(day(21) + timedelta(hours=23)) == "debounced")
check("still one row", len(w.posted) == 1)
check("25h later warns again", w._session_age_heads_up(day(21) + timedelta(hours=25)) == "warned" and len(w.posted) == 2)

print("-- failed post does not consume the debounce --")
w2, cfg2, _ = make()
fw._record_setup(cfg2, T0)
def boom(row): raise OSError("net down")
w2._post_flag = boom
check("error swallowed", w2._session_age_heads_up(day(30)) == "error")
w2.posted = []
w2._post_flag = lambda row: w2.posted.append(row)
check("retried next cycle", w2._session_age_heads_up(day(30) + timedelta(minutes=10)) == "warned" and len(w2.posted) == 1)

print("-- missing timestamp (pre-existing session): start clock, no alert --")
w3, cfg3, tmp3 = make()
check("clock started", w3._session_age_heads_up(day(0)) == "clock_started" and not w3.posted)
info = json.loads((tmp3 / ".findmy_setup_info.json").read_text())
check("marked assumed", info["assumed"] is True and info["setup_at"] == day(0).isoformat())
check("quiet before threshold", w3._session_age_heads_up(day(20)) == "fresh" and not w3.posted)
check("warns at threshold, wording says age is a minimum",
      w3._session_age_heads_up(day(21)) == "warned" and "minimum" in w3.posted[0]["reason"])
(tmp3 / ".findmy_setup_info.json").write_text("{garbage")
check("corrupt file == unknown, restarts clock quietly",
      w3._session_age_heads_up(day(40)) == "clock_started" and len(w3.posted) == 1)

print("-- --setup resets --")
fw._record_setup(cfg, day(22))
check("after re-setup, quiet", w._session_age_heads_up(day(22) + timedelta(hours=1)) == "fresh")
check("warned_at cleared / assumed False",
      fw._read_setup_info(cfg) == {"setup_at": day(22).isoformat(), "assumed": False, "warned_at": None})
n = len(w.posted)
check("warns again 21 days after the new setup",
      w._session_age_heads_up(day(43)) == "warned" and len(w.posted) == n + 1)

print("-- config threshold; bad values fall back --")
wc, cc, _ = make(warn_days=5)
fw._record_setup(cc, T0)
check("custom 5 days", wc._session_age_heads_up(day(4)) == "fresh" and wc._session_age_heads_up(day(5)) == "warned")
for bad in ("abc", 0, -3, None):
    check(f"bad value {bad!r} -> default 21", fw._setup_warn_days({"findmy": {"setup_warn_days": bad}}) == 21)

print("-- dead-session / no-credentials cases left to the session-expired path --")
wd, cd, _ = make()
fw._record_setup(cd, T0)
fw._write_needs_setup(cd, "session_expired")
check("marker present: no heads-up", wd._session_age_heads_up(day(99)) is None and not wd.posted)
wn, cn, _ = make(creds=False)
check("no credentials: no heads-up, no file", wn._session_age_heads_up(day(99)) is None and fw._read_setup_info(cn) is None)

print("-- check_once: age check never replaces or skips the Apple check --")
wa, ca, _ = make()
fw._record_setup(ca, T0)
calls = []
wa._find_my_last_seen = lambda: calls.append("apple") or None
real = fw._read_setup_info
fw._read_setup_info = lambda c: (_ for _ in ()).throw(RuntimeError("bug"))
try:
    wa.check_once()
finally:
    fw._read_setup_info = real
check("internal bug in age check is swallowed; Apple check still runs", calls == ["apple"])
wa2, ca2, _ = make()
wa2._find_my_last_seen = lambda: calls.append("apple2") or None
wa2.check_once()
check("Apple check ran once on normal cycle", calls.count("apple2") == 1)
check("setup info holds only timestamps",
      set(json.loads(Path(ca2["logging"]["flag_log"]).parent.joinpath(".findmy_setup_info.json").read_text())) <= {"setup_at", "assumed", "warned_at"})

print()
if fails:
    print(f"FAILED: {fails}")
    sys.exit(1)
print("all passed")
