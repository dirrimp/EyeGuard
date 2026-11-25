#!/usr/bin/env python3
"""Find My cycle trace: a good cycle is recorded, a death line says how old the session was and when the last good cycle was.
Synthetic data only. Run: python3 tests/test_findmy_cycle_trace.py"""
import sys, tempfile
from datetime import datetime, timedelta
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)
from eyeguard import findmy_watcher as fw
import json
with tempfile.TemporaryDirectory() as t:
    cfg = {"logging": {"flag_log": str(Path(t) / "flags.jsonl")}}
    now = datetime(2026, 11, 25, 6, 0, 0)
    check("no records: says so, does not raise", "no good cycle on record" in fw._session_trace(cfg, now))
    (fw._setup_info_path(cfg)).write_text(json.dumps({"setup_at": (now - timedelta(hours=8, minutes=30)).isoformat(), "assumed": False, "warned_at": None}))
    fw._last_ok_path(cfg).write_text((now - timedelta(minutes=10)).isoformat())
    line = fw._session_trace(cfg, now)
    check("session age in hours", "8.5 h since --setup" in line, line)
    check("minutes since last good cycle", "last good cycle 10 min ago" in line, line)
    fw._note_ok(cfg)
    check("_note_ok writes a parseable time", datetime.fromisoformat(fw._last_ok_path(cfg).read_text().strip()) > now - timedelta(days=1000))
src = (ROOT / "eyeguard/findmy_watcher.py").read_text()
check("a death prints the trace before writing the marker", src.index("death trace") < src.index("_write_needs_setup(self.cfg, reason)", src.index("death trace")))
check("trace carries no token or device-name fields", "session_token" not in src[src.index("def _session_trace"):src.index("def _note_ok")])
if fails: print("FAILED:", fails); sys.exit(1)
print("ALL OK")
