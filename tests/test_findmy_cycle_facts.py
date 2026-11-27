#!/usr/bin/env python3
"""Find My per-cycle facts line: token link/rotation/saved yes-no, minutes, never a token value. Synthetic data only.
Run: python3 tests/test_findmy_cycle_facts.py"""
import json, sys, tempfile
from datetime import datetime, timedelta
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)
from eyeguard import findmy_watcher as fw
VAL_A = "alpha-value-123"
VAL_B = "bravo-value-456"
fp = fw._token_fp(VAL_A)
check("fingerprint is 8 hex chars and not the value", len(fp) == 8 and fp not in VAL_A and fw._token_fp(None) is None)
with tempfile.TemporaryDirectory() as t:
    cfg = {"logging": {"flag_log": str(Path(t) / "flags.jsonl")}}
    now = datetime(2026, 11, 27, 5, 21, 0)
    l1 = fw._cycle_facts_line(cfg, fp, fp, True, now)
    check("first cycle: link unknown, no rotation, saved yes", "previous cycle's end: unknown" in l1 and "rotated this cycle: no" in l1 and "saved to disk after cycle: yes" in l1, l1)
    l2 = fw._cycle_facts_line(cfg, fp, fp, True, now + timedelta(minutes=10))
    check("second cycle: start = previous end yes, gap 10 min", "previous cycle's end: yes" in l2 and "10 min since previous cycle" in l2, l2)
    fp2 = fw._token_fp(VAL_B)
    l3 = fw._cycle_facts_line(cfg, fp, fp2, False, now + timedelta(minutes=20))
    check("rotation yes and a failed save is shown as NO", "rotated this cycle: yes" in l3 and "saved to disk after cycle: NO" in l3, l3)
    l4 = fw._cycle_facts_line(cfg, fp, fp2, True, now + timedelta(minutes=30))
    check("loading a token that is NOT the previous end is flagged NO", "previous cycle's end: NO" in l4, l4)
    check("no value in any line or in the facts file", all(VAL_A not in x and VAL_B not in x for x in (l1, l2, l3, l4)) and VAL_A not in fw._facts_path(cfg).read_text())
    check("saved unknown prints n/a", "saved to disk after cycle: n/a" in fw._cycle_facts_line(cfg, fp, fp, None, now))
    fw._facts_path(cfg).write_text("not json")
    check("corrupt facts file does not raise", fw._cycle_facts_line(cfg, fp, fp, True, now).startswith("facts:"))
    w = fw._mac_wake_age_min()
    check("wake age is a number or unknown", w.lstrip("-").isdigit() or w == "unknown", w)
    class S:
        def __init__(s, path, tok): s.session_path = path; s.data = {"session_token": tok}
    class A:
        def __init__(s, path, tok): s.session = S(path, tok)
    p = Path(t) / "x.session"; p.write_text(json.dumps({"session_token": "a"}))
    check("saved_matches yes when disk equals memory", fw._saved_matches(A(str(p), "a")) is True)
    check("saved_matches NO when disk differs", fw._saved_matches(A(str(p), "b")) is False)
    check("saved_matches None when unreadable", fw._saved_matches(A(str(Path(t) / "none"), "a")) is None)
src = (ROOT / "eyeguard/findmy_watcher.py").read_text()
dead = src.index("_cycle_facts_line(self.cfg, facts['start'], facts['start'], None)")
check("the death path prints the facts before the marker is written", dead < src.index("_write_needs_setup(self.cfg, reason)", dead))
check("the ok path prints facts after _note_ok", src.index("_note_ok(self.cfg)\n        print") < src.index("_cycle_facts_line(self.cfg, facts['start'], _token_fp"))
check("start token is read before any validate call", src.index('facts["start"] = _token_fp') < src.index("api._validate_token()"))
check("facts code makes no network call", "requests" not in src[src.index("def _facts_path"):src.index("def _setup_info_path")])
print()
print("FAILED %d: %s" % (len(fails), ", ".join(fails)) if fails else "ALL OK")
sys.exit(1 if fails else 0)
