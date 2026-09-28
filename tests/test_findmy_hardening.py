#!/usr/bin/env python3
"""Tests for the findmy_watcher.py hardening added 2026-09-28.

Found live: 4 `run_findmy.py --once` cron invocations stuck simultaneously,
oldest 10 days (`ps -axo pid,etime,command | grep run_findmy`), because
nothing bounded a hung network call and nothing stopped cron piling a new
`--once` on top of the last one every 10 minutes. This exercises the two
primitives added to fix that -- _hard_timeout() and the non-blocking
flock pair -- directly, without touching pyicloud or the network, so it
runs anywhere (CI included) with no credentials and no Supabase access.

Not wired into a CI workflow (no guardrail-style workflow exists for the
`eyeguard/` Python package yet -- only config.yaml's invariants are checked
in CI today); run manually: `python3 tests/test_findmy_hardening.py`.
"""
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from eyeguard.findmy_watcher import (  # noqa: E402
    WatcherTimeout, _hard_timeout, _try_acquire_lock, _release_lock,
)

fails: list[str] = []


def check(name: str, ok: bool, detail: str = ""):
    tag = "ok  " if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        fails.append(name)


print("— _hard_timeout bounds a genuinely stuck block —")
start = time.monotonic()
timed_out = False
try:
    with _hard_timeout(1):
        time.sleep(5)  # simulates a hung network call with no timeout of its own
except WatcherTimeout:
    timed_out = True
elapsed = time.monotonic() - start
check("raises WatcherTimeout, not a hang", timed_out)
check("bounded near the requested 1s, not the full 5s", elapsed < 3,
      f"took {elapsed:.2f}s")

print("— _hard_timeout does not fire on a fast block —")
fired = False
try:
    with _hard_timeout(5):
        time.sleep(0.1)
except WatcherTimeout:
    fired = True
check("no false timeout on a normal-speed block", not fired)

print("— _hard_timeout leaves no alarm armed afterwards —")
try:
    with _hard_timeout(1):
        raise ValueError("simulated real error, not a timeout")
except ValueError:
    pass
except WatcherTimeout:
    check("propagates the real exception, not a spurious timeout", False)
# If the alarm weren't cancelled on the exception path, this sleep would be
# interrupted by a stale SIGALRM and WatcherTimeout would leak out here.
leaked = False
try:
    time.sleep(1.5)
except WatcherTimeout:
    leaked = True
check("alarm cancelled even when the block raises", not leaked)

print("— non-blocking lock prevents an overlapping run, then releases —")
with tempfile.TemporaryDirectory() as td:
    cfg = {"logging": {"flag_log": str(Path(td) / "flags.log")}}
    first = _try_acquire_lock(cfg)
    check("first acquire succeeds", first is not None)
    second = _try_acquire_lock(cfg)
    check("a second overlapping acquire is refused (this is the fix for the "
          "4-stuck-processes bug -- cron's next tick would see this and "
          "skip instead of piling up)", second is None)
    if first is not None:
        _release_lock(first)
    third = _try_acquire_lock(cfg)
    check("a new acquire succeeds again after release", third is not None)
    if third is not None:
        _release_lock(third)

print()
if fails:
    print(f"FAILED — {len(fails)} check(s) failed: {fails}")
    sys.exit(1)
print("PASSED — findmy_watcher hardening behaves as expected.")
