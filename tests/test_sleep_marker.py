#!/usr/bin/env python3
"""Fix A (2026-11-25): deploy_watcher never restarts the monitor while the Mac is in a real sleep. Tests the marker, the deploy gate and session_watcher's
sleep/wake handler. Temp files and fakes only; nothing is deployed, restarted or contacted. Run: python3 tests/test_sleep_marker.py"""
import importlib, os, sys, tempfile, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)
from eyeguard import sleep_marker as sm
tmp = Path(tempfile.mkdtemp()); sm.MARKER = tmp / "asleep"
now = 1_800_000_000

print("A. the marker")
check("no marker means awake", sm.is_asleep(now=now) is False)
check("mark then asleep", sm.mark_asleep(now=now) and sm.is_asleep(now=now + 5))
check("still asleep an hour later (DarkWakes send no event)", sm.is_asleep(now=now + 3600))
check("clear means awake", sm.clear_asleep() and sm.is_asleep(now=now + 5) is False)
check("clearing twice is fine", sm.clear_asleep() is True)
sm.mark_asleep(now=now)
check("older than 24 hours is ignored (a missed wake can never block deploys for more than a day)", sm.is_asleep(now=now + 24 * 3600 + 1) is False and sm.is_asleep(now=now + 24 * 3600 - 5))
check("written before the last boot is ignored", sm.is_asleep(now=now + 100, boot_epoch=now + 50) is False and sm.is_asleep(now=now + 100, boot_epoch=now - 50))
check("a time from the future is not trusted", sm.is_asleep(now=now - 3600) is False)
for junk in ("", "abc", "12.5x", "\x00\x01"):
    sm.MARKER.write_text(junk); check(f"malformed marker {junk!r} means awake", sm.is_asleep(now=now) is False)
check("an unwritable location is reported, never raised", sm.mark_asleep(path=tmp / "no" / "such" / "dir" / "m") is False and sm.clear_asleep(path=tmp / "no" / "x") is True)
check("the marker lives in /var/run (emptied at boot) and the module is pure stdlib", str(Path("/var/run/eyeguard.asleep")) in open(ROOT / "eyeguard/sleep_marker.py").read() and "import requests" not in open(ROOT / "eyeguard/sleep_marker.py").read())

print("B. deploy_watcher defers while asleep")
from eyeguard import deploy_watcher as dw
class Rec:
    deployed = []
w = dw.DeployWatcher("https://x.invalid", "k", "o", "r", tmp, "u")
dw._deployed_sha = lambda d: "a" * 40
dw._latest_main_sha = lambda o, r: "b" * 40
dw._commit_summary = lambda *a: "summary"
w._deploy = lambda sha, summary: Rec.deployed.append(sha)
sm.boot_epoch = lambda: None
sm.clear_asleep(); w._check_once()
check("awake and an update exists: it deploys", Rec.deployed == ["b" * 40])
Rec.deployed.clear(); sm.mark_asleep()
w._check_once(); w._check_once(); w._check_once()
check("asleep: it does NOT deploy (three polls, still waiting)", Rec.deployed == [])
check("...and it logs the wait once, not every cycle", w._deferred is True)
sm.clear_asleep(); w._check_once()
check("after the wake it deploys on the next check (nothing is lost)", Rec.deployed == ["b" * 40])
Rec.deployed.clear(); sm.mark_asleep(now=time.time() - 25 * 3600); w._check_once()
check("a marker older than 24 h does not block the deploy", Rec.deployed == ["b" * 40])
Rec.deployed.clear(); sm.mark_asleep(); sm.boot_epoch = lambda: time.time() + 5; w._check_once()
check("a marker from before the last boot does not block the deploy", Rec.deployed == ["b" * 40])
sm.boot_epoch = lambda: None
dw._latest_main_sha = lambda o, r: "a" * 40; Rec.deployed.clear(); sm.mark_asleep(); w._check_once()
check("nothing new to deploy: nothing happens either way", Rec.deployed == [])
src = open(ROOT / "eyeguard/deploy_watcher.py").read()
check("the gate sits before the deploy and after the 'is there an update' test", src.index("latest == deployed") < src.index("sleep_marker.is_asleep") < src.index("self._deploy(latest, summary)"))
check("deploy_watcher never writes or clears the marker (only the IOKit watcher does)", "mark_asleep" not in src and "clear_asleep" not in src)

print("C. session_watcher writes and clears it from the real IOKit events")
try:
    from eyeguard import session_watcher as sw
    ok = True
except Exception as e:
    ok = False; print(f"  [skip] session_watcher not importable here: {e!r}")
if ok:
    calls = []
    class FakeIOKit:
        def IOAllowPowerChange(self, port, arg): calls.append("allow")
    sw._IOKit = FakeIOKit()
    class FakeWatcher:
        def heartbeat_now(self): calls.append("heartbeat_now")
    s = sw.SleepWatcher(FakeWatcher()); s._root_port = 1
    s._report_sleep = lambda reason: calls.append("report:" + reason)
    sm.clear_asleep()
    s._handle(None, 0, sw._K_WILL_SLEEP, 0)
    check("WillSleep writes the marker BEFORE anything else (it must not wait on a network call)", sm.is_asleep() and calls[:2] == ["report:WillSleep", "allow"] and sm.MARKER.exists())
    calls.clear(); s._handle(None, 0, sw._K_HAS_POWERED_ON, 0)
    check("HasPoweredOn (a real full wake) clears it and still forces the check-in", sm.is_asleep() is False and "heartbeat_now" in calls)
    sm.mark_asleep(); s._handle(None, 0, sw._K_WILL_NOT_SLEEP, 0)
    check("a vetoed sleep clears it (the Mac stayed awake)", sm.is_asleep() is False)
    sm.clear_asleep(); s._handle(None, 0, sw._K_CAN_SLEEP, 0)
    check("CanSleep does not mark (only a real WillSleep does)", sm.is_asleep() is False)
    ssrc = open(ROOT / "eyeguard/session_watcher.py").read()
    check("the marker write is the first statement of the WillSleep branch", ssrc.index("sleep_marker.mark_asleep()") < ssrc.index('self._report_sleep("WillSleep")'))
    check("a failing marker write can never block the sleep (it never raises)", sm.mark_asleep(path=tmp / "no" / "dir" / "m") is False)

if fails: print("\nFAILED:", *fails, sep="\n  "); sys.exit(1)
print("\nALL OK")
