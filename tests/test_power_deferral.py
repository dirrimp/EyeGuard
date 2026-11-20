#!/usr/bin/env python3
"""Offline test: a sleep / wake / display-sleep that arrives before the uploader exists is REPLAYED, not dropped
(2026-11-19: deploy restart at 20:27:53, lid closed 20:27:57; the new agent logged no sleep and the server alerted twice).
No macOS events, no network: the app object and the uploader are fakes. Run with the app python (needs rumps):
  /Applications/EyeGuard.app/Contents/Resources/python/bin/python3.12 tests/test_power_deferral.py"""
import re, sys, threading, traceback
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eyeguard.menubar import EyeGuardApp

fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

class FakeUploader:
    def __init__(self): self.calls = []
    def suspend(self): self.calls.append("suspend")
    def resume(self): self.calls.append("resume")
    def note_screen_asleep(self): self.calls.append("screen_asleep")
    def note_screen_resumed(self): self.calls.append("screen_awake")

class FakeApp:
    """Just the attributes the handlers touch; the real methods are borrowed from EyeGuardApp."""
    def __init__(self, uploader=None):
        self._uploader = uploader
        self._power_lock = threading.Lock()
        self._deferred_power = None
        self._deferred_screen = None
        self.diag = []
    def _log_diag(self, msg): self.diag.append(msg)
    _power_event = EyeGuardApp._power_event
    _screen_sleep_event = EyeGuardApp._screen_sleep_event
    _screen_wake_event = EyeGuardApp._screen_wake_event
    _install_uploader = EyeGuardApp._install_uploader

print("events before the uploader exists")
a = FakeApp()
a._power_event("suspend", "sleep"); a._screen_sleep_event()
check("they are remembered, nothing is sent and nothing raises", a._deferred_power == "suspend" and a._deferred_screen == "asleep")
check("and the deferral is logged (it used to be silent)", any("will replay" in d for d in a.diag), str(a.diag))
up = FakeUploader(); a._install_uploader(up)
check("a sleep that arrived early is replayed as a suspend beacon, and the screen sleep is replayed", up.calls == ["suspend", "screen_asleep"], str(up.calls))
check("the deferral is cleared after the replay", a._deferred_power is None and a._deferred_screen is None)

print("only the last state of each kind is replayed")
a = FakeApp(); a._power_event("suspend", "sleep"); a._power_event("resume", "wake"); a._screen_sleep_event(); a._screen_wake_event()
up = FakeUploader(); a._install_uploader(up)
check("sleep then wake replays as a wake (never leaves the Mac marked asleep)", up.calls == ["resume", "screen_awake"], str(up.calls))

print("nothing happened early: nothing is replayed")
a = FakeApp(); up = FakeUploader(); a._install_uploader(up)
check("no replay", up.calls == [])

print("events after the uploader exists behave exactly as before")
up = FakeUploader(); a = FakeApp(up)
a._power_event("suspend", "sleep"); a._power_event("resume", "wake"); a._screen_sleep_event(); a._screen_wake_event()
check("applied directly, in order", up.calls == ["suspend", "resume", "screen_asleep", "screen_awake"], str(up.calls))
check("not deferred", a._deferred_power is None and a._deferred_screen is None)

print("failures cannot break start-up")
class BoomUploader(FakeUploader):
    def suspend(self): raise RuntimeError("network down while asleep")
a = FakeApp(); a._power_event("suspend", "sleep")
try:
    a._install_uploader(BoomUploader()); ok = True
except Exception:
    ok = False
check("a failing replay is logged with its traceback and does not raise", ok and any("replay of a deferred power event failed" in d and "RuntimeError" in d for d in a.diag), str(a.diag))
a = FakeApp(); a._install_uploader(None)
check("cloud sync off (no uploader) is fine", a._uploader is None)

print("wiring in the real source")
src = (ROOT / "eyeguard" / "menubar.py").read_text()
i = src.index("uploader = self._build_uploader()")
j = src.index("interval = cap[\"interval_seconds\"]", i)
blk = src[i:j]
check("the uploader is published only through _install_uploader, after the status provider is set",
      "self._uploader = uploader" not in blk and blk.index("set_status_provider") < blk.index("self._install_uploader(uploader)")
      and "self._install_uploader(None)" in blk)
check("the three handlers no longer return silently when the uploader is missing",
      not re.search(r"up = self\._uploader\n\s+if up is None:\n\s+return", src))
check("the tamper behaviour is untouched: a manual stop still sends no sleep beacon (no new suspend() call outside the handlers and the replay)",
      len(re.findall(r"\.suspend\(\)", src)) == 2)

print()
if fails:
    print("FAILED:", *fails, sep="\n  "); sys.exit(1)
print("PASSED -- early power events are replayed, not dropped.")
