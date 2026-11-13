#!/usr/bin/env python3
"""Offline test: a rejected Screen Recording grant makes the agent report itself blind.
No macOS, no capture, no network: Quartz is faked. Run: python3 tests/test_capture_permission.py"""
import re, sys, types
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eyeguard import capture_permission as cp

fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

def fake_quartz(result=None, boom=False):
    m = types.ModuleType("Quartz")
    def pre():
        if boom: raise RuntimeError("no quartz")
        return result
    m.CGPreflightScreenCaptureAccess = pre
    sys.modules["Quartz"] = m

# the macOS answer is passed through; failure is "unknown", never "denied"
fake_quartz(True);  check("permitted -> True", cp.screen_capture_permitted() is True)
fake_quartz(False); check("denied -> False", cp.screen_capture_permitted() is False)
fake_quartz(boom=True); check("check unavailable -> None (never a denial)", cp.screen_capture_permitted() is None)
sys.modules.pop("Quartz", None)

# debounce: 2 denied probes in a row = blind; a single False is not
w = cp.PermissionWatch()
check("one denied probe is not yet blind", w.update(False) is False)
check("second denied probe in a row is blind", w.update(False) is True)
check("stays blind while denied", w.update(False) is True)
check("a granted probe clears it", w.update(True) is False)
w = cp.PermissionWatch(); w.update(False)
check("unknown (None) restarts the streak", w.update(None) is False and w.update(False) is False)
w = cp.PermissionWatch(); w.update(False); w.update(True)
check("False, True, False is not blind (flapping)", w.update(False) is False)
check("default needs 2 probes (about 30 s)", cp.DENIED_PROBES_REQUIRED == 2)
check("a healthy agent is never blind", not any(cp.PermissionWatch().update(True) for _ in range(50)))

# the module returns booleans only: no capture, no window names
src = (ROOT / "eyeguard" / "capture_permission.py").read_text()
code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
check("uses only the preflight call (no capture or window API)",
      "CGPreflightScreenCaptureAccess" in code
      and not re.search(r"CGWindowList|CGDisplayCreateImage|mss|CGImage", code.split('"""', 2)[2]))

# wiring: the probe feeds screen_ok from it, and the old signals are still there
mb = (ROOT / "eyeguard" / "menubar.py").read_text()
check("menubar imports the watch", "from .capture_permission import PermissionWatch, screen_capture_permitted" in mb)
check("screen_ok keeps the brightness and frozen signals and adds the permission one",
      "ok = not is_black and not frozen and not no_permission" in mb)
check("permission state is written to the durable diagnostic log", "permission_denied={no_permission}" in mb)
check("one PermissionWatch per probe loop, built outside the loop",
      mb.count("perm_watch = PermissionWatch()") == 1 and mb.index("perm_watch = PermissionWatch()") < mb.index("while not self._stop.is_set():"))

print("\nFAILED: " + ", ".join(fails) if fails else "\nALL OK")
sys.exit(1 if fails else 0)
