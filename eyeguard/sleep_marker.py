"""A tiny root-written marker that says "the Mac is in a real sleep right now" (2026-11-25).

WHY: a deploy restarts the monitor and the session watcher. On 2026-11-24 23:56 a deploy ran during a Maintenance DarkWake (the Mac was asleep, lid
closed, on AC). The new monitor process knew nothing about the sleep, sent an "alive" heartbeat, and the Mac went back to sleep without any event:
"monitoring went dark" twice and "lost view of the screen" followed. Restarting things while the Mac is asleep is the problem, so deploys wait.

HOW: session_watcher.py (root, IOKit) writes the marker on WillSleep and removes it on HasPoweredOn / WillNotSleep. deploy_watcher.py (root) defers a
deploy while the marker says asleep. DarkWakes send neither event, so the marker stays set through all of them, which is exactly what is wanted.

SAFE BY DESIGN: it only ever DELAYS a code update, never an alert, and nothing can be watched while the Mac sleeps. The marker lives in /var/run, which
macOS empties at boot, and is also ignored when it is older than the boot time or older than MAX_AGE_S, so a missed wake event can never block deploys for
more than a day. A missing, unreadable or malformed marker means "awake" (deploys proceed). Only root can write /var/run. Pure standard library."""
import os
import time
from pathlib import Path

MARKER = Path("/var/run/eyeguard.asleep")
MAX_AGE_S = 24 * 3600


def mark_asleep(path: Path | None = None, now: float | None = None) -> bool:
    """Write the marker (epoch seconds). Atomic. Never raises; returns False if it could not be written."""
    try:
        path = Path(path) if path else MARKER
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(str(int(now if now is not None else time.time())))
        os.replace(tmp, path)
        return True
    except Exception:
        return False


def clear_asleep(path: Path | None = None) -> bool:
    """Remove the marker. Never raises; True when it is gone afterwards."""
    try:
        (Path(path) if path else MARKER).unlink()
    except FileNotFoundError:
        pass
    except Exception:
        return False
    return True


def is_asleep(path: Path | None = None, now: float | None = None, boot_epoch: float | None = None, max_age_s: int = MAX_AGE_S) -> bool:
    """True only while a fresh marker says a real sleep started and no wake has cleared it. Anything unusual means False (awake)."""
    try:
        t = int((Path(path) if path else MARKER).read_text().strip())
    except Exception:
        return False
    now = now if now is not None else time.time()
    if t > now + 60:                      # a time from the future is not trusted
        return False
    if now - t > max_age_s:               # a missed wake event can never block deploys for more than a day
        return False
    if boot_epoch is not None and t < boot_epoch:   # written before the last boot: stale
        return False
    return True


def boot_epoch() -> float | None:
    """Epoch seconds of the last boot (sysctl kern.boottime), or None."""
    try:
        import re
        import subprocess
        out = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.boottime"], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"sec\s*=\s*(\d+)", out)
        return float(m.group(1)) if m else None
    except Exception:
        return None
