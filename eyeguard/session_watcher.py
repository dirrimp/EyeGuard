"""Session/account watcher — root LaunchDaemon, admin-trust-model pivot.

Why this needs its own root process, separate from the main app: the main
app is a per-user LaunchAgent, so it can only ever see its own user's
session. If the monitored user (who has full admin on their own Mac) creates
a second macOS account and switches to it, the original account's EyeGuard
keeps running and heartbeating "alive" the whole time -- completely blind to
what's happening in the other session. That's a silent bypass needing no
killing, no tampering, no uninstall at all. Only root can see across all
local sessions on the machine, so this one check has to stay root-level --
not to protect a secret (it holds none, the same public anon key as
everything else), but because cross-session visibility is an OS-level
capability no per-user process has, admin or not.

Three checks, every `check_seconds`:
  1. New local user account created (compared against a baseline captured
     on first run -- same "baseline silently, flag drift after" pattern used
     everywhere else in this project: extensions.py, vm_monitor.py, the
     router's config tamper-evidence monitor).
  2. The active console/GUI session is not `expected_user`.
  3. The monitor agent (run_agent.py) has an injected library loaded --
     the classic DYLD_INSERT_LIBRARIES-style in-memory tampering technique,
     used to hook/patch a running process without ever touching disk. This
     specifically closes the "in-memory patching is undetectable" gap
     accepted earlier in this project's design: confirmed on this exact
     Mac that root CAN inspect another process's loaded libraries (`vmmap`
     works without any special entitlement here), so rather than trying to
     diff raw memory bytes (impractical for a Python process -- the actual
     interpreted logic lives in dynamic heap objects, not a fixed
     on-disk-comparable region), this checks WHERE every loaded library
     came from. Every legitimate library loads from a small, fixed set of
     trusted path prefixes (the app bundle, /usr/lib, /System/Library);
     anything loaded from outside those is flagged immediately -- no
     baseline needed, no locally-tamperable trust anchor, matching the
     same "don't trust something a local admin could also tamper with"
     reasoning that moved integrity.py off a local baseline file.
  4. A debugger is attached to the monitor agent. Dylib injection (#3) only
     catches ONE way to patch a running process -- an attacker could
     instead attach lldb/gdb directly and rewrite live Python heap objects
     in place, no external library involved at all. Checked via the
     kernel's own P_TRACED process flag (sysctl CTL_KERN/KERN_PROC/
     KERN_PROC_PID), the same mechanism debuggers themselves rely on to
     know a target is already claimed. The exact byte offset of p_flag
     within struct kinfo_proc, and P_TRACED's value, were extracted by
     compiling a tiny C program against the real macOS system headers
     (never hand-guessed) and cross-checked against the returned struct's
     actual size before being hardcoded here -- ctypes calls into sysctl
     without correctly declared argtypes silently corrupt data rather than
     erroring, which is exactly what happened on a first attempt at this
     during development, caught by comparing the returned size against
     the compiler's own sizeof(). Note: on this Mac, debugger attachment
     is ALREADY blocked by default at the OS level (macOS's Developer
     Tools authorization gate) -- for ANYONE, even root -- which is a
     real, independent barrier this check adds a second layer behind, not
     the only thing standing in the way.

Reports both via eg_watcher_heartbeat() (supabase/anon_client_pivot.sql),
which stamps its own server-side timestamp -- same principle as the main
app's heartbeat, no client-supplied value the watcher itself could forge if
it were ever compromised. Disabling this daemon is just as visible as
disabling the main app: eg_check_gone_dark() alerts independently on
watcher_last_heartbeat staleness.

Tamper-EVIDENT, not tamper-proof, same standing philosophy as the rest of
this project: a determined admin can still kill this daemon (that shows up
as its own gone-dark alert) or delete the baseline file (a missing baseline
just means the next run re-baselines silently -- same honest limit the
file-integrity watcher already has with its own trust anchor, see
integrity.py). What this closes is the SILENT case: switching sessions or
adding an account without anyone noticing at all.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

_BASE = Path(__file__).resolve().parent.parent
_BASELINE_PATH = _BASE / "session_watcher_baseline.json"

# macOS reserves UID < 500 for system/service accounts (root, daemon, _www,
# etc.) -- only UIDs >= 500 are real, human-created accounts.
_MIN_HUMAN_UID = 500

# Every legitimate loaded library/framework the monitor agent should ever
# have mapped comes from one of these roots: the app bundle itself
# (interpreter + bundled site-packages), or standard macOS system paths.
# Anything outside this set is flagged unconditionally -- this list needs
# no baseline file (nothing here for a local admin to tamper with) and
# needs no update when new legitimate dependencies get bundled, since it's
# a set of trusted ROOTS, not a specific list of expected files.
_TRUSTED_LIB_PREFIXES = (
    "/Applications/EyeGuard.app/",
    "/usr/lib/",
    "/usr/libexec/",
    "/System/Library/",
)

# vmmap's plain-text columns aren't fixed-width and a loaded library's path
# can itself contain spaces (e.g. "Library/Application Support/...") -- a
# naive whitespace split breaks on that. Every region line that references a
# file has "SM=<mode>" immediately before the path with nothing after it, so
# anchoring there and capturing the rest of the line is what actually holds
# up against real vmmap output (verified against real captured output,
# including a path with a space in it, before shipping this).
_VMMAP_PATH_RE = re.compile(r"SM=\S+\s+(/.+)$")

# ---- P_TRACED check: sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID, pid) ------
# All four values below were extracted by compiling a tiny C program against
# the REAL macOS system headers (<sys/sysctl.h>, <sys/proc.h>) on the actual
# target OS/arch, never hand-guessed from documentation -- struct layouts
# like kinfo_proc are not something worth risking a wrong offset on, since a
# wrong offset fails silently (always reads as "not traced") rather than
# erroring. _KINFO_PROC_SIZE is checked against sysctl's own returned size
# every call as a cheap sanity guard against this exact failure mode.
_CTL_KERN, _KERN_PROC, _KERN_PROC_PID = 1, 14, 1
_P_FLAG_OFFSET = 32     # offsetof(struct kinfo_proc, kp_proc.p_flag)
_P_TRACED = 0x800
_KINFO_PROC_SIZE = 648  # sizeof(struct kinfo_proc) on this target

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_libc.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint,
                          ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                          ctypes.c_void_p, ctypes.c_size_t]
_libc.sysctl.restype = ctypes.c_int


def _is_debugger_attached(pid: int) -> bool | None:
    """True if the kernel's P_TRACED flag is set for `pid`, None on any
    lookup failure (process exited, sysctl error, or the returned struct
    doesn't match the expected size -- treated as unreadable, not a
    signal, rather than trusting a mismatched buffer)."""
    try:
        mib = (ctypes.c_int * 4)(_CTL_KERN, _KERN_PROC, _KERN_PROC_PID, pid)
        size = ctypes.c_size_t(0)
        if _libc.sysctl(mib, 4, None, ctypes.byref(size), None, 0) != 0:
            return None
        buf = ctypes.create_string_buffer(size.value)
        if _libc.sysctl(mib, 4, buf, ctypes.byref(size), None, 0) != 0:
            return None
        if size.value != _KINFO_PROC_SIZE:
            return None  # not the struct shape this was verified against
        p_flag = int.from_bytes(
            buf.raw[_P_FLAG_OFFSET:_P_FLAG_OFFSET + 4], "little")
        return (p_flag & _P_TRACED) != 0
    except Exception:
        return None


def _local_user_accounts() -> dict[str, int] | None:
    """{username: uid} for real (non-system) local accounts, or None on any
    lookup failure (never raises -- a transient dscl hiccup should skip this
    cycle, not crash the daemon or report a false new-account alert)."""
    try:
        out = subprocess.run(
            ["dscl", ".", "-list", "/Users", "UniqueID"],
            capture_output=True, text=True, timeout=10,
        ).stdout
    except Exception:
        return None
    accounts: dict[str, int] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        name, uid_str = parts
        try:
            uid = int(uid_str)
        except ValueError:
            continue
        if uid >= _MIN_HUMAN_UID:
            accounts[name] = uid
    return accounts


def _active_console_user() -> str | None:
    """The account that owns the active GUI/console session, or None on any
    lookup failure (e.g. no one logged in at the console at all -- not
    itself suspicious, just not checkable this cycle)."""
    try:
        out = subprocess.run(
            ["stat", "-f", "%Su", "/dev/console"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
    except Exception:
        return None
    return out or None


def _monitor_agent_pid() -> int | None:
    """PID of the running run_agent.py process, or None if it's not
    currently running (not itself suspicious -- e.g. the monitored user
    isn't in an active GUI session right now -- just nothing to check this
    cycle; the main app's own absence is already covered separately by its
    heartbeat-based gone-dark check)."""
    try:
        out = subprocess.run(
            ["pgrep", "-f", "run_agent.py"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
    except Exception:
        return None
    if not out:
        return None
    try:
        return int(out.splitlines()[0])
    except ValueError:
        return None


def _loaded_library_paths(pid: int) -> set[str] | None:
    """Every file path vmmap reports as mapped into `pid`'s address space,
    or None on any failure (this daemon already runs as root, so a failure
    here means vmmap itself had a problem -- e.g. the process exited between
    the pgrep and this call -- not a permissions issue; never treated as a
    signal, just skip this cycle)."""
    try:
        out = subprocess.run(
            ["vmmap", str(pid)],
            capture_output=True, text=True, timeout=20,
        ).stdout
    except Exception:
        return None
    paths = set()
    for line in out.splitlines():
        m = _VMMAP_PATH_RE.search(line)
        if m:
            paths.add(m.group(1))
    return paths or None


def _untrusted_library(pid: int) -> str | None:
    """The path of an untrusted loaded library, if the monitor agent has
    one loaded right now -- the classic signature of DYLD_INSERT_LIBRARIES-
    style in-memory injection. None if vmmap couldn't be read this cycle,
    or everything loaded is from a trusted root -- neither is itself
    suspicious."""
    paths = _loaded_library_paths(pid)
    if paths is None:
        return None
    for path in sorted(paths):
        if not any(path.startswith(prefix) for prefix in _TRUSTED_LIB_PREFIXES):
            return path
    return None


def _load_baseline() -> dict[str, int] | None:
    try:
        return json.loads(_BASELINE_PATH.read_text())
    except Exception:
        return None


def _save_baseline(accounts: dict[str, int]):
    try:
        _BASELINE_PATH.write_text(json.dumps(accounts))
    except OSError:
        pass  # a failed save just means the next cycle re-derives it


class SessionWatcher:
    def __init__(self, url: str, api_key: str, expected_user: str,
                 check_seconds: int = 120):
        self.base = url.rstrip("/")
        self.api_key = api_key
        self.expected_user = expected_user
        self.check_seconds = check_seconds

    def _rpc(self, name: str, params: dict):
        req = urllib.request.Request(
            f"{self.base}/rest/v1/rpc/{name}",
            data=json.dumps(params).encode(), method="POST",
            headers={"apikey": self.api_key,
                     "Authorization": f"Bearer {self.api_key}",
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read()

    def _check_once(self) -> tuple[bool, bool, bool, bool]:
        """Returns (new_account, wrong_user, untrusted_library,
        debugger_attached). Baselines silently on first run -- no accounts
        existing yet, or the baseline file missing, both just mean "start
        fresh from here," matching the established baseline-then-flag-new
        pattern used everywhere else in this project. The library and
        debugger checks need no baseline at all -- see _untrusted_library()
        and _is_debugger_attached()."""
        new_account = False
        current = _local_user_accounts()
        if current is not None:
            baseline = _load_baseline()
            if baseline is None:
                _save_baseline(current)
            else:
                added = set(current) - set(baseline)
                if added:
                    print(f"[session_watcher] new account(s) detected: "
                          f"{sorted(added)}", flush=True)
                    new_account = True
                # Baseline always advances to the current set -- an added
                # account that gets deleted later shouldn't keep alerting
                # forever once it's gone; the report already fired.
                _save_baseline(current)

        wrong_user = False
        active = _active_console_user()
        if active is not None and active != self.expected_user:
            print(f"[session_watcher] active console user is '{active}', "
                  f"expected '{self.expected_user}'", flush=True)
            wrong_user = True

        untrusted_library = False
        debugger_attached = False
        pid = _monitor_agent_pid()
        if pid is not None:
            untrusted_path = _untrusted_library(pid)
            untrusted_library = untrusted_path is not None
            if untrusted_library:
                print(f"[session_watcher] untrusted library loaded in "
                      f"monitor agent: {untrusted_path}", flush=True)

            traced = _is_debugger_attached(pid)
            debugger_attached = bool(traced)
            if debugger_attached:
                print(f"[session_watcher] debugger attached to monitor "
                      f"agent (pid {pid})", flush=True)

        return new_account, wrong_user, untrusted_library, debugger_attached

    def run(self):
        print(f"[session_watcher] active, checking every "
              f"{self.check_seconds}s (expected user: {self.expected_user})",
              flush=True)
        while True:
            try:
                (new_account, wrong_user, untrusted_library,
                 debugger_attached) = self._check_once()
                self._rpc("eg_watcher_heartbeat",
                          {"p_new_account": new_account,
                           "p_wrong_user": wrong_user,
                           "p_untrusted_library": untrusted_library,
                           "p_debugger_attached": debugger_attached})
            except urllib.error.URLError as e:
                print(f"[session_watcher] heartbeat network error: {e} "
                      f"-- will retry next cycle", flush=True)
            except Exception as e:
                # A bad check must never kill this daemon -- same rule as
                # every other background watcher in this project.
                print(f"[session_watcher] check raised {e!r} -- continuing",
                      flush=True)
            time.sleep(self.check_seconds)


def main():
    import argparse
    from .main import load_config
    p = argparse.ArgumentParser(prog="eyeguard-session-watcher")
    p.add_argument("--config", default=str(_BASE / "config.yaml"))
    args = p.parse_args()
    cfg = load_config(args.config)
    sw = cfg.get("session_watcher", {})
    sb = cfg.get("supabase", {})
    if not sw.get("enabled", True):
        print("[session_watcher] disabled in config, exiting", flush=True)
        return
    SessionWatcher(
        url=sb["url"], api_key=sb["api_key"],
        expected_user=sw["expected_user"],
        check_seconds=int(sw.get("check_seconds", 120)),
    ).run()


if __name__ == "__main__":
    main()
