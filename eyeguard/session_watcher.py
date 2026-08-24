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

Two checks, every `check_seconds`:
  1. New local user account created (compared against a baseline captured
     on first run -- same "baseline silently, flag drift after" pattern used
     everywhere else in this project: extensions.py, vm_monitor.py, the
     router's config tamper-evidence monitor).
  2. The active console/GUI session is not `expected_user`.

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

import json
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

    def _check_once(self) -> tuple[bool, bool]:
        """Returns (new_account, wrong_user). Baselines silently on first
        run -- no accounts existing yet, or the baseline file missing, both
        just mean "start fresh from here," matching the established
        baseline-then-flag-new pattern used everywhere else in this
        project."""
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

        return new_account, wrong_user

    def run(self):
        print(f"[session_watcher] active, checking every "
              f"{self.check_seconds}s (expected user: {self.expected_user})",
              flush=True)
        while True:
            try:
                new_account, wrong_user = self._check_once()
                self._rpc("eg_watcher_heartbeat",
                          {"p_new_account": new_account,
                           "p_wrong_user": wrong_user})
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
