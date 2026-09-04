"""Find My cross-check for the phone-dark alert (2026-08-31).

Why this exists: the router's phone-dark detection (router/eyeguard-phone.py)
can only see the WireGuard tunnel's own liveness signals -- and those go
silent not just when the phone is genuinely off/disabled, but also whenever
iOS suspends AmneziaWG's background execution during ordinary sleep/idle
periods. Confirmed live (2026-08-29 through 2026-08-31): raising the dark
buffer and fixing a wrong-peer bug both helped real bugs, but couldn't fix
this -- from the router's side, "iOS suspended the VPN" and "the phone is
actually off" are indistinguishable, because both just look like silence.

Researched directly (2026-08-31, not guessed): there is no supported way for
ANY third-party iOS app -- including AmneziaWG, including any hypothetical
fork of it -- to get a "device is about to sleep" notification the way
eyeguard/session_watcher.py does via IOKit on macOS. Apple has actively
blocked the Darwin-notification workarounds developers used to use for this.
Checked AmneziaWG's own source (both the archived amnezia-vpn/awg-apple and
the current amnezia-vpn/amneziawg-apple) directly: neither implements the
NEPacketTunnelProvider sleep()/wake() hooks that DO exist specifically for
VPN tunnel providers, so even the app itself doesn't participate in what
little cooperation iOS offers. Building that in is possible in principle but
means forking and maintaining a security-sensitive VPN app's iOS build
indefinitely, for no guaranteed improvement (iOS's background-time budget
still governs regardless) -- a much bigger, riskier undertaking than this
file, ruled out in favor of this approach instead.

The actual fix: sidestep the problem by using a signal that ISN'T subject to
the same background-suspension rules. Apple's Find My network reports device
status using a privileged background mechanism (including Bluetooth-mesh
relay through nearby Apple devices with zero internet connectivity at all)
that Apple grants only to its own system process -- never to third-party
apps, VPN or otherwise. So Find My's last-seen timestamp stays fresh through
exactly the idle periods that suspend AmneziaWG's own keepalive, giving a
genuinely independent way to tell "phone is asleep, not off" from "phone/VPN
really is down."

No official Apple API exists for this -- `pyicloud` (an unofficial,
actively-maintained, reverse-engineered iCloud client) is the practical way
in. Real, accepted tradeoff: Apple can break its private API without notice,
and this requires storing Jonah's own Apple ID credentials locally (the only
Apple ID that can see this specific iPhone in Find My without Family Sharing
already being set up). Consistent with this project's standing trust model:
Jonah already has full admin on this Mac, so a locally-stored credential
here doesn't change what he can already reach -- the same reasoning already
applied to every other local secret in this project.

Reports via eg_report_findmy_status() (see
supabase/findmy_cross_check.sql), which stamps the report time server-side;
the ACTUAL last-seen value comes from Find My's own timestamp (an honest
signal about the phone, not something this script or the client can fake
more favorably than what Apple's API actually returned).

Two entry points:
  --setup   Interactive. Prompts for the Apple ID + password, walks through
            the 2FA challenge (needs Jonah's own phone in hand to read the
            code -- cannot be run by anyone else, cannot be automated), then
            saves a reusable session. Run this once, in a real terminal.
  (default) The periodic background loop -- reads the session --setup saved,
            checks Find My every check_seconds, reports the result. Meant to
            run as a LaunchAgent (deploy/com.eyeguard.findmy.plist) --
            doesn't need root, only reads a file in Jonah's own data dir.
"""

from __future__ import annotations

import getpass
import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from .net import opener as _opener
from .net import hardened_dns as _hardened_dns

_BASE = Path(__file__).resolve().parent.parent

# Confirmed live (2026-09-02): pyicloud's internal requests.Session() calls
# have no explicit timeout set anywhere -- unlike this project's own network
# code (see net.py's module docstring for the exact same class of problem,
# fixed there but that fix only covers OUR OWN opener, not third-party
# libraries' independent networking). Watched a real bootstrapped run hang
# for 3+ minutes with no progress and no exception, on a Mac already known
# to have intermittent DNS/tunnel instability -- a plain `requests` call
# with no timeout blocks forever on a hung connection rather than failing
# cleanly, which meant every check_seconds cycle could silently wedge the
# whole watcher instead of erroring, retrying, or even being catchable by
# run()'s own try/except. socket.setdefaulttimeout() is process-global and
# applies to every socket this interpreter opens, including ones inside
# pyicloud/requests/urllib3 that never set their own -- turns an indefinite
# hang into a clean, catchable TimeoutError after a bounded wait instead.
socket.setdefaulttimeout(30)


def _data_dir(cfg: dict) -> Path:
    # Same directory flag_log/pending_file already live in -- see
    # config.yaml's logging.flag_log comment for why this is the
    # user-writable one, not the root-owned code tree.
    return Path(cfg["logging"]["flag_log"]).resolve().parent


def _credentials_path(cfg: dict) -> Path:
    return _data_dir(cfg) / ".findmy_credentials.json"


def _cookie_dir(cfg: dict) -> Path:
    d = _data_dir(cfg) / ".findmy_session"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load_credentials(cfg: dict) -> tuple[str, str] | None:
    try:
        data = json.loads(_credentials_path(cfg).read_text())
        return data["apple_id"], data["password"]
    except Exception:
        return None


def _save_credentials(cfg: dict, apple_id: str, password: str):
    path = _credentials_path(cfg)
    path.write_text(json.dumps({"apple_id": apple_id, "password": password}))
    path.chmod(0o600)


def setup(cfg: dict):
    """Interactive one-time login. Must be run by Jonah himself in a real
    terminal -- the 2FA code is sent to his own trusted devices, nothing
    here can read or guess it. Safe to re-run any time the saved session
    stops working (Apple sessions expire after weeks/months)."""
    print("EyeGuard Find My setup -- this needs YOUR Apple ID (the one signed "
          "into the monitored iPhone), and a 2FA code from your own device.")
    apple_id = input("Apple ID email: ").strip()
    password = getpass.getpass("Apple ID password: ")

    from pyicloud import PyiCloudService
    from pyicloud.exceptions import PyiCloudFailedLoginException

    # See net.py's hardened_dns() docstring (2026-09-04): pyicloud manages
    # its own requests.Session(), so this is the only way to give its calls
    # the same tunnel-resilient DNS resolution every other HTTP call in this
    # project already gets.
    with _hardened_dns():
        try:
            api = PyiCloudService(apple_id, password,
                                   cookie_directory=str(_cookie_dir(cfg)))
        except PyiCloudFailedLoginException as e:
            print(f"Login failed: {e}")
            return

        if api.requires_2fa:
            code = input("Enter the 2FA code Apple just sent to your device: ").strip()
            if not api.validate_2fa_code(code):
                print("That code didn't validate -- nothing was saved, try again.")
                return
            # Reduces how often future runs need a fresh 2FA challenge --
            # this trusts the SESSION, not the device, and only lasts as
            # long as Apple's own trust window (weeks/months, not
            # indefinite).
            api.trust_session()

        devices = [d.status().get("deviceDisplayName", "?") + ": " + d.status().get("name", "?")
                   for d in api.devices]
    print(f"Login succeeded. Devices visible in Find My: {devices}")
    _save_credentials(cfg, apple_id, password)
    print(f"Saved to {_credentials_path(cfg)} (chmod 600). "
          "The background watcher will pick this up on its next cycle.")


class FindMyWatcher:
    def __init__(self, cfg: dict, url: str, api_key: str,
                 device_name_contains: str, check_seconds: int = 600):
        self.cfg = cfg
        self.base = url.rstrip("/")
        self.api_key = api_key
        self.device_name_contains = device_name_contains.lower()
        self.check_seconds = check_seconds

    def _rpc(self, name: str, params: dict):
        import urllib.request
        req = urllib.request.Request(
            f"{self.base}/rest/v1/rpc/{name}",
            data=json.dumps(params).encode(), method="POST",
            headers={"apikey": self.api_key,
                     "Authorization": f"Bearer {self.api_key}",
                     "Content-Type": "application/json"})
        with _opener.open(req, timeout=15) as r:
            r.read()

    def _alert_session_expired(self):
        """Called the moment login fails or a fresh 2FA challenge is needed
        -- Jonah asked for this to be immediate, not a delayed staleness
        check (see supabase/findmy_session_expired_alert.sql). Debounced
        server-side, so calling this every check_seconds while the session
        stays dead only sends one email, not one per cycle. Best-effort:
        must never raise back into the caller (which is already mid-error-
        handling for the login failure itself)."""
        try:
            self._rpc("eg_report_findmy_session_expired", {})
        except Exception as e:
            print(f"[findmy_watcher] {datetime.now().isoformat()} failed to "
                  f"report session-expired: {e!r}", flush=True)

    def _find_my_last_seen(self) -> datetime | None:
        """Returns the phone's Find My last-seen timestamp, or None if the
        credentials/session aren't set up yet, the session has expired
        (needs `--setup` re-run), no matching device was found, or Find My
        has no location data for it right now (e.g. it's genuinely offline
        with no recent mesh contact either -- itself meaningful, handled by
        the caller reporting nothing rather than a stale/wrong value)."""
        creds = _load_credentials(self.cfg)
        if creds is None:
            print(f"[findmy_watcher] {datetime.now().isoformat()} no saved "
                  f"credentials -- run 'findmy_watcher.py --setup' once, "
                  f"interactively, as jonahdirrim", flush=True)
            return None
        apple_id, password = creds

        from pyicloud import PyiCloudService
        from pyicloud.exceptions import PyiCloudFailedLoginException

        # See net.py's hardened_dns() docstring (2026-09-04): pyicloud
        # manages its own requests.Session(), so this is the only way to
        # give its calls the same tunnel-resilient DNS resolution every
        # other HTTP call in this project already gets. Confirmed live: a
        # real PyiCloudAPIResponseException("Request failed to iCloud")
        # traced directly to idmsa.apple.com failing to resolve while on
        # the AmneziaWG tunnel -- the exact failure mode this whole module
        # exists to route around, just never wired up for this file.
        with _hardened_dns():
            try:
                api = PyiCloudService(apple_id, password,
                                       cookie_directory=str(_cookie_dir(self.cfg)))
            except PyiCloudFailedLoginException as e:
                print(f"[findmy_watcher] {datetime.now().isoformat()} login "
                      f"failed: {e} -- may need 'findmy_watcher.py --setup' "
                      f"re-run (session expired or password changed)", flush=True)
                self._alert_session_expired()
                return None

            if api.requires_2fa:
                # The saved session's trust expired -- nothing this
                # unattended loop can do (2FA needs Jonah's own device),
                # surface it clearly and wait for a manual --setup re-run
                # rather than looping forever on the same dead session.
                print(f"[findmy_watcher] {datetime.now().isoformat()} "
                      f"session needs a fresh 2FA challenge -- run "
                      f"'findmy_watcher.py --setup' again", flush=True)
                self._alert_session_expired()
                return None

            # Confirmed live (2026-09-02): this Apple ID has visibility into
            # a large shared/family group -- device_name_contains alone is
            # NOT enough to identify the right phone. Two real hazards
            # found: (1) several OTHER family members' devices also contain
            # "iPhone" in their name, so a broad match string can pick a
            # stranger's phone, not just Jonah's own; (2) Jonah's own Find
            # My history has FOUR old iPhones still listed (previously-owned
            # devices never fully expire from this list) alongside the
            # current one -- taking the FIRST name match, as this used to,
            # depended entirely on API ordering luck (confirmed: the current
            # phone happened to sort first, but nothing guarantees that
            # stays true). Fixed to collect EVERY device matching
            # device_name_contains that has ANY live location data (retired
            # devices report loc=None, naturally excluding them), then pick
            # whichever has the MOST RECENT timestamp -- the genuinely-in-
            # use phone, not whichever the API happened to list first. Still
            # depends on device_name_contains being scoped tightly enough to
            # exclude other family members (e.g. "Jonah's iPhone", not a
            # bare "iPhone") -- this fixes the ordering hazard, not the
            # scoping one, which is a config.yaml concern.
            candidates: list[tuple[float, str]] = []
            for device in api.devices:
                name = (device.status().get("name") or "") + " " + \
                       (device.status().get("deviceDisplayName") or "")
                if self.device_name_contains in name.lower():
                    loc = device.location
                    if loc and "timeStamp" in loc:
                        candidates.append((loc["timeStamp"], name))
        if candidates:
            candidates.sort(key=lambda c: c[0], reverse=True)
            ts_ms, matched_name = candidates[0]
            if len(candidates) > 1:
                print(f"[findmy_watcher] {datetime.now().isoformat()} "
                      f"{len(candidates)} devices matched "
                      f"{self.device_name_contains!r} with live location "
                      f"data -- picked the freshest: {matched_name!r}",
                      flush=True)
            # Apple's timeStamp is epoch milliseconds.
            return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        print(f"[findmy_watcher] {datetime.now().isoformat()} no device "
              f"matching {self.device_name_contains!r} has live location "
              f"data in Find My -- check config.yaml's "
              f"findmy.device_name_contains against the actual name in "
              f"Settings -> [name] -> Find My", flush=True)
        return None

    def check_once(self):
        """One check-and-report cycle. Shared by run() (the old
        LaunchAgent-loop mode, kept for now in case cron ever needs
        replacing) and the cron entry point (--once, see main()) -- cron
        itself handles the every-check_seconds scheduling in that mode, so
        this just does a single cycle and returns."""
        try:
            last_seen = self._find_my_last_seen()
            if last_seen is not None:
                self._rpc("eg_report_findmy_status",
                          {"p_last_seen": last_seen.isoformat()})
        except Exception as e:
            # A bad check must never kill the caller -- same rule as every
            # other background watcher in this project.
            print(f"[findmy_watcher] {datetime.now().isoformat()} check "
                  f"raised {e!r} -- continuing", flush=True)

    def run(self):
        print(f"[findmy_watcher] {datetime.now().isoformat()} active, "
              f"checking every {self.check_seconds}s", flush=True)
        while True:
            self.check_once()
            time.sleep(self.check_seconds)


def main():
    import argparse
    from .main import load_config
    p = argparse.ArgumentParser(prog="eyeguard-findmy-watcher")
    p.add_argument("--config", default=str(_BASE / "config.yaml"))
    p.add_argument("--setup", action="store_true",
                   help="Interactive one-time (or re-run if the session "
                        "expired) Apple ID login. Run this yourself, in a "
                        "real terminal -- needs a 2FA code from your phone.")
    p.add_argument("--once", action="store_true",
                   help="Run a single check-and-report cycle and exit, "
                        "instead of looping forever. For cron -- see "
                        "deploy/findmy-cron.txt. Switched to this (2026-09-02) "
                        "after a LaunchAgent running this same script "
                        "reproducibly crash-looped under launchd's GUI "
                        "domain (exit 78/EX_CONFIG, zero log output "
                        "anywhere, not reproducible by running the exact "
                        "same command+environment directly) -- ruled out "
                        "environment variables, ThrottleInterval, and "
                        "-m-module-vs-direct-script invocation as the cause "
                        "before giving up on diagnosing it further and "
                        "switching to cron, which doesn't go through "
                        "launchd/Background Task Management at all.")
    args = p.parse_args()
    cfg = load_config(args.config)

    if args.setup:
        setup(cfg)
        return

    fm = cfg.get("findmy", {})
    if not fm.get("enabled", True):
        print("[findmy_watcher] disabled in config, exiting", flush=True)
        return
    sb = cfg.get("supabase", {})
    watcher = FindMyWatcher(
        cfg=cfg, url=sb["url"], api_key=sb["api_key"],
        device_name_contains=fm.get("device_name_contains", "iPhone"),
        check_seconds=int(fm.get("check_seconds", 600)),
    )
    if args.once:
        watcher.check_once()
    else:
        watcher.run()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise  # argparse's own --help/bad-args exit -- not a crash, don't log it
    except BaseException:
        # Confirmed live (2026-09-02): this LaunchAgent crash-looped
        # (launchctl showing runs climbing fast, exit code 78/EX_CONFIG)
        # with a COMPLETELY EMPTY StandardErrorPath log every single time --
        # running the exact same command manually, outside launchd, worked
        # fine and printed normally. Something about launchd's invocation
        # environment is different enough to cause a crash before Python's
        # own default traceback-to-stderr even reaches the log file (or
        # reaches it in a way this specific launchd config doesn't capture
        # -- unconfirmed which). This is a last-resort catch specifically to
        # find out: writes the full traceback to a fixed path in the SAME
        # user-writable data dir every other diagnostic file in this project
        # already uses, independent of whatever is going wrong with
        # stdout/stderr capture under launchd. If this file appears empty
        # too after a crash, the process is being killed externally (jetsam,
        # a signal) before Python's own exception machinery ever runs at
        # all -- a meaningfully different, more serious finding than a
        # normal unhandled exception.
        import traceback
        tb = f"\n--- {datetime.now().isoformat()} ---\n" + traceback.format_exc()
        # Hardcoded absolute path, NOT Path.home() -- if home-directory
        # resolution itself is what's going wrong under launchd (unproven,
        # but Path.home() depends on $HOME/pwd lookups that could behave
        # differently in a stripped launchd environment), a dynamic path
        # could silently fail here too, hidden by this except-and-continue,
        # making the "empty crash log" finding meaningless either way.
        # Matches the exact path this file's own plist already hardcodes
        # for StandardOutPath/StandardErrorPath.
        wrote = False
        try:
            crash_path = Path("/Users/jonahdirrim/Library/Application Support/EyeGuard-data/findmy_watcher_crash.log")
            crash_path.parent.mkdir(parents=True, exist_ok=True)
            with crash_path.open("a") as f:
                f.write(tb)
            wrote = True
        except Exception:
            pass
        if not wrote:
            # Last-resort fallback: /tmp is world-writable regardless of
            # user/home-resolution issues -- if even THIS fails, something
            # more fundamental than a permissions/path problem is going on.
            try:
                with open("/tmp/findmy_watcher_crash.log", "a") as f:
                    f.write(tb)
            except Exception:
                pass
        raise
