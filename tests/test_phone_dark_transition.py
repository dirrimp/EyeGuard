#!/usr/bin/env python3
"""Tests for eyeguard-phone.py's network-transition grace (2026-09-28).

Evidence this fixes: 17 "phone-dark" flags 2026-09-22 through 2026-09-27,
every single one reading "silent for 168s" or "silent for 169s" (queried
directly from the flags table via the anon key) -- a near-fixed window
repeating across 6 days, matching Jonah's lead that this happens leaving
home while the phone should have been online the whole time (the on-demand
WireGuard tunnel hasn't handshaked yet on the new network -- genuinely
invisible to every liveness signal the router has, for that ~168-169s).

Tests the pure decision function (_evaluate_liveness) directly -- no
subprocess/tcpdump/ping/awg involved, so this runs anywhere with no router
access. router/eyeguard-phone.py loads its config at import time from
EG_PHONE_CONF (or /etc/eyeguard/phone.json); this points it at a throwaway
temp file with the minimum required keys before importing.

Not wired into a CI workflow (no workflow currently runs router/ code, only
config.yaml's invariants via tests/test_guardrail.py); run manually:
`python3 tests/test_phone_dark_transition.py`.
"""
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_tmp_conf = tempfile.NamedTemporaryFile(
    mode="w", suffix=".json", delete=False)
json.dump({"api_key": "test", "supabase_url": "https://example.invalid",
           "dark_buffer_seconds": 150, "transition_grace_seconds": 40}, _tmp_conf)
_tmp_conf.close()
os.environ["EG_PHONE_CONF"] = _tmp_conf.name

_spec = importlib.util.spec_from_file_location(
    "eyeguard_phone_under_test", ROOT / "router" / "eyeguard-phone.py")
phone = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(phone)
os.unlink(_tmp_conf.name)

fails: list[str] = []


def check(name: str, ok: bool, detail: str = ""):
    tag = "ok  " if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        fails.append(name)


DARK = 150
GRACE = 40


def fresh_state(last_home_seen, last_wg_seen, last_activity=None, dark_alerted=False):
    return {
        "last_activity": last_activity if last_activity is not None
                          else max(last_home_seen, last_wg_seen),
        "last_home_seen": last_home_seen,
        "last_wg_seen": last_wg_seen,
        "last_rx": 1000,
        "dark_alerted": dark_alerted,
        "transition_grace_logged": False,
    }


print("— already-away phone going dark is NOT delayed (no coverage loss) —")
# last confirmed signal was WG (away), well before either buffer -> fires at
# the ORIGINAL 150s, exactly as before this PR.
t0 = 1_000_000.0
state = fresh_state(last_home_seen=t0 - 1000, last_wg_seen=t0)
fire, dark_secs, active, _ = phone._evaluate_liveness(
    state, t0 + DARK + 1, ping_ok=False, rx=None, dark=DARK, grace=GRACE)
check("fires at just past the original 150s threshold", fire,
      f"dark_secs={dark_secs}")
check("no grace applied (last signal was WG, not home)",
      dark_secs <= DARK + 1)

print("— leaving-home transition within the observed 168-169s is suppressed —")
state = fresh_state(last_home_seen=t0, last_wg_seen=t0 - 1000)
# 169s silence, matching the real flags exactly -- must NOT fire with the
# fix (150 < 169 <= 150+40).
fire, dark_secs, active, log_line = phone._evaluate_liveness(
    state, t0 + 169, ping_ok=False, rx=None, dark=DARK, grace=GRACE)
check("does not fire at 169s silence right after leaving home", not fire)
check("suppression is logged, not silent", log_line is not None)

print("— but the same transition still alerts once the grace itself expires —")
# 250s silence (well past DARK+GRACE=190) with no WG confirmation ever
# arriving -- proves this isn't an open-ended suppression: a genuinely dead
# phone right at a home departure still alerts, just up to GRACE seconds
# later than a phone that goes dark while already away.
state = fresh_state(last_home_seen=t0, last_wg_seen=t0 - 1000)
fire, dark_secs, active, _ = phone._evaluate_liveness(
    state, t0 + 250, ping_ok=False, rx=None, dark=DARK, grace=GRACE)
check("still fires once dark_secs exceeds DARK+GRACE", fire,
      f"dark_secs={dark_secs}")

print("— a WG handshake/activity during the grace window cancels it immediately —")
state = fresh_state(last_home_seen=t0, last_wg_seen=t0 - 1000)
state["last_rx"] = 1000
# 30s after leaving home, WG traffic resumes (rx grows) -- must NOT fire on
# the very next tick even well past 150s later, since last_wg_seen is now
# the freshest signal.
fire1, _, _, _ = phone._evaluate_liveness(
    state, t0 + 30, ping_ok=False, rx=1500, dark=DARK, grace=GRACE)
check("no false fire the instant WG reconnects", not fire1)
fire2, dark_secs2, _, _ = phone._evaluate_liveness(
    state, t0 + 30 + DARK + 1, ping_ok=False, rx=1500, dark=DARK, grace=GRACE)
check("and the grace does not linger: once WG is the freshest signal, a "
      "SUBSEQUENT gap fires at the tight original 150s again, not 190s",
      fire2, f"dark_secs={dark_secs2}")

print("— home presence resuming (false start, phone never really left) cancels it too —")
state = fresh_state(last_home_seen=t0, last_wg_seen=t0 - 1000)
fire, _, _, _ = phone._evaluate_liveness(
    state, t0 + 60, ping_ok=True, rx=None, dark=DARK, grace=GRACE)
check("ping resuming on home LAN clears the dark clock", not fire)
check("last_home_seen advances on the fresh ping",
      state["last_home_seen"] == t0 + 60)

print("— boot-time tie (last_home_seen == last_wg_seen) grants NO grace —")
state = fresh_state(last_home_seen=t0, last_wg_seen=t0)  # exact tie, as at startup
fire, dark_secs, _, _ = phone._evaluate_liveness(
    state, t0 + 169, ping_ok=False, rx=None, dark=DARK, grace=GRACE)
check("a tie is not treated as 'recently left home' -- fires at the "
      "original 150s, matching pre-fix behavior on a fresh start", fire)

print("— dark-context logging (2026-11-19) is log-only and never blocks the flag —")
st = fresh_state(last_home_seen=t0 - 1000, last_wg_seen=t0)
ctx = phone._dark_context(st, t0 + 168, False, 168, DARK, GRACE)
check("a phone whose freshest signal was WireGuard is reported last=wg, grace not applied, threshold 150",
      "last=wg" in ctx and "grace_applied=False" in ctx and "threshold=150" in ctx and "wg_age=168s" in ctx, ctx)
st = fresh_state(last_home_seen=t0, last_wg_seen=t0 - 1000)
ctx = phone._dark_context(st, t0 + 100, False, 100, DARK, GRACE)
check("a phone that just left home is reported last=home, grace applied, threshold 190",
      "last=home" in ctx and "grace_applied=True" in ctx and "threshold=190" in ctx, ctx)
before = dict(st)
phone._dark_context(st, t0 + 100, False, 100, DARK, GRACE)
check("building the context does not change the state", st == before)
_real_run = phone.subprocess.run
def _boom(*a, **k): raise OSError("no such binary")
phone.subprocess.run = _boom
try:
    probe = phone._dark_probe()
finally:
    phone.subprocess.run = _real_run
check("a failing probe returns text and never raises (so the flag is still sent)",
      isinstance(probe, str) and "neigh=" in probe and "handshake_age=" in probe, probe)
src = (ROOT / "router" / "eyeguard-phone.py").read_text()
i = src.index("if fire_dark:\n            try:")
j = src.index("sb_post(\"/rest/v1/flags\"", i)
check("the context code sits inside try/except BEFORE the flag post, and the flag payload keeps its reason and verdict",
      "except Exception" in src[i:j] and "DARK_VERDICT" in src[j:j + 400] and "phone-dark: silent for" in src[j:j + 700])
check("no secret is logged: the context line carries no key, token or address",
      not any(w in src[src.index("def _dark_context"):src.index("def heartbeat_loop")] for w in ("API_KEY", "TOKEN", "WG_PEER}", "endpoint")))

print()
if fails:
    print(f"FAILED — {len(fails)} check(s) failed: {fails}")
    sys.exit(1)
print("PASSED — phone-dark transition grace behaves as expected.")
