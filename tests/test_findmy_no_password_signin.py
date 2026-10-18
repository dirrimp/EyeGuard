#!/usr/bin/env python3
"""Tests for the 2026-10-18 fix: unattended Find My checks never perform a
password (SRP) sign-in, and back off after the session is found dead.

Bug: cron --once handed pyicloud the Apple ID password every 10 minutes, so any
failed /validate probe (even a transient network error) or a Find My 450
re-auth fell through to a full SRP sign-in -> "Apple Account Sign In
Requested" prompts on Jonah's devices. No network, no credentials needed:
pyicloud's PyiCloudService is replaced by a fake that records how it was built.
Run: python3 tests/test_findmy_no_password_signin.py  (bundled python has pyicloud)
"""
import sys
import tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    import pyicloud
    from pyicloud.exceptions import (PyiCloudAPIResponseException,
                                     PyiCloudFailedLoginException)
except Exception as e:  # pragma: no cover
    print(f"SKIP: pyicloud not importable ({e!r})")
    sys.exit(0)

from eyeguard import findmy_watcher as fw  # noqa: E402

fails: list[str] = []


def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        fails.append(name)


class Dev:
    def __init__(self, name, ts):
        self._n, self._ts = name, ts
        self.location = {"timeStamp": ts} if ts else None

    def status(self):
        return {"name": self._n, "deviceDisplayName": ""}


class Resp:
    def __init__(self, j):
        self._j = j

    def raise_for_status(self):
        pass

    def json(self):
        return self._j


class Sess:
    posts: list = []
    post_result = {"hsaTrustedBrowser": False, "dsInfo": {"hsaVersion": 2}}

    def __init__(self, token=True):
        self.data = {"session_token": "x", "trust_token": "t",
                     "account_country": "USA"} if token else {}
        self.cookies = {"X-APPLE-WEBAUTH-TOKEN": "c"} if token else {}

    def post(self, url, **kw):
        Sess.posts.append((url, kw))
        r = Sess.post_result
        if isinstance(r, Exception):
            raise r
        return Resp(r)


class FakeSvc:
    """validate: 'ok' | exception instance. devices: list or exception."""
    validate = "ok"
    trusted = True
    devices_result = [Dev("Jonah's iPhone", 1_760_000_000_000)]
    token = True
    built = []
    srp_called = 0

    def __init__(self, apple_id, password=None, cookie_directory=None, **kw):
        FakeSvc.built.append({"password": password, **kw})
        self.session = Sess(FakeSvc.token)
        self.data = {}

    def _validate_token(self):
        if isinstance(FakeSvc.validate, Exception):
            raise FakeSvc.validate
        return {"hsaTrustedBrowser": FakeSvc.trusted,
                "dsInfo": {"hsaVersion": 2}}

    def _update_state(self):
        pass

    requires_2sa = False
    _setup_endpoint = "https://setup.example/ws"
    need_reauth = False  # simulate Find My 450 -> pyicloud calls _authenticate

    @property
    def requires_2fa(self):
        return not FakeSvc.trusted

    @property
    def is_trusted_session(self):
        return FakeSvc.trusted

    @property
    def devices(self):
        if FakeSvc.need_reauth:
            self._authenticate()  # what findmyiphone's 450 handler ends up calling
        if isinstance(FakeSvc.devices_result, Exception):
            raise FakeSvc.devices_result
        return FakeSvc.devices_result


def reset(**kw):
    FakeSvc.validate, FakeSvc.trusted, FakeSvc.token = "ok", True, True
    FakeSvc.devices_result = [Dev("Jonah's iPhone", 1_760_000_000_000)]
    FakeSvc.built = []
    FakeSvc.need_reauth = False
    Sess.posts = []
    Sess.post_result = {"hsaTrustedBrowser": False, "dsInfo": {"hsaVersion": 2}}
    for k, v in kw.items():
        setattr(FakeSvc, k, v)


tmp = Path(tempfile.mkdtemp())
cfg = {"logging": {"flag_log": str(tmp / "flags.jsonl")}}
(tmp / ".findmy_credentials.json").write_text(
    '{"apple_id": "a@example.com", "password": "SECRET-PW"}')
pyicloud.PyiCloudService = FakeSvc


def make():
    w = fw.FindMyWatcher(cfg, "http://x", "k", "iphone")
    w.alerts = []
    w._alert_session_expired = lambda reason: w.alerts.append(reason)
    return w


def marker():
    return fw._read_needs_setup(cfg)


print("-- healthy session: reads Find My, never receives the password --")
reset()
w = make()
r = w._find_my_last_seen()
check("returns last-seen", isinstance(r, datetime))
check("password never passed to pyicloud", all(b["password"] is None for b in FakeSvc.built))
check("authenticate=False (no implicit sign-in)", all(b.get("authenticate") is False for b in FakeSvc.built))
check("no marker, no alert", marker() is None and not w.alerts)

print("-- transient network error on validate: no sign-in, no marker, no alert --")
reset(validate=PyiCloudAPIResponseException("Request failed to iCloud"))
w = make()
check("returns None", w._find_my_last_seen() is None)
check("no marker", marker() is None)
check("no alert", not w.alerts)
reset(validate=PyiCloudAPIResponseException("bad gateway", 503))
check("5xx also transient", make()._find_my_last_seen() is None and marker() is None)

print("-- validate rejected (401): alert + back-off marker --")
reset(validate=PyiCloudAPIResponseException("Authentication required", 401))
w = make()
check("returns None", w._find_my_last_seen() is None)
check("marker written", marker() == "session_expired")
check("alerted session_expired", w.alerts == ["session_expired"])

print("-- backed off: later runs make NO Apple call, still alert --")
reset()
w = make()
check("returns None", w._find_my_last_seen() is None)
check("PyiCloudService never constructed", FakeSvc.built == [])
check("still re-alerts (server debounces)", w.alerts == ["session_expired"])

print("-- --setup success clears the marker; checks resume --")
fw._clear_needs_setup(cfg)
check("marker cleared", marker() is None)
reset()
check("healthy again", isinstance(make()._find_my_last_seen(), datetime))

print("-- requires_2fa (untrusted session): alert + marker --")
reset(trusted=False)
w = make()
check("returns None", w._find_my_last_seen() is None)
check("marker + alert", marker() == "session_expired" and w.alerts == ["session_expired"])
fw._clear_needs_setup(cfg)

print("-- no saved session token: alert + marker, no network --")
reset(token=False)
w = make()
check("returns None", w._find_my_last_seen() is None)
check("marker + alert", marker() == "session_expired" and w.alerts == ["session_expired"])
fw._clear_needs_setup(cfg)

print("-- Find My 450 re-auth mid-run fails (no password): alert + marker --")
reset(devices_result=PyiCloudFailedLoginException("No password set"))
w = make()
check("returns None", w._find_my_last_seen() is None)
check("marker + alert", marker() == "session_expired" and w.alerts == ["session_expired"])
fw._clear_needs_setup(cfg)

print("-- Find My 450: token-only accountLogin, untrusted flag tolerated, no SRP --")
reset(need_reauth=True)
w = make()
r = w._find_my_last_seen()
check("still returns last-seen (coverage kept)", isinstance(r, datetime))
check("exactly one accountLogin POST, to setup endpoint",
      len(Sess.posts) == 1 and Sess.posts[0][0].endswith("/accountLogin"))
check("no password in the request", "SECRET-PW" not in str(Sess.posts))
check("no marker, no alert", marker() is None and not w.alerts)

print("-- accountLogin rejected (real expiry): alert + marker --")
reset(need_reauth=True)
Sess.post_result = PyiCloudAPIResponseException("Authentication required", 421)
w = make()
check("returns None", w._find_my_last_seen() is None)
check("marker + alert", marker() == "session_expired" and w.alerts == ["session_expired"])
fw._clear_needs_setup(cfg)

print("-- accountLogin network blip: skip quietly, no marker --")
reset(need_reauth=True)
Sess.post_result = PyiCloudAPIResponseException("Request failed to iCloud")
w = make()
check("returns None", w._find_my_last_seen() is None)
check("no marker, no alert", marker() is None and not w.alerts)

print("-- detection unchanged: freshest matching device wins --")
reset(devices_result=[Dev("Jonah's iPhone", 1_000), Dev("Old iPhone", None),
                      Dev("Jonah's iPhone 2", 5_000), Dev("Mac", 9_999)])
r = make()._find_my_last_seen()
check("freshest iPhone timestamp (5s)", r is not None and int(r.timestamp()) == 5)

print("-- real pyicloud: re-auth without a password cannot reach Apple --")
pyicloud_real = sys.modules["pyicloud.base"].PyiCloudService
d = tempfile.mkdtemp()
svc = pyicloud_real("a@example.com", None, cookie_directory=d, authenticate=False)
calls = []
orig = type(svc.session).request
type(svc.session).request = lambda self, *a, **k: calls.append(a) or (_ for _ in ()).throw(AssertionError("network used"))
try:
    svc.authenticate(force_refresh=True)
    raised = None
except PyiCloudFailedLoginException as e:
    raised = e
except AssertionError as e:
    raised = e
finally:
    type(svc.session).request = orig
check("raises FailedLogin locally", isinstance(raised, PyiCloudFailedLoginException), repr(raised))
check("zero HTTP requests made", calls == [], f"{len(calls)} calls")

print()
if fails:
    print(f"FAILED: {fails}")
    sys.exit(1)
print("all passed")
