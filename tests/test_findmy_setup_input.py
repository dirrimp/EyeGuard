#!/usr/bin/env python3
"""Find My --setup input handling (2026-11-17): stray keys typed ahead of the 2FA prompt must not spoil the code, a mistyped code
can be retried without re-entering the password, and Apple's 503 must read as "Apple is busy", not "wrong password".
No network and no real Apple call: pyicloud is replaced by a fake. Run: python3 tests/test_findmy_setup_input.py"""
import contextlib, io, sys, tempfile, types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eyeguard import findmy_watcher as fw  # noqa: E402

fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + ("" if ok else f" -- {detail}"))
    if not ok: fails.append(name)

print("-- _clean_code keeps only digits --")
check("plain code", fw._clean_code("826337") == "826337")
check("thirteen down-arrow escape sequences typed ahead of the code (the real failure)", fw._clean_code("\x1b[B" * 13 + "826337") == "826337")
check("spaces and dashes", fw._clean_code(" 826 337 ") == "826337" and fw._clean_code("826-337") == "826337")
check("empty and None", fw._clean_code("") == "" and fw._clean_code(None) == "")
check("no digits at all", fw._clean_code("\x1b[B\x1b[B") == "")

print("-- _flush_typeahead never raises (no terminal here) --")
try:
    fw._flush_typeahead(); ok = True
except Exception as e:
    ok = False
check("no-op without a tty", ok)

print("-- _login_failure_message --")
e503 = Exception("('Failed to initiate srp authentication.', PyiCloudAPIResponseException('Service Temporarily Unavailable (503): <html>'))")
m = fw._login_failure_message(e503)
check("503 says it is Apple, says wait, and is not 'login failed'", "Apple" in m and "45 to 60 minutes" in m and "not your password" in m and not m.startswith("Login failed"), m)
check("a real wrong-password error is passed through", fw._login_failure_message(Exception("Invalid email/password combination.")).startswith("Login failed: "))

# ---- full setup() flow with a fake pyicloud ----
class FailedLogin(Exception): pass

def run_setup(inputs, validate, login_exc=None, requires_2fa=True):
    tmp = Path(tempfile.mkdtemp())
    cfg = {"logging": {"flag_log": str(tmp / "flags.jsonl")}}
    (tmp / ".findmy_needs_setup").write_text('{"reason": "session_expired", "at": "2026-11-17T11:40:03"}')
    calls = {"validate": [], "trusted": False, "prompts": 0}

    class Dev:
        def status(self): return {"deviceDisplayName": "iPhone", "name": "X"}
    class Svc:
        def __init__(self, apple_id, password, cookie_directory=None):
            if login_exc: raise login_exc
            self.requires_2fa = requires_2fa
            self.devices = [Dev()]
        def validate_2fa_code(self, code):
            calls["validate"].append(code)
            return validate(code)
        def trust_session(self): calls["trusted"] = True

    pkg = types.ModuleType("pyicloud"); pkg.PyiCloudService = Svc
    exc = types.ModuleType("pyicloud.exceptions"); exc.PyiCloudFailedLoginException = FailedLogin
    pkg.exceptions = exc
    saved = {k: sys.modules.get(k) for k in ("pyicloud", "pyicloud.exceptions")}
    sys.modules["pyicloud"], sys.modules["pyicloud.exceptions"] = pkg, exc
    it = iter(inputs)
    def fake_input(prompt=""):
        calls["prompts"] += 1
        return next(it)
    old_input, old_gp, old_dns = fw.__dict__.get("input"), fw.getpass.getpass, fw._hardened_dns
    fw.input = fake_input
    fw.getpass.getpass = lambda prompt="": "PW"
    fw._hardened_dns = contextlib.nullcontext
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            fw.setup(cfg)
    finally:
        fw.getpass.getpass = old_gp
        fw._hardened_dns = old_dns
        if old_input is None: del fw.input
        else: fw.input = old_input
        for k, v in saved.items():
            if v is None: sys.modules.pop(k, None)
            else: sys.modules[k] = v
    return out.getvalue(), calls, tmp

GOOD = "826337"
print("-- setup(): the 2026-11-17 failure, replayed --")
out, calls, tmp = run_setup(["jonah@x.test", "\x1b[B" * 13 + GOOD], lambda c: c == GOOD)
check("code with 13 arrow-key sequences typed ahead is accepted", calls["validate"] == [GOOD], str(calls["validate"]))
check("session trusted, credentials saved, back-off marker cleared",
      calls["trusted"] and (tmp / ".findmy_credentials.json").exists() and not (tmp / ".findmy_needs_setup").exists())

print("-- setup(): retries without asking for the password again --")
out, calls, tmp = run_setup(["a@x.test", "111111", GOOD], lambda c: c == GOOD)
check("a wrong code, then the right one, succeeds", calls["validate"] == ["111111", GOOD] and (tmp / ".findmy_credentials.json").exists(), str(calls))
check("the user was told to use the newest code", "newest code" in out)
check("the Apple ID was asked for once", calls["prompts"] == 1 + 2, str(calls["prompts"]))

print("-- setup(): input that is not a 6-digit code is never sent to Apple --")
out, calls, tmp = run_setup(["a@x.test", "\x1b[B\x1b[B", "12345", GOOD], lambda c: c == GOOD)
check("only the 6-digit code reached Apple", calls["validate"] == [GOOD], str(calls["validate"]))
check("and it still succeeded within the three tries", (tmp / ".findmy_credentials.json").exists())

print("-- setup(): three bad tries save nothing --")
out, calls, tmp = run_setup(["a@x.test", "111111", "222222", "333333"], lambda c: False)
check("three codes sent, all refused", calls["validate"] == ["111111", "222222", "333333"])
check("nothing saved, marker kept, clear message", not (tmp / ".findmy_credentials.json").exists() and (tmp / ".findmy_needs_setup").exists() and "nothing was saved" in out)

print("-- setup(): Apple's 503 --")
out, calls, tmp = run_setup(["a@x.test"], lambda c: True, login_exc=FailedLogin(e503.args[0]))
check("503 prints the Apple-is-busy message", "Apple is temporarily refusing" in out and "45 to 60 minutes" in out, out)
check("nothing saved, marker kept, no code prompt", not (tmp / ".findmy_credentials.json").exists() and (tmp / ".findmy_needs_setup").exists() and calls["prompts"] == 1)
out, calls, tmp = run_setup(["a@x.test"], lambda c: True, login_exc=RuntimeError("Service Temporarily Unavailable (503)"))
check("a non-login exception is handled too (no traceback)", "Apple is temporarily refusing" in out)

print("-- setup(): an account without 2FA still works --")
out, calls, tmp = run_setup(["a@x.test"], lambda c: True, requires_2fa=False)
check("no code asked, credentials saved", calls["validate"] == [] and (tmp / ".findmy_credentials.json").exists())

if fails: print("\nFAILED:", *fails, sep="\n  "); sys.exit(1)
print("\nALL OK")
