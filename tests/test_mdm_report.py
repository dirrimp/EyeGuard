#!/usr/bin/env python3
"""Tests for the G11 MDM event reporter (g11/eg_report.py) against a local mock
of the Supabase RPC, plus static checks on supabase/mdm_app_events.sql.
Synthetic data only. Run: python3 tests/test_mdm_report.py"""
import json, os, re, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "g11" / "eg-report.sh")
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

STATE = {"mode": "ok", "seen": []}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        STATE["seen"].append((self.path, dict(self.headers), body))
        code = {"ok": 200, "down": 503, "auth": 401, "bad": 400}[STATE["mode"]]
        self.send_response(code); self.end_headers(); self.wfile.write(b"{}")
srv = HTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

tmp = tempfile.mkdtemp()
conf = os.path.join(tmp, "c.json"); q = os.path.join(tmp, "q")
json.dump({"supabase_url": "https://x.invalid", "anon_key": "anon", "device_token": "t" * 64}, open(conf, "w"))
os.chmod(conf, 0o600)

# The sender insists on https; point the module at the mock by patching via env-free import.
sys.path.insert(0, str(ROOT / "g11"))
import eg_report as R
R.CONF, R.QDIR, R.ATTEMPTS = conf, q, 2
R.time.sleep = lambda s: None
_load = R.load_conf
def load_mock():
    c = _load(); c["supabase_url"] = f"http://127.0.0.1:{srv.server_port}"; return c
R.load_conf = load_mock

def run(arg):
    import io, contextlib
    out, e = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(e):
        rc = R.main(["x", arg])
    return rc, out.getvalue().strip(), e.getvalue()

EV = {"type": "app_installed", "detected_at": "2026-10-03T14:00:00Z", "window_start": "2026-10-03T13:45:00Z",
      "device": "Jonah iPhone", "name": "Some App", "bundle_id": "com.x.y", "version": "1.2"}

STATE["mode"] = "ok"
rc, out, _ = run(json.dumps(EV))
check("delivered when online", rc == 0 and out == "delivered" and R.queued() == [])
path, hdr, body = STATE["seen"][-1]
check("posts to the RPC with token + event", path.endswith("/rest/v1/rpc/eg_report_mdm_event")
      and body["p_token"] == "t" * 64 and body["p_event"]["bundle_id"] == "com.x.y")

STATE["mode"] = "down"
rc, out, _ = run(json.dumps(EV))
check("offline: exit 0 and queued, event not lost", rc == 0 and out == "queued" and len(R.queued()) == 1)
ev2 = dict(EV, bundle_id="com.z", detected_at="2026-10-03T14:15:00Z")
rc, out, _ = run(json.dumps(ev2))
check("second event queues behind first", len(R.queued()) == 2)
STATE["mode"] = "ok"; STATE["seen"].clear()
rc, out, _ = run("--flush")
check("flush delivers all, oldest first", rc == 0 and R.queued() == []
      and [b["p_event"]["bundle_id"] for _, _, b in STATE["seen"]] == ["com.x.y", "com.z"])

STATE["mode"] = "auth"
rc, out, err_ = run(json.dumps(EV))
check("401: stays queued, exit 3, token not printed", rc == 3 and len(R.queued()) == 1 and "t" * 64 not in err_ + out)
STATE["mode"] = "bad"
rc, out, _ = run("--flush")
check("400: moved to dead/, not retried forever", R.queued() == [] and len(os.listdir(os.path.join(q, "dead"))) == 1)

check("rejects bad type", run(json.dumps(dict(EV, type="nope")))[0] == 2)
check("rejects app event without bundle_id", run(json.dumps({k: v for k, v in EV.items() if k != "bundle_id"}))[0] == 2)
check("rejects bad timestamp", run(json.dumps(dict(EV, detected_at="yesterday")))[0] == 2)
check("rejects non-json", run("not json")[0] == 2)
rc, out, _ = run(json.dumps({"type": "device_unreachable", "detected_at": "2026-10-03T14:00:00+00:00"}))
check("device events need no bundle_id", rc in (0, 3) and True)

os.chmod(conf, 0o644)
n = len(R.queued())
STATE["mode"] = "ok"
rc, out, err_ = run(json.dumps(dict(EV, bundle_id="com.q")))
check("group/world-readable config: event queued anyway, exit 3", rc == 3 and len(R.queued()) == n + 1 and "0600" in err_)
os.chmod(conf, 0o600)
check("queue dir is 0700", oct(os.stat(q).st_mode & 0o777) == "0o700")
check("shell wrapper runs", subprocess.run([SCRIPT, "--status"], env=dict(os.environ, EG_REPORT_QUEUE=q),
      capture_output=True, text=True).stdout.startswith("queued="))

# ---- static SQL checks -------------------------------------------------------
sql = (ROOT / "supabase" / "mdm_app_events.sql").read_text()
check("sql: RPC granted to anon, revoked from public first",
      "revoke execute on function public.eg_report_mdm_event(text, jsonb)\n  from public, anon, authenticated, service_role;" in sql
      and "grant execute on function public.eg_report_mdm_event(text, jsonb) to anon;" in sql)
for fn in ("eg_send_email_mdm(text, text)", "eg_on_mdm_event()", "eg_mdm_esc(text)"):
    check(f"sql: {fn} locked from anon", re.search(r"revoke execute on function public\." + re.escape(fn) + r"\s+from public, anon, authenticated, service_role", sql) is not None)
check("sql: token stored only as sha256", "token_sha256" in sql and "encode(digest(p_token, 'sha256'), 'hex')" in sql)
check("sql: wording 'Installed some time between'", "Installed some time between" in sql)
check("sql: no existing function redefined", not re.search(r"create or replace function public\.(eg_on_red|eg_send_email|eg_daily_digest|eg_check_gone_dark)\(", sql))
check("sql: does not touch flags or existing triggers", not re.search(r"(on|into|table) public\.flags|eg_red_alert", sql))
check("sql: placeholder recipient guard", "dad@CHANGE-ME.invalid" in sql and "NOT sending" in sql)
check("sql: html escaped", sql.count("public.eg_mdm_esc(") >= 6)
check("sql: no secrets", not re.search(r"eyJ[A-Za-z0-9_-]{20,}|re_[A-Za-z0-9]{20,}", sql))

print("\nFAILED: " + ", ".join(fails) if fails else "\nall passed")
sys.exit(1 if fails else 0)
