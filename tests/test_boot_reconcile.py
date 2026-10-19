#!/usr/bin/env python3
"""Boot-time reconciliation: client helpers (Part A) and the server function in a real throwaway
Postgres (Part B, supabase/boot_reconcile.sql). Synthetic only.
Run: python3 tests/test_boot_reconcile.py   (Part B needs docker + postgres:16-alpine; the Mac has
none, so run it on the G11. EG_REQUIRE_SQL=1 turns a skip into a failure.)"""
import importlib.util, os, re, shlex, shutil, subprocess, sys, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

# ============================ Part A: client ============================
print("A1. parsers, against real output from the 2026-10-18 incident")
from eyeguard import session_watcher as sw
check("kern.boottime parses to the real boot instant (2026-10-19T01:48:55Z)",
      sw.boot_time_utc("{ sec = 1792374535, usec = 983612 } Sun Oct 18 21:48:55 2026\n") == "2026-10-19T01:48:55+00:00")
check("garbage boot time -> None, never raises", sw.boot_time_utc("nonsense") is None)
UNCLEAN = """reboot time                                Sun Oct 18 21:48
reboot time                                Fri Oct  2 12:59
shutdown time                              Fri Oct  2 12:58
reboot time                                Thu Sep 17 15:45
shutdown time                              Thu Sep 17 15:38

wtmp begins Mon Jul 21 21:23
"""
CLEAN = """reboot time                                Fri Oct  2 12:59
shutdown time                              Fri Oct  2 12:58
reboot time                                Thu Sep 17 15:45
shutdown time                              Thu Sep 17 15:38
"""
check("a reboot with no shutdown row before it = UNCLEAN (the real 10-18 output)", sw.prev_shutdown_clean(UNCLEAN) is False)
check("a reboot preceded by a shutdown row = clean", sw.prev_shutdown_clean(CLEAN) is True)
check("only one row, or empty, or not starting with a reboot -> unknown",
      sw.prev_shutdown_clean("reboot time  Sun Oct 18 21:48\n") is None and sw.prev_shutdown_clean("") is None
      and sw.prev_shutdown_clean("shutdown time x\nreboot time y\n") is None)

print("A2. ordering and failure behaviour of the watcher")
class W(sw.SessionWatcher):
    def __init__(self):                       # skip the real constructor: no network, no files
        import threading
        self.calls = []; self._rpc_lock = threading.Lock(); self.fail_boot = False
    def _rpc(self, name, params, timeout=15):
        self.calls.append(name)
        if name == "eg_report_boot" and self.fail_boot:
            raise OSError("network down")
    def _check_once(self): return (False, False, False, False, False)
    def _rpc_with_fast_retry(self, fn, args): self._rpc(fn, args)
sw.boot_time_utc_orig = sw.boot_time_utc
sw.boot_time_utc = lambda out=None: "2026-10-19T01:48:55+00:00"
sw.prev_shutdown_clean = lambda out=None: False
w = W(); w._check_and_heartbeat()
check("boot is reported BEFORE the first heartbeat", w.calls == ["eg_report_boot", "eg_watcher_heartbeat"], str(w.calls))
w._check_and_heartbeat()
check("reported once per start (second cycle only heartbeats)", w.calls[2:] == ["eg_watcher_heartbeat"], str(w.calls))
w = W(); w.fail_boot = True; w._check_and_heartbeat()
check("a failed boot report never blocks the heartbeat", w.calls == ["eg_report_boot", "eg_watcher_heartbeat"], str(w.calls))
w.fail_boot = False; w._check_and_heartbeat()
check("...and is retried next cycle until it succeeds", w.calls[2:] == ["eg_report_boot", "eg_watcher_heartbeat"], str(w.calls))

import urllib.error
class W404(W):
    def _rpc(self, name, params, timeout=15):
        self.calls.append(name)
        if name == "eg_report_boot":
            raise urllib.error.HTTPError("u", 404, "not found", {}, None)
w = W404(); w._check_and_heartbeat(); w._check_and_heartbeat()
check("a 404 (SQL not run yet) is not retried every cycle, and heartbeats keep flowing",
      w.calls == ["eg_report_boot", "eg_watcher_heartbeat", "eg_watcher_heartbeat"], str(w.calls))

# ============================ Part B: server ============================
print("B. server function in a throwaway Postgres")
sql_path = ROOT / "supabase" / "boot_reconcile.sql"
src = sql_path.read_text()
check("SQL is pure ASCII (it gets pasted into a browser)", all(ord(c) < 128 for c in src))
check("never redefines the live hand-edited alert/heartbeat/sender functions",
      not re.search(r"create or replace function public\.(eg_check_gone_dark|eg_watcher_heartbeat|eg_send_email)\b", src))

# EG_DOCKER="ssh g11 docker" runs the throwaway Postgres on the G11 (the Mac has no Docker)
D = shlex.split(os.environ.get("EG_DOCKER", "docker"))
have = shutil.which(D[0]) and subprocess.run(D + ["image", "inspect", "postgres:16-alpine"],
                                             capture_output=True).returncode == 0
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1": check("SQL tests could run (docker + postgres:16-alpine)", False)
    else: print("  [skip] docker/postgres:16-alpine unavailable")
    print()
    if fails:
        print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
    print("client tests passed; SQL part skipped"); sys.exit(0)

name = "egboot-" + uuid.uuid4().hex[:8]
subprocess.run(D + ["run", "-d", "--rm", "--name", name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
                "postgres:16-alpine"], check=True, capture_output=True)
try:
    for _ in range(60):
        if subprocess.run(D + ["exec", name, "pg_isready", "-U", "postgres"], capture_output=True).returncode == 0: break
        time.sleep(1)
    time.sleep(2)
    def psql(sql, err_ok=False):
        r = subprocess.run(D + ["exec", "-i", name, "psql", "-U", "postgres", "-X", "-q", "-t", "-A",
                            "-v", "ON_ERROR_STOP=1"], input=sql, capture_output=True, text=True)
        if r.returncode != 0 and not err_ok: raise RuntimeError(r.stderr[-800:])
        return r.stdout.strip(), r.stderr
    val = lambda sql: psql(sql)[0]
    psql("""
create role anon nologin; create role authenticated nologin; create role service_role nologin;
create table public.device_status (id int primary key, watcher_last_heartbeat timestamptz,
  alerted boolean not null default false, watcher_dark_alerted boolean not null default false);
insert into public.device_status (id) values (1);
create table public.mails (id serial, subject text, html text);
create function public.eg_send_email(subject text, html text) returns void language plpgsql as
$f$ begin if current_setting('eg.fail_mail', true) = 'on' then raise exception 'mail down'; end if;
insert into public.mails(subject, html) values (subject, html); end $f$;
grant usage on schema public to anon, authenticated;
""")
    psql(src); psql(src)                      # applies, and re-runs cleanly
    check("applies cleanly and re-runs", True)
    mails = lambda: int(val("select count(*) from public.mails"))
    last_subj = lambda: val("select subject from public.mails order by id desc limit 1")
    last_html = lambda: val("select html from public.mails order by id desc limit 1")
    rows = lambda: int(val("select count(*) from public.mac_boots"))
    def ds(pre_min=None, alerted=False, wd=False):
        pre = "null" if pre_min is None else f"now() - interval '{pre_min} minutes'"
        psql(f"update public.device_status set watcher_last_heartbeat={pre}, alerted={alerted}, watcher_dark_alerted={wd} where id=1;")
    def unthrottle(): psql("update public.mac_boots set reported_at = reported_at - interval '5 minutes';")
    def boot(min_ago, clean="null"):
        return val(f"select public.eg_report_boot(now() - interval '{min_ago} minutes', {clean});")

    ds(None); n0 = mails()
    check("first report ever -> baseline, recorded, no email", boot(600) == "baseline" and rows() == 1 and mails() == n0)

    unthrottle(); ds(10, alerted=True, wd=True); n0 = mails()
    v = boot(5, "false")
    check("new boot after the watcher's last heartbeat + alert outstanding -> rebooted, ONE email", v == "rebooted" and mails() == n0 + 1, v)
    check("email says restarted and names the unclean shutdown", "restarted" in last_subj() and "No clean shutdown was recorded" in last_html(), last_subj())
    check("gap and last-seen are stored server-side", val("select gap_seconds between 590 and 610 from public.mac_boots order by id desc limit 1") == "t")

    unthrottle(); ds(10, alerted=True); n0 = mails()
    v = boot(5, "true")
    check("SAME boot time after a >3 min silence + alert outstanding -> restarted_no_reboot, ONE email",
          v == "restarted_no_reboot" and mails() == n0 + 1 and "WITHOUT a reboot" in last_subj(), v + " / " + last_subj())

    unthrottle(); ds(10, alerted=False, wd=False); n0 = mails()
    check("restart without reboot but NO outstanding alert -> recorded, silent (ordinary relaunch/deploy)",
          boot(5) == "restarted_no_reboot" and mails() == n0)

    unthrottle(); ds(1, alerted=True); n0 = mails()
    check("same boot after a short gap (deploy relaunch) -> same_boot, silent even with an alert flag", boot(5) == "same_boot" and mails() == n0)

    unthrottle(); ds(10, alerted=False); n0 = mails()
    check("a reboot with nothing outstanding -> rebooted but silent", boot(2) == "rebooted" and mails() == n0)

    unthrottle(); ds(1, alerted=True); n0 = mails()
    check("new boot older than the watcher's own heartbeat (late report) -> late_report, silent", boot(30) == "late_report" and mails() == n0)

    r0 = rows(); v = boot(1)
    check("a second call within 60 s is throttled and writes nothing", v == "throttled" and rows() == r0)

    for label, expr in (("null", "null"), ("future", "now() + interval '1 hour'"), ("ancient", "now() - interval '500 days'")):
        err = psql(f"select public.eg_report_boot({expr}, null);", err_ok=True)[1]
        check(f"bad boot time rejected: {label}", "bad boot time" in err, err[-120:])

    unthrottle(); ds(10, alerted=True); n0 = mails()
    out = psql("set eg.fail_mail = 'on'; select public.eg_report_boot(now() - interval '1 minute', null);", err_ok=True)
    check("a failing email never breaks the report", out[0].splitlines()[-1] in ("rebooted", "restarted_no_reboot") and mails() == n0, str(out))

    print("permissions")
    unthrottle(); ds(None)
    r = psql("set role anon; select public.eg_report_boot(now() - interval '1 minute', null);", err_ok=True)
    check("anon (the Mac's key) can call it", "bad" not in r[1] and "permission" not in r[1], r[1])
    check("anon cannot read the table", "permission denied" in psql("set role anon; select * from public.mac_boots;", err_ok=True)[1])
    check("authenticated and service_role cannot call it",
          "permission denied" in psql("set role authenticated; select public.eg_report_boot(now(), null);", err_ok=True)[1]
          and "permission denied" in psql("set role service_role; select public.eg_report_boot(now(), null);", err_ok=True)[1])
    check("the file's own verify row reads t,t,t,f,f",
          val("select has_function_privilege('anon','public.eg_report_boot(timestamptz, boolean)','execute'), "
              "exists (select 1 from pg_class where relname='mac_boots' and relrowsecurity), "
              "not has_table_privilege('anon','public.mac_boots','select'), "
              "has_function_privilege('authenticated','public.eg_report_boot(timestamptz, boolean)','execute'), "
              "has_function_privilege('service_role','public.eg_report_boot(timestamptz, boolean)','execute')") == "t|t|t|f|f")
finally:
    subprocess.run(D + ["rm", "-f", name], capture_output=True)

print()
if fails:
    print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
print("all boot-reconcile tests passed")
