#!/usr/bin/env python3
"""supabase/fake_asleep_grace.sql in a real throwaway Postgres: the 'possible fake asleep signal' email waits
3 minutes after the watcher's real wake, and still fires for a real fake-sleep. Synthetic data only.
Run: EG_DOCKER="ssh g11 docker" EG_REQUIRE_SQL=1 python3 tests/test_fake_asleep_grace.py"""
import os, re, shlex, shutil, subprocess, sys, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SQL = (ROOT / "supabase/fake_asleep_grace.sql").read_text()
BASE = (ROOT / "supabase/merge_dark_alerts_same_outage.sql").read_text()   # newest committed definition
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

print("A. static")
live = re.sub(r"--[^\n]*", "", SQL)
check("the SQL Dad copies is pure ASCII", all(ord(c) < 128 for c in SQL))
check("no mail API, no sender, no key", "api.resend" + ".com" not in SQL and "alerts@" not in SQL and not re.search(r"eyJ[A-Za-z0-9_-]{20,}", SQL))
check("it patches the live text and does not carry its own copy of the function", "create or replace function" not in live.lower())
check("it refuses to run unless the expected line is present exactly once", "if n <> 1 then" in live and "raise exception" in live)
check("the grace is exactly 3 minutes", live.count("interval ''3 minutes''") >= 2 and "5 minutes" not in live)
check("the committed newest definition contains the one line the patch targets, once",
      BASE.count("and d.watcher_confirmed_awake_at > d.last_heartbeat") == 1)

print("B. real Postgres")
dock = shlex.split(os.environ.get("EG_DOCKER", "docker"))
have = shutil.which(dock[0]) and subprocess.run(dock + ["image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1": check("SQL tests could run", False, "docker/postgres:16-alpine unavailable")
    else: print("  [skip] docker/postgres:16-alpine unavailable")
else:
    name = "egfag-" + uuid.uuid4().hex[:8]
    subprocess.run(dock + ["run", "-d", "--rm", "--name", name, "--network", "none", "--memory", "512m",
                           "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "postgres:16-alpine"], check=True, capture_output=True)
    try:
        for _ in range(60):
            if subprocess.run(dock + ["exec", name, "pg_isready", "-U", "postgres"], capture_output=True).returncode == 0: break
            time.sleep(1)
        time.sleep(2)
        def psql(sql, err_ok=False):
            r = subprocess.run(dock + ["exec", "-i", name, "psql", "-U", "postgres", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1"],
                               input=sql, capture_output=True, text=True)
            if r.returncode != 0 and not err_ok: raise RuntimeError(r.stderr[-1500:])
            return r.stdout.strip(), r.stderr, r.returncode
        val = lambda q: psql(q)[0]
        psql("""
create role anon nologin; create role authenticated nologin; create role service_role nologin;
create table public.sent(id serial, subject text, html text);
create function public.eg_send_email(subject text, html text) returns void language plpgsql security definer as $$
  begin insert into public.sent(subject, html) values (subject, html); end $$;
create table public.device_status(id int primary key, status text, last_heartbeat timestamptz,
  alerted boolean default false, blind_alerted boolean default false, detector_alerted boolean default false,
  detector_ok boolean default true, screen_dark_since timestamptz, screen_ok boolean default true,
  suspend_abuse_alerted boolean default false, watcher_agent_unhardened boolean default false,
  watcher_alerted boolean default false, watcher_confirmed_awake_at timestamptz, watcher_dark_alerted boolean default false,
  watcher_debugger_attached boolean default false, watcher_last_heartbeat timestamptz, watcher_new_account boolean default false,
  watcher_sleep_signaled_at timestamptz, watcher_untrusted_library boolean default false, watcher_wrong_user boolean default false);
""")
        # the committed newest definition stands in for the live function
        psql(BASE)
        before = val("select md5(pg_get_functiondef('public.eg_check_gone_dark()'::regprocedure))")

        def scenario(status, awake_ago_s, slept_after=False, hb_ago_s=None):
            """clean_shutdown/alive row; watcher woke awake_ago_s seconds ago, main heartbeat hb_ago_s ago; returns emails sent"""
            if hb_ago_s is None: hb_ago_s = awake_ago_s + 60      # main's last beat predates the wake (it said "asleep" before)
            psql("delete from public.sent; delete from public.device_status;")
            psql(f"""insert into public.device_status(id, status, last_heartbeat, watcher_last_heartbeat, watcher_confirmed_awake_at, watcher_sleep_signaled_at)
              values (1, '{status}', now() - interval '{hb_ago_s} seconds', now(),
                      now() - interval '{awake_ago_s} seconds',
                      {"now() - interval '" + str(max(awake_ago_s - 10, 0)) + " seconds'" if slept_after else "now() - interval '3 hours'"});""")
            psql("select public.eg_check_gone_dark();")
            return [r for r in psql("select subject from public.sent order by id;")[0].splitlines() if r]
        FAKE = "possible fake"

        print("B1. baseline: the committed function really does send the false alarm")
        e = scenario("clean_shutdown", 30)
        check("before the patch: a wake 30 seconds ago with main still 'asleep' DOES email (the 2026-11-20 08:48 case)",
              any(FAKE in s for s in e), str(e))

        out = psql(SQL)[0].splitlines()[-1].split("|")
        check("the file's own verify select is all true (3 columns)", out == ["t", "t", "t"], str(out))
        after = val("select md5(pg_get_functiondef('public.eg_check_gone_dark()'::regprocedure))")
        check("the function changed", before != after)
        psql(SQL)
        check("re-running is a no-op", val("select md5(pg_get_functiondef('public.eg_check_gone_dark()'::regprocedure))") == after)

        print("B2. the false case is quiet")
        e = scenario("clean_shutdown", 30)
        check("watcher woke 30 seconds ago, main not back yet -> no email (inside the grace)", not any(FAKE in s for s in e), str(e))
        e = scenario("clean_shutdown", 170)
        check("watcher woke 170 seconds ago -> still no email (just inside 3 minutes)", not any(FAKE in s for s in e), str(e))

        print("B3. real detection is unchanged")
        e = scenario("clean_shutdown", 200)
        check("watcher woke 200 seconds ago and main STILL says asleep -> the email fires (the real fake-sleep case)", sum(FAKE in s for s in e) == 1, str(e))
        e = scenario("clean_shutdown", 3600)
        check("watcher awake for an hour while main says asleep -> email fires", sum(FAKE in s for s in e) == 1, str(e))
        check("the alert flag is set so it does not repeat every minute",
              val("select suspend_abuse_alerted from public.device_status where id = 1") == "t")
        psql("select public.eg_check_gone_dark();")
        check("a second run sends no second copy", val("select count(*) from public.sent where subject like '%possible fake%'") == "1")
        e = scenario("alive", 3600, hb_ago_s=20)
        check("main is alive -> no email", not any(FAKE in s for s in e), str(e))
        e = scenario("clean_shutdown", 3600, slept_after=True)
        check("watcher went back to sleep after the wake -> no email (existing rule kept)", not any(FAKE in s for s in e), str(e))
        e = scenario("clean_shutdown", 200)
        check("same email text as before", any('EyeGuard — possible fake "asleep" signal' in s for s in e), str(e))

        print("B4. refuses to patch a function it does not recognise")
        psql("create or replace function public.eg_check_gone_dark() returns void language plpgsql as $$ begin null; end $$;")
        _, err, rc = psql(SQL, err_ok=True)
        check("unknown live function -> error, nothing changed", rc != 0 and "exactly once" in err
              and "null;" in val("select pg_get_functiondef('public.eg_check_gone_dark()'::regprocedure)"), err[-300:])
    finally:
        subprocess.run(dock + ["rm", "-f", name], capture_output=True)

print()
if fails:
    print("FAILED:"); [print("  " + f) for f in fails]; sys.exit(1)
print("ALL OK")
