#!/usr/bin/env python3
"""supabase/jada_sustained_dark.sql: Jada's phone gets the same 'dark for >10 min' re-check
Jonah's phone has. Part A is static; Part B replays scenarios in a throwaway postgres:16-alpine
(local docker, or on a host via EG_TEST_SSH=<host>); SKIPs if neither is available.
Synthetic data only. Run: python3 tests/test_jada_sustained_dark.py"""
import os, re, subprocess, sys, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SQL = (ROOT / "supabase" / "jada_sustained_dark.sql").read_text()
JADA_DDL = (ROOT / "supabase" / "jada_phone.sql").read_text()
fails = []
def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok: fails.append(name)

print("A. static")
check("pure ASCII (Dad pastes this)", all(ord(c) < 128 for c in SQL))
check("sends only through Jada's sender, never the shared one",
      "eg_send_email_jada(" in SQL and not re.search(r"eg_send_email\(", SQL))
check("not callable by any API role", "from public, anon, authenticated, service_role" in SQL)
check("additive: no 'create or replace' of any existing function except its own",
      re.findall(r"create or replace function (\S+)", SQL) == ["public.eg_check_phone_jada_sustained_dark()"])

ssh = os.environ.get("EG_TEST_SSH")
def sh(cmd, inp=None):
    full = ["ssh", ssh] + [" ".join(cmd)] if ssh else cmd
    return subprocess.run(full, input=inp, capture_output=True, text=True)
have = sh(["docker", "image", "inspect", "postgres:16-alpine"]).returncode == 0
if not have:
    print("B. SKIP (no docker/postgres:16-alpine)"); sys.exit(1 if fails else 0)

name = "egjsd-" + uuid.uuid4().hex[:8]
def psql(sql, expect_error=False):
    r = sh(["docker", "exec", "-i", name, "psql", "-U", "postgres", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1"], sql)
    if r.returncode and not expect_error: print(r.stderr[:600])
    return r.stdout.strip(), r.returncode
def val(sql): return psql(sql)[0]

def setup():
    sh(["docker", "run", "-d", "--rm", "--name", name, "-e", "POSTGRES_PASSWORD=x", "postgres:16-alpine"])
    for _ in range(40):
        if sh(["docker", "exec", name, "pg_isready", "-U", "postgres"]).returncode == 0: break
        time.sleep(1)
    time.sleep(2)
    stub = """
create role anon; create role authenticated; create role service_role;
create schema cron; create table cron.job(jobname text, schedule text, command text);
create function cron.unschedule(n text) returns void language sql as $$ delete from cron.job where jobname = n $$;
create function cron.schedule(n text, s text, c text) returns void language sql as $$ insert into cron.job values (n,s,c) $$;
create schema auth; create function auth.uid() returns uuid language sql as $$ select null::uuid $$;
create table public.sent(id serial, via text, subject text);
create function public.eg_send_email_jada(s text, h text) returns void language sql as $$ insert into public.sent(via,subject) values ('jada',s) $$;
create function public.eg_send_email(s text, h text) returns void language sql as $$ insert into public.sent(via,subject) values ('SHARED',s) $$;
"""
    # the real status table + heartbeat exactly as the live system defines them
    ddl = JADA_DDL[JADA_DDL.index("-- ---- 1. status row"):JADA_DDL.index("-- ---- 3. sender")]
    ddl = re.sub(r"alter table public.phone_status_jada enable row level security;.*?(?=\n-- ---- 2)", "", ddl, flags=re.S)
    ddl = re.sub(r"revoke all on function[^;]*;\s*grant execute[^;]*;", "", ddl)
    out, rc = psql(stub + ddl)
    return rc == 0

def run_fn(sql_text):
    return psql(sql_text)

def set_state(active, last_seen_min, beat_min):
    ls = "null" if last_seen_min is None else f"now() - interval '{last_seen_min} minutes'"
    bt = "null" if beat_min is None else f"now() - interval '{beat_min} minutes'"
    psql(f"update public.phone_status_jada set phone_active={active}, last_seen={ls}, monitor_beat={bt} where id=1;")

def emails(): return int(val("select count(*) from public.sent where via='jada'"))

def scenarios(label, fn_sql):
    print(f"B. {label}")
    psql("truncate public.sent; update public.phone_status_jada set sustained_dark_alerted=false;")
    psql(fn_sql)
    call = lambda: psql("select public.eg_check_phone_jada_sustained_dark();")
    res = {}
    set_state("false", 5, 1);  call(); res["dark 5 min: no email"] = emails() == 0
    set_state("false", 11, 1); call(); res["dark 11 min: exactly one email"] = emails() == 1
    call(); call();            res["still dark, checked again: still one email"] = emails() == 1
    set_state("true", 0, 0);   call()
    res["back on network: re-armed"] = val("select sustained_dark_alerted from public.phone_status_jada") == "f"
    set_state("false", 12, 1); call(); res["next dark period: a second email"] = emails() == 2
    psql("update public.phone_status_jada set sustained_dark_alerted=false;")
    set_state("false", 60, 30); call(); res["monitor itself silent 30 min: no email (MONITOR offline covers it)"] = emails() == 2
    set_state("false", None, 1); call(); res["never confirmed alive: no email"] = emails() == 2
    # the gap this closes: Jada's immediate email is debounced to 1 per 30 min, so a long dark period after a
    # swallowed flag was never reported. The re-check does not look at that debounce at all.
    psql("update public.phone_status_jada set last_dark_email_at = now() where id=1;")
    set_state("false", 90, 1); call(); res["debounce active, 90 min dark: still reported"] = emails() == 3
    res["never uses the shared (Dad's) sender"] = val("select count(*) from public.sent where via='SHARED'") == "0"
    return res

try:
    if not setup(): print("  setup failed"); sys.exit(1)
    # apply the real file (cron + grants need the stubs above)
    out, rc = psql(SQL); check("SQL file applies cleanly", rc == 0)
    check("verify row is all true", val("select cron.job.jobname from cron.job limit 1") == "eyeguard-phone-sustained-dark-jada")
    check("anon cannot execute it", val("select has_function_privilege('anon','public.eg_check_phone_jada_sustained_dark()','execute')") == "f")
    r = scenarios("real function", SQL)
    for k, v in r.items(): check(k, v)
    out, rc = psql(SQL); check("re-running the file is safe (idempotent)", rc == 0)
    # mutation checks: the tests must be able to fail
    m1 = SQL.replace(" or p.sustained_dark_alerted", "")
    r = scenarios("MUTANT: no once-per-dark-period flag", m1)
    check("mutant (repeats every minute) is caught", not all(r.values()))
    m2 = SQL.replace("interval '10 minutes' or", "interval '10000 minutes' or")
    r = scenarios("MUTANT: never fires", m2)
    check("mutant (never fires) is caught", not all(r.values()))
finally:
    sh(["docker", "rm", "-f", name])

print("\nFAILED: " + "; ".join(fails) if fails else "\nall passed")
sys.exit(1 if fails else 0)
