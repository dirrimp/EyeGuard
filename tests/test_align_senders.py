#!/usr/bin/env python3
"""supabase/align_alert_senders.sql in a real throwaway Postgres: the MDM and Jada-phone alert
functions must take the live sender, keep Dad's recipient edits / security / privileges, and fail
safe. Synthetic addresses only. Run: python3 tests/test_align_senders.py  (needs docker +
postgres:16-alpine; EG_REQUIRE_SQL=1 makes a skip a failure)."""
import json, os, re, shutil, subprocess, sys, time, uuid
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)
have = shutil.which("docker") and subprocess.run(["docker", "image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1": check("SQL tests could run", False)
    else: print("  [skip] docker/postgres:16-alpine unavailable")
    sys.exit(1 if fails else 0)
name = "egsend-" + uuid.uuid4().hex[:8]
subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "postgres:16-alpine"], check=True, capture_output=True)
try:
    for _ in range(60):
        if subprocess.run(["docker", "exec", name, "pg_isready", "-U", "postgres"], capture_output=True).returncode == 0: break
        time.sleep(1)
    time.sleep(2)
    def psql(sql, err_ok=False):
        r = subprocess.run(["docker", "exec", "-i", name, "psql", "-U", "postgres", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1"], input=sql, capture_output=True, text=True)
        if r.returncode != 0 and not err_ok: raise RuntimeError(r.stderr[-700:])
        return r.stdout.strip(), r.stderr
    val = lambda q: psql(q)[0]
    SQL = (ROOT / "supabase/align_alert_senders.sql").read_text()
    check("the SQL Dad copies is pure ASCII", all(ord(c) < 128 for c in SQL))
    LIVE = "EyeGuard <alerts@verified.example>"
    psql("""
create role anon nologin; create role authenticated nologin; create role service_role nologin;
create schema extensions; create extension pgcrypto with schema extensions;
create schema vault; create table vault.s(name text, decrypted_secret text); insert into vault.s values ('resend_api_key','re_test');
create view vault.decrypted_secrets as select * from vault.s;
create schema net; create table net.sent(id serial, body jsonb);
create function net.http_post(url text, headers jsonb, body jsonb) returns bigint language sql as $$ insert into net.sent(body) values (body) returning id::bigint $$;
create schema cron; create table cron.job(jobid serial primary key, jobname text, schedule text, command text);
create function cron.schedule(n text, s text, c text) returns bigint language sql as $$ select 1::bigint $$;
create function cron.unschedule(n text) returns boolean language sql as $$ select true $$;
create schema auth; create function auth.uid() returns uuid language sql as $$ select null::uuid $$;
grant usage on schema public, extensions to anon, authenticated;
""")
    def live(frm): psql(f"""create or replace function public.eg_send_email(subject text, html text) returns void
language plpgsql security definer set search_path = public, vault as $$
begin
  perform net.http_post(url := 'https://api.resend.com/emails', headers := '{{}}'::jsonb,
    body := jsonb_build_object('from', '{frm}', 'to', jsonb_build_array('dad@live.example'), 'subject', subject, 'html', html));
end $$;""")
    live(LIVE)
    # the REAL MDM sender from the repo (as Dad has it: recipients edited), sender = the unverified one
    mdm = (ROOT / "supabase/mdm_app_events.sql").read_text().replace("create extension if not exists pg_net;", "").replace("dad@CHANGE-ME.invalid", "dad@example.test")
    psql(mdm)
    # a stand-in for eg_send_email_jada with its own recipient and the same unverified sender
    psql("""create or replace function public.eg_send_email_jada(subject text, html text) returns void
language plpgsql security definer set search_path = public, vault as $$
begin
  perform net.http_post(url := 'https://api.resend.com/emails', headers := '{}'::jsonb,
    body := jsonb_build_object('from', 'EyeGuard <alerts@orthanc.me>', 'to', jsonb_build_array('jada@custom.example'), 'subject', subject, 'html', html));
end $$;
revoke execute on function public.eg_send_email_jada(text, text) from public, anon, authenticated, service_role;""")
    def meta(fn): return val(f"select prosecdef::text || '|' || coalesce(array_to_string(proconfig, ','), '') || '|' || has_function_privilege('anon','{fn}','execute')::text || '|' || has_function_privilege('authenticated','{fn}','execute')::text from pg_proc where oid = '{fn}'::regprocedure")
    def send(fn):
        psql("truncate net.sent;"); psql(f"select public.{fn}('s', 'h');")
        return json.loads(val("select body::text from net.sent order by id desc limit 1"))
    before_m, before_j = meta("public.eg_send_email_mdm(text,text)"), meta("public.eg_send_email_jada(text,text)")
    check("BEFORE: the MDM and Jada senders use the unverified orthanc.me (the bug)",
          send("eg_send_email_mdm")["from"].endswith("alerts@orthanc.me>") and send("eg_send_email_jada")["from"].endswith("alerts@orthanc.me>"))
    r = psql(SQL)
    m, j = send("eg_send_email_mdm"), send("eg_send_email_jada")
    check("AFTER: both now send from exactly the live sender", m["from"] == LIVE and j["from"] == LIVE, f"{m['from']} / {j['from']}")
    check("Dad's recipient edits are untouched (MDM: Jada + Dad's address; Jada function: its own)",
          sorted(m["to"]) == ["dad@example.test", "jadadirrim@pm.me"] and j["to"] == ["jada@custom.example"], f"{m['to']} {j['to']}")
    check("security definer, search_path and privileges are unchanged (anon/authenticated still cannot call them)",
          meta("public.eg_send_email_mdm(text,text)") == before_m and meta("public.eg_send_email_jada(text,text)") == before_j
          and before_m.endswith("|false|false"), f"{before_m} -> {meta('public.eg_send_email_mdm(text,text)')}")
    check("the live eg_send_email itself is not modified", send("eg_send_email")["from"] == LIVE)
    out = psql(SQL)
    check("re-running changes nothing (idempotent)", "functions changed: 0" in out[1], out[1])
    check("the result table shows ONE sender for all three",
          len({l.split("|")[1] for l in val("select p.proname||'|'||substring(pg_get_functiondef(p.oid) from $re$'from',\\s*'([^']+)'$re$) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.proname in ('eg_send_email','eg_send_email_mdm','eg_send_email_jada')").splitlines()}) == 1)

    print("   fail-safe behaviour")
    psql("create or replace function public.eg_send_email_mdm(subject text, html text) returns void language plpgsql security definer set search_path = public, vault as $$ begin perform net.http_post(url:='x', headers:='{}'::jsonb, body:=jsonb_build_object('from','EyeGuard <alerts@orthanc.me>','to',jsonb_build_array('keep@me.example'))); end $$;")
    psql("drop function public.eg_send_email_jada(text, text);")
    r = psql(SQL)
    check("a function that is not installed is skipped, the other is still fixed", "eg_send_email_jada(text,text) is not installed" in r[1] and send("eg_send_email_mdm")["from"] == LIVE and send("eg_send_email_mdm")["to"] == ["keep@me.example"], r[1][-200:])
    psql("create or replace function public.eg_send_email_mdm(subject text, html text) returns void language plpgsql as $$ begin perform 1; end $$;")
    before = val("select pg_get_functiondef('public.eg_send_email_mdm(text,text)'::regprocedure)")
    r = psql(SQL)
    check("a function with no readable sender is left alone", val("select pg_get_functiondef('public.eg_send_email_mdm(text,text)'::regprocedure)") == before and "no readable sender" in r[1])
    psql("create or replace function public.eg_send_email(subject text, html text) returns void language plpgsql as $$ begin perform 1; end $$;")
    psql("create or replace function public.eg_send_email_mdm(subject text, html text) returns void language plpgsql as $$ begin perform net.http_post(url:='x', headers:='{}'::jsonb, body:=jsonb_build_object('from','EyeGuard <alerts@orthanc.me>')); end $$;")
    before = val("select pg_get_functiondef('public.eg_send_email_mdm(text,text)'::regprocedure)")
    r = psql(SQL, err_ok=True)
    check("if the live sender cannot be read it STOPS with a clear message and changes nothing",
          "Could not read the sender from the live" in r[1] and val("select pg_get_functiondef('public.eg_send_email_mdm(text,text)'::regprocedure)") == before, r[1][-200:])
    psql("drop function public.eg_send_email(text, text);")
    r = psql(SQL, err_ok=True)
    check("if the live function is missing it STOPS and changes nothing", "was not found" in r[1])
finally:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
print()
if fails: print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
print("all alert-sender alignment tests passed")
