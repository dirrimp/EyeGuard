#!/usr/bin/env python3
"""supabase/central_mail_sender.sql in a real throwaway Postgres: one sender for all three alert
functions, pinned to orthanc.me, Dad's customisations untouched, fails safe. Synthetic addresses.
Run: python3 tests/test_central_sender.py (docker + postgres:16-alpine; EG_REQUIRE_SQL=1 = skip is failure)."""
import json, os, shutil, subprocess, sys, time, uuid
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
name = "egcen-" + uuid.uuid4().hex[:8]
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
    SQL = (ROOT / "supabase/central_mail_sender.sql").read_text()
    check("the SQL Dad copies is pure ASCII", all(ord(c) < 128 for c in SQL))
    G = "EyeGuard <alerts@orthanc.me>"
    psql("""
create role anon nologin; create role authenticated nologin; create role service_role nologin;
create schema extensions; create extension pgcrypto with schema extensions;
create schema vault; create table vault.s(name text, decrypted_secret text); insert into vault.s values ('resend_api_key','re_test');
create view vault.decrypted_secrets as select * from vault.s;
create schema net; create table net.sent(id serial, body jsonb);
create function net.http_post(url text, headers jsonb, body jsonb) returns bigint language sql as $$ insert into net.sent(body) values (body) returning id::bigint $$;
create schema auth; create function auth.uid() returns uuid language sql as $$ select null::uuid $$;
grant usage on schema public, extensions to anon, authenticated;
""")
    def mk(fn, frm, to, extra_priv=True):
        psql(f"""create or replace function public.{fn}(subject text, html text) returns void
language plpgsql security definer set search_path = public, vault as $$
begin
  perform net.http_post(url := 'https://api.resend.com/emails', headers := '{{}}'::jsonb,
    body := jsonb_build_object('from', '{frm}', 'to', jsonb_build_array('{to}'), 'subject', subject, 'html', html));
end $$;
revoke execute on function public.{fn}(text, text) from public, anon, authenticated, service_role;""")
    def send(fn):
        psql("truncate net.sent;"); psql(f"select public.{fn}('s','h');")
        return json.loads(val("select body::text from net.sent order by id desc limit 1"))
    def meta(fn): return val(f"select prosecdef::text||'|'||coalesce(array_to_string(proconfig,','),'')||'|'||has_function_privilege('anon','{fn}','execute')::text from pg_proc where oid='{fn}'::regprocedure")
    def setup():
        mk("eg_send_email", G, "dad@live.example")
        mdm = (ROOT / "supabase/mdm_app_events.sql").read_text().replace("create extension if not exists pg_net;", "").replace("dad@CHANGE-ME.invalid", "dad@example.test")
        psql(mdm)
        mk("eg_send_email_jada", "EyeGuard <alerts@orthanc.me>", "jada@custom.example")
    setup()
    before = {f: meta(f"public.{f}(text,text)") for f in ("eg_send_email", "eg_send_email_jada", "eg_send_email_mdm")}
    out = psql(SQL)
    check("the config row is seeded from the LIVE sender", val("select from_address from public.eg_mail_config") == G, out[1][-200:])
    check("all three functions now take the sender from eg_mail_from()",
          all("eg_mail_from()" in val(f"select pg_get_functiondef('public.{f}(text,text)'::regprocedure)") for f in before))
    check("they still send exactly the same From as before", all(send(f)["from"] == G for f in before))
    check("recipients are untouched (live: dad; MDM: Jada + Dad; Jada fn: her own)",
          send("eg_send_email")["to"] == ["dad@live.example"] and sorted(send("eg_send_email_mdm")["to"]) == ["dad@example.test", "jadadirrim@pm.me"]
          and send("eg_send_email_jada")["to"] == ["jada@custom.example"])
    check("security definer, search_path and privileges are unchanged", {f: meta(f"public.{f}(text,text)") for f in before} == before)

    print("   one place to change it")
    psql("update public.eg_mail_config set from_address = 'EyeGuard Alerts <noreply@orthanc.me>', changed_at = now() where id = 1;")
    check("changing the one row changes the sender of ALL THREE at once", all(send(f)["from"] == "EyeGuard Alerts <noreply@orthanc.me>" for f in before))
    for label, bad in (("another domain", "EyeGuard <alerts@evil.example>"), ("no display name", "alerts@orthanc.me"), ("a look-alike domain", "EyeGuard <alerts@orthanc.me.evil.example>"), ("a second address", "EyeGuard <a@orthanc.me>, <b@evil.example>")):
        r = psql(f"update public.eg_mail_config set from_address = $q${bad}$q$ where id = 1;", err_ok=True)
        check(f"the constraint refuses {label}", "violates check constraint" in r[1], r[1][-120:])
    psql("update public.eg_mail_config set from_address = 'EyeGuard <alerts@orthanc.me>' where id = 1;")

    print("   safety")
    out = psql(SQL)
    check("re-running changes nothing and does not overwrite the configured sender", "functions changed: 0" in out[1] and val("select from_address from public.eg_mail_config") == G, out[1][-160:])
    check("no API role can read or change the config, or call eg_mail_from()",
          "permission denied" in psql("begin; set local role anon; select * from public.eg_mail_config; rollback;", err_ok=True)[1]
          and "permission denied" in psql("begin; set local role authenticated; update public.eg_mail_config set from_address='x'; rollback;", err_ok=True)[1]
          and "permission denied" in psql("begin; set local role anon; select public.eg_mail_from(); rollback;", err_ok=True)[1])
    psql("drop table public.eg_mail_config cascade;", err_ok=True)
    psql("drop function if exists public.eg_mail_from();")
    setup(); mk("eg_send_email", "EyeGuard <alerts@alerts.jjpetwasteservices.com>", "dad@live.example")
    snap = val("select pg_get_functiondef('public.eg_send_email_mdm(text,text)'::regprocedure)")
    r = psql(SQL, err_ok=True)
    check("if the live sender is NOT orthanc.me it STOPS with a clear message and changes nothing",
          "not an orthanc.me address" in r[1] and val("select pg_get_functiondef('public.eg_send_email_mdm(text,text)'::regprocedure)") == snap, r[1][-200:])
    psql("drop table if exists public.eg_mail_config cascade; drop function if exists public.eg_mail_from();")
    psql("drop function public.eg_send_email(text,text);")
    r = psql(SQL, err_ok=True)
    check("if the live function is missing it STOPS", "was not found" in r[1])
    setup(); psql("drop function public.eg_send_email_jada(text,text);")
    r = psql(SQL, err_ok=True)
    check("a sender function that is not installed is skipped; the others are centralised",
          "eg_send_email_jada(text,text) is not installed" in r[1] and "eg_mail_from()" in val("select pg_get_functiondef('public.eg_send_email_mdm(text,text)'::regprocedure)"), r[1][-160:])
finally:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
print()
if fails: print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
print("all central-sender tests passed")
