#!/usr/bin/env python3
"""Onn monitor phase 5a SQL (supabase/onn_monitor_phase5a_titlefacts.sql): four optional title-fact counts on the heartbeat.
Synthetic data only, throwaway Postgres in docker. Run: EG_DOCKER="ssh g11 docker" EG_REQUIRE_SQL=1 python3 tests/test_onn_phase5a.py"""
import hashlib, json, os, re, shlex, shutil, subprocess, sys, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SQL5 = (ROOT / "supabase/onn_monitor_phase5a_titlefacts.sql").read_text()
SQL3 = (ROOT / "supabase/onn_monitor_phase3.sql").read_text()
SQL1 = (ROOT / "supabase/onn_monitor_phase1.sql").read_text()
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

print("A. static checks")
live = re.sub(r"--[^\n]*", "", SQL5)
check("no placeholder, key material or token value", "CHANGE-ME" not in SQL5 and not re.search(r"PRIVATE KEY|service_role_key|eyJ[A-Za-z0-9_-]{20,}", SQL5))
check("only the heartbeat is replaced and granted to anon", len(re.findall(r"create or replace function", live)) == 1 and len(re.findall(r"grant execute on function[^;]*to anon", live)) == 1)
f3 = SQL3[SQL3.index("create or replace function public.eg_onn_heartbeat"):SQL3.index("revoke execute on function public.eg_onn_heartbeat")]
f5 = SQL5[SQL5.index("create or replace function public.eg_onn_heartbeat"):SQL5.index("revoke execute on function public.eg_onn_heartbeat")]
removed = [l for l in f3.splitlines() if l not in f5.splitlines()]
check("every phase 3 line is kept except the two statements that gain the new columns", len(removed) == 2 and all("flags_dropped" in l or "ff, fd" in l for l in removed), str(removed))
added = [l for l in f5.splitlines() if l not in f3.splitlines()]
check("no alert, threshold or incident is touched (none of the added lines mention one)", added and not re.search(r"eg_onn_mail|incident|gap_armed|alerted|_beats\s*[<>=]", "\n".join(added)), str(added))

print("B. real Postgres")
dock = shlex.split(os.environ.get("EG_DOCKER", "docker"))
have = shutil.which(dock[0]) and subprocess.run(dock + ["image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1": check("SQL tests could run", False, "docker/postgres:16-alpine unavailable")
    else: print("  [skip] docker/postgres:16-alpine unavailable")
else:
    name = "egonn5a-" + uuid.uuid4().hex[:8]
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
            return r.stdout.strip(), r.stderr
        val = lambda q: psql(q)[0]
        DAD, JONAH = "0e02aa87-1cd5-4bb6-a263-f51d4e2642b6", "99999999-9999-9999-9999-999999999999"
        psql("""
create role anon nologin; create role authenticated nologin; create role service_role nologin bypassrls;
create schema extensions; create extension pgcrypto with schema extensions;
create schema vault; create table vault.s(name text, decrypted_secret text); insert into vault.s values ('resend_api_key','re_test');
create view vault.decrypted_secrets as select * from vault.s;
create schema net; create table net.sent(id serial, body jsonb);
create function net.http_post(url text, headers jsonb, body jsonb) returns bigint language sql as $$ insert into net.sent(body) values (body) returning id::bigint $$;
create schema cron; create table cron.job(jobid serial primary key, jobname text, schedule text, command text);
create function cron.schedule(n text, s text, c text) returns bigint language sql as $$ insert into cron.job(jobname,schedule,command) values (n,s,c) returning jobid::bigint $$;
create function cron.unschedule(n text) returns boolean language sql as $$ delete from cron.job where jobname = n returning true $$;
create schema auth; create table auth.users(id uuid primary key, email text);
create function auth.uid() returns uuid language sql as $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
create schema storage; create table storage.objects(bucket_id text, name text);
create table public.flags (id uuid primary key default gen_random_uuid(), created_at timestamptz not null default now(),
  flagged_at timestamptz not null, verdict text not null check (verdict in ('flagged','alert','clear')),
  is_nudity boolean not null default false, grade text, risk text, app text, url text, window_title text, reason text,
  score real, image_path text);
create table public.red_emails(id serial, flag_id uuid, subject text);
create function public.stand_in_eg_on_red() returns trigger language plpgsql as $$ begin
  insert into public.red_emails(flag_id, subject) values (NEW.id, NEW.app || ' ' || NEW.reason); return NEW; end $$;
create trigger eg_red_alert after insert on public.flags for each row when (NEW.verdict = 'flagged') execute function public.stand_in_eg_on_red();
grant usage on schema public, extensions, auth to anon, authenticated, service_role;
""" + f"insert into auth.users values ('{DAD}','dad@example.test'),('{JONAH}','jonah@example.test');")
        base = (ROOT / "supabase/mdm_app_events.sql").read_text().replace("create extension if not exists pg_net;", "")
        psql(base.replace("dad@CHANGE-ME.invalid", "dad@example.test"))
        p1 = SQL1.replace("create extension if not exists pg_net;", "")
        p3 = SQL3.replace("create extension if not exists pg_net;", "")
        psql(p1)
        psql(p3)
        p5 = SQL5.replace("create extension if not exists pg_net;", "")
        psql(p5); psql(p5)
        verify = psql(p5)[0].splitlines()[-1]
        check("the file's own verify select is all true", set(verify.split("|")) == {"t"}, verify)

        tok = "ab" * 32
        psql(f"insert into public.onn_auth(token_sha256, note) values ('{hashlib.sha256(tok.encode()).hexdigest()}','t');")
        CERT = "c" * 64; MODEL = "d" * 64
        GOOD = dict(selftest_argmax=8355, selftest_max=319.69696044921875, model_ms=272)
        def beat(**kw):
            info = dict(app_version="0.2.2", cert_sha256=CERT, svc_enabled=True, screen_state="on", screen_on_s=300, window_s=300,
                        interval_s=15, attempted=20, succeeded=20, analysed=20, black=0, distinct_hashes=12, model_sha256=MODEL, **GOOD)
            info.update(kw); info = {k: v for k, v in info.items() if v is not None}
            return psql(f"select public.eg_onn_heartbeat('{tok}', $j${json.dumps(info)}$j$::jsonb);", err_ok=True)
        allow = lambda: psql("update public.onn_status set last_beat_at = now() - interval '1 minute' where id = 1;")
        row = lambda col: val(f"select {col} from public.onn_beats order by id desc limit 1")
        sent = lambda: int(val("select count(*) from net.sent"))
        print("B1. phase 3 behaviour is unchanged")
        out, err = beat(); check("a phase 3 heartbeat without title counts is accepted", '"ok": true' in out, err)
        check("omitted counts are stored as 0", row("title_events || ',' || title_with_text || ',' || title_specific || ',' || title_distinct") == "0,0,0,0")
        check("the server still marks the self-test passed", row("selftest_ok") == "t")
        allow(); beat(selftest_argmax=1)
        check("a wrong self-test is still marked failed", row("selftest_ok") == "f")
        print("B2. the new counts")
        allow(); out, err = beat(title_events=40, title_with_text=30, title_specific=12, title_distinct=5)
        check("counts are accepted and stored", '"ok": true' in out and row("title_events || ',' || title_with_text || ',' || title_specific || ',' || title_distinct") == "40,30,12,5", err)
        for label, kw in [("with_text above events", dict(title_events=3, title_with_text=4)),
                          ("specific above with_text", dict(title_events=5, title_with_text=3, title_specific=4)),
                          ("distinct above with_text", dict(title_events=5, title_with_text=3, title_distinct=4)),
                          ("negative", dict(title_events=-1)), ("huge", dict(title_events=2000000, title_with_text=0))]:
            check(f"{label} -> rejected", "bad info" in beat(**kw)[1], beat(**kw)[1])
        check("the stored row has no text column for titles", val("select count(*) from information_schema.columns where table_name='onn_beats' and column_name like 'title%' and data_type <> 'integer'") == "0")
        print("B3. permissions")
        out, err = psql("set role anon; select public.eg_onn_heartbeat('" + "00" * 32 + "', '{}'::jsonb);", err_ok=True)
        check("anon needs a valid token", "unauthorized" in err, err)
        check("anon cannot read the beats table", psql("set role anon; select count(*) from public.onn_beats;", err_ok=True)[1].lower().count("permission denied") == 1)
    finally:
        subprocess.run(dock + ["rm", "-f", name], capture_output=True)

if fails:
    print("\nFAILED:", *fails, sep="\n  ")
    sys.exit(1)
print("\nALL OK")
