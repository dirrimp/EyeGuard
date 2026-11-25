#!/usr/bin/env python3
"""Onn media-exempt SQL (supabase/onn_media_exempt.sql): YouTube TV black-frame exemption, server side.
Synthetic data only, throwaway Postgres in docker. Run: EG_DOCKER="ssh g11 docker" EG_REQUIRE_SQL=1 python3 tests/test_onn_media_exempt.py"""
import hashlib, json, os, re, shlex, shutil, subprocess, sys, time, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SQL5 = (ROOT / "supabase/onn_monitor_phase5a_titlefacts.sql").read_text()
SQLX = (ROOT / "supabase/onn_media_exempt.sql").read_text()
SQL3 = (ROOT / "supabase/onn_monitor_phase3.sql").read_text()
SQL1 = (ROOT / "supabase/onn_monitor_phase1.sql").read_text()
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

print("A. static checks")
live = re.sub(r"--[^\n]*", "", SQLX)
check("the file is pure ASCII (Dad copies it into a browser)", all(ord(c) < 128 for c in SQLX))
check("no placeholder, key material or token value", "CHANGE-ME" not in SQLX and not re.search(r"PRIVATE KEY|service_role_key|eyJ[A-Za-z0-9_-]{20,}", SQLX))
check("it starts by saying it reduces coverage and that the running app is unaffected", "REDUCES COVERAGE" in SQLX[:1200] and "CHANGES NOTHING for the running 0.2.2" in SQLX)
check("it never contains the mail API literal (mail goes only through eg_onn_mail)", "api.resend.com" not in SQLX)
check("only YouTube TV is ever named as an exempt package", set(re.findall(r"com\.google\.android\.youtube\.[a-z]+", SQLX)) == {"com.google.android.youtube.tvunplugged"})
check("exactly two functions are created and two granted/revoked as intended", len(re.findall(r"create or replace function", live)) == 2 and len(re.findall(r"grant execute on function[^;]*to anon", live)) == 1)
check("the heartbeat is patched with nine exactly-once fragments (no rebuild from an old copy)", "for i in 1 .. array_length(f, 1) loop" in SQLX and live.count("exactly once") >= 1)
check("the exemption needs listener_ok AND a title record AND is capped by the black count", "lok is true" in SQLX and "onn_titles where received_at" in SQLX and "bx not between 0 and blk" in SQLX)

print("B. real Postgres")
dock = shlex.split(os.environ.get("EG_DOCKER", "docker"))
have = shutil.which(dock[0]) and subprocess.run(dock + ["image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1": check("SQL tests could run", False, "docker/postgres:16-alpine unavailable")
    else: print("  [skip] docker/postgres:16-alpine unavailable")
else:
    name = "egonnmx-" + uuid.uuid4().hex[:8]
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
        psql(p5)
        pX = SQLX.replace("create extension if not exists pg_net;", "")
        psql(pX); psql(pX)
        verify = psql(pX)[0].splitlines()[-1]
        check("the file's own verify select is all true (run three times: idempotent)", set(verify.split("|")) == {"t"}, verify)

        tok = "ab" * 32
        psql(f"insert into public.onn_auth(token_sha256, note) values ('{hashlib.sha256(tok.encode()).hexdigest()}','t');")
        CERT = "c" * 64; MODEL = "d" * 64
        GOOD = dict(selftest_argmax=8355, selftest_max=319.69696044921875, model_ms=272)
        PKG = "com.google.android.youtube.tvunplugged"
        def beat(**kw):
            info = dict(app_version="0.3.0", cert_sha256=CERT, svc_enabled=True, screen_state="on", screen_on_s=300, window_s=300,
                        interval_s=15, attempted=20, succeeded=20, analysed=20, black=0, distinct_hashes=12, model_sha256=MODEL, **GOOD)
            info.update(kw); info = {k: v for k, v in info.items() if v is not None}
            return psql(f"select public.eg_onn_heartbeat('{tok}', $j${json.dumps(info)}$j$::jsonb);", err_ok=True)
        allow = lambda: psql("update public.onn_status set last_beat_at = now() - interval '1 minute' where id = 1;")
        st = lambda col: val(f"select {col} from public.onn_status where id = 1")
        row = lambda col: val(f"select {col} from public.onn_beats order by id desc limit 1")
        def reset(): psql("update public.onn_status set black_beats = 0, frozen_beats = 0, black_alerted = false, listener_alerted = false where id = 1; delete from public.onn_titles;")
        def title(ago_s=0, pkg=PKG, ct=None, obj=None, token=None, err_ok=True):
            ts = (datetime.now(timezone.utc) - timedelta(seconds=ago_s)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "+00:00"
            info = {"pkg": pkg, "object": obj or f"onn-title/{ts}_title.enc", "ct": ct or ("RUdGMg" + "A" * 120)}
            return psql(f"select public.eg_onn_title('{token or tok}', $j${json.dumps(info)}$j$::jsonb);", err_ok=err_ok)
        BLACK = dict(attempted=20, succeeded=20, analysed=20, black=20, distinct_hashes=1)

        print("B1. nothing changes for the running 0.2.2 build (it sends none of the new fields)")
        reset(); out, err = beat(**BLACK); check("a black beat without the new fields is accepted", '"ok": true' in out, err)
        check("it counts as black exactly as before", st("black_beats") == "1" and st("frozen_beats") == "0")
        check("new columns are stored empty/zero for it", row("coalesce(black_exempt,0) || ',' || coalesce(titles_sent,0)") == "0,0" and row("listener_ok is null") == "t")
        print("B2. the exemption: only with the listener on AND an encrypted title record in the window")
        reset(); allow(); title(); out, err = beat(**BLACK, black_exempt=20, titles_sent=1, listener_ok=True)
        check("YouTube TV playing + title record + listener on: black frames do NOT count", '"ok": true' in out and st("black_beats") == "0", err + st("black_beats"))
        check("...and the all-black beat is not turned into an 'identical frames' alert either", st("frozen_beats") == "0")
        reset(); allow(); out, err = beat(**BLACK, black_exempt=20, titles_sent=0, listener_ok=True)
        check("exempt claimed but NO title record uploaded: counts as black", st("black_beats") == "1", st("black_beats"))
        reset(); allow(); title(); beat(**BLACK, black_exempt=20, titles_sent=1, listener_ok=False)
        check("exempt claimed with the listener OFF: counts as black", st("black_beats") == "1", st("black_beats"))
        reset(); allow(); title(); beat(**BLACK, black_exempt=20, titles_sent=1)
        check("exempt claimed with no listener field: counts as black", st("black_beats") == "1", st("black_beats"))
        reset(); allow(); title(); psql("update public.onn_titles set received_at = now() - interval '10 minutes';"); beat(**BLACK, black_exempt=20, titles_sent=1, listener_ok=True)
        check("a title record from 10 minutes ago does not back this beat", st("black_beats") == "1", st("black_beats"))
        reset(); allow(); title(); beat(**BLACK, black_exempt=5, titles_sent=1, listener_ok=True)
        check("only the exempt part is excused: 15 of 20 frames still black (75%) is NOT an alert beat, 19 would be", st("black_beats") == "0")
        reset(); allow(); title(); beat(attempted=20, succeeded=20, analysed=20, black=20, distinct_hashes=1, black_exempt=1, titles_sent=1, listener_ok=True)
        check("exempting 1 of 20 black frames still leaves 19 black (95%): alert beat", st("black_beats") == "1", st("black_beats"))
        reset(); allow(); title(); out, err = beat(**BLACK, black_exempt=21, titles_sent=1, listener_ok=True)
        check("black_exempt above the beat's own black count is rejected", "bad info" in err, err)
        out, err = beat(**BLACK, black_exempt=-1, titles_sent=1, listener_ok=True)
        check("negative black_exempt is rejected", "bad info" in err, err)
        out, err = beat(**BLACK, black_exempt=1, titles_sent=5000, listener_ok=True)
        check("absurd titles_sent is rejected", "bad info" in err, err)
        print("B3. a black beat that is not exempt still raises the alert path (real detection untouched)")
        reset(); psql("update public.onn_status set last_beat_at = now() - interval '1 minute' where id = 1;")
        for _ in range(6):
            allow(); beat(**BLACK)
        check("6 black beats (SmartTube, browser, no listener...) reach the onn_black threshold", st("black_beats") == "6", st("black_beats"))
        psql("select public.eg_check_onn_status();")
        check("and the black alert email is sent", int(val("select count(*) from net.sent where body::text like '%only seeing black%'")) == 1)
        allow(); title(); beat(**BLACK, black_exempt=20, titles_sent=1, listener_ok=True)
        check("an exempt YouTube TV beat clears it (the screen is explained)", st("black_beats") == "0")
        print("B4. eg_onn_title")
        reset(); out, err = title(); check("a valid encrypted record is stored", '"ok": true' in out and val("select count(*) from public.onn_titles") == "1", err)
        ts = (datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "+00:00"
        o = f"onn-title/{ts}_title.enc"; title(obj=o); out, _ = title(obj=o)
        check("the same object twice is a duplicate, not a second row", "duplicate" in out and val("select count(*) from public.onn_titles") == "2")
        for label, kw in [("another package (SmartTube)", dict(pkg="org.smarttube.stable")), ("Jellyfin", dict(pkg="org.jellyfin.androidtv")),
                          ("not an EGF2 blob", dict(ct="AAAA" * 40)), ("too short", dict(ct="RUdGMg")), ("plain text", dict(ct="RUdGMg" + "!" * 100)),
                          ("object outside the pattern", dict(obj="onn-title/../x_title.enc")), ("object from an hour ago", dict(ago_s=3600))]:
            check(f"{label} -> rejected", "bad " in title(**kw)[1] or "outside" in title(**kw)[1], title(**kw)[1])
        check("bad token -> unauthorized", "unauthorized" in title(token="00" * 32)[1])
        psql("insert into public.onn_titles (object_name, pkg, ciphertext) select 'onn-title/2026-01-01T00:00:00+00:00_t' || g || '_title.enc', '" + PKG + "', 'RUdGM' || repeat('A', 100) from generate_series(1,119) g;") if False else None
        psql("insert into public.onn_titles (object_name, pkg, ciphertext) select 'onn-title/2026-01-01T00:00:' || lpad((g % 60)::text, 2, '0') || '.' || lpad(g::text, 6, '0') || '+00:00_title.enc', '" + PKG + "', 'RUdGM' || repeat('A', 100) from generate_series(1,120) g;")
        check("more than 120 records an hour is refused", "too many" in title()[1], title()[1])
        print("B5. permissions and retention")
        check("anon cannot read titles", psql("set role anon; select count(*) from public.onn_titles;", err_ok=True)[1].lower().count("permission denied") == 1)
        check("anon cannot write titles directly", psql("set role anon; insert into public.onn_titles (object_name, pkg, ciphertext) values ('x','y','z');", err_ok=True)[1].lower().count("permission denied") == 1)
        check("a stranger signed-in user cannot read titles", psql("set role authenticated; set request.jwt.claim.sub = '" + JONAH + "'; select count(*) from public.onn_titles;", err_ok=True)[0] == "0")
        check("Dad can read the rows (ciphertext only)", int(psql("set role authenticated; set request.jwt.claim.sub = '" + DAD + "'; select count(*) from public.onn_titles;", err_ok=True)[0].splitlines()[-1]) > 0)
        check("the prune job deletes only records older than 30 days", "30 days" in val("select command from cron.job where jobname = 'eyeguard-onn-titles-prune'"))
        print("B6. the listener alert")
        reset(); psql("delete from net.sent; delete from public.onn_incidents where kind = 'onn_listener_off';")
        allow(); beat(listener_ok=False)
        psql("select public.eg_check_onn_listener();")
        check("listener off for under 3 minutes: no email yet", int(val("select count(*) from net.sent where body::text like '%listener is OFF%'")) == 0)
        psql("update public.onn_status set listener_off_since = now() - interval '4 minutes', last_beat_at = now() where id = 1;")
        psql("select public.eg_check_onn_listener(); select public.eg_check_onn_listener();")
        check("off for 4 minutes: exactly one email and one incident", int(val("select count(*) from net.sent where body::text like '%listener is OFF%'")) == 1 and val("select count(*) from public.onn_incidents where kind = 'onn_listener_off' and ended_at is null") == "1")
        allow(); beat(listener_ok=True); psql("select public.eg_check_onn_listener();")
        check("listener back on: one all-clear and the incident is closed", int(val("select count(*) from net.sent where body::text like '%listener is back on%'")) == 1 and val("select count(*) from public.onn_incidents where kind = 'onn_listener_off' and ended_at is null") == "0")
        reset(); allow(); beat()
        psql("select public.eg_check_onn_listener();")
        check("a 0.2.2 build (no listener field) never raises the listener alert", int(val("select count(*) from net.sent where body::text like '%listener is OFF%'")) == 1)
        print("B7. the patch refuses a live function that differs from the repo")
        psql("create or replace function public.eg_onn_heartbeat(p_token text, p_info jsonb default '{}'::jsonb) returns jsonb language sql as $$ select '{}'::jsonb $$;")
        out, err = psql(pX, err_ok=True)
        check("a different live heartbeat: stops with an error and changes nothing", "exactly once" in err and "black_exempt" not in val("select pg_get_functiondef('public.eg_onn_heartbeat(text, jsonb)'::regprocedure)"), err[-300:])
    finally:
        subprocess.run(dock + ["rm", "-f", name], capture_output=True)

if fails:
    print("\nFAILED:", *fails, sep="\n  ")
    sys.exit(1)
print("\nALL OK")
