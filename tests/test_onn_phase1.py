#!/usr/bin/env python3
"""Onn monitor phase 1 (supabase/onn_monitor_phase1.sql) in a throwaway Postgres with synthetic data only.
Part A: static checks (run anywhere). Part B: real Postgres via docker (postgres:16-alpine).
Run: python3 tests/test_onn_phase1.py
  EG_DOCKER="ssh g11 docker"  run the container on another host (stdin is passed through)
  EG_REQUIRE_SQL=1            a skipped Part B counts as a failure"""
import hashlib, json, os, re, shlex, shutil, subprocess, sys, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SQL = (ROOT / "supabase/onn_monitor_phase1.sql").read_text()
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

print("A. static checks")
live = re.sub(r"--[^\n]*", "", SQL)
check("no placeholder Dad would have to edit", "CHANGE-ME" not in SQL and ".invalid" not in SQL)
check("every function is locked down to the API roles it needs",
      all(f"revoke execute on function public.{f}" in SQL for f in
          ("eg_onn_mail", "eg_onn_open", "eg_onn_close", "eg_onn_heartbeat", "eg_check_onn_status")))
check("only the heartbeat is granted to anon", len(re.findall(r"grant execute on function[^;]*to anon", live)) == 1
      and "grant execute on function public.eg_onn_heartbeat" in live)
check("no service-role key, private key or token value appears in the file",
      not re.search(r"BEGIN [A-Z ]*PRIVATE KEY|service_role_key|eyJ[A-Za-z0-9_-]{20,}", SQL))
check("the token and approved-build inserts are commented out (nothing is registered by running the file)",
      not re.search(r"^insert into public\.onn_(auth|approved)", live, re.M))
check("the gap alert ships disarmed", "gap_armed        boolean not null default false" in SQL)
check("no table in the file is writable by an API role",
      not re.search(r"grant\s+(insert|update|delete|all)", live, re.I))

print("B. real Postgres")
dock = shlex.split(os.environ.get("EG_DOCKER", "docker"))
have = shutil.which(dock[0]) and subprocess.run(dock + ["image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1": check("SQL tests could run", False, "docker/postgres:16-alpine unavailable")
    else: print("  [skip] docker/postgres:16-alpine unavailable")
else:
    name = "egonn-" + uuid.uuid4().hex[:8]
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
            if r.returncode != 0 and not err_ok: raise RuntimeError(r.stderr[-1200:])
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
grant usage on schema public, extensions, auth to anon, authenticated, service_role;
""" + f"insert into auth.users values ('{DAD}','dad@example.test'),('{JONAH}','jonah@example.test');")
        base = (ROOT / "supabase/mdm_app_events.sql").read_text().replace("create extension if not exists pg_net;", "")
        psql(base.replace("dad@CHANGE-ME.invalid", "dad@example.test"))
        sql_run = SQL.replace("create extension if not exists pg_net;", "")
        psql(sql_run); psql(sql_run)
        check("applies on top of the live MDM files and re-runs cleanly (one cron job)",
              val("select count(*) from cron.job where jobname='eyeguard-onn-status'") == "1")
        verify = psql(sql_run)[0].splitlines()[-1]
        check("the file's own verify select is all true", set(verify.split("|")) == {"t"}, verify)

        tok = "ab" * 32
        sent = lambda: int(val("select count(*) from net.sent"))
        subj = lambda: val("select body->>'subject' from net.sent order by id desc limit 1")
        check_fn = lambda: psql("select public.eg_check_onn_status();")
        CERT = "c" * 64; CERT2 = "d" * 64
        def beat(token=tok, **kw):
            info = dict(app_version="0.1.0", cert_sha256=CERT, svc_enabled=True, screen_state="on", screen_on_s=300, window_s=300,
                        interval_s=15, attempted=20, succeeded=20, analysed=20, black=0, distinct_hashes=12)
            info.update(kw)
            info = {k: v for k, v in info.items() if v is not None}
            return psql(f"select public.eg_onn_heartbeat('{token}', $j${json.dumps(info)}$j$::jsonb);", err_ok=True)
        def as_role(role, sql, sub=None):
            pre = f"set role {role};" + (f" set request.jwt.claim.sub = '{sub}';" if sub else "")
            return psql(pre + sql, err_ok=True)

        print("B1. nothing happens before the first heartbeat, and a bad token does nothing")
        n0 = sent()
        psql("update public.onn_status set silent_alerted = false where id = 1;")
        check("checks do nothing while the monitor has never reported", check_fn()[1] == "" and sent() == n0)
        out, err = beat(token="ff" * 32)
        check("an unregistered token is refused", "unauthorized" in err and val("select count(*) from public.onn_beats") == "0", err)
        psql(f"insert into public.onn_auth(token_sha256, note) values ('{hashlib.sha256(tok.encode()).hexdigest()}','t');")
        out, err = beat(token="short")
        check("a short token is refused", "unauthorized" in err)

        print("B2. the heartbeat validates everything (missing or inconsistent fields cannot dodge a check)")
        for label, kw in [("missing svc_enabled", dict(svc_enabled=None)), ("missing analysed", dict(analysed=None)),
                          ("succeeded > attempted", dict(attempted=5, succeeded=6)), ("analysed > succeeded", dict(analysed=21)),
                          ("bad screen_state", dict(screen_state="maybe")), ("bad cert", dict(cert_sha256="xyz")),
                          ("window 0", dict(window_s=0)), ("distinct > succeeded", dict(distinct_hashes=21))]:
            check(f"{label} -> rejected", "bad info" in beat(**kw)[1], beat(**kw)[1])
        check("none of those left a row", val("select count(*) from public.onn_beats") == "0")
        out, err = beat()
        check("a good heartbeat is accepted", '"ok": true' in out and val("select count(*) from public.onn_beats") == "1", out + err)
        beat()
        check("two beats within 30 s store one history row (flood guard)", val("select count(*) from public.onn_beats") == "1")
        check("the server clock is used (client time is not even an input)", val("select last_beat_at is not null from public.onn_status") == "t")

        print("B3. silence")
        n0 = sent()
        psql("update public.onn_status set last_beat_at = now() - interval '20 minutes' where id = 1;")
        check_fn()
        check("20 min of silence -> one STOPPED email", sent() == n0 + 1 and "STOPPED" in subj(), subj())
        check_fn(); check("re-check does not email again", sent() == n0 + 1)
        check("an incident is open", val("select count(*) from public.onn_incidents where kind='onn_silent' and ended_at is null") == "1")
        beat()
        check("the next heartbeat sends the ALL-CLEAR and closes the incident",
              sent() == n0 + 2 and "reporting again" in subj() and val("select count(*) from public.onn_incidents where kind='onn_silent' and ended_at is null") == "0", subj())

        print("B4. service switched off")
        n0 = sent()
        beat(svc_enabled=False); check_fn()
        check("service off for under 3 minutes: no email yet", sent() == n0)
        psql("update public.onn_status set svc_off_since = now() - interval '5 minutes' where id = 1;")
        check_fn()
        check("service off for 5 minutes -> one OFF email", sent() == n0 + 1 and "OFF" in subj(), subj())
        beat(svc_enabled=True)
        check("service back -> ALL-CLEAR", sent() == n0 + 2 and "back on" in subj(), subj())

        print("B5. service on but blind (the 2026-11-12 lesson)")
        n0 = sent()
        for _ in range(2): beat(analysed=0, succeeded=0, attempted=0, distinct_hashes=0)
        check_fn(); check("2 blind beats: no email yet", sent() == n0)
        beat(analysed=0, succeeded=0, attempted=0, distinct_hashes=0); check_fn()
        check("3 blind beats with the screen on -> one 'not seeing the screen' email", sent() == n0 + 1 and "not seeing" in subj(), subj())
        beat(analysed=0, succeeded=0, attempted=0, distinct_hashes=0, screen_state="off", screen_on_s=0); check_fn()
        check("a screen-off beat with 0 frames does not clear it (and does not re-alert)", sent() == n0 + 1)
        beat()
        check("a beat that analyses frames -> ALL-CLEAR", sent() == n0 + 2 and "examining the screen again" in subj(), subj())
        for _ in range(5): beat(analysed=0, succeeded=0, attempted=0, distinct_hashes=0, screen_state="off", screen_on_s=0)
        check_fn(); check("TV off overnight (0 frames, screen off) never alerts", sent() == n0 + 2)

        print("B6. black frames and identical frames")
        n0 = sent()
        for _ in range(5): beat(black=20, distinct_hashes=1)
        check_fn(); check("5 all-black beats: no email yet", sent() == n0)
        beat(black=20, distinct_hashes=1); check_fn()
        check("6 all-black beats -> one 'only seeing black' email that names DRM", sent() == n0 + 1 and "only seeing black" in subj(), subj())
        beat(); check("real picture again -> ALL-CLEAR", sent() == n0 + 2 and "no longer all black" in subj(), subj())
        n0 = sent()
        for _ in range(11): beat(distinct_hashes=1)
        check_fn(); check("11 identical-frame beats: no email", sent() == n0)
        beat(distinct_hashes=1); check_fn()
        check("12 identical-frame beats -> one 'same picture' email", sent() == n0 + 1 and "same picture" in subj(), subj())
        beat(); check("frames change -> ALL-CLEAR", sent() == n0 + 2 and "changing screen again" in subj(), subj())

        print("B7. the screenshot-gap alert is OFF until Dad arms it")
        n0 = sent()
        for _ in range(4): beat(succeeded=2, attempted=2, analysed=2, distinct_hashes=2)
        check_fn(); check("too few screenshots, gap disarmed: silent", sent() == n0)
        psql("update public.onn_status set gap_armed = true where id = 1;")
        for _ in range(3): beat(succeeded=2, attempted=2, analysed=2, distinct_hashes=2)
        check_fn(); check("gap armed, 3 slow beats -> one 'too few screenshots' email", sent() == n0 + 1 and "too few screenshots" in subj(), subj())
        beat(); check("rate recovers -> ALL-CLEAR", sent() == n0 + 2 and "taking screenshots again" in subj(), subj())
        psql("update public.onn_status set gap_armed = false where id = 1;")

        print("B8. build integrity (version + signing cert + model, approved by Dad by hand)")
        n0 = sent()
        beat(cert_sha256=CERT2); check_fn()
        check("no approved build registered yet: no build alert", sent() == n0)
        psql(f"insert into public.onn_approved(app_version, cert_sha256) values ('0.1.0', '{CERT}');")
        beat(cert_sha256=CERT2); check_fn()
        check("a signing cert that matches no approved build -> immediate DRIFT email", sent() == n0 + 1 and "nobody approved" in subj(), subj())
        check_fn(); check("no repeat", sent() == n0 + 1)
        beat(); check_fn()
        check("the approved build again -> ALL-CLEAR", sent() == n0 + 2 and "approved one again" in subj(), subj())
        beat(model_sha256="e" * 64); check_fn()
        check("an unapproved model hash is drift too", sent() == n0 + 3 and "nobody approved" in subj(), subj())
        beat(); check_fn()
        psql(f"insert into public.onn_approved(app_version, cert_sha256) values ('0.2.0', '{CERT}');")
        n0 = sent(); beat(); check_fn()
        check("an older approved build: no immediate email", sent() == n0)
        psql("update public.onn_status set outdated_since = now() - interval '25 hours' where id = 1;"); check_fn()
        check("older approved build after 24 h -> one reminder", sent() == n0 + 1 and "not been updated" in subj(), subj())
        beat(app_version="0.2.0"); check_fn()
        check("newest approved build -> ALL-CLEAR", sent() == n0 + 2 and "approved one again" in subj(), subj())

        print("B9. who can see or call what")
        out, err = as_role("anon", "select count(*) from public.onn_status;")
        check("anon cannot read status", "permission denied" in err, err)
        out, err = as_role("anon", "select count(*) from public.onn_auth;")
        check("anon cannot read the token hashes", "permission denied" in err, err)
        out, err = as_role("anon", "select public.eg_check_onn_status();")
        check("anon cannot run the check", "permission denied" in err, err)
        out, err = as_role("anon", "select public.eg_onn_mail('x','y');")
        check("anon cannot send mail", "permission denied" in err, err)
        out, err = as_role("anon", "insert into public.onn_beats(svc_enabled,screen_state,screen_on_s,window_s,interval_s,attempted,succeeded,analysed,black,distinct_hashes) values (true,'on',0,1,1,0,0,0,0,0);")
        check("anon cannot write history", "permission denied" in err, err)
        out, err = as_role("authenticated", "select count(*) from public.onn_incidents;", sub=DAD)
        check("Dad can read the incident log", err == "" and int(out) > 0, err + out)
        out, err = as_role("authenticated", "select count(*) from public.onn_beats;", sub=DAD)
        check("Dad can read the history", err == "" and int(out) > 0, err + out)
        out, err = as_role("authenticated", "select count(*) from public.onn_incidents;", sub=JONAH)
        check("a non-partner account reads nothing", err == "" and out == "0", err + out)
        out, err = as_role("authenticated", "update public.onn_incidents set ended_at = null;", sub=DAD)
        check("even a partner cannot change the incident log", "permission denied" in err, err)
        out, err = as_role("authenticated", "select count(*) from public.onn_approved;", sub=DAD)
        check("approved builds are not readable or writable through the API", "permission denied" in err, err)

        print("B10. housekeeping")
        psql("insert into public.onn_beats(received_at,svc_enabled,screen_state,screen_on_s,window_s,interval_s,attempted,succeeded,analysed,black,distinct_hashes) "
             "values (now() - interval '40 days', true,'on',0,1,1,0,0,0,0,0);")
        check_fn()
        check("history older than 30 days is purged", val("select count(*) from public.onn_beats where received_at < now() - interval '31 days'") == "0")
    finally:
        subprocess.run(dock + ["rm", "-f", name], capture_output=True)

if fails:
    print("\nFAILED:", *fails, sep="\n  ")
    sys.exit(1)
print("\nALL OK")
