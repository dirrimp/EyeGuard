#!/usr/bin/env python3
"""Onn monitor phase 3 SQL (supabase/onn_monitor_phase3.sql) in a throwaway Postgres with synthetic data only.
Part A: static checks. Part B: real Postgres via docker (postgres:16-alpine).
Run: python3 tests/test_onn_phase3.py
  EG_DOCKER="ssh g11 docker"  run the container on another host   |   EG_REQUIRE_SQL=1  a skipped Part B is a failure"""
import hashlib, json, os, re, shlex, shutil, subprocess, sys, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SQL3 = (ROOT / "supabase/onn_monitor_phase3.sql").read_text()
SQL3B = (ROOT / "supabase/onn_monitor_phase3b.sql").read_text()
SQL1 = (ROOT / "supabase/onn_monitor_phase1.sql").read_text()
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

print("A. static checks")
live = re.sub(r"--[^\n]*", "", SQL3)
check("no placeholder Dad would have to edit", "CHANGE-ME" not in SQL3 and ".invalid" not in SQL3)
check("no key material, token value or service-role key in the file", not re.search(r"BEGIN [A-Z ]*PRIVATE KEY|service_role_key|eyJ[A-Za-z0-9_-]{20,}", SQL3))
check("every new function is locked down, and only the heartbeat and the flag call are granted to anon",
      "revoke execute on function public.eg_onn_flag(text, jsonb) from public, anon, authenticated, service_role" in SQL3
      and len(re.findall(r"grant execute on function[^;]*to anon", live)) == 2)
check("the approve-a-build insert is commented out (running the file approves nothing)", not re.search(r"^insert into public\.onn_approved", live, re.M))
check("the flag floor and labels are the Mac's (config.yaml)",
      "sc < 0.80" in SQL3 and all(l in SQL3 for l in ("FEMALE_BREAST_EXPOSED", "FEMALE_GENITALIA_EXPOSED", "BUTTOCKS_EXPOSED", "ANUS_EXPOSED"))
      and "MALE_GENITALIA_EXPOSED" not in SQL3.replace("FEMALE_GENITALIA_EXPOSED", ""))
cfg = (ROOT / "config.yaml").read_text()
check("config.yaml's flag_threshold is 0.80 and its explicit labels are those four", "flag_threshold: 0.80" in cfg and
      set(re.findall(r"^\s+- ([A-Z_]+_EXPOSED)\s*$", cfg[cfg.index("explicit_labels:"):cfg.index("arbiter:")], re.M)) ==
      {"FEMALE_BREAST_EXPOSED", "FEMALE_GENITALIA_EXPOSED", "BUTTOCKS_EXPOSED", "ANUS_EXPOSED"})
ref = json.loads((ROOT / "android/onn-fit/reference-mac.json").read_text())
check("the golden values in the SQL equal the Mac reference run", f"{ref['argmax']}, {ref['max']!r}" in SQL3.replace("319.69696044921875", repr(ref["max"])) and str(ref["argmax"]) in SQL3 and "319.69696044921875" in SQL3 and repr(ref["max"]) == "319.69696044921875")
check("the object-name pattern matches the uploader's naming (timestamp with ':' replaced by '-', _flagged_d1.jpg.enc)",
      "_flagged_d1\\.jpg\\.enc$" in SQL3 and "+00-00" in SQL3)
check("phase 3b adds only the ONN_TEST label (no placeholder, no key material, grants kept)", "CHANGE-ME" not in SQL3B and ".invalid" not in SQL3B and "grant execute on function public.eg_onn_flag(text, jsonb) to anon" in SQL3B and not re.search(r"BEGIN [A-Z ]*PRIVATE KEY|eyJ[A-Za-z0-9_-]{20,}", SQL3B))
check("nothing is dropped: the volume rule demotes to yellow, it never skips the insert", "case when recent then 'alert' else 'flagged' end" in SQL3)

print("B. real Postgres")
dock = shlex.split(os.environ.get("EG_DOCKER", "docker"))
have = shutil.which(dock[0]) and subprocess.run(dock + ["image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1": check("SQL tests could run", False, "docker/postgres:16-alpine unavailable")
    else: print("  [skip] docker/postgres:16-alpine unavailable")
else:
    name = "egonn3-" + uuid.uuid4().hex[:8]
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
        psql(p3); psql(p3)
        check("phase 3 applies on top of phase 1 and re-runs cleanly (still one cron job)",
              val("select count(*) from cron.job where jobname='eyeguard-onn-status'") == "1")
        verify = psql(p3)[0].splitlines()[-1]
        check("the file's own verify select is all true", set(verify.split("|")) == {"t"}, verify)

        tok = "ab" * 32
        psql(f"insert into public.onn_auth(token_sha256, note) values ('{hashlib.sha256(tok.encode()).hexdigest()}','t');")
        sent = lambda: int(val("select count(*) from net.sent"))
        subj = lambda: val("select body->>'subject' from net.sent order by id desc limit 1")
        check_fn = lambda: psql("select public.eg_check_onn_status();")
        CERT = "c" * 64; MODEL = "d" * 64
        GOOD = dict(selftest_argmax=8355, selftest_max=319.69696044921875, model_ms=272)
        def beat(**kw):
            info = dict(app_version="0.2.0", cert_sha256=CERT, svc_enabled=True, screen_state="on", screen_on_s=300, window_s=300,
                        interval_s=15, attempted=20, succeeded=20, analysed=20, black=0, distinct_hashes=12)
            info.update(kw); info = {k: v for k, v in info.items() if v is not None}
            return psql(f"select public.eg_onn_heartbeat('{tok}', $j${json.dumps(info)}$j$::jsonb);", err_ok=True)

        allow = lambda: psql("update public.onn_status set last_beat_at = now() - interval '1 minute' where id = 1;")
        last_beat_row = lambda col: val(f"select {col} from public.onn_beats order by id desc limit 1")
        print("B1. phase 2 apps (no model) behave exactly as before")
        out, err = beat()
        check("a heartbeat without a model is accepted", '"ok": true' in out, err)
        n0 = sent()
        for _ in range(5): beat()
        check_fn(); check("no detector alert is possible without a model", sent() == n0)
        psql("update public.onn_status set last_beat_at = now() - interval '20 minutes' where id = 1;")
        check_fn()
        check("phase 1 silence alert still fires", sent() == n0 + 1 and "STOPPED" in subj(), subj())
        beat()
        check("phase 1 all-clear still fires", sent() == n0 + 2 and "reporting again" in subj(), subj())

        print("B2. a build that reports a model must report its self-test")
        for label, kw in [("missing selftest_argmax", dict(model_sha256=MODEL, selftest_max=319.7, model_ms=270)),
                          ("missing selftest_max", dict(model_sha256=MODEL, selftest_argmax=8355, model_ms=270)),
                          ("missing model_ms", dict(model_sha256=MODEL, selftest_argmax=8355, selftest_max=319.7)),
                          ("model_ms zero", dict(model_sha256=MODEL, selftest_argmax=8355, selftest_max=319.7, model_ms=0)),
                          ("negative flags_dropped", dict(model_sha256=MODEL, flags_dropped=-1, **GOOD))]:
            check(f"{label} -> rejected", "bad info" in beat(**kw)[1], beat(**kw)[1])
        allow()
        out, err = beat(model_sha256=MODEL, frames_flagged=1, flags_dropped=0, **GOOD)
        check("a complete phase 3 heartbeat is accepted, and the SERVER marks the self-test passed",
              '"ok": true' in out and last_beat_row("selftest_ok") == "t", out + err)
        check("new fields are stored", last_beat_row("model_ms || ',' || frames_flagged") == "272,1")

        print("B3. the server decides the self-test, not the app")
        n0 = sent()
        allow()
        beat(model_sha256=MODEL, selftest_argmax=1234, selftest_max=319.69696044921875, model_ms=272)
        check("a wrong argmax is recorded as a failed self-test", last_beat_row("selftest_ok") == "f")
        check_fn(); check("one failed beat: no email yet", sent() == n0)
        beat(model_sha256=MODEL, selftest_argmax=8355, selftest_max=320.0, model_ms=272)   # relative error ~1e-3, above the 1e-4 tolerance
        check_fn()
        check("two failed beats in a row -> one 'detector may be broken' email", sent() == n0 + 1 and "detector may be broken" in subj(), subj())
        check("an incident is open", val("select count(*) from public.onn_incidents where kind='onn_detector' and ended_at is null") == "1")
        for _ in range(3): beat(model_sha256=MODEL, selftest_argmax=8355, selftest_max=320.0, model_ms=272)
        check_fn()
        check("no repeat while it stays failed", sent() == n0 + 1, str(sent() - n0))
        beat(model_sha256=MODEL, selftest_argmax=8355, selftest_max=319.69696044921875 * (1 + 5e-5), model_ms=272)
        check("a tiny numerical difference (5e-5, inside the tolerance) passes and sends the ALL-CLEAR",
              sent() == n0 + 2 and "passes again" in subj() and val("select count(*) from public.onn_incidents where kind='onn_detector' and ended_at is null") == "0", subj())
        n0 = sent()
        beat(model_sha256=MODEL, selftest_argmax=1, selftest_max=1.0, model_ms=272, svc_enabled=False); check_fn()
        check("a beat with the service off does not count as a detector failure", val("select detector_bad_beats from public.onn_status") == "0")
        beat(model_sha256=MODEL, selftest_argmax=1, selftest_max=1.0, model_ms=272, detector_ok=True)
        check("the app's own opinion is not an input: a made-up detector_ok=true still counts as a failure",
              val("select detector_bad_beats from public.onn_status") == "1")

        print("B4. eg_onn_flag: validation")
        NOW = lambda secs=0: val(f"select to_char((now() at time zone 'utc') + interval '{secs} seconds', 'YYYY-MM-DD\"T\"HH24-MI-SS.US')") + "+00-00"
        def obj(secs=0): return f"onn/{NOW(secs)}_flagged_d1.jpg.enc"
        def put(o): psql(f"insert into storage.objects values ('frames', '{o}');")
        def flag(o, label="FEMALE_BREAST_EXPOSED", score=0.91, fg="org.jellyfin.androidtv", token=tok, extra=None):
            info = {"label": label, "score": score, "object": o, "foreground": fg}
            if extra: info.update(extra)
            info = {k: v for k, v in info.items() if v is not None}
            return psql(f"select public.eg_onn_flag('{token}', $j${json.dumps(info)}$j$::jsonb);", err_ok=True)
        o = obj(); put(o)
        check("a bad token is refused", "unauthorized" in flag(o, token="ff" * 32)[1])
        check("a short token is refused", "unauthorized" in flag(o, token="x")[1])
        check("an unknown label is refused", "bad info" in flag(o, label="MALE_GENITALIA_EXPOSED")[1])
        check("a made-up label is refused", "bad info" in flag(o, label="DROP TABLE")[1])
        check("a score below the Mac's 0.80 floor is refused", "bad info" in flag(o, score=0.79)[1])
        check("a score above 1 is refused", "bad info" in flag(o, score=1.5)[1])
        check("HTML in the foreground text is refused (it is shown in the alert email)", "bad info" in flag(o, fg="<script>x</script>")[1])
        check("a path-traversal object name is refused", "bad object name" in flag("onn/../x_flagged_d1.jpg.enc")[1])
        check("an object outside onn/ is refused", "bad object name" in flag("2026-11-17T10-00-00.000000+00-00_flagged_d1.jpg.enc")[1])
        check("a frame that was never uploaded is refused", "frame not uploaded" in flag(obj(1))[1])
        o_old = obj(-1200); put(o_old)
        check("a frame name older than 15 minutes is refused", "accepted window" in flag(o_old)[1])
        o_fut = obj(600); put(o_fut)
        check("a frame name from the future is refused", "accepted window" in flag(o_fut)[1])
        check("none of those left a flag row", val("select count(*) from public.flags") == "0")

        print("B5. eg_onn_flag: recording, the volume rule, nothing dropped")
        out, err = flag(o, score=0.80)
        check("a score of exactly 0.80 is accepted and is RED", '"verdict": "flagged"' in out, out + err)
        row = val("select app||'|'||is_nudity||'|'||grade||'|'||risk||'|'||reason||'|'||verdict||'|'||window_title from public.flags")
        check("the flags row has what eg_on_red and the dashboard use", row == "Onn TV|true|Likely|high|nudenet:FEMALE_BREAST_EXPOSED=0.80|flagged|org.jellyfin.androidtv", row)
        name_ts = o.split("/")[1].split("_")[0].replace("+00-00", "+00")
        name_ts = name_ts[:10] + " " + name_ts[11:13] + ":" + name_ts[14:16] + ":" + name_ts[17:]
        check("flagged_at is taken from the frame's own file name (to the microsecond)",
              val(f"select flagged_at = timestamptz '{name_ts}' from public.flags") == "t", name_ts)
        check("the first detection emails (the RED trigger fired once)", val("select count(*) from public.red_emails") == "1")
        out, _ = flag(o); check("the same frame again is a duplicate, not a second row", '"duplicate": true' in out and val("select count(*) from public.flags") == "1")
        o2 = obj(1); put(o2)
        out, _ = flag(o2, label="BUTTOCKS_EXPOSED", score=0.95)
        check("a second detection inside 10 minutes is stored as YELLOW (alert)", '"verdict": "alert"' in out, out)
        check("and it does NOT email", val("select count(*) from public.red_emails") == "1")
        check("it is still a full row with its encrypted frame path", val("select count(*) from public.flags where verdict='alert' and image_path like 'onn/%' and is_nudity") == "1")
        psql("update public.onn_flag_log set received_at = now() - interval '11 minutes';")
        o3 = obj(2); put(o3)
        out, _ = flag(o3, label="ANUS_EXPOSED", score=0.88)
        check("after a quiet 10 minutes the next detection is RED and emails again", '"verdict": "flagged"' in out and val("select count(*) from public.red_emails") == "2")
        check("every detection was kept (3 rows, none dropped)", val("select count(*) from public.flags") == "3" and val("select count(*) from public.onn_flag_log") == "3")
        psql("insert into public.onn_flag_log(object, flagged_at, label, score, verdict) select 'onn/x' || g, now(), 'ANUS_EXPOSED', 0.9, 'alert' from generate_series(1, 400) g;")
        o4 = obj(3); put(o4)
        check("the 400-per-hour sanity ceiling refuses loudly", "too many flags" in flag(o4)[1])

        print("B6. who can see or call what")
        for fn_, sql_ in [("eg_check_onn_status", "select public.eg_check_onn_status();"), ("eg_onn_mail", "select public.eg_onn_mail('x','y');")]:
            out, err = psql("set role anon;" + sql_, err_ok=True)
            check(f"anon cannot call {fn_}", "permission denied" in err, err)
        for t in ("onn_golden", "onn_flag_log", "onn_status", "onn_beats", "onn_approved", "onn_auth"):
            out, err = psql(f"set role anon; select count(*) from public.{t};", err_ok=True)
            check(f"anon cannot read {t}", "permission denied" in err, err)
        out, err = psql("set role anon; select public.eg_onn_flag('" + "00" * 32 + "', '{}'::jsonb);", err_ok=True)
        check("anon can CALL eg_onn_flag (it then refuses the unknown token itself)", "unauthorized" in err, err)
        out, err = psql(f"set role authenticated; set request.jwt.claim.sub = '{DAD}'; select count(*) from public.onn_flag_log;", err_ok=True)
        check("Dad can read the flag log", err == "" and int(out) > 0, err + out)
        out, err = psql(f"set role authenticated; set request.jwt.claim.sub = '{JONAH}'; select count(*) from public.onn_flag_log;", err_ok=True)
        check("a non-partner account reads nothing", err == "" and out == "0", err + out)
        out, err = psql(f"set role authenticated; set request.jwt.claim.sub = '{DAD}'; update public.onn_flag_log set label = 'x';", err_ok=True)
        check("even a partner cannot change the flag log", "permission denied" in err, err)

        print("B7. phase 3b: the end-to-end self-test label ONN_TEST")
        o_t = obj(); put(o_t)
        out, err = flag(o_t, label="ONN_TEST", score=1.0, fg="selftest")
        check("before phase 3b, ONN_TEST is refused", "bad info" in err, err)
        p3b = SQL3B.replace("create extension if not exists pg_net;", "")
        psql(p3b); psql(p3b)
        verify = psql(p3b)[0].splitlines()[-1]
        check("phase 3b applies on top of phase 3, re-runs cleanly, and its own verify select is all true", set(verify.split("|")) == {"t"}, verify)
        psql("delete from public.onn_flag_log; delete from public.flags; delete from public.red_emails;")
        o_t = obj(); put(o_t)
        out, err = flag(o_t, label="ONN_TEST", score=1.0, fg="selftest")
        check("a test flag is accepted and is YELLOW", '"verdict": "alert"' in out, out + err)
        row = val("select app||'|'||is_nudity||'|'||grade||'|'||risk||'|'||verdict||'|'||window_title from public.flags")
        check("it is clearly labelled: not nudity, grade Test, risk low, verdict alert", row == "Onn TV|false|Test|low|alert|selftest", row)
        check("its reason says it is a synthetic self-test", val("select reason like 'onn-test:%synthetic%' from public.flags") == "t")
        check("it sends NO email", val("select count(*) from public.red_emails") == "0")
        o_r = obj(1); put(o_r)
        out, _ = flag(o_r, label="FEMALE_BREAST_EXPOSED", score=0.9)
        check("a test flag does not use up the 10-minute RED window: the next REAL detection is still RED and emails", '"verdict": "flagged"' in out and val("select count(*) from public.red_emails") == "1", out)
        o_r2 = obj(2); put(o_r2)
        out, _ = flag(o_r2, label="ONN_TEST", score=1.0, fg="selftest")
        check("and a test flag after a real one is still yellow and still silent", '"verdict": "alert"' in out and val("select count(*) from public.red_emails") == "1")
        check("the real labels and the 0.80 floor are unchanged", "bad info" in flag(obj(3), label="MALE_GENITALIA_EXPOSED")[1] and "bad info" in flag(obj(3), label="ONN_TEST", score=0.5)[1])
        out, err = flag(o_t, label="ONN_TEST", score=1.0, fg="selftest")
        check("the same test frame again is a duplicate", '"duplicate": true' in out, out + err)
        o_bad = obj(4)
        check("a test flag still needs its frame to exist", "frame not uploaded" in flag(o_bad, label="ONN_TEST", score=1.0)[1])
        out, err = psql("set role anon; select public.eg_onn_flag('" + "00" * 32 + "', '{}'::jsonb);", err_ok=True)
        check("anon can still only call it with a valid token", "unauthorized" in err, err)
    finally:
        subprocess.run(dock + ["rm", "-f", name], capture_output=True)

if fails:
    print("\nFAILED:", *fails, sep="\n  ")
    sys.exit(1)
print("\nALL OK")
