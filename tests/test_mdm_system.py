#!/usr/bin/env python3
"""Tests for the G11 MDM system: webhook (g11/mdm/hook.py), poller heartbeat
(g11/mdm/poll.py), reporter --heartbeat (g11/eg_report.py) and the server SQL
(supabase/mdm_app_events.sql + supabase/mdm_heartbeat.sql, run in a real
throwaway Postgres container with Supabase's vault/pg_net/cron stubbed).
Synthetic data only. Run: python3 tests/test_mdm_system.py
Part B needs docker + postgres:16-alpine; without them it SKIPs, unless
EG_REQUIRE_SQL=1 (then a skip is a failure)."""
import base64, hashlib, importlib.util, json, os, plistlib, re, shutil, stat
import subprocess, sys, tempfile, threading, time, uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

def load_module(path, name, env):
    for k, v in env.items(): os.environ[k] = v
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

def plist_ack(apps):
    pl = {"Status": "Acknowledged",
          "InstalledApplicationList": [{"Identifier": b, "Name": n, "ShortVersion": "1"} for b, n in apps]}
    return {"udid": "UDID-TEST-1", "raw_payload": base64.b64encode(plistlib.dumps(pl)).decode()}

def events(state):
    out = Path(state) / "outbox"
    return [json.load(open(p)) for p in sorted(out.glob("*.json"))] if out.is_dir() else []

# ============================ Part A: python ============================
print("A1. hook.py behaviour")
def hook_flow(hook_path, tag):
    st = tempfile.mkdtemp()
    h = load_module(hook_path, "hook_" + tag, {"HOOK_STATE": st})
    h.handle_checkin({"udid": "UDID-TEST-1", "message_type": "Authenticate"})
    h.handle_ack(plist_ack([("com.a", "A"), ("com.b", "B")]))
    base = len(events(st))
    h.handle_ack(plist_ack([("com.a", "A"), ("com.b", "B"), ("com.c", "C")]))
    inst = [e for e in events(st) if e["type"] == "app_installed"]
    h.handle_ack(plist_ack([("com.a", "A"), ("com.c", "C")]))
    rem = [e for e in events(st) if e["type"] == "app_removed"]
    return h, st, base, inst, rem

h, st, base, inst, rem = hook_flow(str(ROOT / "g11/mdm/hook.py"), "new")
check("first app list is a silent baseline (no events)", base == 0, f"{base} events")
check("a new app emits one app_installed with bundle_id",
      len(inst) == 1 and inst[0]["bundle_id"] == "com.c" and inst[0]["window_start"], str(inst))
check("a removed app emits app_removed", len(rem) == 1 and rem[0]["bundle_id"] == "com.b", str(rem))

# profile removal -> re-enrol: the server debounce must be re-armed
h.handle_checkin({"udid": "UDID-TEST-1", "message_type": "CheckOut"})
dev = json.load(open(Path(st) / "devices.json"))["UDID-TEST-1"]
check("CheckOut emits device_unreachable",
      sum(e["type"] == "device_unreachable" for e in events(st)) == 1)
check("CheckOut marks device unreachable_reported (so re-enrol can re-arm)",
      dev["unreachable_reported"] is True and dev["enrolled"] is False)
h.handle_checkin({"udid": "UDID-TEST-1", "message_type": "TokenUpdate"})
h.handle_ack(plist_ack([("com.a", "A"), ("com.c", "C"), ("com.d", "D")]))   # D installed while profile was off
evs = events(st)
check("first ack after re-enrol emits device_reachable_again exactly once",
      sum(e["type"] == "device_reachable_again" for e in evs) == 1)
check("app installed while the profile was removed is still caught (diff vs old list)",
      any(e["type"] == "app_installed" and e["bundle_id"] == "com.d" for e in evs))
h.handle_ack(plist_ack([("com.a", "A"), ("com.c", "C"), ("com.d", "D")]))
check("no repeat reachable_again on later acks",
      sum(e["type"] == "device_reachable_again" for e in events(st)) == 1)

# prove the bug existed in the unchanged live code (commit 1 imports it verbatim)
orig = subprocess.run(["git", "-C", str(ROOT), "log", "--format=%H", "--diff-filter=A", "--", "g11/mdm/hook.py"],
                      capture_output=True, text=True).stdout.split()
if orig:
    src = subprocess.run(["git", "-C", str(ROOT), "show", f"{orig[-1]}:g11/mdm/hook.py"],
                         capture_output=True, text=True).stdout
    p = Path(tempfile.mkdtemp()) / "hook_orig.py"; p.write_text(src)
    ho, sto, *_ = hook_flow(str(p), "orig")
    ho.handle_checkin({"udid": "UDID-TEST-1", "message_type": "CheckOut"})
    ho.handle_checkin({"udid": "UDID-TEST-1", "message_type": "TokenUpdate"})
    ho.handle_ack(plist_ack([("com.a", "A"), ("com.c", "C")]))
    check("REGRESSION PROOF: the original hook never re-armed (bug reproduced)",
          sum(e["type"] == "device_reachable_again" for e in events(sto)) == 0)
else:
    print("  [skip] original-hook regression proof (no git history)")

print("A2. poll.py heartbeat payload")
rec = Path(tempfile.mkdtemp()) / "args.txt"
sender = Path(tempfile.mkdtemp()) / "fake-sender.sh"
sender.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > {rec}\nexit 0\n'); sender.chmod(0o755)
pst = tempfile.mkdtemp()
pl = load_module(str(ROOT / "g11/mdm/poll.py"), "poll_t",
                 {"MDM_STATE": pst, "MDM_SENDER": str(sender), "MDM_LOG": str(Path(pst) / "log")})
def put_devices(d): json.dump(d, open(Path(pst) / "devices.json", "w"))
now = datetime.now(timezone.utc)
put_devices({})
info = pl.heartbeat()
check("no devices -> enrolled 0, no app age", info["enrolled"] == 0 and info["stalest_apps_age_s"] is None, str(info))
check("heartbeat invokes sender --heartbeat with that JSON",
      rec.read_text().split("\n")[0] == "--heartbeat" and json.loads(rec.read_text().split("\n")[1]) == info)
put_devices({"u1": {"enrolled": True, "last_apps_at": (now - timedelta(hours=4)).isoformat()},
             "u2": {"enrolled": True},
             "u3": {"enrolled": False, "last_apps_at": (now - timedelta(days=9)).isoformat()}})
info = pl.heartbeat()
check("enrolled counts only enrolled devices (2), unlisted=1", info["enrolled"] == 2 and info["unlisted"] == 1, str(info))
check("stalest age ~4h (ignores checked-out device)", 14300 < info["stalest_apps_age_s"] < 14500, str(info))
check("heartbeat carries counts only (no app names / bundle ids / udids)",
      set(info) == {"enrolled", "unlisted", "stalest_apps_age_s", "outbox_pending"})
pl.SENDER = str(Path(pst) / "missing.sh")
try:
    pl.heartbeat(); ok = True
except Exception as e:
    ok = False
check("missing sender does not crash the poller", ok)

print("A3. eg_report.py --heartbeat")
class H:
    seen = []; code = 200

tmp = tempfile.mkdtemp(); conf = os.path.join(tmp, "c.json"); q = os.path.join(tmp, "q")
json.dump({"supabase_url": "https://x.invalid", "anon_key": "anon", "device_token": "t" * 64}, open(conf, "w"))
os.chmod(conf, 0o600)
rep = load_module(str(ROOT / "g11/eg_report.py"), "rep_t",
                  {"EG_REPORT_CONF": conf, "EG_REPORT_QUEUE": q, "EG_REPORT_TIMEOUT": "2"})
def fake_open(req, timeout=0):
    body = json.loads(req.data)
    H.seen.append((req.full_url, body))
    if H.code != 200:
        raise rep.urllib.error.HTTPError(req.full_url, H.code, "x", {}, None)
    class R:
        def __enter__(s): return s
        def __exit__(s, *a): pass
    return R()
rep.urllib.request.urlopen = fake_open
H.seen.clear(); H.code = 200
rc = rep.main(["eg-report.sh", "--heartbeat", '{"enrolled":1}'])
check("heartbeat ok -> exit 0", rc == 0)
check("posts to /rpc/eg_mdm_heartbeat with token + info",
      H.seen and H.seen[0][0].endswith("/rest/v1/rpc/eg_mdm_heartbeat")
      and H.seen[0][1] == {"p_token": "t" * 64, "p_info": {"enrolled": 1}})
H.code = 401; check("401 -> exit 3", rep.main(["x", "--heartbeat", '{"enrolled":1}']) == 3)
H.code = 503; check("503 -> exit 4 (transient)", rep.main(["x", "--heartbeat", '{"enrolled":1}']) == 4)
check("heartbeat is never queued", not os.path.isdir(q) or not rep.queued())
check("bad JSON -> exit 2", rep.main(["x", "--heartbeat", "not json"]) == 2)
os.chmod(conf, 0o644)
check("wrong config mode -> exit 3", rep.main(["x", "--heartbeat", '{"enrolled":1}']) == 3)
os.chmod(conf, 0o600)

# ============================ Part B: real Postgres ============================
print("B. SQL behaviour in a throwaway Postgres")
have = shutil.which("docker") and subprocess.run(
    ["docker", "image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
if not have:
    msg = "docker/postgres:16-alpine unavailable"
    if os.environ.get("EG_REQUIRE_SQL") == "1":
        check("SQL tests could run", False, msg)
    else:
        print(f"  [skip] {msg}")
else:
    name = "egtest-" + uuid.uuid4().hex[:8]
    subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
                    "postgres:16-alpine"], check=True, capture_output=True)
    try:
        for _ in range(60):
            if subprocess.run(["docker", "exec", name, "pg_isready", "-U", "postgres"],
                              capture_output=True).returncode == 0: break
            time.sleep(1)
        time.sleep(2)
        def psql(sql, expect_error=False):
            r = subprocess.run(["docker", "exec", "-i", name, "psql", "-U", "postgres", "-X", "-q", "-t", "-A",
                                "-v", "ON_ERROR_STOP=1"], input=sql, capture_output=True, text=True)
            if r.returncode != 0 and not expect_error:
                raise RuntimeError(r.stderr[-600:])
            return (r.stdout.strip(), r.stderr)
        def val(sql): return psql(sql)[0]
        stubs = """
create role anon nologin; create role authenticated nologin; create role service_role nologin;
create schema extensions; create extension pgcrypto with schema extensions;
create schema vault; create table vault.s(name text, decrypted_secret text);
insert into vault.s values ('resend_api_key','re_test');
create view vault.decrypted_secrets as select * from vault.s;
create schema net; create table net.sent(id serial, body jsonb);
create function net.http_post(url text, headers jsonb, body jsonb) returns bigint language sql
  as $$ insert into net.sent(body) values (body) returning id::bigint $$;
create schema cron; create table cron.job(jobid serial primary key, jobname text, schedule text, command text);
create function cron.schedule(n text, s text, c text) returns bigint language sql
  as $$ insert into cron.job(jobname,schedule,command) values (n,s,c) returning jobid::bigint $$;
create function cron.unschedule(n text) returns boolean language sql
  as $$ delete from cron.job where jobname = n returning true $$;
create schema auth; create function auth.uid() returns uuid language sql as $$ select null::uuid $$;
grant usage on schema public, extensions to anon, authenticated;
"""
        psql(stubs)
        def run_file(rel):
            s = (ROOT / rel).read_text()
            s = s.replace("create extension if not exists pg_net;", "")
            s = s.replace("dad@CHANGE-ME.invalid", "dad@example.test")   # what Dad edits
            psql(s)
        run_file("supabase/mdm_app_events.sql")
        run_file("supabase/mdm_heartbeat.sql")
        run_file("supabase/mdm_heartbeat.sql")   # idempotent re-run
        check("heartbeat SQL re-runs cleanly (idempotent) with exactly one cron job",
              val("select count(*) from cron.job where jobname='eyeguard-mdm-status'") == "1")
        tok = "ab" * 32
        psql(f"insert into public.mdm_auth(token_sha256, note) values ('{hashlib.sha256(tok.encode()).hexdigest()}','t');")
        def sent(): return int(val("select count(*) from net.sent"))
        def subjects(): return val("select string_agg(body->>'subject', ' | ' order by id) from net.sent")
        def hb(info, token=tok):
            return psql(f"select public.eg_mdm_heartbeat('{token}', '{json.dumps(info)}'::jsonb);", expect_error=True)
        def chk(): psql("select public.eg_check_mdm_status();")
        def age(col, interval): psql(f"update public.mdm_status set {col} = now() - interval '{interval}' where id=1;")

        # auth + validation
        r = hb({"enrolled": 1}, "ff" * 32)
        check("heartbeat with an unregistered token -> 401", "unauthorized" in r[1])
        r = hb({"unlisted": 0})
        check("heartbeat without 'enrolled' is rejected (cannot dodge the blind check)", "bad info" in r[1])
        check("negative / absurd values rejected", "bad info" in hb({"enrolled": -1})[1] and "bad info" in hb({"enrolled": 99999})[1])
        check("non-object info rejected",
              "JSON object" in psql(f"select public.eg_mdm_heartbeat('{tok}', '[1]'::jsonb);", expect_error=True)[1])

        # first-run grace
        chk(); check("first run: seeded grace -> no email", sent() == 0)
        check("grace seed is in the future",
              val("select last_heartbeat_at > now() from public.mdm_status") == "t")

        # healthy
        r = hb({"enrolled": 1, "unlisted": 0, "stalest_apps_age_s": 600, "outbox_pending": 0})
        check("valid heartbeat accepted", r[0].find("ok") >= 0, r[1])
        chk(); check("healthy -> no email", sent() == 0)
        check("heartbeat stamps the SERVER clock",
              val("select now() - last_heartbeat_at < interval '5 seconds' from public.mdm_status") == "t")

        # 1. gone quiet
        age("last_heartbeat_at", "44 minutes"); chk()
        check("44 min since beat -> no email yet", sent() == 0)
        age("last_heartbeat_at", "50 minutes"); chk()
        check("50 min since beat -> exactly one STOPPED email", sent() == 1 and "STOPPED" in subjects(), subjects() or "")
        chk(); chk(); check("repeated checks do not re-email", sent() == 1)
        check("the silence is recorded as an OPEN incident in the permanent log", val("select count(*) from public.mdm_incidents where kind='monitor_silent' and ended_at is null") == "1" and val("select count(*) from public.mdm_incidents") == "1" ,
              val("select * from public.mdm_incidents"))
        age("last_heartbeat_at", "72 minutes")
        hb({"enrolled": 1, "unlisted": 0, "stalest_apps_age_s": 600, "outbox_pending": 0})
        check("a heartbeat re-arms the quiet alert", val("select quiet_alerted from public.mdm_status") == "f")
        check("...and sends ONE all-clear that says how long it was silent",
              sent() == 2 and "back online" in subjects().split(" | ")[-1] and "silent for about 01:" in val("select body->>'html' from net.sent order by id desc limit 1"),
              subjects().split(" | ")[-1])
        check("recovery CLOSES the incident but never deletes it", val("select count(*) from public.mdm_incidents where kind='monitor_silent' and ended_at is null") == "0" and val("select count(*) from public.mdm_incidents where kind='monitor_silent' and ended_at is not null") == "1")
        check("the all-clear does not claim nothing happened (gap is permanent, blind spots admitted)",
              "not proof nothing happened" in val("select body->>'html' from net.sent order by id desc limit 1"))
        n = sent(); hb({"enrolled": 1, "unlisted": 0, "stalest_apps_age_s": 600, "outbox_pending": 0})
        check("a normal heartbeat afterwards sends no further all-clear", sent() == n)
        age("last_heartbeat_at", "60 minutes"); chk()
        check("a second outage emails again", sent() == n + 1)
        hb({"enrolled": 1, "unlisted": 0, "stalest_apps_age_s": 600, "outbox_pending": 0})
        check("...and is closed out again", sent() == n + 2 and "back online" in subjects().split(" | ")[-1])

        # 2. blind (no phone enrolled)
        n0 = sent(); hb({"enrolled": 0, "unlisted": 0, "outbox_pending": 0}); chk()
        check("no phone enrolled: no email in the first hour", sent() == n0)
        age("blind_since", "3 hours"); chk()
        check("no phone enrolled for 3h -> one 'no iPhone is being watched' email",
              sent() == n0 + 1 and "no iPhone" in subjects().split(" | ")[-1])
        chk(); check("not repeated", sent() == n0 + 1)
        hb({"enrolled": 1, "unlisted": 1, "outbox_pending": 0})
        check("enrolled but never listed also counts as blind (timer kept)",
              val("select blind_since is not null from public.mdm_status") == "t")
        check("a 'no phone watched' incident is open while the alert stands", val("select count(*) from public.mdm_incidents where kind='no_phone_watched' and ended_at is null") == "1")
        n = sent(); hb({"enrolled": 1, "unlisted": 0, "stalest_apps_age_s": 60, "outbox_pending": 0})
        check("...and closed (kept) when a phone is watched again", val("select count(*) from public.mdm_incidents where kind='no_phone_watched' and ended_at is null") == "0" and val("select count(*) from public.mdm_incidents where kind='no_phone_watched' and ended_at is not null") == "1")
        check("phone watched again -> blind state and alert re-armed",
              val("select blind_since is null and not blind_alerted from public.mdm_status") == "t")
        check("...with ONE all-clear ('being watched again')", sent() == n + 1 and "being watched again" in subjects().split(" | ")[-1], subjects().split(" | ")[-1])
        n = sent(); hb({"enrolled": 0, "unlisted": 0, "outbox_pending": 0}); hb({"enrolled": 1, "unlisted": 0, "stalest_apps_age_s": 60, "outbox_pending": 0})
        check("no all-clear when the 'no iPhone' alert was never sent (short blip, nothing to close)", sent() == n)

        # 3. stale app list
        n1 = sent(); hb({"enrolled": 1, "unlisted": 0, "stalest_apps_age_s": 11000, "outbox_pending": 0}); chk()
        check("app list 3h+ old -> one 'stale' email", sent() == n1 + 1 and "stale" in subjects().split(" | ")[-1])
        chk(); check("stale email not repeated", sent() == n1 + 1)
        check("a stale app list opens an incident", val("select count(*) from public.mdm_incidents where kind='app_list_stale' and ended_at is null") == "1")
        n = sent(); hb({"enrolled": 1, "unlisted": 0, "stalest_apps_age_s": 100, "outbox_pending": 0})
        check("...closed on recovery", val("select count(*) from public.mdm_incidents where kind='app_list_stale' and ended_at is null") == "0" and val("select count(*) from public.mdm_incidents where kind='app_list_stale' and ended_at is not null") == "1")
        check("fresh app list again -> ONE all-clear closing the 'stale' alert", sent() == n + 1 and "fresh again" in subjects().split(" | ")[-1], subjects().split(" | ")[-1])
        psql("update public.mdm_status set unreachable_alerted = true where id=1;")
        n2 = sent(); hb({"enrolled": 1, "unlisted": 0, "stalest_apps_age_s": 12000, "outbox_pending": 0}); chk()
        check("no double mail when the poller's own unreachable alert is active", sent() == n2)
        psql("update public.mdm_status set unreachable_alerted = false where id=1;")

        # privileges
        def as_anon(sql): return psql("begin; set local role anon; " + sql + " rollback;", expect_error=True)
        check("anon CAN call the heartbeat RPC", "ok" in as_anon(f"select public.eg_mdm_heartbeat('{tok}', '{{\"enrolled\":1}}'::jsonb);")[0])
        check("anon cannot run the check", "permission denied" in as_anon("select public.eg_check_mdm_status();")[1])
        check("anon cannot read mdm_status", "permission denied" in as_anon("select * from public.mdm_status;")[1])
        check("anon cannot read mdm_events or mdm_auth",
              "permission denied" in as_anon("select * from public.mdm_events;")[1]
              and "permission denied" in as_anon("select * from public.mdm_auth;")[1])
        check("anon cannot send email through the sender",
              "permission denied" in as_anon("select public.eg_send_email_mdm('x','y');")[1])
        check("authenticated cannot run the check either",
              "permission denied" in psql("begin; set local role authenticated; select public.eg_check_mdm_status(); rollback;", expect_error=True)[1])

        # existing PR-113 behaviour untouched; debounce re-arm contract the hook fix relies on
        def ev(t, **kw):
            e = {"type": t, "detected_at": (datetime.now(timezone.utc) + timedelta(seconds=len(kw) + time.time_ns() % 1000)).isoformat()}
            e.update(kw)
            return psql(f"select public.eg_report_mdm_event('{tok}', '{json.dumps(e)}'::jsonb);", expect_error=True)
        psql("update public.mdm_status set unreachable_alerted=false where id=1;")
        n = sent(); ev("device_reachable_again", device="d")
        check("reachable_again with no 'unreachable' alert outstanding sends nothing", sent() == n)
        n = sent(); ev("app_installed", bundle_id="com.x", name="X")
        check("PR #113 app_installed still emails", sent() == n + 1)
        n = sent(); ev("device_unreachable", device="d"); ev("device_unreachable", device="d", name="again")
        check("device_unreachable emails once per outage", sent() == n + 1)
        ev("device_reachable_again", device="d")
        check("phone answers again -> ONE all-clear closing the unreachable email",
              sent() == n + 2 and "reachable again" in subjects().split(" | ")[-1], subjects().split(" | ")[-1])
        ev("device_unreachable", device="d", name="third")
        check("device_reachable_again re-arms; the next outage emails again", sent() == n + 3)
        ev("device_reachable_again", device="d")          # clear whatever is armed
        fixed_u = {"type": "device_unreachable", "detected_at": "2026-02-01T00:00:00Z", "device": "d"}
        fixed_r = {"type": "device_reachable_again", "detected_at": "2026-02-01T03:00:00Z", "device": "d"}
        psql("update public.mdm_status set unreachable_alerted=false where id=1;")
        psql(f"select public.eg_report_mdm_event('{tok}', '{json.dumps(fixed_u)}'::jsonb);")
        n = sent()
        for _ in range(2): psql(f"select public.eg_report_mdm_event('{tok}', '{json.dumps(fixed_r)}'::jsonb);")
        check("a RETRIED reachable_again delivers exactly ONE all-clear (BEFORE trigger + dedupe)", sent() == n + 1, f"{sent() - n} sent")
        check("an unreachable phone is logged as a closed incident with its true start and end",
              val("select ended_at - started_at from public.mdm_incidents where kind='phone_unreachable' order by id desc limit 1") == "03:00:00"
              and val("select count(*) from public.mdm_incidents where kind='phone_unreachable' and ended_at is null") == "0")
        check("the all-clear reports how long the phone was unreachable", "03:00:00" in val("select body->>'html' from net.sent order by id desc limit 1"))
        dd = {"type": "app_installed", "detected_at": "2026-01-01T00:00:00Z", "bundle_id": "com.dup2"}
        n = sent()
        for _ in range(2): psql(f"select public.eg_report_mdm_event('{tok}', '{json.dumps(dd)}'::jsonb);")
        check("identical event twice -> one email (dedupe intact)", sent() == n + 1)
        check("event log stays append-only (authenticated cannot update/delete)",
              "permission denied" in psql("begin; set local role authenticated; update public.mdm_events set device='x'; rollback;", expect_error=True)[1]
              and "permission denied" in psql("begin; set local role authenticated; delete from public.mdm_events; rollback;", expect_error=True)[1])
        psql("grant usage on schema public to anon, authenticated;")
        def as_role(role, sql): return psql(f"begin; set local role {role}; {sql}; rollback;", expect_error=True)
        check("anon cannot read the incident log", "permission denied" in as_role("anon", "select * from public.mdm_incidents")[1])
        check("a logged-in user cannot edit or delete incidents",
              "permission denied" in as_role("authenticated", "update public.mdm_incidents set ended_at = now()")[1]
              and "permission denied" in as_role("authenticated", "delete from public.mdm_incidents")[1])
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)

print()
if fails:
    print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
print("all MDM system tests passed")
