#!/usr/bin/env python3
"""Server side of 'deny -> app actually gone' (supabase/mdm_requeue_removal.sql) in a real throwaway
Postgres, on top of the real mdm_app_events + mdm_heartbeat + mdm_approvals SQL. Synthetic app names.
Run: python3 tests/test_mdm_requeue.py   (needs docker + postgres:16-alpine; the Mac has none:
EG_DOCKER="ssh g11 docker" EG_REQUIRE_SQL=1 python3 tests/test_mdm_requeue.py)"""
import hashlib, json, os, re, shlex, shutil, subprocess, sys, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

DAD = "0e02aa87-1cd5-4bb6-a263-f51d4e2642b6"
JADA = "1818ac68-7ecf-4e39-a758-8526e496247d"

print("A. the file")
old_src = (ROOT / "supabase" / "mdm_approvals.sql").read_text()
new_src = (ROOT / "supabase" / "mdm_requeue_removal.sql").read_text()
a = old_src.index("create or replace function public.eg_mdm_sync(p_token text) returns jsonb")
b = old_src.index("grant execute on function public.eg_mdm_sync(text) to anon;")
old_lines = [l for l in old_src[a:b].splitlines() if l.strip()]
check("every line of the committed eg_mdm_sync survives unchanged in the new file", all(l in new_src.splitlines() for l in old_lines),
      str([l for l in old_lines if l not in new_src.splitlines()][:3]))
check("pure ASCII (pasted into a browser)", all(ord(c) < 128 for c in new_src))
check("redefines ONLY eg_mdm_sync", re.findall(r"create or replace function (public\.\w+)", new_src) == ["public.eg_mdm_sync"])
check("no new table, no change to other objects", not re.search(r"create table|alter table|drop ", new_src))

D = shlex.split(os.environ.get("EG_DOCKER", "docker"))
have = shutil.which(D[0]) and subprocess.run(D + ["image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1": check("SQL tests could run (docker + postgres:16-alpine)", False)
    else: print("  [skip] docker/postgres:16-alpine unavailable")
    print()
    if fails: print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
    print("file checks passed; SQL part skipped"); sys.exit(0)

print("B. behaviour in Postgres")
name = "egreq-" + uuid.uuid4().hex[:8]
subprocess.run(D + ["run", "-d", "--rm", "--name", name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "postgres:16-alpine"], check=True, capture_output=True)
try:
    for _ in range(60):
        if subprocess.run(D + ["exec", name, "pg_isready", "-U", "postgres"], capture_output=True).returncode == 0: break
        time.sleep(1)
    time.sleep(2)
    def psql(sql, err_ok=False):
        r = subprocess.run(D + ["exec", "-i", name, "psql", "-U", "postgres", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1"],
                           input=sql, capture_output=True, text=True)
        if r.returncode != 0 and not err_ok: raise RuntimeError(r.stderr[-800:])
        return r.stdout.strip(), r.stderr
    val = lambda sql: psql(sql)[0]
    psql("""
create role anon nologin; create role authenticated nologin; create role service_role nologin;
create schema extensions; create extension pgcrypto with schema extensions;
create schema vault; create table vault.s(name text, decrypted_secret text); insert into vault.s values ('resend_api_key','re_test');
create view vault.decrypted_secrets as select * from vault.s;
create schema net; create table net.sent(id serial, body jsonb);
create function net.http_post(url text, headers jsonb, body jsonb) returns bigint language sql
  as $$ insert into net.sent(body) values (body) returning id::bigint $$;
create schema cron; create table cron.job(jobid serial primary key, jobname text, schedule text, command text);
create function cron.schedule(n text, s text, c text) returns bigint language sql
  as $$ insert into cron.job(jobname,schedule,command) values (n,s,c) returning jobid::bigint $$;
create function cron.unschedule(n text) returns boolean language sql as $$ delete from cron.job where jobname = n returning true $$;
create schema auth; create table auth.users(id uuid primary key, email text);
create function auth.uid() returns uuid language sql
  as $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
grant usage on schema public, extensions, auth to anon, authenticated;
""" + f"insert into auth.users values ('{DAD}','dad@example.test'),('{JADA}','jada@example.test');")
    def apply(rel):
        s = (ROOT / rel).read_text().replace("create extension if not exists pg_net;", "")
        psql(s.replace("dad@CHANGE-ME.invalid", "dad@example.test"))
    for f in ("mdm_app_events", "mdm_heartbeat", "mdm_approvals", "mdm_requeue_removal"):
        apply(f"supabase/{f}.sql")
    tok = "cd" * 32
    psql(f"insert into public.mdm_auth(token_sha256, note) values ('{hashlib.sha256(tok.encode()).hexdigest()}','t');")
    clock = [0]
    def snap(apps, det=None):
        clock[0] += 1
        d = det or f"2026-10-07T12:{clock[0]:02d}:00Z"
        s = {"device": "test", "detected_at": d, "supervised": True, "apps": [{"bundle_id": b, "name": n, "version": "1"} for b, n in apps]}
        return psql(f"select public.eg_mdm_snapshot('{tok}', $j${json.dumps(s)}$j$::jsonb);", err_ok=True)
    def as_user(uid, sql):
        return psql(f"begin; set local role authenticated; select set_config('request.jwt.claim.sub','{uid}',true); {sql}; commit;", err_ok=True)
    def sync():
        out = val(f"select public.eg_mdm_sync('{tok}');")
        return json.loads(out)
    BASE = [("com.base.one", "Base One")]
    snap(BASE)                                                   # baseline
    snap(BASE + [("com.dl.app", "Downloaded App")])             # new -> pending
    as_user(DAD, "select public.eg_mdm_decide('com.dl.app','deny')")
    n_actions = lambda where="true": int(val(f"select count(*) from public.mdm_actions where bundle_id='com.dl.app' and {where}"))

    check("deny of an installed app queues a removal at once (existing behaviour)", n_actions("status='queued'") == 1)
    r = sync()
    check("sync hands the removal to the G11 (marks it sent) and lists the app as blocked",
          [x["bundle_id"] for x in r["actions"]] == ["com.dl.app"] and r["blocked"] == ["com.dl.app"], str(r))
    check("a second sync does not duplicate an in-flight removal", sync()["actions"] == [])

    psql("select public.eg_mdm_action_result('%s', (select id from public.mdm_actions order by id desc limit 1), true, 'Acknowledged');" % tok)
    check("the phone's ack still closes the action as done (unchanged)", n_actions("status='done'") == 1)
    check("within the first hour the server does NOT ask again (give the next snapshot time to show it gone)", sync()["actions"] == [])

    psql("update public.mdm_actions set updated_at = now() - interval '2 hours' where bundle_id='com.dl.app';")
    r = sync()
    check("an hour later the app is STILL shown installed -> a fresh removal is queued and handed out",
          [x["bundle_id"] for x in r["actions"]] == ["com.dl.app"] and n_actions() == 2, str(r))

    psql(f"select public.eg_mdm_action_result('{tok}', (select id from public.mdm_actions order by id desc limit 1), true, 'Acknowledged');")
    snap(BASE)                                                   # the app is gone from the phone
    psql("update public.mdm_actions set updated_at = now() - interval '3 hours' where bundle_id='com.dl.app';")
    check("once a snapshot shows the app gone, nothing more is queued", sync()["actions"] == [] and n_actions() == 2)

    snap(BASE + [("com.dl.app", "Downloaded App")])             # it comes back (reinstalled)
    check("...and it was recorded present again", val("select present from public.mdm_apps where bundle_id='com.dl.app'") == "t")
    r = sync()
    check("a denied app that REAPPEARS later is removed again with no new partner action",
          [x["bundle_id"] for x in r["actions"]] == ["com.dl.app"] and n_actions() == 3, str(r))

    print("limits")
    psql("update public.mdm_actions set status='failed', updated_at = now() where bundle_id='com.dl.app' and status='sent';")
    psql("update public.mdm_actions set updated_at = now() - interval '2 hours' where bundle_id='com.dl.app' and status<>'failed';")
    psql("update public.mdm_actions set updated_at = now() - interval '90 minutes' where bundle_id='com.dl.app' and status='failed';")
    check("a FAILED removal in the last 24 h is not retried (its failure email already went out)", sync()["actions"] == [] and n_actions() == 3)
    psql("update public.mdm_actions set updated_at = now() - interval '26 hours' where bundle_id='com.dl.app';")
    r = sync()
    check("after 24 h the failure no longer blocks a new attempt", [x["bundle_id"] for x in r["actions"]] == ["com.dl.app"], str(r))

    psql("delete from public.mdm_actions where bundle_id='com.dl.app';")
    psql("insert into public.mdm_actions (bundle_id, action, status, created_at, updated_at) "
         "select 'com.dl.app','remove','done', now() - interval '3 hours', now() - interval '2 hours' from generate_series(1,8);")
    check("at most 8 removals per app per 24 h", sync()["actions"] == [] and n_actions() == 8)

    print("what must NOT change")
    psql("delete from public.mdm_actions where bundle_id='com.dl.app';")
    as_user(JADA, "select public.eg_mdm_decide('com.dl.app','approve')")
    check("an APPROVED app is never queued for removal", sync()["actions"] == [] and n_actions() == 0)
    as_user(JADA, "select public.eg_mdm_decide('com.dl.app','revoke')")
    check("a pending (undecided) app is never queued for removal", sync()["actions"] == [] and n_actions() == 0)
    check("the blocked list still contains only denied apps", sync()["blocked"] == [])
    err = psql("select public.eg_mdm_sync('" + "ee" * 32 + "');", err_ok=True)[1]
    check("an unregistered token is still rejected (401)", "unauthorized" in err, err[-100:])
    check("permissions: anon can call with a token; authenticated and service_role cannot",
          val("select has_function_privilege('anon','public.eg_mdm_sync(text)','execute'), "
              "has_function_privilege('authenticated','public.eg_mdm_sync(text)','execute'), "
              "has_function_privilege('service_role','public.eg_mdm_sync(text)','execute')") == "t|f|f")
    psql(new_src)
    check("re-running the file is harmless", True)
finally:
    subprocess.run(D + ["rm", "-f", name], capture_output=True)

print()
if fails:
    print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
print("all MDM requeue tests passed")
