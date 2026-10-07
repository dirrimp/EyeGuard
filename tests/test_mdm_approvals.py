#!/usr/bin/env python3
"""Server-side tests for the MDM official-list / approve-deny system
(supabase/mdm_approvals.sql) run in a real throwaway Postgres container with
Supabase's vault/pg_net/cron/auth stubbed. Synthetic app names only.
Run: python3 tests/test_mdm_approvals.py
Needs docker + postgres:16-alpine; otherwise SKIPs unless EG_REQUIRE_SQL=1."""
import hashlib, json, os, shutil, subprocess, sys, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

DAD   = "0e02aa87-1cd5-4bb6-a263-f51d4e2642b6"
JADA  = "1818ac68-7ecf-4e39-a758-8526e496247d"
JONAH = "99999999-9999-9999-9999-999999999999"     # the monitored user: NOT a partner

have = shutil.which("docker") and subprocess.run(
    ["docker", "image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1":
        check("SQL tests could run (docker + postgres:16-alpine)", False)
    else:
        print("  [skip] docker/postgres:16-alpine unavailable")
    sys.exit(1 if fails else 0)

name = "egappr-" + uuid.uuid4().hex[:8]
subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
                "postgres:16-alpine"], check=True, capture_output=True)
try:
    for _ in range(60):
        if subprocess.run(["docker", "exec", name, "pg_isready", "-U", "postgres"], capture_output=True).returncode == 0: break
        time.sleep(1)
    time.sleep(2)
    def psql(sql, err_ok=False):
        r = subprocess.run(["docker", "exec", "-i", name, "psql", "-U", "postgres", "-X", "-q", "-t", "-A",
                            "-v", "ON_ERROR_STOP=1"], input=sql, capture_output=True, text=True)
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
""" + f"insert into auth.users values ('{DAD}','dad@example.test'),('{JADA}','jada@example.test'),('{JONAH}','jonah@example.test');")
    def apply(rel):
        s = (ROOT / rel).read_text().replace("create extension if not exists pg_net;", "")
        psql(s.replace("dad@CHANGE-ME.invalid", "dad@example.test"))
    for f in ("mdm_app_events", "mdm_heartbeat", "mdm_approvals", "mdm_approvals"):
        apply(f"supabase/{f}.sql")
    check("approvals SQL applies cleanly on top of #113 + #114 and re-runs (one cron job)",
          val("select count(*) from cron.job where jobname='eyeguard-mdm-apps'") == "1")

    tok = "cd" * 32
    psql(f"insert into public.mdm_auth(token_sha256, note) values ('{hashlib.sha256(tok.encode()).hexdigest()}','t');")
    clock = [0]
    def snap(apps, supervised=None, det=None, token=tok):
        clock[0] += 1
        d = det or f"2026-10-07T12:{clock[0]:02d}:00Z"
        s = {"device": "test", "detected_at": d, "apps": [{"bundle_id": b, "name": n, "version": "1"} for b, n in apps]}
        if supervised is not None: s["supervised"] = supervised
        return psql(f"select public.eg_mdm_snapshot('{token}', $j${json.dumps(s)}$j$::jsonb);", err_ok=True)
    sent = lambda: int(val("select count(*) from net.sent"))
    last_subject = lambda: val("select body->>'subject' from net.sent order by id desc limit 1")
    last_html = lambda: val("select body->>'html' from net.sent order by id desc limit 1")
    status = lambda b: val(f"select status from public.mdm_apps where bundle_id='{b}'")
    def as_user(uid, sql, role="authenticated"):
        return psql(f"begin; set local role {role}; select set_config('request.jwt.claim.sub','{uid or ''}',true); {sql}; commit;", err_ok=True)
    decide = lambda uid, b, d: as_user(uid, f"select public.eg_mdm_decide('{b}','{d}')")

    BASE = [("com.base.one", "Base One"), ("com.base.two", "Base Two"), ("com.base.three", "Base Three")]
    NEW = [("com.new.game", "Cool Game"), ("com.x.one", "X One"), ("com.x.two", "X Two")]
    EVIL = ("com.evil", '<script>alert(1)</script>')

    print("snapshot validation + first-run baseline")
    check("unregistered token -> 401", "unauthorized" in snap(BASE, token="ee" * 32)[1])
    check("empty app list rejected (never a real phone)", "bad app count" in snap([])[1])
    check("non-array apps rejected", "apps array" in psql(f"select public.eg_mdm_snapshot('{tok}','{{\"apps\":1}}'::jsonb);", err_ok=True)[1])
    check("missing detected_at rejected",
          "detected_at" in psql(f"select public.eg_mdm_snapshot('{tok}','{{\"apps\":[{{\"bundle_id\":\"a\"}}]}}'::jsonb);", err_ok=True)[1])
    n0 = sent(); r = snap(BASE, supervised=False)
    check("first snapshot auto-trusts all apps as baseline (no email)",
          '"baseline": true' in r[0] and sent() == n0
          and val("select count(*) from public.mdm_apps where status='approved' and source='baseline'") == "3", r[0] + r[1])
    check("baseline is now closed; supervised flag recorded",
          val("select baseline_closed and supervised is false from public.mdm_status") == "t")
    n0 = sent(); snap(BASE)
    check("unchanged snapshot -> nothing new, no email", sent() == n0)
    r = snap(BASE, det="2026-10-07T00:00:00Z")
    check("older detected_at is ignored (replay / out-of-order)", '"stale": true' in r[0])

    print("new apps")
    n0 = sent(); r = snap(BASE + [("com.new.game", "Cool Game")])
    check("new app -> pending + exactly one email naming it",
          status("com.new.game") == "pending" and sent() == n0 + 1 and "Cool Game" in last_subject(), last_subject())
    check("email points partners at the dashboard", "dirrimp.github.io/EyeGuard" in last_html())
    n0 = sent(); snap(BASE + [("com.new.game", "Cool Game")])
    check("same pending app on the next snapshot does not re-email", sent() == n0)
    n0 = sent(); snap(BASE + [("com.new.game", "Cool Game"), ("com.x.one", "X One"), ("com.x.two", "X Two")])
    check("two new apps in one snapshot -> ONE email ('2 new apps')", sent() == n0 + 1 and "2 new apps" in last_subject(), last_subject())
    check("the G11 can never approve: a snapshot cannot change a status",
          status("com.new.game") == "pending" and status("com.x.one") == "pending")
    snap(BASE + NEW + [EVIL])
    check("app names are HTML-escaped in the email", "<script>" not in last_html() and "&lt;script&gt;" in last_html())

    print("partner decisions")
    check("anon cannot decide", "permission denied" in as_user(None, "select public.eg_mdm_decide('com.new.game','approve')", "anon")[1])
    check("Jonah (authenticated, not a partner) cannot decide",
          "not allowed" in decide(JONAH, "com.new.game", "approve")[1] and status("com.new.game") == "pending")
    n0 = sent(); r = decide(DAD, "com.new.game", "approve")
    check("Dad approves -> approved, decision logged with who/when",
          status("com.new.game") == "approved"
          and val("select count(*) from public.mdm_decisions where bundle_id='com.new.game' and decision='approve' and email='dad@example.test'") == "1", r[1])
    check("both partners are told (one email, names the decider)", sent() == n0 + 1 and "dad@example.test" in last_html())
    n0 = sent(); decide(JADA, "com.new.game", "approve")
    check("repeating the same decision is a no-op (no second email, no extra log)",
          sent() == n0 and val("select count(*) from public.mdm_decisions where bundle_id='com.new.game'") == "1")
    check("unknown app -> 404", "unknown app" in decide(DAD, "com.nope", "approve")[1])
    check("bad decision -> 400", "bad decision" in decide(DAD, "com.new.game", "delete")[1])
    decide(JADA, "com.new.game", "revoke")
    check("revoke moves an approved app back to pending", status("com.new.game") == "pending")

    print("deny, removal queue, block list")
    n0 = sent(); decide(JADA, "com.x.one", "deny")
    check("deny on an UNSUPERVISED phone says plainly that it cannot be blocked",
          status("com.x.one") == "denied" and "not supervised" in last_html(), last_html()[:200])
    check("deny queues exactly one removal", val("select count(*) from public.mdm_actions where bundle_id='com.x.one'") == "1")
    decide(DAD, "com.x.one", "approve"); decide(DAD, "com.x.one", "deny")
    check("deny -> approve -> deny does not stack removals",
          val("select count(*) from public.mdm_actions where bundle_id='com.x.one' and status in ('queued','sent')") == "1")
    snap(BASE + NEW + [EVIL], supervised=True)
    decide(JADA, "com.x.two", "deny")
    check("deny on a SUPERVISED phone says the app is on the block list", "block list" in last_html())

    def sync(token=tok): return psql(f"select public.eg_mdm_sync('{token}');", err_ok=True)
    check("sync rejects a bad token", "unauthorized" in sync("ee" * 32)[1])
    s = json.loads(sync()[0])
    check("sync returns the denied bundle ids as the desired block list",
          s["blocked"] == ["com.x.one", "com.x.two"], str(s))
    ids = {a["bundle_id"]: a["id"] for a in s["actions"]}
    check("sync hands out the queued removals", set(ids) == {"com.x.one", "com.x.two"}, str(s))
    check("a second sync does not hand them out again (in flight)", json.loads(sync()[0])["actions"] == [])
    psql("update public.mdm_actions set updated_at = now() - interval '31 minutes' where status='sent';")
    check("an unanswered action is re-offered after 30 min", len(json.loads(sync()[0])["actions"]) == 2)

    def result(i, ok, d="x"): return psql(f"select public.eg_mdm_action_result('{tok}', {i}, {str(ok).lower()}, '{d}');", err_ok=True)
    n0 = sent(); result(ids["com.x.two"], True, "removed")
    check("successful removal -> done, no email",
          val(f"select status from public.mdm_actions where id={ids['com.x.two']}") == "done" and sent() == n0)
    n0 = sent(); result(ids["com.x.one"], False, "NotManaged")
    check("first failure is retried quietly (back to queued)",
          val(f"select status from public.mdm_actions where id={ids['com.x.one']}") == "queued" and sent() == n0)
    for _ in range(2):
        sync(); result(ids["com.x.one"], False, "NotManaged <b>x</b>")
    check("after 3 failed attempts -> failed + ONE email with the reason (escaped)",
          val(f"select status from public.mdm_actions where id={ids['com.x.one']}") == "failed"
          and sent() == n0 + 1 and "NotManaged" in last_html() and "<b>x</b>" not in last_html())
    check("a failed action is never re-offered", json.loads(sync()[0])["actions"] == [])
    check("late result for an unknown/finished action is ignored", '"ignored": true' in result(ids["com.x.one"], True)[0])

    n0 = sent(); psql(f"select public.eg_mdm_block_result('{tok}', false, 2, 'not supervised');")
    check("block-list failure emails once", sent() == n0 + 1)
    psql(f"select public.eg_mdm_block_result('{tok}', false, 2, 'not supervised');")
    check("repeated block failure does not re-email", sent() == n0 + 1)
    psql(f"select public.eg_mdm_block_result('{tok}', true, 2, 'ok');")
    check("block-list success recorded", val("select block_ok from public.mdm_status") == "t")

    print("removed / reinstalled apps")
    decide(DAD, "com.evil", "deny")
    snap(BASE)     # everything but the baseline apps is gone
    check("apps absent from the snapshot are marked gone and logged",
          val("select not present from public.mdm_apps where bundle_id='com.x.one'") == "t"
          and int(val("select count(*) from public.mdm_app_log where kind='gone'")) >= 4)
    check("a pending removal is closed when the app is gone",
          val("select count(*) from public.mdm_actions where bundle_id='com.evil' and status='done'") == "1")
    n0 = sent(); snap(BASE + [("com.x.one", "X One")])
    check("reinstalled DENIED app is logged as reappeared and stays denied (no new-app email)",
          status("com.x.one") == "denied" and sent() == n0
          and int(val("select count(*) from public.mdm_app_log where bundle_id='com.x.one' and kind='reappeared'")) >= 1)
    check("reinstalling an approved baseline app needs no approval",
          status("com.base.one") == "approved")

    print("reminders")
    psql("update public.mdm_apps set first_seen_at = now() - interval '2 days', last_nag_at = null;")
    snap(BASE + [("com.x.one", "X One"), ("com.x.two", "X Two"), ("com.new.game", "Cool Game")])
    psql("update public.mdm_apps set first_seen_at = now() - interval '2 days', last_nag_at = null;")
    psql("select public.eg_check_mdm_apps();")
    texts = val("select string_agg(body->>'subject', ' | ') from (select * from net.sent order by id desc limit 2) q")
    check("reminders: one for pending 24h+, one for denied-still-installed",
          "awaiting approval" in texts and "DENIED" in texts, texts)
    n0 = sent(); psql("select public.eg_check_mdm_apps();")
    check("reminders are throttled to once per 24h", sent() == n0)
    check("approved apps are never nagged",
          val("select count(*) from public.mdm_apps where status='approved' and last_nag_at is not null") == "0")

    print("privileges and RLS")
    for t in ("mdm_apps", "mdm_app_log", "mdm_decisions", "mdm_actions"):
        check(f"anon cannot read {t}", "permission denied" in as_user(None, f"select * from public.{t}", "anon")[1])
    check("a logged-in NON-partner (Jonah) sees zero apps (RLS)",
          as_user(JONAH, "select count(*) from public.mdm_apps")[0].split("\n")[-1].strip() == "0",
          as_user(JONAH, "select count(*) from public.mdm_apps")[0])
    check("a partner can read the list",
          int(as_user(DAD, "select count(*) from public.mdm_apps")[0].split("\n")[-1].strip()) > 0)
    check("partners cannot write the list directly (only through eg_mdm_decide)",
          "permission denied" in as_user(DAD, "update public.mdm_apps set status='approved'")[1])
    check("decision log is append-only for everyone",
          "permission denied" in as_user(DAD, "delete from public.mdm_decisions")[1]
          and "permission denied" in as_user(DAD, "update public.mdm_decisions set decision='approve'")[1])
    check("nobody but cron can run the reminder check",
          "permission denied" in as_user(DAD, "select public.eg_check_mdm_apps()")[1])
    check("token RPCs are not callable by a logged-in user",
          "permission denied" in as_user(DAD, f"select public.eg_mdm_sync('{tok}')")[1])
finally:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)

print()
if fails:
    print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
print("all MDM approval tests passed")
