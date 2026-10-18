#!/usr/bin/env python3
"""supabase/alerts_to_both_partners.sql in a real throwaway Postgres (postgres:16-alpine; local docker,
or on a host via EG_TEST_SSH=<host>): one recipient list for all three senders (union, nobody dropped),
real triggers replayed so Jada's events arrive ONCE (correctly worded) at BOTH partners, and every other
alert path is unchanged. Synthetic addresses/data only. Run: python3 tests/test_alerts_both_partners.py"""
import json, os, re, subprocess, sys, time, uuid
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
S = lambda n: (ROOT / "supabase" / n).read_text()
SQL = S("alerts_to_both_partners.sql")
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

print("A. static")
check("pure ASCII (Dad pastes this)", all(ord(c) < 128 for c in SQL))
check("does not send mail itself and never touches the Resend key", "api.resend.com" not in SQL and "vault" not in SQL.lower().replace("-- ", ""))

ssh = os.environ.get("EG_TEST_SSH")
def sh(cmd, inp=None):
    full = ["ssh", ssh, " ".join(cmd)] if ssh else cmd
    return subprocess.run(full, input=inp, capture_output=True, text=True)
if sh(["docker", "image", "inspect", "postgres:16-alpine"]).returncode != 0:
    print("B. SKIP (no docker/postgres:16-alpine)"); sys.exit(1 if fails else 0)

name = "egbp-" + uuid.uuid4().hex[:8]
def psql(sql, err_ok=False):
    r = sh(["docker", "exec", "-i", name, "psql", "-U", "postgres", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1"], sql)
    if r.returncode and not err_ok: raise RuntimeError(r.stderr[-700:])
    return r.stdout.strip(), r.stderr
val = lambda q: psql(q)[0]

def block(file, fname):
    m = re.search(r"create or replace function public\." + fname + r"\(.*?\nend \$\$;", S(file), re.S)
    assert m, fname
    return m.group(0)

def mk(fn, to):
    psql(f"""create or replace function public.{fn}(subject text, html text) returns void
language plpgsql security definer set search_path = public, vault as $$
declare api_key text;
begin
  select decrypted_secret into api_key from vault.decrypted_secrets where name = 'resend_api_key' limit 1;
  perform net.http_post(url := 'https://api.resend.com/emails', headers := '{{}}'::jsonb,
    body := jsonb_build_object('fn', '{fn}', 'from', 'EyeGuard <alerts@orthanc.me>',
      'to',   jsonb_build_array({to}),  -- hand-typed by Dad
      'subject', subject, 'html', html));
end $$;
revoke execute on function public.{fn}(text, text) from public, anon, authenticated, service_role;""")

def setup():
    psql("""
create role anon nologin; create role authenticated nologin; create role service_role nologin;
create schema extensions; create extension pgcrypto with schema extensions;
create schema vault; create table vault.s(name text, decrypted_secret text); insert into vault.s values ('resend_api_key','re_test');
create view vault.decrypted_secrets as select * from vault.s;
create schema net; create table net.sent(id serial, body jsonb);
create function net.http_post(url text, headers jsonb, body jsonb) returns bigint language sql as $$ insert into net.sent(body) values (body) returning id $$;
create schema auth; create function auth.uid() returns uuid language sql as $$ select null::uuid $$;
create schema cron; create table cron.job(jobname text, schedule text, command text);
grant usage on schema public, extensions to anon, authenticated;
create table public.phone_status(id int primary key default 1, findmy_last_seen timestamptz, findmy_reported_at timestamptz);
insert into public.phone_status(id) values (1);
create table public.flags(id uuid primary key default gen_random_uuid(), created_at timestamptz default now(),
  flagged_at timestamptz not null default now(), verdict text not null, is_nudity boolean default false, grade text, risk text,
  app text, url text, window_title text, reason text, score real, image_path text);
""")
    # live-like hand-edited senders: Dad's has an extra address (Jonah) to prove nobody is dropped
    mk("eg_send_email", "'dad@x.test', 'jonah@x.test'")
    mk("eg_send_email_jada", "'jada@x.test'")
    psql(block("mdm_app_events.sql", "eg_send_email_mdm").replace("dad@CHANGE-ME.invalid", "dad@x.test").replace("jadadirrim@pm.me", "jada@x.test"))
    psql(S("central_mail_sender.sql"))
    j = S("jada_phone.sql")
    ddl = j[j.index("-- ---- 1. status row"):j.index("-- ---- 2. server-stamped")]
    ddl = re.sub(r"alter table public.phone_status_jada enable row level security;.*", "", ddl, flags=re.S)
    psql(ddl)
    psql(block("explicit_search_red_and_digest_fix.sql", "eg_on_red"))
    psql(block("jada_phone.sql", "eg_on_jada_flag"))
    psql("""create trigger eg_red_alert after insert on public.flags for each row when (NEW.verdict = 'flagged') execute function public.eg_on_red();
create trigger eg_jada_alert after insert on public.flags for each row when (NEW.app = 'Jada''s iPhone' and NEW.verdict in ('flagged','alert')) execute function public.eg_on_jada_flag();""")

def meta(fn): return val(f"select prosecdef::text||'|'||coalesce(array_to_string(proconfig,','),'')||'|'||has_function_privilege('anon','{fn}','execute')::text from pg_proc where oid='{fn}'::regprocedure")
def fire(app, verdict, reason):
    psql("truncate net.sent;")
    psql(f"insert into public.flags(app, verdict, reason) values ($a${app}$a$, '{verdict}', $r${reason}$r$);")
    rows = json.loads(val("select coalesce(jsonb_agg(body order by id), '[]') from net.sent"))
    return rows
SENDERS = ("eg_send_email", "eg_send_email_jada", "eg_send_email_mdm")
BOTH = ["dad@x.test", "jada@x.test", "jonah@x.test"]

try:
    sh(["docker", "run", "-d", "--rm", "--name", name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "postgres:16-alpine"])
    for _ in range(60):
        if sh(["docker", "exec", name, "pg_isready", "-U", "postgres"]).returncode == 0: break
        time.sleep(1)
    time.sleep(2)
    setup()
    before_meta = {f: meta(f"public.{f}(text,text)") for f in SENDERS}

    print("B. BEFORE (the problem, reproduced with the repo's real triggers)")
    r = fire("Jada's iPhone", "flagged", "jada-phone-signal: DNS-over-HTTPS bypass attempt to 1.2.3.4")
    check("a Jada-phone event is emailed TWICE today (generic mislabeled one from eg_on_red + hers)", len(r) == 2, str(len(r)))
    check("...and the two copies go to different people", len({tuple(sorted(x['to'])) for x in r}) == 2)

    print("C. APPLY")
    out = psql(SQL)
    check("the file applies cleanly", True)
    check("recipients = union of all three live lists (Dad's extra address kept)",
          sorted(json.loads(val("select recipients::text from public.eg_mail_config"))) == BOTH, out[1][-200:])
    check("all three senders take recipients from eg_mail_to()",
          all("eg_mail_to()" in val(f"select pg_get_functiondef('public.{f}(text,text)'::regprocedure)") for f in SENDERS))
    check("MDM sender still has its placeholder guard", ".invalid" in val("select pg_get_functiondef('public.eg_send_email_mdm(text,text)'::regprocedure)"))
    check("security definer / search_path / privileges of the senders unchanged",
          {f: meta(f"public.{f}(text,text)") for f in SENDERS} == before_meta)
    for f in SENDERS:
        psql("truncate net.sent;"); psql(f"select public.{f}('s','h');")
        b = json.loads(val("select body::text from net.sent"))
        check(f"{f} sends to BOTH partners (+ the existing extra), same From", sorted(b["to"]) == BOTH and b["from"] == "EyeGuard <alerts@orthanc.me>")

    print("D. AFTER: every alert path replayed")
    r = fire("Jada's iPhone", "flagged", "jada-phone-signal: DNS-over-HTTPS bypass attempt to 1.2.3.4")
    check("Jada-phone explicit/DoH event: exactly ONE email, from her sender, to everyone",
          len(r) == 1 and r[0]["fn"] == "eg_send_email_jada" and sorted(r[0]["to"]) == BOTH)
    psql("truncate net.sent;")
    r = fire("Jada's iPhone", "alert", "jada-phone-dark: silent for 169s")
    check("Jada-phone dark event: exactly one email to everyone", len(r) == 1 and sorted(r[0]["to"]) == BOTH)
    r = fire("iPhone", "flagged", "phone-signal: Tor connection to guard relay 9.9.9.9")
    check("Jonah's phone explicit-site event: still exactly one email, now to everyone",
          len(r) == 1 and "explicit site" in r[0]["subject"] and sorted(r[0]["to"]) == BOTH)
    r = fire("Router", "flagged", "tamper: AdGuard DNS log -- jada-querylog stale")
    check("router/AdGuard tamper (even Jada's instance): still emailed, as tampering, to everyone",
          len(r) == 1 and "tampering" in r[0]["subject"] and sorted(r[0]["to"]) == BOTH)
    r = fire("Safari", "flagged", "very revealing content")
    check("Mac content red: unchanged, one email, to everyone", len(r) == 1 and "alert" in r[0]["subject"].lower() and sorted(r[0]["to"]) == BOTH)
    r = fire("EyeGuard", "flagged", "x")
    check("app='EyeGuard' tamper: still emailed", len(r) == 1 and "tampering" in r[0]["subject"])
    check("a look-alike app name is NOT swallowed (only the exact Jada phone app is skipped)",
          len(fire("Jadas iPhone", "flagged", "very revealing content")) == 1)

    print("E. safety")
    out = psql(SQL)
    check("re-running changes nothing", "functions changed: 0" in out[1])
    for label, bad in (("a placeholder", "'[\"dad@CHANGE-ME.invalid\"]'"), ("a non-address", "'[\"not an address\"]'"), ("a non-array", "'\"a@b.com\"'"), ("an empty list", "'[]'")):
        rr = psql(f"update public.eg_mail_config set recipients = {bad}::jsonb where id = 1;", err_ok=True)
        check(f"the constraint refuses {label}", "violates check constraint" in rr[1], rr[1][-100:])
    check("no API role can read the list or call eg_mail_to()",
          "permission denied" in psql("begin; set local role anon; select * from public.eg_mail_config; rollback;", err_ok=True)[1]
          and "permission denied" in psql("begin; set local role anon; select public.eg_mail_to(); rollback;", err_ok=True)[1])
    # all three senders now read the central list (no hand-typed list left to seed from), and the list is emptied
    snap = val("select pg_get_functiondef('public.eg_send_email(text,text)'::regprocedure)")
    psql("update public.eg_mail_config set recipients = null where id = 1;")
    rr = psql(SQL, err_ok=True)
    check("if no live recipient can be read it STOPS and changes nothing",
          "Could not read any recipient" in rr[1] and val("select pg_get_functiondef('public.eg_send_email(text,text)'::regprocedure)") == snap, rr[1][-200:])

    print("F. mutants: the tests must be able to fail")
    def fresh(sqltext):
        global name
        sh(["docker", "rm", "-f", name]); name = "egbp-" + uuid.uuid4().hex[:8]
        sh(["docker", "run", "-d", "--rm", "--name", name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "postgres:16-alpine"])
        for _ in range(60):
            if sh(["docker", "exec", name, "pg_isready", "-U", "postgres"]).returncode == 0: break
            time.sleep(1)
        time.sleep(2); setup(); psql(sqltext)
        a = fire("Jada's iPhone", "flagged", "jada-phone-signal: x")
        b = fire("iPhone", "flagged", "phone-signal: y")
        return a, b
    m1 = SQL.replace("if NEW.app = ''Jada''''s iPhone'' then return NEW; end if;", "")
    a, b = fresh(m1)
    check("mutant without the eg_on_red skip is caught (duplicate)", len(a) != 1)
    m2 = SQL.replace("and not (lower(tok) = any (select lower(x) from unnest(found) x))", "and false")
    try:
        fresh(m2); caught = False
    except RuntimeError: caught = True
    check("mutant that reads no recipients is caught", caught)
    m3 = SQL.replace("if NEW.app = ''Jada''''s iPhone'' then", "if true then")
    a, b = fresh(m3)
    check("mutant that skips ALL rows is caught (coverage would drop)", len(b) != 1)
finally:
    sh(["docker", "rm", "-f", name])
print()
if fails: print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
print("all both-partners tests passed")
