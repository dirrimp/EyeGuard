#!/usr/bin/env python3
"""supabase/phone_dead_mdm_wording.sql: the "Phone dead" battery wording also reaches the MDM "cannot reach the phone" email (wording only).
Throwaway Postgres with email_source_labels.sql + phone_battery.sql underneath. Synthetic data only.
Run: EG_DOCKER="ssh g11 docker" EG_REQUIRE_SQL=1 python3 tests/test_phone_dead_mdm.py"""
import hashlib, os, re, shlex, shutil, subprocess, sys, time, uuid
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)
SQL_L = (ROOT / "supabase/email_source_labels.sql").read_text()
SQL_B = (ROOT / "supabase/phone_battery.sql").read_text()
SQL_X = (ROOT / "supabase/phone_dead_mdm_wording.sql").read_text()
live = re.sub(r"--[^\n]*", "", SQL_X)
print("A. static")
check("pure ASCII, no placeholder, no mail API literal", all(ord(c) < 128 for c in SQL_X) and "CHANGE-ME" not in SQL_X and ("api.resend" + ".com") not in SQL_X)
check("it defines no function and grants nothing (it only patches the hook in place)", "create or replace function" not in live and "grant " not in live)
check("it says it is wording only and names the rollback", "WORDING ONLY" in SQL_X and "ROLLBACK" in SQL_X)
dock = shlex.split(os.environ.get("EG_DOCKER", "docker"))
have = shutil.which(dock[0]) and subprocess.run(dock + ["image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
print("B. real Postgres")
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1": check("SQL tests could run", False, "docker/postgres:16-alpine unavailable")
    else: print("  [skip] docker/postgres:16-alpine unavailable")
else:
    name = "egdeadmdm-" + uuid.uuid4().hex[:8]
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
        tok = "ab" * 32
        psql(f"""
create role anon nologin; create role authenticated nologin; create role service_role nologin;
create schema extensions; create extension pgcrypto with schema extensions;
create table public.mdm_auth(token_sha256 text, note text);
insert into public.mdm_auth values ('{hashlib.sha256(tok.encode()).hexdigest()}', 't');
create table public.sent(id serial, via text, subject text, html text);
create function public.eg_send_email(subject text, html text) returns void language plpgsql security definer as $$
  begin insert into public.sent(via, subject, html) values ('main', subject, html); end $$;
create function public.eg_send_email_jada(subject text, html text) returns void language plpgsql security definer as $$
  begin insert into public.sent(via, subject, html) values ('jada', subject, html); end $$;
create function public.eg_send_email_mdm(subject text, html text) returns void language plpgsql security definer as $$
  begin insert into public.sent(via, subject, html) values ('mdm', subject, html); end $$;
revoke execute on function public.eg_send_email(text,text), public.eg_send_email_jada(text,text), public.eg_send_email_mdm(text,text) from public, anon, authenticated, service_role;
grant usage on schema public, extensions to anon;
""")
        psql(SQL_L)
        psql(SQL_B); out = psql(SQL_B)[0].splitlines()[-1]
        check("the file's own verify select is all true (and it re-runs cleanly)", set(out.split("|")) == {"t"}, out)

        psql(SQL_L); psql(SQL_B)
        DARK = "\U0001F4F5 EyeGuard \u2014 phone went dark"
        MDM = "\U0001F4F5 EyeGuard \u2014 Jonah iPhone app monitoring cannot reach the phone"
        MBODY = "<p><b>App-install monitoring cannot reach Jonah iPhone.</b></p><p>Detected: Nov 24, 10:45 PM . Last successful check: Nov 24, 10:10 PM .</p>"
        DBODY = "<p><b>The iPhone stopped routing through the monitored network.</b></p><p>When: Nov 24, 10:45 PM.</p>"
        def send(fn, subj, html):
            psql("delete from public.sent;")
            psql(f"select public.{fn}($q${subj}$q$, $q${html}$q$);")
            r = psql("select subject || E'\\x1f' || html from public.sent;")[0].split("\x1f")
            return r[0], r[1], int(val("select count(*) from public.sent"))
        def reading(pct, mins):
            psql(f"insert into public.phone_battery(id, pct, read_at) values (1, {pct}, now() - interval '{mins} minutes') on conflict (id) do update set pct = excluded.pct, read_at = excluded.read_at;")
        reading(3, 35)
        s0, h0, _ = send("eg_send_email_mdm", MDM, MBODY)
        check("BEFORE the patch the MDM email is only labelled (this is the bug)", "likely dead" not in s0 and "likely dead" not in h0, s0)
        psql(SQL_X); psql(SQL_X)
        v = psql(SQL_X)[0].splitlines()[-1]
        check("the verify select is all true (and the file re-runs cleanly three times)", set(v.split("|")) == {"t"}, v)

        print("the new wording")
        s, h, n = send("eg_send_email_mdm", MDM, MBODY)
        check("3% read 35 minutes ago: the subject keeps its text and gains the battery note", s == "\U0001F4F5 EyeGuard [Jonah's Phone] \u2014 Jonah iPhone app monitoring cannot reach the phone (battery was 3%: phone likely dead)", s)
        check("the body starts with the Source line, then the inference, gives the reading and its age, and ends with the original text",
              h.startswith("<p><b>Source: Jonah's Phone</b></p><p><b>Phone likely dead:") and "3%" in h and "35 minute" in h and "inference" in h and "not a confirmation" in h and h.endswith(MBODY), h)
        check("exactly one email is sent (reworded, never replaced or doubled)", n == 1)
        reading(5, 89); s, h, _ = send("eg_send_email_mdm", MDM, MBODY)
        check("5% and 89 minutes old is used", "likely dead" in s)
        reading(5, 91); s, h, _ = send("eg_send_email_mdm", MDM, MBODY)
        check("a reading older than 90 minutes is not used", "likely dead" not in s and "likely dead" not in h)
        reading(6, 35); s, h, _ = send("eg_send_email_mdm", MDM, MBODY)
        check("6% is not 'dead': normal email", "likely dead" not in s and "likely dead" not in h)
        psql("delete from public.phone_battery;"); s, h, n = send("eg_send_email_mdm", MDM, MBODY)
        check("no reading at all: normal email, still sent once", "likely dead" not in s and n == 1)

        print("nothing else changes")
        reading(3, 35)
        s, h, _ = send("eg_send_email", DARK, DBODY)
        check("the dark email with a 35-minute-old reading is NOT reworded (its 30-minute rule is unchanged)", "Phone dead" not in s, s)
        reading(3, 5); s, h, _ = send("eg_send_email", DARK, DBODY)
        check("the dark email with a fresh reading still says Phone dead (#187 behaviour kept)", s.endswith("Phone dead (battery was 3%)") and "Phone dead:" in h, s)
        for subj in ["\U0001F6D1 EyeGuard \u2014 iPhone app monitoring STOPPED reporting", "\U0001F4F2 EyeGuard \u2014 new app on Jonah iPhone: X", "\u2705 EyeGuard \u2014 iPhone app list is fresh again"]:
            s, h, _ = send("eg_send_email_mdm", subj, "<p>x</p>")
            check(f"other MDM email untouched: {subj[:40]}", "likely dead" not in s and "likely dead" not in h)
        s, h, _ = send("eg_send_email", MDM, MBODY)
        check("the MDM wording applies only through the MDM sender", "likely dead" not in s)
        s, _, _ = send("eg_send_email_jada", "\U0001F4F5 EyeGuard \u2014 Jada's phone went dark", "<p>x</p>")
        check("Jada's emails are never reworded by Jonah's battery", "dead" not in s)
        psql("create or replace function public.eg_email_adjust(via text, subject text, html text, out new_subject text, out new_html text) language plpgsql as $$ begin raise exception 'boom'; end $$;")
        s, h, n = send("eg_send_email_mdm", MDM, MBODY)
        check("if the wording hook ever fails, the labelled email is still sent once", n == 1 and s.endswith("cannot reach the phone"), s)

        print("the patch refuses a live hook that differs from the repo")
        out, err = psql(SQL_X, err_ok=True)
        check("a different live hook: it stops (here the stand-in has no fragments) and changes nothing", "exactly once" in err or "already applied" in (out + err), (out + err)[-300:])
    finally:
        subprocess.run(dock + ["rm", "-f", name], capture_output=True)

if fails:
    print("\nFAILED:", *fails, sep="\n  "); sys.exit(1)
print("\nALL OK")
