#!/usr/bin/env python3
"""supabase/outage_digest.sql in a real throwaway Postgres: a home-network pile-up becomes one first email plus one digest,
and nothing is ever dropped. Synthetic data only. Run: EG_DOCKER="ssh g11 docker" EG_REQUIRE_SQL=1 python3 tests/test_outage_digest.py"""
import os, re, shlex, shutil, subprocess, sys, time, uuid
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
SQL = (ROOT / "supabase/outage_digest.sql").read_text()
LABELS = (ROOT / "supabase/email_source_labels.sql").read_text()
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

print("A. static")
live = re.sub(r"--[^\n]*", "", SQL)
check("the SQL Dad copies is pure ASCII", all(ord(c) < 128 for c in SQL))
check("no mail API, no hand-typed sender, no key", "api.resend" + ".com" not in SQL and "alerts@" not in SQL and not re.search(r"eyJ[A-Za-z0-9_-]{20,}", SQL))
check("it sends only through the existing raw senders", "net.http_post" not in live and live.count("_raw(") >= 3)
check("every new function and table is closed to the API roles", "revoke execute on function public.eg_outage_kind" in live and "revoke all on public.outage_burst, public.outage_held" in live and "grant " not in live)
check("it patches live wrappers with exactly-once guards", "cnt <> 1" in live and "raise exception" in live)
check("window is 10 minutes and the safety release is 15", live.count("interval '10 minutes'") >= 1 and "interval '15 minutes'" in live)
kinds = re.search(r"create or replace function public\.eg_outage_kind.*?\$\$;", live, re.S).group(0)
check("four 'went quiet' subject patterns (five alerts: Jonah's and Jada's monitor share one) and two recovery subjects are involved",
      kinds.count("then 'down'") == 4 and kinds.count("then 'up'") == 2)
check("alerts about content, the Mac, the phone itself and tampering are not in the list",
      not re.search(r"went dark|explicit|nudity|tamper|unmonitored|lost view|Mac", kinds))

print("B. real Postgres")
dock = shlex.split(os.environ.get("EG_DOCKER", "docker"))
have = shutil.which(dock[0]) and subprocess.run(dock + ["image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1": check("SQL tests could run", False, "docker/postgres:16-alpine unavailable")
    else: print("  [skip] docker/postgres:16-alpine unavailable")
else:
    name = "egod-" + uuid.uuid4().hex[:8]
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
            return r.stdout.strip(), r.stderr, r.returncode
        val = lambda q: psql(q)[0]
        psql("""
create role anon nologin; create role authenticated nologin; create role service_role nologin;
create schema cron; create table cron.job(jobid serial, jobname text, schedule text, command text);
create function cron.schedule(n text, s text, c text) returns bigint language sql as $$ insert into cron.job(jobname, schedule, command) values (n, s, c) returning jobid::bigint $$;
create function cron.unschedule(n text) returns boolean language sql as $$ delete from cron.job where jobname = n returning true $$;
create table public.sent(id serial, via text, subject text, html text);
create function public.eg_send_email(subject text, html text) returns void language plpgsql security definer as $$
  begin insert into public.sent(via, subject, html) values ('main', subject, html); end $$;
create function public.eg_send_email_jada(subject text, html text) returns void language plpgsql security definer as $$
  begin insert into public.sent(via, subject, html) values ('jada', subject, html); end $$;
create function public.eg_send_email_mdm(subject text, html text) returns void language plpgsql security definer as $$
  begin insert into public.sent(via, subject, html) values ('mdm', subject, html); end $$;
revoke execute on function public.eg_send_email(text,text), public.eg_send_email_jada(text,text), public.eg_send_email_mdm(text,text)
  from public, anon, authenticated, service_role;
""")
        psql(LABELS)
        out = psql(SQL)[0].splitlines()[-1].split("|")
        check("the file's own verify select is all true (8 columns)", out == ["t"] * 8, str(out))
        before = val("select md5(pg_get_functiondef('public.eg_send_email(text,text)'::regprocedure) || pg_get_functiondef('public.eg_send_email_mdm(text,text)'::regprocedure))")
        psql(SQL)
        check("re-running is a no-op", val("select md5(pg_get_functiondef('public.eg_send_email(text,text)'::regprocedure) || pg_get_functiondef('public.eg_send_email_mdm(text,text)'::regprocedure))") == before
              and val("select count(*) from cron.job where jobname = 'eyeguard-outage-flush'") == "1")

        def reset():
            psql("delete from public.sent; delete from public.outage_held; update public.outage_burst set opened_at=null, window_end=null, first_subject=null, first_via=null where id=1;")
        def send(fn, subj, html="<p>x</p>"):
            psql(f"select public.{fn}($q${subj}$q$, $q${html}$q$);")
        def sent(): return [r.split("\x1f") for r in psql("select via || E'\\x1f' || subject from public.sent order by id;")[0].splitlines() if r]
        def end_window(): psql("update public.outage_burst set window_end = now() - interval '1 minute' where id = 1;")
        PHONE = "⚫ EyeGuard — phone MONITOR offline"
        JADA = "⚫ EyeGuard — Jada's phone MONITOR offline"
        ROUTER = "⚫ EyeGuard — router watcher offline"
        ONN = "\U0001F6D1 EyeGuard — the Onn TV monitor STOPPED reporting"
        MDM = "\U0001F6D1 EyeGuard — iPhone app monitoring STOPPED reporting"
        ONNUP = "✅ EyeGuard — the Onn TV monitor is reporting again"
        MDMUP = "✅ EyeGuard — iPhone app monitoring is back online"

        print("B1. the 2026-11-20 pile-up: 5 'went quiet' + 2 'back' emails")
        reset()
        send("eg_send_email", PHONE); send("eg_send_email_jada", JADA); send("eg_send_email_mdm", ONN)
        send("eg_send_email_mdm", ONN); send("eg_send_email_mdm", MDM); send("eg_send_email", ROUTER)
        send("eg_send_email_mdm", ONNUP); send("eg_send_email_mdm", MDMUP)
        s = sent()
        check("only the FIRST alert was sent at once, and it is unchanged apart from the label and one added line", len(s) == 1 and "phone MONITOR offline" in s[0][1], str(s))
        h = val("select html from public.sent order by id limit 1")
        check("...it says the others will arrive together at a stated time", "sent together in one email at about" in h and "Nothing is dropped" in h)
        check("the other 7 are held, in full", val("select count(*) from public.outage_held where released_at is null") == "7")
        psql("select public.eg_outage_flush();")
        check("inside the window the minute job releases nothing", len(sent()) == 1)
        end_window(); psql("select public.eg_outage_flush();")
        s = sent()
        check("after the window: exactly ONE more email, so 2 instead of 8", len(s) == 2, str(s))
        d = val("select subject from public.sent order by id desc limit 1"); dh = val("select html from public.sent order by id desc limit 1")
        check("the digest is titled as a home-network email with the right count", "home network: 7 more monitor alerts" in d and "[Home network]" in d, d)
        check("it contains every original subject, so nothing is left out",
              all(x.split(" — ", 1)[1].split("&")[0].replace("'", "&#39;") in dh.replace("&#39;", "&#39;") or x.split(" — ", 1)[1] in dh
                  for x in (JADA, ONN, MDM, ROUTER, ONNUP, MDMUP)), dh[:300])
        check("nothing is left held and the window is closed",
              val("select count(*) from public.outage_held where released_at is null") == "0" and val("select window_end is null from public.outage_burst where id=1") == "t")

        print("B2. other cases")
        reset(); send("eg_send_email", PHONE); send("eg_send_email_mdm", ONN); end_window(); psql("select public.eg_outage_flush();")
        s = sent()
        check("one held alert is released on its own, unchanged, with a note", len(s) == 2 and "Onn TV monitor STOPPED" in s[1][1] and s[1][0] == "mdm", str(s))
        check("...and still through the same sender it started on", s[1][0] == "mdm")
        reset(); send("eg_send_email", PHONE)
        for subj, fn in [("\U0001F6A8 EyeGuard — monitoring went dark", "eg_send_email"), ("\U0001F4F5 EyeGuard — phone went dark", "eg_send_email"),
                         ("\U0001F534 EyeGuard alert — Explicit nudity", "eg_send_email"), ("\U0001F6A8 EyeGuard — router monitor tampering detected", "eg_send_email"),
                         ("EyeGuard - Jada's phone on but unmonitored", "eg_send_email_jada"), ("\U0001F6A8 EyeGuard — G11 code differs from what Dad approved", "eg_send_email_mdm")]:
            send(fn, subj)
        check("during an open window, Mac / phone / content / tamper / unmonitored / G11 emails still send IMMEDIATELY (6 of 6)", len(sent()) == 7, str(len(sent())))
        check("none of them was held", val("select count(*) from public.outage_held") == "0")
        reset(); send("eg_send_email_mdm", ONNUP)
        check("a recovery email with no window open is sent as-is", len(sent()) == 1 and val("select count(*) from public.outage_held") == "0")
        reset(); send("eg_send_email", PHONE); end_window(); psql("select public.eg_outage_flush();"); send("eg_send_email", ROUTER)
        check("after a window ends, the next alert starts a NEW window and is sent at once", len(sent()) == 2 and val("select window_end > now() from public.outage_burst where id=1") == "t")

        print("B3. nothing can be stranded")
        reset(); send("eg_send_email", PHONE); send("eg_send_email_jada", JADA); end_window()
        send("eg_send_email", "\U0001F6A8 EyeGuard — monitoring went dark")     # no cron ran: the NEXT email passing through releases it
        s = sent()
        check("minute job stopped: the next email through any sender releases the held alert", any("Jada" in x[1] for x in s) and val("select count(*) from public.outage_held where released_at is null") == "0", str(s))
        reset(); send("eg_send_email", PHONE); send("eg_send_email_jada", JADA)
        psql("update public.outage_held set held_at = now() - interval '16 minutes'; update public.outage_burst set window_end = now() + interval '30 minutes';")
        psql("select public.eg_outage_flush();")
        check("anything held for 16 minutes goes out even if the window state is wrong", len(sent()) == 2)
        reset(); send("eg_send_email", PHONE); send("eg_send_email", ROUTER); end_window()
        psql("alter function public.eg_send_email_raw(text,text) rename to eg_send_email_raw_ok; create function public.eg_send_email_raw(s text, h text) returns void language plpgsql as $$ begin raise exception 'mail down'; end $$;")
        _, err, rc = psql("select public.eg_outage_flush();", err_ok=True)
        check("a failed send raises and the alert stays held for the next try", rc != 0 and val("select count(*) from public.outage_held where released_at is null") == "1")
        psql("drop function public.eg_send_email_raw(text,text); alter function public.eg_send_email_raw_ok(text,text) rename to eg_send_email_raw;")
        psql("select public.eg_outage_flush();")
        check("...and the next run sends it", len(sent()) == 2 and val("select count(*) from public.outage_held where released_at is null") == "0")

        print("B4. fail-open")
        reset()
        psql("alter function public.eg_outage_gate(text,text,text) rename to eg_outage_gate_ok; create function public.eg_outage_gate(v text, s text, h text, out action text, out new_subject text, out new_html text) language plpgsql as $$ begin raise exception 'gate broken'; end $$;")
        send("eg_send_email", PHONE); send("eg_send_email_jada", JADA)
        check("if the gate itself fails, BOTH emails are sent at once, unchanged", len(sent()) == 2, str(sent()))
        psql("drop function public.eg_outage_gate(text,text,text); alter function public.eg_outage_gate_ok(text,text,text) rename to eg_outage_gate;")
        reset(); psql("create or replace function public.eg_outage_kind(subject text) returns text language sql immutable as $$ select null::text $$;")
        send("eg_send_email", PHONE); send("eg_send_email_jada", JADA); send("eg_send_email_mdm", ONN)
        check("the documented rollback (kind returns null) makes everything send at once again", len(sent()) == 3)

        print("B5. refuses what it does not recognise")
        reset()
        psql("create or replace function public.eg_send_email_mdm(subject text, html text) returns void language plpgsql as $$ begin null; end $$;")
        _, err, rc = psql(SQL, err_ok=True)
        check("a wrapper that is not the labelling wrapper -> error, nothing changed", rc != 0 and "email_source_labels.sql first" in err, err[-300:])
    finally:
        subprocess.run(dock + ["rm", "-f", name], capture_output=True)

print()
if fails:
    print("FAILED:"); [print("  " + f) for f in fails]; sys.exit(1)
print("ALL OK")
