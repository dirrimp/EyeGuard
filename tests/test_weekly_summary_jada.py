#!/usr/bin/env python3
"""supabase/weekly_summary_jada.sql in a real throwaway postgres:16-alpine (local docker, or EG_TEST_SSH=<host>).
Starts from the LIVE function text Dad pasted on 2026-10-18 (tests/fixtures/live_weekly_summary_2026-10-18.sql
is the repo's definition, byte-identical in the pieces that matter), replays Jada/Jonah events, reads the email
body. Synthetic data only. Run: python3 tests/test_weekly_summary_jada.py"""
import os, re, subprocess, sys, time, uuid
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
SQL = (ROOT / "supabase/weekly_summary_jada.sql").read_text()
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)
check("pure ASCII (Dad pastes this)", all(ord(c) < 128 for c in SQL))
ssh = os.environ.get("EG_TEST_SSH")
def sh(cmd, inp=None):
    return subprocess.run(["ssh", ssh, " ".join(cmd)] if ssh else cmd, input=inp, capture_output=True, text=True)
if sh(["docker", "image", "inspect", "postgres:16-alpine"]).returncode != 0:
    print("  [skip] no docker/postgres:16-alpine"); sys.exit(1 if fails else 0)
name = "egws-" + uuid.uuid4().hex[:8]
def psql(sql, err_ok=False):
    r = sh(["docker", "exec", "-i", name, "psql", "-U", "postgres", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1"], sql)
    if r.returncode and not err_ok: raise RuntimeError(r.stderr[-600:])
    return r.stdout.strip(), r.stderr
val = lambda q: psql(q)[0]
src = (ROOT / "supabase/eg_send_weekly_summary.sql").read_text()
fn = re.search(r"create or replace function public\.eg_send_weekly_summary\(\).*?\nend \$\$;", src, re.S).group(0)
def li(body, label):
    m = re.search(r"<li>[^<]*?" + re.escape(label) + r"[^<]*?(\d+)", body)
    return int(m.group(1)) if m else None
def summary():
    psql("truncate public.sent;"); psql("select public.eg_send_weekly_summary();")
    return val("select body from public.sent order by id desc limit 1")
def ins(app, verdict, reason):
    psql(f"insert into public.flags(app, verdict, reason) values ($a${app}$a$, '{verdict}', $r${reason}$r$);")
try:
    sh(["docker", "run", "-d", "--rm", "--name", name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "postgres:16-alpine"])
    for _ in range(60):
        if sh(["docker", "exec", name, "pg_isready", "-U", "postgres"]).returncode == 0: break
        time.sleep(1)
    time.sleep(2)
    psql("""create table public.flags(id uuid primary key default gen_random_uuid(), flagged_at timestamptz not null default now(),
      verdict text not null, app text, reason text);
create table public.sent(id serial, body text);
create function public.eg_send_email(s text, h text) returns void language sql as $$ insert into public.sent(body) values (h) $$;""")
    psql(fn)
    for a, v, r in (("iPhone", "flagged", "phone-signal: Tor connection to guard relay 1.1.1.1"),
                    ("Jada's iPhone", "flagged", "jada-phone-signal: DNS-over-HTTPS bypass attempt to 2.2.2.2"),
                    ("Jada's iPhone", "flagged", "jada-phone-signal: Tor connection to guard relay 3.3.3.3"),
                    ("iPhone", "flagged", "phone-dark: silent for 160s (x)"),
                    ("iPhone", "flagged", "phone-dark: silent for 400s (x)"),
                    ("Jada's iPhone", "alert", "jada-phone-dark: silent for 190s (x)"),
                    ("Jada's iPhone", "alert", "jada-phone-dark: silent for 210s (x)"),
                    ("Router", "flagged", "tamper: AdGuard DNS log -- jada-stale"),
                    ("Safari", "flagged", "very revealing content")):
        ins(a, v, r)
    b = summary()
    print("B. BEFORE (live text)")
    check("Jada's two DoH/Tor rows are miscounted as content flags (3 instead of 1)", li(b, "Explicit/revealing content flagged") == 3)
    check("her dark events are not reported anywhere", "Jada" not in b)
    before_body = b
    out = psql(SQL)
    print("C. AFTER")
    b = summary()
    check("content bucket now only the real content flag", li(b, "Explicit/revealing content flagged") == 1)
    check("explicit-site bucket = Jonah's 1 + Jada's 2", li(b, "Phone hit an explicit site") == 3)
    check("tamper unchanged", li(b, "Tampering detected") == 1)
    check("Jonah's phone-dark total/band unchanged (2 total, 1 in band, 1 outside)",
          re.search(r"Phone-dark: 2 total [^0-9]*1 in the 150[^<]*?1 outside", b) is not None)
    check("new line reports Jada's phone-dark = 2", re.search(r"Jada's phone-dark: 2<", b) is not None)
    check("the rest of the email (PR links, wording) is byte-identical",
          re.sub(r"<li>.*?</li>", "", b) == re.sub(r"<li>.*?</li>", "", before_body))
    out = psql(SQL)
    check("re-running is a no-op", "already counts" in out[1])
    print("D. fail-safe + mutants")
    psql("create or replace function public.eg_send_weekly_summary() returns void language plpgsql as $$ begin null; end $$;")
    r = psql(SQL, err_ok=True)
    check("if the live function differs from what the script was written for it STOPS and changes nothing",
          "matched 0 times" in r[1] and "n_jada_dark" not in val("select pg_get_functiondef('public.eg_send_weekly_summary()'::regprocedure)"), r[1][-200:])
    psql(fn)
    m = SQL.replace("or reason like 'jada-phone-blocked%' or reason like 'jada-phone-signal%'", "")
    psql(m); b = summary()
    check("mutant that forgets to bucket her signals is caught", li(b, "Phone hit an explicit site") != 3)
    psql(fn)
    m = SQL.replace("and reason not like 'jada-phone-signal%'", "")
    psql(m); b = summary()
    check("mutant that leaves her rows in the content bucket is caught", li(b, "Explicit/revealing content flagged") != 1)
finally:
    sh(["docker", "rm", "-f", name])
print()
if fails: print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
print("all weekly-summary tests passed")
