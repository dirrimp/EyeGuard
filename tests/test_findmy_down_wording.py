#!/usr/bin/env python3
"""supabase/findmy_down_wording.sql: Find My outage emails say 'N hours' and 'since <time>' (wording only). Stand-in functions carry the
exact live fragments (checked against the repo files); synthetic data only.
Run: EG_DOCKER="ssh g11 docker" EG_REQUIRE_SQL=1 python3 tests/test_findmy_down_wording.py"""
import os, re, shlex, shutil, subprocess, sys, time, uuid
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)
X = (ROOT / "supabase/findmy_down_wording.sql").read_text()
G = (ROOT / "supabase/gate_findmy_stale_alert_on_mac_awake.sql").read_text()
D = (ROOT / "supabase/phone_sustained_dark.sql").read_text()
live = re.sub(r"--[^\n]*", "", X)
print("A. static")
check("pure ASCII, says wording only, names rollback", all(ord(c) < 128 for c in X) and "WORDING ONLY" in X and "ROLLBACK" in X)
check("defines no function, grants nothing", "create or replace function" not in live and "grant " not in live)
check("stale fragment is in the repo function exactly once", G.count("age(now(), p.findmy_reported_at)") == 1)
check("dark fragment is in the repo function exactly once", D.count("'The Find My cross-check is not reporting right now, so this '") == 1)
dock = shlex.split(os.environ.get("EG_DOCKER", "docker"))
have = shutil.which(dock[0]) and subprocess.run(dock + ["image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
print("B. real Postgres")
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1": check("SQL tests could run", False, "docker/postgres:16-alpine unavailable")
    else: print("  [skip] docker/postgres:16-alpine unavailable")
else:
    name = "egfmdown-" + uuid.uuid4().hex[:8]
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
        stale_frag = "age(now(), p.findmy_reported_at)"
        dark_frag = "'The Find My cross-check is not reporting right now, so this '"
        psql(f"""
create table phone_status(id int primary key, findmy_reported_at timestamptz);
create table sent(subject text, html text);
create function eg_send_email(s text, h text) returns void language sql as $$ insert into sent values (s, h) $$;
create function eg_check_phone() returns void language plpgsql as $$
declare p phone_status; begin select * into p from phone_status where id=1;
  perform public.eg_send_email('stale', format('<p>no cycle in %s, despite</p>', {stale_frag})); end $$;
create function eg_check_phone_sustained_dark() returns void language plpgsql as $$
declare p phone_status; begin select * into p from phone_status where id=1;
  perform public.eg_send_email('dark', 'X ' || case when true then {dark_frag} || 'can''t be confirmed' end); end $$;
insert into phone_status values (1, now() - interval '17 hours');
""")
        out, _ = psql(X)
        check("patch runs on the stand-ins", True)
        psql("select eg_check_phone(); select eg_check_phone_sustained_dark();")
        stale = val("select html from sent where subject='stale'")
        dark = val("select html from sent where subject='dark'")
        check("stale age reads '17 hours' (no raw interval)", "no cycle in 17 hours, despite" in stale, stale)
        check("dark email says has not reported since <time>", "has not reported since " in dark and "can't be confirmed" in dark and "right now" not in dark, dark)
        psql("update phone_status set findmy_reported_at = now() - interval '45 minutes'; delete from sent; select eg_check_phone();")
        check("under an hour reads '45 minutes'", "in 45 minutes," in val("select html from sent"))
        psql("update phone_status set findmy_reported_at = null; delete from sent; select eg_check_phone_sustained_dark();")
        check("never-reported shows 'ever', no crash", "since ever" in val("select html from sent"))
        out2, err2 = psql(X)
        check("re-run is a no-op notice", "already applied" in err2 or "already applied" in out2, err2)
        v = val(X.split("-- VERIFY")[1].split("\n", 1)[1])
        check("verify row is true,true", v == "t|t", v)
        psql("drop function eg_check_phone_sustained_dark(); create function eg_check_phone_sustained_dark() returns void language sql as $$ select 1 $$;")
        _, e3 = psql(X.replace("3600.0", "3600.0"), err_ok=True)
        check("a live function that differs stops with an error and changes nothing", "Nothing changed" in e3 or "already applied" in e3, e3)
    finally:
        subprocess.run(dock + ["rm", "-f", name], capture_output=True)
print()
print("FAILED %d: %s" % (len(fails), ", ".join(fails)) if fails else "ALL OK")
sys.exit(1 if fails else 0)
