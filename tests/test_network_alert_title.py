#!/usr/bin/env python3
"""supabase/network_alert_title.sql: app='Network' alerts get their own email wording.
Part A is static (every old line survives, one new branch). Part B replays the real function in a
throwaway postgres:16-alpine (local docker, or on a host via EG_TEST_SSH=<host>) with a STUBBED
sender; SKIPs if neither is available. Synthetic data only. Run: python3 tests/test_network_alert_title.py"""
import os, re, subprocess, sys, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NEW = (ROOT / "supabase" / "network_alert_title.sql").read_text()
OLD = (ROOT / "supabase" / "explicit_search_red_and_digest_fix.sql").read_text()
fn = lambda t: re.search(r"create or replace function public\.eg_on_red\(\).*?\nend \$\$;\n", t, re.S).group(0)
fails = []
def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok: fails.append(name)

print("A. static")
old_lines, new_lines = fn(OLD).splitlines(), fn(NEW).splitlines()
it = iter(new_lines)
check("every old line survives, in order", all(any(l == n for n in it) for l in old_lines))
start = NEW.index("  -- NEW (2026-10-20): router network monitor")
end = NEW.index("  if NEW.app = 'EyeGuard' or NEW.reason like 'tamper:%' then")
check("removing the Network branch gives back the old function exactly",
      (fn(NEW).replace(NEW[start:end], "") == fn(OLD)) and start < end)
check("redefines only eg_on_red", re.findall(r"create or replace function (\S+)", NEW) == ["public.eg_on_red()"])
check("recipients untouched: eg_send_email is not (re)defined", "function public.eg_send_email" not in NEW)
check("branch sits before the tamper branch", NEW.index("app = 'Network'") < NEW.index("tamper:%"))
check("reason is HTML-escaped", "'&amp;'" in NEW and "'&lt;'" in NEW)

ssh = os.environ.get("EG_TEST_SSH")
def sh(cmd, inp=None):
    full = ["ssh", ssh] + [" ".join(cmd)] if ssh else cmd
    return subprocess.run(full, input=inp, capture_output=True, text=True)
if sh(["docker", "image", "inspect", "postgres:16-alpine"]).returncode != 0:
    print("B. SKIP (no docker/postgres:16-alpine)"); sys.exit(1 if fails else 0)

name = "egnat-" + uuid.uuid4().hex[:8]
def psql(sql):
    r = sh(["docker", "exec", "-i", name, "psql", "-U", "postgres", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1"], sql)
    if r.returncode: print(r.stderr[:600])
    return r.stdout.strip()
try:
    sh(["docker", "run", "-d", "--rm", "--name", name, "-e", "POSTGRES_PASSWORD=x", "postgres:16-alpine"])
    for _ in range(40):
        if sh(["docker", "exec", name, "pg_isready", "-U", "postgres"]).returncode == 0: break
        time.sleep(1)
    time.sleep(2)
    psql("""
create table public.flags(id serial primary key, flagged_at timestamptz default now(), app text, reason text,
  url text, window_title text, is_nudity boolean default false, verdict text);
create table public.sent(id serial, subject text, body text);
create function public.eg_send_email(s text, b text) returns void language sql as
  $$ insert into public.sent(subject, body) values (s, b) $$;
""")
    psql(fn(NEW).replace("$$;", "$$;"))
    psql("create trigger t after insert on public.flags for each row execute function public.eg_on_red();")
    ins = lambda app, reason, nud="false": psql(
        f"insert into public.flags(app, reason, verdict, is_nudity) values ('{app}', '{reason}', 'flagged', {nud});")
    ins("Network", "net-bypass: connection to iCloud Private Relay mask-api.icloud.com from Jadas-iPhone: 192.168.8.113, home LAN")
    ins("Network", "net-signal: explicit domain example.test from <b>Tablet</b> & co: 192.168.8.9, home LAN")
    ins("Chrome", "signal: explicit term - foo")
    ins("EyeGuard", "tamper: something")
    ins("Photos", "nudity", "true")
    rows = psql("select subject || ' | ' || body from public.sent order by id").splitlines()
    print("B. behaviour")
    check("exactly 5 emails (one per row, none lost)", len(rows) == 5)
    check("Network bypass: own subject, names the device, no image wording",
          "network bypass signal" in rows[0] and "Jadas-iPhone" in rows[0] and "image" not in rows[0].lower().replace("no image", ""))
    check("Network explicit: own subject", "explicit site on the home network" in rows[1])
    check("device name is HTML-escaped", "&lt;b&gt;Tablet&lt;/b&gt; &amp; co" in rows[1] and "<b>Tablet" not in rows[1])
    check("search branch unchanged", "explicit search or URL" in rows[2])
    check("tamper branch unchanged", "tampering detected" in rows[3])
    check("image alert unchanged (nudity)", "Explicit nudity" in rows[4])
finally:
    sh(["docker", "rm", "-f", name])
print("FAILED: " + ", ".join(fails) if fails else "ALL OK")
sys.exit(1 if fails else 0)
