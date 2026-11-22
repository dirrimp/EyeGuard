#!/usr/bin/env python3
"""Find My cross-check for Jada's phone: watcher device matching (A) and the server change in a real throwaway
Postgres (B, supabase/jada_findmy_crosscheck.sql). Synthetic names/data only.
Run: EG_DOCKER="ssh g11 docker" EG_REQUIRE_SQL=1 python3 tests/test_jada_findmy_crosscheck.py"""
import os, re, shlex, shutil, subprocess, sys, time, uuid
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
SQL = (ROOT / "supabase/jada_findmy_crosscheck.sql").read_text()
BASE = (ROOT / "supabase/jada_phone.sql").read_text()
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

print("A. watcher device matching")
from eyeguard import findmy_watcher as fw
class Dev:
    def __init__(s, name, disp, ts=None): s._n, s._d, s._ts, s.asked = name, disp, ts, 0
    def status(s): return {"name": s._n, "deviceDisplayName": s._d}
    @property
    def location(s):
        s.asked += 1
        return {"timeStamp": s._ts} if s._ts else None
devs = [Dev("Jonah’s iPhone", "iPhone SE", 1000), Dev("Jonah Dirrim’s iPhone", "iPhone 16", 2000),
        Dev("Patrick Dirrim’s iPhone", "iPhone 16", 3000), Dev("Jonah Dirrim’s iPhone", "iPhone 12", 4000),
        Dev("Old phone", "iPhone 7", None), Dev("StudBunny", "AirPods", 5000)]
prim, ext = fw._collect_last_seen(devs, "jonah’s iphone", {"jada": ["jonah dirrim", "iphone 16"]})
check("Jonah's phone still matches by the old single substring and only that one", [c[0] for c in prim] == [1000])
check("Jada's iPhone 16 matches on both words", [c[0] for c in ext["jada"]] == [2000], str(ext))
check("Dad's iPhone 16 does NOT match (needs 'jonah dirrim' too)", 3000 not in [c[0] for c in ext["jada"]])
check("an older iPhone under the same name does NOT match (needs 'iphone 16')", 4000 not in [c[0] for c in ext["jada"]])
check("devices that match nothing are never asked for a location", devs[4].asked == 0 and devs[5].asked == 0 and devs[2].asked == 0 and devs[3].asked == 0)
prim2, ext2 = fw._collect_last_seen(devs, "jonah’s iphone", None)
check("no extra phones configured -> identical to the old behaviour", [c[0] for c in prim2] == [1000] and ext2 == {})
_, ext3 = fw._collect_last_seen([Dev("Jonah Dirrim’s iPhone", "iPhone 16", None)], "x", {"jada": ["jonah dirrim", "iphone 16"]})
check("a matching device with no live location is not reported (fail-safe: no data, no suppression)", ext3["jada"] == [])
src = (ROOT / "eyeguard/findmy_watcher.py").read_text()
co = src[src.index("    def check_once(self):"):src.index("    def run(self")] if "    def run(self" in src else src[src.index("    def check_once(self):"):]
check("the Jada report is inside its own try and cannot stop Jonah's report",
      co.index('self._rpc("eg_report_findmy_status"') < co.index("_EXTRA_PHONE_RPC.get(key)") and "Jonah's report is unaffected" in co)
check("the new RPC is the only new server call", src.count("eg_report_findmy_status_jada") == 1)
cfg = (ROOT / "config.yaml").read_text()
check("config.yaml names Jada's phone with BOTH words, lowercase", 'jada_device_name_contains: ["jonah dirrim", "iphone 16"]' in cfg)

print("B. static SQL")
live = re.sub(r"--[^\n]*", "", SQL)
check("the SQL Dad copies is pure ASCII", all(ord(c) < 128 for c in SQL))
check("no mail API, no sender typed by hand, no key", "api.resend" + ".com" not in SQL and "alerts@" not in SQL and not re.search(r"eyJ[A-Za-z0-9_-]{20,}", SQL))
check("it patches the live text and carries no copy of the function", "create or replace function public.eg_on_jada_flag" not in live.lower())
check("the new RPC is anon-callable but nothing else is granted", live.count("grant execute") == 1 and "to anon" in live)
check("the sustained-dark and MONITOR-offline functions are not touched",
      "eg_check_phone_jada" not in live)

print("C. real Postgres")
dock = shlex.split(os.environ.get("EG_DOCKER", "docker"))
have = shutil.which(dock[0]) and subprocess.run(dock + ["image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1": check("SQL tests could run", False, "docker/postgres:16-alpine unavailable")
    else: print("  [skip] docker/postgres:16-alpine unavailable")
else:
    name = "egjf-" + uuid.uuid4().hex[:8]
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
create table public.sent(id serial, subject text, html text);
create function public.eg_send_email_jada(subject text, html text) returns void language plpgsql security definer as $$
  begin insert into public.sent(subject, html) values (subject, html); end $$;
create table public.phone_status_jada(id int primary key, last_dark_email_at timestamptz);
insert into public.phone_status_jada values (1, null);
create table public.flags(id serial primary key, flagged_at timestamptz default now(), app text, verdict text, reason text);
""")
        m = re.search(r"create or replace function public\.eg_on_jada_flag\(\).*?\nend \$\$;", BASE, re.S)
        t = re.search(r"drop trigger if exists eg_jada_alert.*?execute function public\.eg_on_jada_flag\(\);", BASE, re.S)
        check("found the committed function and trigger in jada_phone.sql", bool(m and t))
        psql(m.group(0)); psql(t.group(0))

        def dark(reset=True):
            if reset: psql("delete from public.sent; update public.phone_status_jada set last_dark_email_at = null where id = 1;")
            psql("insert into public.flags(app, verdict, reason) values ('Jada''s iPhone', 'alert', 'jada-phone-dark: silent for 168s');")
            return [r for r in psql("select subject from public.sent order by id;")[0].splitlines() if r]
        def setfm(seen_ago, rep_ago):
            f = lambda x: "null" if x is None else f"now() - interval '{x} minutes'"
            psql(f"update public.phone_status_jada set findmy_last_seen = {f(seen_ago)}, findmy_reported_at = {f(rep_ago)} where id = 1;")

        print("C1. before the change the committed trigger emails every time")
        check("baseline: a dark flag sends the email", len(dark()) == 1)

        out = psql(SQL)[0].splitlines()[-1].split("|")
        check("the file's own verify select is all true (6 columns)", out == ["t"] * 6, str(out))
        after = val("select md5(pg_get_functiondef('public.eg_on_jada_flag()'::regprocedure))")
        psql(SQL)
        check("re-running is a no-op", val("select md5(pg_get_functiondef('public.eg_on_jada_flag()'::regprocedure))") == after)

        print("C2. the false case is quiet, everything else still alerts")
        setfm(None, None)
        check("no Find My data at all -> still emails (fail-safe)", len(dark()) == 1)
        setfm(5, 1)
        e = dark()
        check("Find My saw her 5 minutes ago and the report is 1 minute old -> no email", e == [], str(e))
        check("...and the debounce timer was not used up",
              val("select last_dark_email_at is null from public.phone_status_jada where id = 1") == "t")
        check("...and the flag row is still recorded", val("select count(*) from public.flags where reason like 'jada-phone-dark%'") != "0")
        setfm(19, 1)
        check("seen 19 minutes ago -> still quiet (inside 20)", dark() == [])
        setfm(25, 1)
        e = dark()
        check("seen 25 minutes ago -> emails", len(e) == 1, str(e))
        check("...and the wording no longer claims there is no Find My check",
              "There is no Find My cross-check" not in val("select html from public.sent order by id desc limit 1")
              and "Find My has not placed this phone" in val("select html from public.sent order by id desc limit 1"))
        setfm(5, 30)
        check("seen 5 minutes ago but the Find My report is 30 minutes old (watcher stopped) -> emails", len(dark()) == 1)
        setfm(120, 1)
        check("not seen for 2 hours -> emails", len(dark()) == 1)
        setfm(5, 1)
        psql("delete from public.sent;")
        psql("insert into public.flags(app, verdict, reason) values ('Jada''s iPhone', 'flagged', 'explicit site example.invalid');")
        check("an explicit-site flag still emails even while Find My says she is nearby",
              val("select count(*) from public.sent where subject like '%explicit site%'") == "1")
        setfm(30, 1)
        dark()
        check("the 30-minute debounce still works",
              len(dark(reset=False)) == 1)   # first dark() sent one; this second one (no reset) must add none -> list still has just the first
        check("...exactly one email in that window", val("select count(*) from public.sent where subject like '%went dark%'") == "1")

        print("C3. the RPC")
        psql("select public.eg_report_findmy_status_jada(now() - interval '3 minutes');")
        check("a normal report sets both columns",
              val("select findmy_last_seen is not null and findmy_reported_at is not null from public.phone_status_jada where id = 1") == "t")
        before_seen = val("select findmy_last_seen from public.phone_status_jada where id = 1")
        psql("select public.eg_report_findmy_status_jada(now() + interval '2 hours');")
        check("a time in the future is ignored (cannot pre-silence the alert)",
              val("select findmy_last_seen from public.phone_status_jada where id = 1") == before_seen)
        check("the public key can call the RPC",
              val("select has_function_privilege('anon','public.eg_report_findmy_status_jada(timestamptz)','execute')") == "t")

        print("C4. refuses to patch a function it does not recognise")
        psql("create or replace function public.eg_on_jada_flag() returns trigger language plpgsql as $$ begin return new; end $$;")
        _, err, rc = psql(SQL, err_ok=True)
        check("unknown live function -> error, nothing changed", rc != 0 and "exactly once" in err, err[-300:])
    finally:
        subprocess.run(dock + ["rm", "-f", name], capture_output=True)

print()
if fails:
    print("FAILED:"); [print("  " + f) for f in fails]; sys.exit(1)
print("ALL OK")
