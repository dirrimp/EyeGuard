#!/usr/bin/env python3
"""Phone battery -> "Phone dead" wording. Part A: G11 python (hook records the battery, poller reports it once, reporter --battery).
Part B: supabase/phone_battery.sql on top of supabase/email_source_labels.sql in a real throwaway Postgres.
Synthetic data only. Run: EG_DOCKER="ssh g11 docker" EG_REQUIRE_SQL=1 python3 tests/test_phone_battery.py"""
import base64, hashlib, importlib.util, json, os, plistlib, re, shlex, shutil, stat, subprocess, sys, tempfile, time, uuid
from datetime import datetime, timedelta, timezone
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
def ack(qr):
    pl = {"Status": "Acknowledged", "QueryResponses": qr}
    return {"udid": "UDID-TEST-1", "raw_payload": base64.b64encode(plistlib.dumps(pl)).decode()}

print("A1. hook.py records a battery answer")
st = tempfile.mkdtemp()
h = load_module(str(ROOT / "g11/mdm/hook.py"), "hook_b", {"HOOK_STATE": st})
h.handle_checkin({"udid": "UDID-TEST-1", "message_type": "Authenticate"})
dev = lambda: json.load(open(Path(st) / "devices.json"))["UDID-TEST-1"]
h.handle_ack(ack({"BatteryLevel": 0.04}))
check("0.04 is stored as 4 percent with a time", dev().get("battery") == 4 and dev().get("battery_at"), str(dev()))
h.handle_ack(ack({"IsSupervised": True, "BatteryLevel": 0.5}))
check("supervision and battery in one answer are both kept", dev().get("battery") == 50 and dev().get("supervised") is True)
for bad in (-1.0, 1.5, True, "0.3"):
    before = dict(dev())
    h.handle_ack(ack({"BatteryLevel": bad}))
    check(f"BatteryLevel {bad!r} is ignored (unknown / invalid)", dev().get("battery") == before.get("battery") and dev().get("battery_at") == before.get("battery_at"))
h.handle_ack(ack({"BatteryLevel": 0.0}))
check("0.0 is a valid reading (0 percent)", dev().get("battery") == 0)

print("A2. poll.py reports a reading once, only when fresh")
pst = tempfile.mkdtemp(); rec = Path(pst) / "rec"; sender = Path(pst) / "sender.sh"
def mk_sender(rc): sender.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" >> {rec}\nexit {rc}\n'); sender.chmod(0o755)
mk_sender(0)
pl = load_module(str(ROOT / "g11/mdm/poll.py"), "poll_b", {"MDM_STATE": pst, "MDM_SENDER": str(sender), "MDM_LOG": str(Path(pst) / "log")})
def put(**kw): json.dump({"u1": dict({"enrolled": True, "name": "d"}, **kw)}, open(Path(pst) / "devices.json", "w"))
iso = lambda dt: dt.replace(microsecond=0).isoformat()
now = datetime.now(timezone.utc)
put(battery=4, battery_at=iso(now - timedelta(seconds=120)))
pl.report_battery()
calls = rec.read_text().split() if rec.exists() else []
check("a fresh reading is sent as --battery <pct> <age>", calls[:2] == ["--battery", "4"] and 115 <= int(calls[2]) <= 130, str(calls))
rec.unlink(); pl.report_battery()
check("the same reading is not sent twice", not rec.exists())
put(battery=3, battery_at=iso(now - timedelta(seconds=30)))
pl.report_battery()
check("a newer reading is sent", rec.exists() and rec.read_text().split()[:2] == ["--battery", "3"])
rec.unlink(); put(battery=4, battery_at=iso(now - timedelta(hours=7)))
pl.report_battery()
check("a reading older than 6 hours is not sent", not rec.exists())
put(); pl.report_battery()
check("no reading, nothing sent", not rec.exists())
mk_sender(4); put(battery=9, battery_at=iso(now - timedelta(seconds=10))); pl.report_battery()
rec.unlink()
mk_sender(0); pl.report_battery()
check("a failed send is retried next run (not marked reported)", rec.exists() and rec.read_text().split()[:2] == ["--battery", "9"])
enq = []
pl.api_key = lambda: "k"; pl.enqueue = lambda u, k: 200; pl.push = lambda u, k: 200
pl.enqueue_command = lambda u, k, r: enq.append(r) or "cid"
put(last_apps_at=iso(now), last_seen=iso(now))
json.dump({}, open(Path(pst) / "poll-state.json", "w"))
pl.main()
check("each normal poll also queues a BatteryLevel question", any(r.get("Queries") == ["BatteryLevel"] for r in enq), str(enq))
check("the wake-up poke also asks for it", '"IsSupervised", "BatteryLevel"' in (ROOT / "g11/mdm/poke_listener.py").read_text())

print("A3. eg_report.py --battery")
tmp = tempfile.mkdtemp(); conf = os.path.join(tmp, "c.json")
json.dump({"supabase_url": "https://x.invalid", "anon_key": "anon", "device_token": "t" * 64}, open(conf, "w")); os.chmod(conf, 0o600)
rep = load_module(str(ROOT / "g11/eg_report.py"), "rep_b", {"EG_REPORT_CONF": conf, "EG_REPORT_QUEUE": os.path.join(tmp, "q"), "EG_REPORT_TIMEOUT": "2"})
seen = []
def fake_open(req, timeout=0):
    seen.append((req.full_url, json.loads(req.data)))
    class R:
        def __enter__(s): return s
        def __exit__(s, *a): pass
        def read(s): return b"{}"
    return R()
rep.urllib.request.urlopen = fake_open
check("--battery 4 120 posts to eg_mdm_battery with the token and both numbers",
      rep.main(["x", "--battery", "4", "120"]) == 0 and seen[0][0].endswith("/rpc/eg_mdm_battery") and seen[0][1] == {"p_token": "t" * 64, "p_pct": 4, "p_age_s": 120}, str(seen))
check("bad numbers are rejected before any request", rep.main(["x", "--battery", "101", "0"]) == 2 and rep.main(["x", "--battery", "4", "-1"]) == 2 and rep.main(["x", "--battery", "x", "1"]) == 2 and len(seen) == 1)

print("B. SQL (real Postgres)")
SQL_L = (ROOT / "supabase/email_source_labels.sql").read_text()
SQL_B = (ROOT / "supabase/phone_battery.sql").read_text()
check("the SQL Dad copies is pure ASCII, no placeholder, no mail API", all(ord(c) < 128 for c in SQL_B) and "CHANGE-ME" not in SQL_B and ("api.resend" + ".com") not in SQL_B)
check("no function other than the RPC and the hook is defined, and only the RPC is granted to anon",
      sorted(re.findall(r"create or replace function public\.([a-z_]+)", re.sub(r"--[^\n]*", "", SQL_B))) == ["eg_email_adjust", "eg_mdm_battery"]
      and len(re.findall(r"grant execute on function[^;]*to anon", re.sub(r"--[^\n]*", "", SQL_B))) == 1)
dock = shlex.split(os.environ.get("EG_DOCKER", "docker"))
have = shutil.which(dock[0]) and subprocess.run(dock + ["image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1": check("SQL tests could run", False, "docker/postgres:16-alpine unavailable")
    else: print("  [skip] docker/postgres:16-alpine unavailable")
else:
    name = "egbat-" + uuid.uuid4().hex[:8]
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

        DARK = "📵 EyeGuard — phone went dark"
        BODY = "<p><b>The iPhone stopped routing through the monitored network.</b></p><p>When: Nov 19, 09:57 PM. The VPN may be off.</p>"
        def send(fn, subj, html=BODY):
            psql("delete from public.sent;")
            psql(f"select public.{fn}($q${subj}$q$, $q${html}$q$);")
            r = psql("select subject || E'\\x1f' || html from public.sent;")[0].split("\x1f")
            return r[0], r[1]
        def beat(pct, age=0):
            return psql(f"select public.eg_mdm_battery('{tok}', {pct}, {age});", err_ok=True)

        print("no reading yet: nothing changes")
        s, h2 = send("eg_send_email", DARK)
        check("with no reading the dark email is the normal labelled one", s == "📵 EyeGuard [Jonah's Phone] — phone went dark" and "Phone dead" not in h2, s)

        print("the RPC")
        check("a wrong token is refused", "unauthorized" in psql("select public.eg_mdm_battery('" + "00" * 32 + "', 4, 0);", err_ok=True)[1])
        for label, args in [("101 percent", (101, 0)), ("negative percent", (-1, 0)), ("age over 6 hours", (4, 21601)), ("negative age", (4, -1))]:
            check(f"{label} -> rejected", "bad info" in beat(*args)[1])
        check("anon without the token cannot read or write the table",
              "permission denied" in psql("set role anon; select * from public.phone_battery;", err_ok=True)[1]
              and "permission denied" in psql("set role anon; insert into public.phone_battery values (1, 1, now());", err_ok=True)[1])
        out, err = beat(4, 120)
        check("a valid reading is stored, with the time the phone answered", '"ok": true' in out and val("select pct from public.phone_battery") == "4"
              and 100 <= int(float(val("select extract(epoch from now() - read_at) from public.phone_battery"))) <= 140, out + err)
        beat(3, 600)
        check("an OLDER reading never replaces a newer one", val("select pct from public.phone_battery") == "4")
        beat(2, 5)
        check("a newer reading does", val("select pct from public.phone_battery") == "2")

        print("the wording")
        psql("update public.phone_battery set pct = 5, read_at = now() - interval '1 minute';")
        s, h2 = send("eg_send_email", DARK)
        check("at 5 percent the subject says Phone dead and gives the battery", s == "📵 EyeGuard [Jonah's Phone] — Phone dead (battery was 5%)", s)
        check("the body says it is an inference, gives the reading and its time, keeps the Source line first and the original text after",
              h2.startswith("<p><b>Source: Jonah's Phone</b></p><p><b>Phone dead:") and "5%" in h2 and "about 1 minute" in h2 and "inference" in h2 and "most likely" in h2
              and h2.endswith(BODY), h2)
        check("exactly one email is sent (it is reworded, never replaced by nothing)", val("select count(*) from public.sent") == "1")
        beat(6, 0)
        s, h2 = send("eg_send_email", DARK)
        check("at 6 percent the email is the normal one", "Phone dead" not in s and "Phone dead" not in h2 and s.endswith("phone went dark"), s)
        beat(4, 0); psql("update public.phone_battery set read_at = now() - interval '31 minutes';")
        s, h2 = send("eg_send_email", DARK)
        check("a reading older than 30 minutes is not used", "Phone dead" not in s, s)
        psql("update public.phone_battery set read_at = now() - interval '29 minutes';")
        check("a reading 29 minutes old is", "Phone dead" in send("eg_send_email", DARK)[0])
        s, _ = send("eg_send_email_jada", "📵 EyeGuard — Jada's phone went dark")
        check("Jada's phone email is never reworded by Jonah's battery", s == "📵 EyeGuard [Jada's Phone] — Jada's phone went dark", s)
        s, _ = send("eg_send_email", "⚫ EyeGuard — monitoring went dark")
        check("no other email is reworded", s == "⚫ EyeGuard [Jonah's Mac] — monitoring went dark", s)
        s, _ = send("eg_send_email", "📵 EyeGuard — phone on but unmonitored", "<p>x</p>")
        check("the 'phone on but unmonitored' email is untouched", "Phone dead" not in s, s)
        psql("update public.phone_battery set pct = 4, read_at = now();")
        psql("create or replace function public.eg_email_adjust(via text, subject text, html text, out new_subject text, out new_html text) language plpgsql as $$ begin raise exception 'boom'; end $$;")
        check("if the wording hook ever fails, the labelled email is still sent once", send("eg_send_email", DARK)[0].endswith("phone went dark") and val("select count(*) from public.sent") == "1")
    finally:
        subprocess.run(dock + ["rm", "-f", name], capture_output=True)

if fails:
    print("\nFAILED:", *fails, sep="\n  "); sys.exit(1)
print("\nALL OK")
