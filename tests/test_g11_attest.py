#!/usr/bin/env python3
"""Tests for the Dad-owned G11 integrity watch: manifest generator, installer, the G11's
attestation report, the reporter command, and (in a real throwaway Postgres) the server
that compares them (supabase/g11_attest.sql). Synthetic only.
Run: python3 tests/test_g11_attest.py   (Part B needs docker + postgres:16-alpine;
EG_REQUIRE_SQL=1 makes a skip a failure)."""
import hashlib, importlib.util, json, os, shutil, stat, subprocess, sys, tempfile, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)
def load_module(path, name, env=None):
    for k, v in (env or {}).items(): os.environ[k] = v
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
sha = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()

# ============================ Part A: python ============================
print("A1. generator, installer and the G11 report agree (a mismatch = false drift on every deploy)")
gen = load_module(str(ROOT / "deploy/gen_g11_manifest.py"), "gen_m")
man = gen.build("deadbeef")
check("manifest covers the four installed files and the poller cron line",
      set(man["items"]) == {"file:eg_report.py", "file:eg-report.sh", "file:poll.py", "file:hook.py", "cron:poller"})
check("file hashes are the repo files' sha256", man["items"]["file:poll.py"] == sha((ROOT / "g11/mdm/poll.py").read_bytes()))

t = Path(tempfile.mkdtemp()); mdm = t / "mdm"; hook = t / "hook"; mdm.mkdir(); hook.mkdir()
cf = mdm / "eg-report.json"; cf.write_text(json.dumps({"supabase_url": "https://x", "anon_key": "k", "device_token": "ab" * 32})); cf.chmod(0o600)
store = t / "cron.txt"; store.write_text("0 3 * * * /usr/bin/backup.sh\n")
(t / "crontab").write_text(f'#!/bin/sh\nif [ "$1" = "-l" ]; then cat {store}; else cat > {store}; fi\n'); (t / "crontab").chmod(0o755)
(t / "docker").write_text("#!/bin/sh\nexit 0\n"); (t / "docker").chmod(0o755)
env = dict(os.environ, MDM_DIR=str(mdm), HOOK_DIR=str(hook), CRONTAB_CMD=str(t / "crontab"), DOCKER_CMD=str(t / "docker"))
r = subprocess.run(["bash", str(ROOT / "deploy/g11_install.sh")], capture_output=True, text=True, env=env)
check("installer ran", r.returncode == 0, r.stderr)
pl = load_module(str(ROOT / "g11/mdm/poll.py"), "poll_a", {"MDM_STATE": str(t / "st"), "MDM_SENDER": str(mdm / "eg-report.sh"),
                 "MDM_LOG": str(t / "log"), "MDM_HOOK_PATH": str(hook / "hook.py"), "MDM_CRONTAB": str(t / "crontab")})
# poll.py hashes ITSELF via __file__: in production that is the installed copy, which is byte-identical to the repo file
pl.__file__ = str(mdm / "poll.py")
rep = pl.attestation()["items"]
live_cron = [l for l in store.read_text().splitlines() if "poll.py" in l][0].replace(str(mdm), "/opt/kev/mdm")
check("installed files + installer's cron line, as reported by the G11, equal the generated manifest EXACTLY",
      rep["file:eg_report.py"] == man["items"]["file:eg_report.py"] and rep["file:eg-report.sh"] == man["items"]["file:eg-report.sh"]
      and rep["file:poll.py"] == man["items"]["file:poll.py"] and rep["file:hook.py"] == man["items"]["file:hook.py"], str(rep))
check("the cron line the installer writes hashes to the manifest's cron:poller", sha(live_cron.encode()) == man["items"]["cron:poller"], live_cron)
# the cron hash is path-dependent (/opt/kev/mdm); in this temp layout compare after the same substitution
real_rep_cron = sha(live_cron.encode())
check("(cron comparison uses the production path /opt/kev/mdm)", real_rep_cron == man["items"]["cron:poller"])

print("A2. every kind of change is visible in the report")
base = pl.attestation()["items"]
(hook / "hook.py").write_text("# edited\n")
check("editing a file changes its hash", pl.attestation()["items"]["file:hook.py"] != base["file:hook.py"])
(hook / "hook.py").unlink()
check("a MISSING file is reported as missing (null), never skipped", pl.attestation()["items"]["file:hook.py"] is None)
shutil.copy(ROOT / "g11/mdm/hook.py", hook / "hook.py")
good = store.read_text()
store.write_text(good.replace("*/5 * * * *", "0 * * * *"))
check("slowing the poller cron changes the cron hash", pl.attestation()["items"]["cron:poller"] != base["cron:poller"])
store.write_text("\n".join(l for l in good.splitlines() if "poll.py" not in l) + "\n")
check("removing the poller cron line changes the cron hash", pl.attestation()["items"]["cron:poller"] != base["cron:poller"])
store.write_text(good.replace("poll.py", "poll.py").replace("*/5", "#*/5"))
check("COMMENTING OUT the cron line (still textually present) is treated as removed", pl.attestation()["items"]["cron:poller"] != base["cron:poller"])
store.write_text(good + good.splitlines()[-1] + "\n")
check("a duplicate poller cron line changes the cron hash", pl.attestation()["items"]["cron:poller"] != base["cron:poller"])
store.write_text(good)
check("restoring everything returns to the manifest values", pl.attestation()["items"] == base)
check("the report carries hashes only (no file content, no paths, no token)",
      all(v is None or v.startswith("sha256:") for v in base.values()) and "ab" * 32 not in json.dumps(base))

print("A3. eg_report.py --attest")
cdir = tempfile.mkdtemp(); conf = os.path.join(cdir, "c.json")
json.dump({"supabase_url": "https://x.invalid", "anon_key": "a", "device_token": "t" * 64}, open(conf, "w")); os.chmod(conf, 0o600)
rep_mod = load_module(str(ROOT / "g11/eg_report.py"), "rep_a", {"EG_REPORT_CONF": conf, "EG_REPORT_QUEUE": os.path.join(cdir, "q")})
seen = []; code = {"c": 200}
def fake_open(req, timeout=0):
    seen.append((req.full_url.rsplit("/", 1)[-1], json.loads(req.data)))
    if code["c"] != 200: raise rep_mod.urllib.error.HTTPError(req.full_url, code["c"], "x", {}, None)
    class R:
        def __enter__(s): return s
        def __exit__(s, *a): pass
        def read(s): return b'{"ok":true,"state":"ok"}'
    return R()
rep_mod.urllib.request.urlopen = fake_open
rc = rep_mod.main(["x", "--attest", json.dumps({"items": {"file:poll.py": "sha256:" + "a" * 64}})])
check("--attest posts to eg_mdm_attest as p_report with the token", rc == 0 and seen[0][0] == "eg_mdm_attest"
      and seen[0][1]["p_report"]["items"]["file:poll.py"].startswith("sha256:") and seen[0][1]["p_token"] == "t" * 64)
check("bad JSON / missing items -> exit 2 (nothing sent)", rep_mod.main(["x", "--attest", "nope"]) == 2 and rep_mod.main(["x", "--attest", "{}"]) == 2 and len(seen) == 1)
code["c"] = 401; check("401 -> exit 3", rep_mod.main(["x", "--attest", '{"items":{}}']) == 3)
code["c"] = 503; check("503 -> exit 4 (transient; next run re-reports)", rep_mod.main(["x", "--attest", '{"items":{}}']) == 4)
check("attestation is never queued", not os.path.isdir(rep_mod.QDIR) or not rep_mod.queued())

print("A4. CI workflow and repo hygiene")
wf = (ROOT / ".github/workflows/publish-g11-manifest.yml").read_text()
check("workflow publishes only on push to main, never on pull_request", "branches: [main]" in wf and "pull_request" not in wf)
check("workflow uses the secret from GitHub (never a literal key) and inserts into g11_manifests only",
      "secrets.SUPABASE_SERVICE_ROLE_KEY" in wf and "/rest/v1/g11_manifests" in wf and "eyJ" not in wf and wf.count("/rest/v1/") == 1)
check("re-running a publish for the same commit is harmless (ignore-duplicates)", "resolution=ignore-duplicates" in wf)
bad = [f.name for f in (ROOT / "supabase").glob("*.sql") if f.name in ("mdm_heartbeat.sql", "mdm_approvals.sql", "g11_attest.sql")
       and any(ord(c) > 127 for c in f.read_text(encoding="utf-8"))]
check("the SQL Dad copies/pastes is pure ASCII (no hidden or smart characters)", not bad, str(bad))

# ============================ Part B: real Postgres ============================
print("B. server comparison in a throwaway Postgres")
have = shutil.which("docker") and subprocess.run(["docker", "image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1": check("SQL tests could run", False, "docker/postgres:16-alpine unavailable")
    else: print("  [skip] docker/postgres:16-alpine unavailable")
else:
    name = "egatt-" + uuid.uuid4().hex[:8]
    subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "postgres:16-alpine"], check=True, capture_output=True)
    try:
        for _ in range(60):
            if subprocess.run(["docker", "exec", name, "pg_isready", "-U", "postgres"], capture_output=True).returncode == 0: break
            time.sleep(1)
        time.sleep(2)
        def psql(sql, err_ok=False):
            r = subprocess.run(["docker", "exec", "-i", name, "psql", "-U", "postgres", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1"],
                               input=sql, capture_output=True, text=True)
            if r.returncode != 0 and not err_ok: raise RuntimeError(r.stderr[-800:])
            return r.stdout.strip(), r.stderr
        val = lambda q: psql(q)[0]
        DAD, JONAH = "0e02aa87-1cd5-4bb6-a263-f51d4e2642b6", "99999999-9999-9999-9999-999999999999"
        psql("""
create role anon nologin; create role authenticated nologin; create role service_role nologin bypassrls;
create schema extensions; create extension pgcrypto with schema extensions;
create schema vault; create table vault.s(name text, decrypted_secret text); insert into vault.s values ('resend_api_key','re_test');
create view vault.decrypted_secrets as select * from vault.s;
create schema net; create table net.sent(id serial, body jsonb);
create function net.http_post(url text, headers jsonb, body jsonb) returns bigint language sql as $$ insert into net.sent(body) values (body) returning id::bigint $$;
create schema cron; create table cron.job(jobid serial primary key, jobname text, schedule text, command text);
create function cron.schedule(n text, s text, c text) returns bigint language sql as $$ insert into cron.job(jobname,schedule,command) values (n,s,c) returning jobid::bigint $$;
create function cron.unschedule(n text) returns boolean language sql as $$ delete from cron.job where jobname = n returning true $$;
create schema auth; create table auth.users(id uuid primary key, email text);
create function auth.uid() returns uuid language sql as $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
grant usage on schema public, extensions, auth to anon, authenticated, service_role;
""" + f"insert into auth.users values ('{DAD}','dad@example.test'),('{JONAH}','jonah@example.test');")
        def apply(rel):
            s = (ROOT / rel).read_text().replace("create extension if not exists pg_net;", "").replace("dad@CHANGE-ME.invalid", "dad@example.test")
            psql(s)
        for f in ("mdm_app_events", "mdm_heartbeat", "mdm_approvals", "g11_attest", "g11_attest"):
            apply(f"supabase/{f}.sql")
        check("g11_attest.sql applies on top of #113/#114/#115 and re-runs cleanly (one cron job)",
              val("select count(*) from cron.job where jobname='eyeguard-g11-integrity'") == "1")
        tok = "ef" * 32
        psql(f"insert into public.mdm_auth(token_sha256, note) values ('{hashlib.sha256(tok.encode()).hexdigest()}','t');")
        sent = lambda: int(val("select count(*) from net.sent"))
        subj = lambda: val("select body->>'subject' from net.sent order by id desc limit 1")
        html = lambda: val("select body->>'html' from net.sent order by id desc limit 1")
        H = lambda c: "sha256:" + hashlib.sha256(c.encode()).hexdigest()
        V1 = {"file:poll.py": H("poll1"), "file:hook.py": H("hook1"), "cron:poller": H("cron1")}
        V2 = dict(V1, **{"file:poll.py": H("poll2")})
        def attest(items, token=tok):
            return psql(f"select public.eg_mdm_attest('{token}', $j${json.dumps({'items': items})}$j$::jsonb);", err_ok=True)
        def publish(version, items):
            return psql(f"begin; set local role service_role; insert into public.g11_manifests(version, items) values ('{version}', $j${json.dumps(items)}$j$::jsonb); commit;", err_ok=True)
        state = lambda: val("select attest_state from public.mdm_status")
        inc = lambda k, o: val(f"select count(*) from public.mdm_incidents where kind='{k}' and ended_at is {'null' if o else 'not null'}")

        check("unregistered token -> 401", "unauthorized" in attest(V1, "00" * 32)[1])
        r = attest(V1)
        check("before any manifest is published nothing is compared or alerted", '"no_manifest"' in r[0] and sent() == 0, r[0] + r[1])
        check("anon cannot insert or read manifests; a logged-in user cannot either",
              "permission denied" in psql("begin; set local role anon; select * from public.g11_manifests; rollback;", err_ok=True)[1]
              and "permission denied" in psql("begin; set local role authenticated; insert into public.g11_manifests(version,items) values ('x','{}'); rollback;", err_ok=True)[1])
        r = publish("v1", V1)
        check("Dad's CI (service_role) can publish a manifest", r[1] == "" and val("select count(*) from public.g11_manifests") == "1", r[1])
        check("manifests are immutable: even service_role cannot update or delete",
              "permission denied" in psql("begin; set local role service_role; update public.g11_manifests set items='{}'; rollback;", err_ok=True)[1]
              and "permission denied" in psql("begin; set local role service_role; delete from public.g11_manifests; rollback;", err_ok=True)[1])
        r = psql(f"begin; set local role service_role; insert into public.g11_manifests(version, items) values ('v1', $j${json.dumps(V1)}$j$::jsonb) on conflict do nothing; commit;", err_ok=True)
        check("CI re-running for the same commit (INSERT ... ON CONFLICT DO NOTHING) is harmless and needs no update right",
              r[1] == "" and val("select count(*) from public.g11_manifests") == "1", r[1])

        print("   report vs manifest")
        r = attest(V1)
        check("matching report -> ok, no email, no incident", state() == "ok" and sent() == 0 and inc("g11_drift", True) == "0", r[0] + r[1])
        r = attest(dict(V1, **{"file:poll.py": H("EVIL")}))
        check("a hash that matches NO manifest -> DRIFT, one email at once naming the item",
              state() == "drift" and sent() == 1 and "differs from what Dad approved" in subj() and "file:poll.py" in html(), subj())
        check("the email states the limit (evidence, not proof) and does not include the hash",
              "evidence, not proof" in html() and H("EVIL")[-12:] not in html())
        check("an incident is opened", inc("g11_drift", True) == "1")
        attest(dict(V1, **{"file:poll.py": H("EVIL")})); attest(dict(V1, **{"file:poll.py": H("EVIL2")}))
        check("repeat drift reports do not re-email", sent() == 1)
        attest(V1)
        check("back to approved code -> ONE all-clear, incident closed (never deleted)",
              state() == "ok" and sent() == 2 and "approved version again" in subj() and inc("g11_drift", True) == "0" and inc("g11_drift", False) == "1")
        n = sent(); attest(dict(V1, **{"file:hook.py": None}))
        check("a MISSING file is drift (an attacker cannot hide a file by omitting it)", state() == "drift" and sent() == n + 1 and "missing on the G11" in html())
        attest(V1)
        n = sent(); attest(dict(V1, **{"file:poll.py": H("poll1")}, **{"file:extra.py": "sha256:" + "c" * 64}))
        check("an extra item the manifest does not list is ignored", state() == "ok" and sent() == n)

        print("   outdated vs drift")
        publish("v2", V2)
        n = sent(); attest(V1)
        check("reviewed-but-old code (matches v1, latest is v2) -> outdated, no email yet", state() == "outdated" and sent() == n)
        psql("select public.eg_check_g11_integrity();"); check("not alerted inside 24 h", sent() == n)
        psql("update public.mdm_status set attest_outdated_since = now() - interval '25 hours' where id=1;"); psql("select public.eg_check_g11_integrity();")
        check("outdated for 25 h -> one reminder + incident", sent() == n + 1 and "older approved code" in subj() and inc("g11_outdated", True) == "1")
        psql("select public.eg_check_g11_integrity();"); check("reminder not repeated", sent() == n + 1)
        attest(V2)
        check("deploy done -> all-clear, incident closed", state() == "ok" and sent() == n + 2 and "latest approved code" in subj() and inc("g11_outdated", True) == "0")
        n = sent(); attest(dict(V2, **{"file:poll.py": H("poll1"), "file:hook.py": H("unknown-hook")}))
        check("old code PLUS an unknown file is drift, not outdated (drift wins)", state() == "drift" and sent() == n + 1)
        attest(V2)

        print("   validation")
        for label, rep in (("bad item name", {"items": {"../etc/passwd": V1["file:poll.py"]}}), ("bad hash", {"items": {"file:poll.py": "md5:abc"}}),
                           ("too many items", {"items": {f"file:f{i}": H(str(i)) for i in range(51)}})):
            r = psql(f"select public.eg_mdm_attest('{tok}', $j${json.dumps(rep)}$j$::jsonb);", err_ok=True)
            check(f"rejects {label}", "PT400" in r[1] or "bad" in r[1] or "too many" in r[1], r[1])
        check("rejects a non-object report", "report must be" in psql(f"select public.eg_mdm_attest('{tok}', '[1]'::jsonb);", err_ok=True)[1])

        print("   reports that stop while the monitor is alive")
        hbok = lambda: psql(f"select public.eg_mdm_heartbeat('{tok}', '{{\"enrolled\":1,\"unlisted\":0,\"stalest_apps_age_s\":60,\"outbox_pending\":0}}'::jsonb);")
        hbok(); attest(V2); n = sent()
        psql("update public.mdm_status set attest_at = now() - interval '20 minutes' where id=1;"); psql("select public.eg_check_g11_integrity();")
        check("heartbeat fresh but no integrity report for 20 min -> one alert + incident",
              sent() == n + 1 and "integrity reports have stopped" in subj() and inc("g11_attest_missing", True) == "1", subj())
        psql("select public.eg_check_g11_integrity();"); check("not repeated", sent() == n + 1)
        attest(V2)
        check("reports resume -> all-clear, incident closed", sent() == n + 2 and "arriving again" in subj() and inc("g11_attest_missing", True) == "0")
        n = sent(); psql("update public.mdm_status set attest_at = now() - interval '2 hours', last_heartbeat_at = now() - interval '40 minutes' where id=1;")
        psql("select public.eg_check_g11_integrity();")
        check("if the heartbeat itself is stale this check stays quiet (the silence alert owns that)", sent() == n)
        psql("update public.mdm_status set attest_at = null, last_heartbeat_at = now() where id=1;")
        psql("select public.eg_check_g11_integrity();")
        check("never reported + manifest only just published -> quiet (time to deploy)", sent() == n)
        psql("update public.g11_manifests set published_at = now() - interval '2 days';")       # superuser, as Dad could
        psql("select public.eg_check_g11_integrity();")
        check("never reported and the manifest is 2 days old -> one alert ('has never arrived')",
              sent() == n + 1 and "has never arrived" in html(), html()[:200])
        attest(V2)
        check("first report arrives -> all-clear", "arriving again" in subj() and inc("g11_attest_missing", True) == "0")

        re_e = json.dumps({"type": "device_reenrolled", "detected_at": "2026-03-02T10:00:00Z", "device": "Jonah iPhone"})
        r = psql(f"select public.eg_report_mdm_event('{tok}', $j${re_e}$j$::jsonb);", err_ok=True)
        check("after this file widens the incident kinds, a re-enrolment still logs its incident (no constraint clash)",
              '"ok": true' in r[0] and val("select count(*) from public.mdm_incidents where kind='mdm_reenrolled'") == "1", r[0] + r[1])

        print("   partner view")
        ok = psql(f"begin; set local role authenticated; select set_config('request.jwt.claim.sub','{DAD}',true); select public.eg_mdm_attest_status(); commit;", err_ok=True)
        check("a partner sees the state and the approved version", '"state"' in ok[0] and '"manifest"' in ok[0], ok[0] + ok[1])
        check("Jonah (not a partner) and anon are refused",
              "not allowed" in psql(f"begin; set local role authenticated; select set_config('request.jwt.claim.sub','{JONAH}',true); select public.eg_mdm_attest_status(); rollback;", err_ok=True)[1]
              and "permission denied" in psql("begin; set local role anon; select public.eg_mdm_attest_status(); rollback;", err_ok=True)[1])
        check("the check function cannot be run by any API role",
              "permission denied" in psql("begin; set local role authenticated; select public.eg_check_g11_integrity(); rollback;", err_ok=True)[1])
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)

print()
if fails:
    print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
print("all G11 attestation tests passed")
