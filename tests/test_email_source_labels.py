#!/usr/bin/env python3
"""supabase/email_source_labels.sql in a real throwaway Postgres: every alert email is tagged with its source, nothing else changes.
Synthetic data only. Part A static (no docker), Part B real Postgres.
Run: EG_DOCKER="ssh g11 docker" EG_REQUIRE_SQL=1 python3 tests/test_email_source_labels.py"""
import json, os, re, shlex, shutil, subprocess, sys, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SQL = (ROOT / "supabase/email_source_labels.sql").read_text()
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

print("A. static")
check("the SQL Dad copies is pure ASCII", all(ord(c) < 128 for c in SQL))
live = re.sub(r"--[^\n]*", "", SQL)
check("it calls no mail API and hand-types no sender (the guard test's rules)", "api.resend" + ".com" not in SQL and not re.search(r"'from'\s*,", live) and "alerts@" not in SQL)
check("no placeholder, key or token", "CHANGE-ME" not in SQL and ".invalid" not in SQL and not re.search(r"eyJ[A-Za-z0-9_-]{20,}|PRIVATE KEY", SQL))
check("the wrappers and helpers are closed to every API role",
      len(re.findall(r"revoke execute on function[^;]*from public, anon, authenticated, service_role", live)) >= 3
      and "grant execute" not in live)
check("labelling failure falls back to the original email", "exception when others" in live and "ns := subject; nh := html;" in live)

# every subject literal the repo's SQL can send, with the sender it goes through
def sender_for(fname):
    if fname.startswith("jada_"): return "jada"
    if fname.startswith(("mdm_", "g11_", "onn_")): return "mdm"
    return "main"
def unescape(lit):
    lit = lit.replace("''", "'")
    return re.sub(r"\\u([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), re.sub(r"\\U([0-9A-Fa-f]{8})", lambda m: chr(int(m.group(1), 16)), lit))
subjects = {}
for f in sorted((ROOT / "supabase").glob("*.sql")):
    if f.name in ("email_source_labels.sql", "phase4_pause.sql"): continue
    for m in re.finditer(r"""E?'((?:[^'\n]|'')*?EyeGuard(?:[^'\n]|'')*)'""", f.read_text()):
        t = unescape(m.group(1))
        if len(t) < 14 or "<" in t or "%" in t.split("EyeGuard")[0] or t.startswith("EyeGuard <"): continue
        if re.match(r"^\W*EyeGuard( alert)?\b", t) is None: continue
        subjects[(t, sender_for(f.name))] = f.name
print(f"  ({len(subjects)} distinct subject literals found in the repo's SQL)")

print("B. real Postgres")
dock = shlex.split(os.environ.get("EG_DOCKER", "docker"))
have = shutil.which(dock[0]) and subprocess.run(dock + ["image", "inspect", "postgres:16-alpine"], capture_output=True).returncode == 0
if not have:
    if os.environ.get("EG_REQUIRE_SQL") == "1": check("SQL tests could run", False, "docker/postgres:16-alpine unavailable")
    else: print("  [skip] docker/postgres:16-alpine unavailable")
else:
    name = "egsrc-" + uuid.uuid4().hex[:8]
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
        # stand-ins for Dad's three live senders: same names, same signature, same privileges; they record what they were given
        psql("""
create role anon nologin; create role authenticated nologin; create role service_role nologin;
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
        out = psql(SQL)[0].splitlines()[-1]
        cols = out.split("|")
        check("the file's own verify select is all true (raw_still_sends is false here only because the stand-in does not call the mail API)",
              len(cols) == 8 and [c for i, c in enumerate(cols) if i != 3] == ["t"] * 7 and cols[3] == "f", out)
        psql(SQL)
        check("re-running is a no-op (still wrapped once, raw senders unchanged)",
              val("select count(*) from pg_proc where proname in ('eg_send_email_raw','eg_send_email_jada_raw','eg_send_email_mdm_raw')") == "3")

        def send(fn, subj, html="<p>x</p>"):
            psql("delete from public.sent;")
            psql(f"select public.{fn}($q${subj}$q$, $q${html}$q$);")
            return psql("select subject || E'\\x1f' || html from public.sent;")[0].split("\x1f")

        s, h = send("eg_send_email", "⚫ EyeGuard — monitoring went dark")
        check("a Mac alert is tagged in the subject, after the emoji and the word EyeGuard", s == "⚫ EyeGuard [Jonah's Mac] — monitoring went dark", s)
        check("and the body starts with the source line, original body kept", h == "<p><b>Source: Jonah's Mac</b></p><p>x</p>", h)
        check("exactly one email is sent per call", val("select count(*) from public.sent") == "1")

        print("every known subject has a source")
        EXPECT_NOT_UNKNOWN = []
        bad = []
        for (subj, via), fname in sorted(subjects.items()):
            fn = {"main": "eg_send_email", "jada": "eg_send_email_jada", "mdm": "eg_send_email_mdm"}[via]
            ns, nh = send(fn, subj)
            if "Source: not identified" in nh: bad.append(f"{fname}: {subj[:60]}")
        # dynamic subjects (a name or kind is appended at send time)
        for subj, via in [("📲 EyeGuard — new app on iPhone: Some App", "mdm"), ("📵 EyeGuard — iPhone app monitoring cannot reach the phone", "mdm"),
                          ("🔴 EyeGuard alert — Explicit nudity", "main"), ("🔴 EyeGuard alert — Very revealing content", "main"),
                          ("🗳️ EyeGuard — app request", "mdm"), ("🚫 EyeGuard — app blocked", "mdm")]:
            fn = {"main": "eg_send_email", "jada": "eg_send_email_jada", "mdm": "eg_send_email_mdm"}[via]
            ns, nh = send(fn, subj)
            if "Source: not identified" in nh: bad.append(f"dynamic: {subj}")
        check("no known email subject is left 'not identified' (add new subjects to eg_email_source)", not bad, "; ".join(bad[:8]))

        print("the four named sources")
        cases = [
            ("eg_send_email", "⚫ EyeGuard — monitoring went dark", "<p>x</p>", "Jonah's Mac"),
            ("eg_send_email", "🚨 EyeGuard — lost view of the screen", "<p>x</p>", "Jonah's Mac"),
            ("eg_send_email", "⚫ EyeGuard — session watcher went dark", "<p>x</p>", "Jonah's Mac"),
            ("eg_send_email", "🔴 EyeGuard alert — Explicit nudity", "<p><b>Where:</b> Zen — x</p>", "Jonah's Mac"),
            ("eg_send_email", "🔴 EyeGuard — explicit search or URL", "<p>x</p>", "Jonah's Mac"),
            ("eg_send_email", "📵 EyeGuard — phone went dark", "<p>x</p>", "Jonah's Phone"),
            ("eg_send_email", "🔑 EyeGuard — Find My session expired, needs immediate refresh", "<p>x</p>", "Jonah's Phone"),
            ("eg_send_email", "🔴 EyeGuard — phone hit an explicit site", "<p>x</p>", "Jonah's Phone"),
            ("eg_send_email_jada", "📵 EyeGuard — Jada's phone went dark", "<p>x</p>", "Jada's Phone"),
            ("eg_send_email_jada", "🔴 EyeGuard — anything at all", "<p>x</p>", "Jada's Phone"),
            ("eg_send_email_mdm", "📲 EyeGuard — new app on iPhone: Mac Photos", "<p>x</p>", "Jonah's Phone"),
            ("eg_send_email_mdm", "🚨 EyeGuard — the Onn detector may be broken", "<p>x</p>", "TV"),
            ("eg_send_email_mdm", "🛑 EyeGuard — the Onn TV monitor STOPPED reporting", "<p>x</p>", "TV"),
            ("eg_send_email", "🔴 EyeGuard alert — Explicit nudity", "<p><b>Where:</b> Onn TV — Chrome</p>", "TV"),
            ("eg_send_email", "🔴 EyeGuard — explicit site on the home network", "<p>x</p>", "Home network"),
            ("eg_send_email", "⚫ EyeGuard — router watcher offline", "<p>x</p>", "Router"),
            ("eg_send_email", "📊 EyeGuard weekly summary", "<p>x</p>", "All devices"),
            ("eg_send_email_mdm", "🚨 EyeGuard — G11 code differs from what Dad approved", "<p>x</p>", "Home server (G11)"),
        ]
        for fn, subj, html, want in cases:
            ns, nh = send(fn, subj, html)
            check(f"{want:<18} <- {subj[:58]}", f"[{want}]" in ns and f"Source: {want}" in nh, ns)

        print("the wording hook")
        ns, nh = send("eg_send_email", "⚫ EyeGuard — monitoring went dark", "<p>keep</p>")
        check("the hook is the identity today", ns == "⚫ EyeGuard [Jonah's Mac] — monitoring went dark" and nh == "<p><b>Source: Jonah's Mac</b></p><p>keep</p>", ns)
        psql("create or replace function public.eg_email_adjust(via text, subject text, html text, out new_subject text, out new_html text) language plpgsql as $$ begin raise exception 'boom'; end $$;")
        ns, nh = send("eg_send_email", "⚫ EyeGuard — monitoring went dark", "<p>keep</p>")
        check("a failing hook keeps the LABELLED email (still sent, once)", ns == "⚫ EyeGuard [Jonah's Mac] — monitoring went dark" and val("select count(*) from public.sent") == "1", ns)
        psql("create or replace function public.eg_email_adjust(via text, subject text, html text, out new_subject text, out new_html text) language plpgsql as $$ begin new_subject := subject; new_html := html; end $$;")

        print("nothing else changes")
        ns, nh = send("eg_send_email", "weird subject without the brand", "<p>y</p>")
        check("a subject without 'EyeGuard' gets a leading tag, and is still sent", ns.startswith("[") and "weird subject" in ns, ns)
        psql("create or replace function public.eg_email_label(via text, subject text, html text, out new_subject text, out new_html text) language plpgsql as $$ begin raise exception 'boom'; end $$;")
        ns, nh = send("eg_send_email", "⚫ EyeGuard — monitoring went dark", "<p>keep</p>")
        check("if labelling raises, the ORIGINAL email is sent unchanged (an alert can never be lost to a label bug)",
              ns == "⚫ EyeGuard — monitoring went dark" and nh == "<p>keep</p>", ns)
        check("the wrappers cannot be called by the public key",
              "permission denied" in psql("set role anon; select public.eg_send_email('a','b');", err_ok=True)[1]
              and "permission denied" in psql("set role anon; select public.eg_send_email_raw('a','b');", err_ok=True)[1])
    finally:
        subprocess.run(dock + ["rm", "-f", name], capture_output=True)

if fails:
    print("\nFAILED:", *fails, sep="\n  "); sys.exit(1)
print("\nALL OK")
