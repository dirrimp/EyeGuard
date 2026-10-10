#!/usr/bin/env python3
"""Repo-wide guard: EVERY EyeGuard email must go through the three known SQL sender functions
(whose sender comes from ONE place, eg_mail_from(), pinned to orthanc.me). Fails if a new file adds
another Resend call, hand-types another sender, or if non-SQL code starts sending mail itself.
No docker, no network. Run: python3 tests/test_mail_sender_guard.py"""
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

SQL = sorted((ROOT / "supabase").glob("*.sql"))
KNOWN_SENDERS = {"alerts.sql", "jada_phone.sql", "mdm_app_events.sql"}      # define the three functions
# files that may mention a sender literal: the three above, the historical switch note, the central file
LITERAL_OK = KNOWN_SENDERS | {"switch_sender_to_orthanc.sql", "central_mail_sender.sql", "align_alert_senders.sql"}

callers = sorted(f.name for f in SQL if "api.resend.com" in f.read_text())
check("only the three known SQL files call Resend directly", set(callers) == KNOWN_SENDERS, f"found {callers}")

central = ROOT / "supabase" / "central_mail_sender.sql"
c = central.read_text() if central.exists() else ""
check("central_mail_sender.sql exists and pins the sender to an orthanc.me address",
      bool(c) and "check (from_address ~" in c and "orthanc" in c)
check("it rewrites all three sender functions",
      all(n in c for n in ("eg_send_email(text,text)", "eg_send_email_jada(text,text)", "eg_send_email_mdm(text,text)")))
check("the config table is closed to every API role",
      "revoke all on public.eg_mail_config from public, anon, authenticated, service_role" in c
      and "revoke execute on function public.eg_mail_from() from public, anon, authenticated, service_role" in c)

stray = []
for f in SQL:
    if f.name in LITERAL_OK: continue
    for i, line in enumerate(f.read_text().splitlines(), 1):
        if re.search(r"'from'\s*,\s*'", line) and not line.lstrip().startswith("--"):
            stray.append(f"{f.name}:{i}")
check("no other SQL file hand-types a 'from' sender", not stray, ", ".join(stray))

bad_domain = []
for f in SQL:
    if f.name in LITERAL_OK: continue
    if re.search(r"alerts@(?!orthanc\.me)", f.read_text()):
        bad_domain.append(f.name)
check("no other SQL file mentions an alerts@ address on another domain", not bad_domain, ", ".join(bad_domain))

code_hits = []
pat = re.compile(r"api\.resend\.com|smtplib|sendmail|\bsmtp\b|mailgun|sendgrid|\bmsmtp\b", re.I)
for ext in ("*.py", "*.sh", "*.js", "*.yml", "*.yaml", "*.plist"):
    for f in ROOT.rglob(ext):
        rel = f.relative_to(ROOT).parts
        if rel[0] in ("tests", ".git", "node_modules"): continue
        if pat.search(f.read_text(errors="ignore")): code_hits.append("/".join(rel))
check("no Python/shell/JS/workflow code sends mail itself (all alerts go through the SQL senders)", not code_hits, ", ".join(code_hits))

print()
if fails: print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
print("all mail-sender guard checks passed")
