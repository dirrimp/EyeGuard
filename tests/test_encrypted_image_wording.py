#!/usr/bin/env python3
"""Offline test for the encrypted-image wording change (no Postgres, no network).
Emulates the SQL's read-live-text / swap-one-sentence step on the committed eg_on_red() text.
Run: python3 tests/test_encrypted_image_wording.py"""
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

new_sql = (ROOT / "supabase" / "encrypted_image_wording.sql").read_text()
OLD = re.search(r"old_s constant text := '(.*?)';", new_sql).group(1)
NEW = re.search(r"new_s constant text := '(.*?)';", new_sql).group(1)
live = (ROOT / "supabase" / "network_alert_title.sql").read_text()   # newest committed eg_on_red()
fn = live[live.index("create or replace function public.eg_on_red"):live.index("end $$;")]

check("the old sentence appears exactly once in the newest eg_on_red()", fn.count(OLD) == 1, str(fn.count(OLD)))
out = fn.replace(OLD, NEW)
check("the new sentence replaces it", NEW in out and OLD not in out)
check("only that sentence changed (every other line identical)",
      [l for a, b in zip(fn.splitlines(), out.splitlines()) if a != b for l in (a,)] == [l for l in fn.splitlines() if OLD in l])
check("the new text has no % or single quote (cannot break format() or the string)", "%" not in NEW and "'" not in NEW)
check("format placeholders are unchanged", fn.count("%s") == out.count("%s"))
check("subject lines and recipients untouched (no eg_send_email edits)",
      re.findall(r"eg_send_email\(\s*'[^']*'", fn) == re.findall(r"eg_send_email\(\s*'[^']*'", out))
check("the SQL fails closed (raises unless exactly one match)", "n <> 1" in new_sql and "raise exception" in new_sql)
live_sql = "\n".join(l for l in new_sql.splitlines() if not l.lstrip().startswith("--"))
check("the SQL touches only eg_on_red() (no other function, no eg_send_email)",
      live_sql.count("public.eg_on_red()") >= 1 and "eg_send_email" not in live_sql
      and re.findall(r"public\.(\w+)\(\)", live_sql) == ["eg_on_red"] * len(re.findall(r"public\.(\w+)\(\)", live_sql)))
check("the old claim is nowhere in the new wording", "is on the dashboard: " not in NEW)

h = (ROOT / "docs" / "index.html").read_text()
check("dashboard does not fetch signed URLs for .enc frames", re.search(r"filter\(r=>r\.image_path && !isEnc\(r\.image_path\)\)", h))
check("an .enc frame renders a lock placeholder, never an <img>",
      "const img = isEnc(r.image_path)" in h and 'class="thumb-enc"' in h)
check("a non-.enc image still renders as before", '<img class="thumb" src="${url}" loading="lazy">' in h)
check("the footer no longer promises a viewable image", "flags carry a review image," not in h and "viewing key" in h)
check("'see image' wording is gone from the dashboard cards", "— see image" not in h)

print("\nFAILED: " + ", ".join(fails) if fails else "\nALL OK")
sys.exit(1 if fails else 0)
