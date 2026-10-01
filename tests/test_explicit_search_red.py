#!/usr/bin/env python3
"""Explicit URL/search hits are RED (2026-10-01); OCR'd on-screen text stays
YELLOW. Also checks the SQL that words the email. Run:
`python3 tests/test_explicit_search_red.py`."""
import json, sys, tempfile, importlib.util, types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

# logger.py only needs log_text(); load it without importing the whole package.
src = (ROOT / "eyeguard" / "logger.py").read_text()
import ast
tree = ast.parse(src)
cls = next(n for n in tree.body if isinstance(n, ast.ClassDef)
           and any(isinstance(m, ast.FunctionDef) and m.name == "log_text" for m in n.body))
fn = next(m for m in cls.body if isinstance(m, ast.FunctionDef) and m.name == "log_text")
mod = ast.Module(body=[ast.ImportFrom("__future__", [ast.alias("annotations")], 0),
                       ast.ImportFrom("datetime", [ast.alias("datetime"), ast.alias("timezone")], 0),
                       ast.Import([ast.alias("json")]), fn], type_ignores=[])
ns = {}
exec(compile(ast.fix_missing_locations(mod), "logger_log_text", "exec"), ns)
d = Path(tempfile.mkdtemp())
me = types.SimpleNamespace(flag_log=d / "flags.jsonl")
ctx = {"app": "Zen", "url": "https://example.com/search?q=x", "window_title": "x"}

r = ns["log_text"](me, ["porn"], "url", ctx, red=True)
check("URL/search hit with red=True is verdict flagged", r["verdict"] == "flagged", str(r))
check("... graded Likely / high", r["grade"] == "Likely" and r["risk"] == "high")
check("... reason starts 'signal:' (what eg_on_red's new branch matches)", r["reason"].startswith("signal: "))
check("... still imageless", r.get("no_image") is True)
r = ns["log_text"](me, ["porn"], "url", ctx)
check("URL/search hit inside the repeat window (red=False) stays yellow", r["verdict"] == "alert")
r = ns["log_text"](me, ["porn", "nude"], "screen", ctx)
check("on-screen OCR text stays yellow", r["verdict"] == "alert" and r["reason"].startswith("text: "))
check("every record was written to the flag log", len((d / "flags.jsonl").read_text().splitlines()) == 3)

menu = (ROOT / "eyeguard" / "menubar.py").read_text()
check("menubar passes red= to log_text for URL hits", 'logger.log_text(hits, "url", actx, red=red)' in menu)
check("menubar leaves OCR hits unchanged", 'logger.log_text(hits, "screen", ctx))' in menu)
check("red repeat window defaults to 600s", '"signal_red_repeat_seconds", 600' in menu)

sql = (ROOT / "supabase" / "explicit_search_red_and_digest_fix.sql").read_text()
old = (ROOT / "supabase" / "findmy_ToS_gap_and_stale_backstop.sql").read_text()
i = old.index("create or replace function public.eg_on_red() returns trigger")
old_fn = old[i:old.index("end $$;", i)].split("\n")
new_lines = set(sql.split("\n"))
missing = [l for l in old_fn if l not in new_lines]
check("every line of the newest committed eg_on_red() is preserved", not missing, str(missing[:3]))
check("new branch sits before the tamper branch",
      sql.index("like 'signal:%' then") < sql.index("if NEW.app = 'EyeGuard' or NEW.reason like 'tamper:%' then"))
check("phone-dark branch is still first", sql.index("like 'phone-dark%' then") < sql.index("like 'signal:%' then"))
check("digest excludes Jada's dark rows", "reason not like 'jada-phone-dark%'" in sql)
code = "\n".join(l for l in sql.splitlines() if not l.strip().startswith("--"))
check("eg_send_email() is not redefined", "function public.eg_send_email(" not in code)

print()
if fails:
    print(f"FAILED: {len(fails)} — {fails}"); sys.exit(1)
print("all passed")
