#!/usr/bin/env python3
"""Offline test for the session-based digest (supabase/digest_sessions.sql). No Postgres here, so:
 (1) static checks on the SQL text (same filter, nothing dropped, placeholders match, guard present);
 (2) the session logic (lag + running sum of gap>10 min) run for real in SQLite and compared with a plain-Python
     reference on synthetic timestamps. Timestamps only: no flag content. Run: python3 tests/test_digest_sessions.py"""
import random, re, sqlite3, sys
from datetime import datetime, timedelta
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

sql = (ROOT / "supabase" / "digest_sessions.sql").read_text()
live = "\n".join(l for l in sql.splitlines() if not l.lstrip().startswith("--"))
fn = live[live.index("create or replace function public.eg_daily_digest"):live.rindex("end $$;")]
old = __import__("subprocess").run(["git", "show", "origin/main:supabase/explicit_search_red_and_digest_fix.sql"],
                                    cwd=ROOT, capture_output=True, text=True).stdout

# ---- static ----
check("same row filter as the 2026-10-01 digest (alert, 24 h, jada-phone-dark excluded)",
      "verdict = 'alert'" in fn and "interval '24 hours'" in fn and "reason not like 'jada-phone-dark%'" in fn)
check("old digest has the same filter (nothing newly excluded)",
      all(x in old for x in ["verdict = 'alert'", "interval '24 hours'", "reason not like 'jada-phone-dark%'"]))
check("still stays quiet only when there are zero items", "if n = 0 then return; end if;" in fn)
check("still sends through eg_send_email, link to the dashboard kept",
      fn.count("perform public.eg_send_email(") == 1 and "https://dirrimp.github.io/EyeGuard/" in fn)
check("item count and session count both reported", "%s session(s), %s item(s)" in fn and "viewing session(s)" in fn)
body = fn[fn.index("format('<p><b>%s suggestive"):]
check("format placeholders match arguments (4 in the body)",
      body.split("'<a href")[0].count("%s") + body.count("</ul>%s") >= 3 and
      len(re.findall(r"%s", body[:body.index("n, s, coalesce")])) == 4)
check("the app name is HTML-escaped in the list", "'&amp;'" in fn and "'&lt;'" in fn and "'&gt;'" in fn)
check("the list is capped at 12 sessions and says so", "limit 12" in fn and "Showing the 12 most recent" in fn)
check("refuses to overwrite a hand-edited live function", "raise exception" in sql and "position('jada-phone-dark'" in sql)
check("touches only eg_daily_digest (no other function, no cron change)",
      re.findall(r"create or replace function (public\.\w+)", live) == ["public.eg_daily_digest"] and "cron." not in live)
check("RED alerts untouched (no eg_on_red edit)", "eg_on_red" not in live)
check("a read-only preview and a rollback note are included", "PREVIEW" in sql and "Rollback" in sql)

# ---- logic: same shape as the SQL (lag + running sum of gaps > 10 min), executed in SQLite ----
def sqlite_sessions(times):
    c = sqlite3.connect(":memory:"); c.execute("create table f(t text)")
    c.executemany("insert into f values (?)", [(t.strftime("%Y-%m-%d %H:%M:%S"),) for t in times])
    return c.execute("""
      with a as (select t, lag(t) over (order by t) as prev from f),
           g as (select t, sum(case when prev is null or cast(strftime('%s', t) as integer) - cast(strftime('%s', prev) as integer) > 600 then 1 else 0 end)
                              over (order by t) as sess from a)
      select count(*), count(distinct sess) from g""").fetchone()
def ref_sessions(times):
    ts = sorted(times); s = 0; prev = None
    for t in ts:
        if prev is None or (t - prev) > timedelta(minutes=10): s += 1
        prev = t
    return len(ts), s

base = datetime(2026, 11, 15, 12, 0, 0)
check("no rows -> 0 items, 0 sessions (email stays quiet)", ref_sessions([]) == (0, 0))
check("one row is one session", sqlite_sessions([base]) == (1, 1))
burst = [base + timedelta(seconds=15 * i) for i in range(200)]
check("200 rows 15 s apart are ONE session", sqlite_sessions(burst) == (200, 1))
two = burst + [base + timedelta(hours=3, seconds=15 * i) for i in range(50)]
check("a 3 h gap starts a second session", sqlite_sessions(two) == (250, 2))
check("exactly 10 min apart stays one session, 10 min 1 s splits",
      sqlite_sessions([base, base + timedelta(minutes=10)]) == (2, 1)
      and sqlite_sessions([base, base + timedelta(minutes=10, seconds=1)]) == (2, 2))
check("identical timestamps do not split a session", sqlite_sessions([base, base, base]) == (3, 1))
random.seed(7); ok = True
for _ in range(200):
    n = random.randint(1, 60)
    ts = [base + timedelta(seconds=random.randint(0, 6 * 3600)) for _ in range(n)]
    if sqlite_sessions(ts) != ref_sessions(ts): ok = False
check("200 random timelines: SQL-shaped logic == plain reference", ok)
check("item count is never reduced by sessionising (every row still counted)",
      all(sqlite_sessions(t)[0] == len(t) for t in (burst, two)))

print("\nFAILED: " + ", ".join(fails) if fails else "\nALL OK")
sys.exit(1 if fails else 0)
