"""Render the JSONL flag log into a human-readable text file and a branded
live HTML report.

The HTML report mirrors the partner dashboard (docs/index.html) so the local
view and the remote view look and behave the same: a full-width top bar, stat
cards, Revealing/Suggestive/Browsing filters, and a responsive card grid that
fills a landscape desktop.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

_EMOJI = {"flagged": "🔴", "alert": "🟡", "review": "⚪", "clear": "🟢"}
_LABEL = {"flagged": "REVEALING", "alert": "suggestive", "review": "review",
          "clear": "browsing"}


def _fmt_record(rec: dict) -> str:
    # UTC ISO -> local, human time.
    try:
        ts = datetime.fromisoformat(rec["timestamp"]).astimezone()
        when = ts.strftime("%Y-%m-%d %I:%M:%S %p")
    except Exception:
        when = rec.get("timestamp", "?")
    v = rec.get("verdict", "?")
    emoji = _EMOJI.get(v, "•")
    label = _LABEL.get(v, v)

    app = rec.get("app") or "unknown app"
    where = rec.get("url") or rec.get("window_title")
    location = f"  ·  {where}" if where else ""

    # Pull the human bits out of the reason string (e.g. clip-yellow:0.92:tile5:...).
    reason = rec.get("reason", "")
    detail = reason.split("->")[-1].strip() if "->" in reason else reason

    return (f"{when}   {emoji} {label:9}  {app}{location}\n"
            f"        {detail}")


def write_readable(flag_log: str | Path, out_path: str | Path,
                   newest_first: bool = True) -> Path:
    src = Path(flag_log)
    out = Path(out_path)
    records = []
    if src.exists():
        with src.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    if newest_first:
        records = records[::-1]

    reds = sum(1 for r in records if r.get("verdict") == "flagged")
    yellows = sum(1 for r in records if r.get("verdict") == "alert")
    header = (f"EyeGuard flag log — generated {datetime.now().strftime('%Y-%m-%d %I:%M %p')}\n"
              f"{len(records)} entries  ·  {reds} explicit (red)  ·  {yellows} suggestive (yellow)\n"
              f"(newest first)\n"
              + "=" * 72 + "\n\n")
    with out.open("w") as f:
        f.write(header)
        if not records:
            f.write("No flags recorded.\n")
        for r in records:
            f.write(_fmt_record(r) + "\n\n")
    return out


# ---------------------------------------------------------------------------
# Branded HTML report — mirrors the partner dashboard.
# ---------------------------------------------------------------------------

# The eye logo (white), inlined so the report is a single self-contained file.
_EYE_SVG = (
    '<svg viewBox="0 0 100 100" width="30" height="30" fill="none">'
    '<path stroke="#fff" stroke-width="2.5" d="M5.5,50 C25.5,21 74.5,21 94.5,50 '
    'C74.5,79 25.5,79 5.5,50 Z"/><path fill="#fff" fill-rule="evenodd" '
    'd="M12.5,50 C31,28 69,28 87.5,50 C69,72 31,72 12.5,50 Z M45.5,49 A5.5,5.5 '
    '0 1 1 54.5,49 L53,57.5 L47,57.5 Z"/></svg>'
)


def _esc(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _local(rec: dict) -> datetime | None:
    try:
        return datetime.fromisoformat(rec["timestamp"]).astimezone()
    except Exception:
        return None


def _what(rec: dict) -> str:
    """Plain-language description of what was detected.

    RED is the immediate-alert tier (very revealing OR nude). CLIP can't reliably
    tell a string bikini from nudity, so we DON'T parrot its raw "exposed
    genitals" match — that would mislabel clothed-but-revealing content as nudity.
    Show an honest generic line and let the thumbnail show the specifics.
    """
    reason0 = rec.get("reason") or ""
    if reason0.startswith("phone"):
        return _esc(reason0.split(":", 1)[-1].strip()) + " (iPhone, via network)"
    if reason0.startswith("drm"):
        return ("Not a content flag — macOS blanks DRM-protected video, so "
                "EyeGuard couldn't view it. The title is logged so you can "
                "review it yourself.")
    if reason0.startswith("tamper"):
        return _esc(reason0.split(":", 1)[-1].strip()) + \
            " — a possible attempt to defeat monitoring."
    if reason0.startswith("extension"):
        return _esc(reason0.split(":", 1)[-1].strip()) + \
            " — review whether it's legitimate."
    if reason0.startswith("vm"):
        return _esc(reason0.split(":", 1)[-1].strip()) + \
            " — review whether it's legitimate."
    if reason0.startswith("text"):
        return "Explicit text on screen — " + \
            _esc(reason0.split("—", 1)[-1].strip())
    if reason0.startswith("signal"):
        return "Explicit term in the URL / search — " + \
            _esc(reason0.split("—", 1)[-1].strip())
    if rec.get("verdict") == "flagged":
        # NudeNet (trained nudity detector, runs first) fires on ACTUAL exposed
        # body parts, not bikinis — so a nudenet hit means real nudity.
        if (rec.get("reason") or "").startswith("nudenet"):
            return "explicit nudity / exposed body — see image"
        return "very revealing content — see image"
    # YELLOW: the matched suggestive concept is accurate (bikini, gym, etc.).
    reason = rec.get("reason", "")
    if ":" in reason:
        tail = reason.split(":")[-1].strip()
    elif reason.startswith("nudenet"):
        tail = "exposed skin"
    else:
        tail = reason.strip()
    return _esc(tail or "flagged content")


def _where(rec: dict) -> str:
    app = rec.get("app") or "an app"
    loc = rec.get("url") or rec.get("window_title")
    return _esc(app) + (f" — {_esc(loc)}" if loc else "")


def _thumb(rec: dict, report_dir: Path) -> str:
    """A thumbnail <img> if the flagged frame was saved to disk."""
    p = rec.get("saved_frame")
    if not p:
        return ""
    path = Path(p)
    if not path.is_absolute():
        path = report_dir / path
    if not path.exists():
        return ""
    # file:// URL so it loads regardless of how the report was opened.
    return f'<img class="thumb" src="file://{_esc(str(path))}" loading="lazy">'


def _card(rec: dict, dt: datetime, report_dir: Path) -> str:
    """One feed card — matches the partner dashboard's markup."""
    time = dt.strftime("%-I:%M %p")
    verdict = rec.get("verdict", "")
    # GREEN: a clean browsing record — no image, just where + when.
    if verdict == "clear":
        return (f'<div class="card green"><div class="body"><div class="rtop">'
                f'<span class="time">{time}</span>'
                f'<span class="pill green">Browsing</span></div>'
                f'<div class="where">{_where(rec)}</div></div></div>')
    red = verdict == "flagged"
    sev = "red" if red else "yellow"
    _r = rec.get("reason") or ""
    if red:
        sev_txt = ("Phone" if _r.startswith("phone")
                   else "Tamper" if _r.startswith("tamper")
                   else "Nudity" if _r.startswith("nudenet")
                   else "Revealing")
    elif _r.startswith("drm"):
        sev_txt = "DRM Video"
    elif _r.startswith("extension"):
        sev_txt = "Extension"
    elif _r.startswith("vm"):
        sev_txt = "Virtualization"
    elif _r.startswith("text"):
        sev_txt = "Text"
    elif _r.startswith("signal") or _r.startswith("phone"):
        sev_txt = "Phone" if _r.startswith("phone") else "Search"
    else:
        sev_txt = "Suggestive"
    grade = rec.get("grade") or ""
    gcls = {"Likely": "g-hi", "Possible": "g-mid", "Borderline": "g-lo"}.get(grade, "")
    grade_html = f'<span class="grade {gcls}">{grade}</span>' if grade else ""
    return (f'<div class="card {sev}">{_thumb(rec, report_dir)}'
            f'<div class="body"><div class="rtop">'
            f'<span class="time">{time}</span>'
            f'<span class="pill {sev}">{sev_txt}</span>{grade_html}</div>'
            f'<div class="where">{_where(rec)}</div>'
            f'<div class="what">{_what(rec)}</div></div></div>')


def write_html_report(flag_log: str | Path, out_path: str | Path,
                      days: int = 7, refresh: int = 0) -> Path:
    src, out = Path(flag_log), Path(out_path)
    records = []
    if src.exists():
        with src.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    records.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    reds = sum(1 for r in records if r.get("verdict") == "flagged")
    yellows = sum(1 for r in records if r.get("verdict") == "alert")
    greens = sum(1 for r in records if r.get("verdict") == "clear")

    # "Last activity" — the newest record of any kind.
    last_seen = ""
    for r in records:
        dt = _local(r)
        if dt:
            last_seen = "Last activity " + dt.strftime("%b %-d, %-I:%M %p")
            break

    # Group cards by local day.
    cards_by_day: dict[str, list[str]] = {}
    order: list[str] = []
    for r in records:
        dt = _local(r)
        if dt is None:
            continue
        day = dt.strftime("%A, %B %-d")
        if day not in cards_by_day:
            cards_by_day[day] = []
            order.append(day)
        cards_by_day[day].append(_card(r, dt, out.parent))

    sections = ""
    for day in order:
        sections += (f'<section class="day"><h2>{day}'
                     f'<span class="daycount">{len(cards_by_day[day])}</span></h2>'
                     f'<div class="grid">{"".join(cards_by_day[day])}</div>'
                     f'</section>')
    if not records:
        sections = '<div class="empty">NO ACTIVITY YET — ALL CLEAR ✓</div>'

    refresh_tag = (f'<meta http-equiv="refresh" content="{refresh}">'
                   if refresh and refresh > 0 else "")
    live_tag = ('<span class="live"><span class="dot"></span>Live</span>'
                if refresh and refresh > 0 else "")

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">{refresh_tag}
<title>EyeGuard Activity Report</title><style>
:root{{--bg:#0b0e12;--card:#151b22;--line:#2a333d;--ink:#eef2f6;--muted:#7e8a98;
--teal:#1b4b63;--red:#e5403a;--yellow:#f2a200;--green:#2fb85c;
--head:"Futura","Jost","Century Gothic","Trebuchet MS",sans-serif;
--body:"Helvetica Neue",Helvetica,Arial,sans-serif;}}
*{{box-sizing:border-box;}}html,body{{margin:0;}}
body{{background:var(--bg);color:var(--ink);font:15px/1.45 var(--body);min-height:100vh;}}

/* top bar (full width) */
.topbar{{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:16px;
padding:14px 28px;background:linear-gradient(135deg,#1b4b63,#08161f);
border-bottom:1px solid var(--line);}}
.topbar h1{{font-family:var(--head);font-size:19px;margin:0;font-weight:700;
text-transform:uppercase;letter-spacing:.07em;}}
.topbar .sub{{color:#a9c2cf;font-size:11px;text-transform:uppercase;letter-spacing:.06em;}}
.spacer{{flex:1;}}
.live{{display:inline-flex;align-items:center;gap:7px;color:var(--green);font-size:11px;
text-transform:uppercase;letter-spacing:.06em;}}
.dot{{width:8px;height:8px;border-radius:50%;background:var(--green);
animation:pulse 1.4s infinite;}}
@keyframes pulse{{0%,100%{{opacity:1;}}50%{{opacity:.25;}}}}
.seen{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em;}}

/* controls */
.controls{{display:flex;align-items:center;gap:20px;flex-wrap:wrap;
max-width:1680px;margin:0 auto;padding:18px 28px 4px;}}
.stats{{display:flex;gap:12px;}}
.stat{{background:var(--card);border:1px solid var(--line);border-top:3px solid var(--line);
padding:12px 20px;min-width:104px;}}
.stat .n{{font-family:var(--head);font-size:26px;font-weight:700;line-height:1;}}
.stat .l{{font-size:10.5px;color:var(--muted);margin-top:5px;text-transform:uppercase;
letter-spacing:.09em;font-weight:600;}}
.stat.red{{border-top-color:var(--red);}}.stat.red .n{{color:var(--red);}}
.stat.yellow{{border-top-color:var(--yellow);}}.stat.yellow .n{{color:var(--yellow);}}
.stat.green{{border-top-color:var(--green);}}.stat.green .n{{color:var(--green);}}
.filters{{display:flex;gap:8px;margin-left:auto;}}
.fbtn{{font-family:var(--head);font-size:12px;font-weight:700;text-transform:uppercase;
letter-spacing:.07em;color:var(--muted);background:var(--card);
border:1px solid var(--line);padding:10px 18px;cursor:pointer;}}
.fbtn.active{{color:var(--ink);border-color:#46c;background:#1d2630;}}
.fbtn[data-sev="red"].active{{border-color:var(--red);color:#ff8a85;}}
.fbtn[data-sev="yellow"].active{{border-color:var(--yellow);color:#ffc24d;}}
.fbtn[data-sev="green"].active{{border-color:var(--green);color:#5fd98a;}}

/* feed — wide grid that fills landscape */
.feed{{max-width:1680px;margin:0 auto;padding:8px 28px 60px;}}
.day{{margin-top:26px;}}
.day h2{{font-family:var(--head);font-size:13px;color:var(--muted);text-transform:uppercase;
letter-spacing:.1em;margin:0 0 12px;display:flex;align-items:center;gap:9px;font-weight:700;}}
.daycount{{background:var(--card);border:1px solid var(--line);padding:2px 9px;
font-size:11px;color:var(--muted);}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));
gap:14px;align-items:start;}}
.card{{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--line);
overflow:hidden;}}
.card.red{{border-left-color:var(--red);}}
.card.yellow{{border-left-color:var(--yellow);}}
.card.green{{border-left-color:var(--green);}}
.card img.thumb{{width:100%;height:190px;object-fit:cover;background:#000;display:block;
border-bottom:1px solid var(--line);cursor:pointer;}}
.card img.thumb:hover{{outline:2px solid #46c;outline-offset:-2px;}}
.card .body{{padding:11px 14px;}}
.card.green .body{{padding:9px 14px;}}
.rtop{{display:flex;align-items:center;gap:9px;flex-wrap:wrap;}}
.time{{font-family:var(--head);color:var(--muted);font-size:12px;letter-spacing:.03em;}}
.pill{{font-family:var(--head);font-size:10px;font-weight:700;padding:3px 10px;
text-transform:uppercase;letter-spacing:.06em;}}
.pill.red{{background:rgba(229,64,58,.18);color:#ff8a85;}}
.pill.yellow{{background:rgba(242,162,0,.18);color:#ffc24d;}}
.pill.green{{background:rgba(47,184,92,.16);color:#5fd98a;}}
.grade{{font-family:var(--head);font-size:9.5px;font-weight:700;padding:3px 8px;
text-transform:uppercase;letter-spacing:.06em;border:1px solid var(--line);}}
.grade.g-hi{{color:#ff8a85;border-color:#5a2b2b;}}
.grade.g-mid{{color:#ffc24d;border-color:#5a4a1f;}}
.grade.g-lo{{color:var(--muted);}}
.where{{font-weight:700;font-size:13.5px;margin-top:8px;word-break:break-word;}}
.card.green .where{{margin-top:7px;font-size:13px;}}
.what{{color:var(--muted);font-size:12px;margin-top:4px;}}
.empty{{font-family:var(--head);text-align:center;color:var(--green);padding:80px 0;
font-size:20px;letter-spacing:.05em;}}
footer{{color:var(--muted);font-size:11px;text-align:center;padding:24px;
text-transform:uppercase;letter-spacing:.04em;line-height:1.8;}}

/* filtering (CSS :has() hides days that end up empty) */
body[data-filter="red"] .card:not(.red),
body[data-filter="yellow"] .card:not(.yellow),
body[data-filter="green"] .card:not(.green){{display:none;}}
body[data-filter="red"] .day:not(:has(.card.red)),
body[data-filter="yellow"] .day:not(:has(.card.yellow)),
body[data-filter="green"] .day:not(:has(.card.green)){{display:none;}}

@media(max-width:640px){{
.topbar,.controls,.feed{{padding-left:16px;padding-right:16px;}}
.filters{{margin-left:0;}}.controls{{gap:14px;}}
}}
</style></head><body data-filter="all">

<div class="topbar">{_EYE_SVG}
<div><h1>EyeGuard</h1><div class="sub">Activity Report</div></div>
{live_tag}<span class="seen">{last_seen}</span><span class="spacer"></span>
<span class="seen">Last {days} days</span></div>

<div class="controls">
<div class="stats">
<div class="stat red"><div class="n">{reds}</div><div class="l">Revealing</div></div>
<div class="stat yellow"><div class="n">{yellows}</div><div class="l">Suggestive</div></div>
<div class="stat green"><div class="n">{greens}</div><div class="l">Browsing</div></div>
</div>
<div class="filters">
<button class="fbtn active" data-sev="all" onclick="flt('all')">All</button>
<button class="fbtn" data-sev="red" onclick="flt('red')">Revealing</button>
<button class="fbtn" data-sev="yellow" onclick="flt('yellow')">Suggestive</button>
<button class="fbtn" data-sev="green" onclick="flt('green')">Browsing</button>
</div></div>

<div class="feed">{sections}</div>
<footer>Screen watched locally on this Mac · flags and browsing activity shared with your accountability partner<br>
History auto-deletes after {days} days · Revealing = immediate-alert (very revealing or nude) · Suggestive = mildly revealing / borderline · Browsing = clean activity (site/app only, no image)</footer>

<script>
function flt(s){{document.body.dataset.filter=s;
document.querySelectorAll('.fbtn').forEach(function(b){{
b.classList.toggle('active',b.dataset.sev===s);}});
try{{localStorage.setItem('eg_filter',s);}}catch(e){{}}}}
// restore the chosen filter across the live auto-refresh
try{{var s=localStorage.getItem('eg_filter');if(s&&s!=='all')flt(s);}}catch(e){{}}
// click a thumbnail to open the full frame
document.querySelectorAll('img.thumb').forEach(function(t){{
t.onclick=function(){{window.open(t.src,'_blank');}};}});
</script></body></html>"""
    out.write_text(html)
    return out
