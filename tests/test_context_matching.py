#!/usr/bin/env python3
"""Context rules: 'app:Name' entries match only the app NAME; a low-risk CLIP RED demotes to YELLOW instead of
vanishing. Uses the REAL config.yaml and the real risk.assess / context.is_ignored. Run: python3 tests/test_context_matching.py"""
import sys
from pathlib import Path
import yaml
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eyeguard.risk import assess, pattern_hits
from eyeguard.context import is_ignored
CFG = yaml.safe_load((ROOT / "config.yaml").read_text())
R, IGN = CFG["context_risk"], CFG["ignore"]["window_title_contains"]
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + ("" if ok else f" -- {detail}"))
    if not ok: fails.append(name)
RED, YEL = "clear -> clip-red:0.88:full:a woman in only underwear", "clear -> clip-yellow:0.95:full:a woman in swimwear"
def ctx(app, title="", url=None): return {"app": app, "window_title": title, "url": url}
def keep(v, reason, c, rules=R): return assess(v, reason, c, rules)

print("A. words in a title/URL can no longer trigger 'safe app' rules (these were all DROPPED, RED included)")
for name, c in [("'Use code SAVE20' email subject", ctx("Proton Mail", "Use code SAVE20 | Proton Mail")),
                ("'promo code' in a webmail tab", ctx("Zen", "Your promo code inside - Inbox", "https://mail.example.com/")),
                ("'Striped bikini set' shop page", ctx("Zen", "Striped bikini set - Shop", "https://shop.example.com/p/1")),
                ("'barcode' in the URL", ctx("Zen", "Lingerie", "https://shop.example.com/barcode/123")),
                ("'Keynote speaker' article", ctx("Zen", "Keynote speaker photos", "https://news.example.org/a")),
                ("'airport terminal' page (also on the ignore list)", ctx("Zen", "Airport terminal photos"))]:
    a = keep("flagged", RED, c); b = keep("alert", YEL, c)
    check(f"{name}: not suppressed", a["risk"] != "suppressed" and b["risk"] != "suppressed", f"{a['risk']}/{b['risk']}")
    check(f"{name}: not ignored", not is_ignored(c, IGN))

print("B. the real apps are still suppressed / ignored (no new noise from dev tools)")
for app in ("Code", "Terminal", "iTerm2", "Xcode", "Keynote", "Microsoft PowerPoint", "Photo Booth", "System Settings", "Activity Monitor", "Accordance", "loginwindow"):
    check(f"{app}: suppressed", keep("flagged", RED, ctx(app, "anything"))["risk"] == "suppressed")
for app in ("Terminal", "iTerm2", "loginwindow"): check(f"{app}: ignored", is_ignored(ctx(app, "x"), IGN))
check("VS Code by title still suppressed", keep("flagged", RED, ctx("Electron", "main.py — Visual Studio Code"))["risk"] == "suppressed")
check("github.com / supabase.com by URL still suppressed", keep("alert", YEL, ctx("Zen", "x", "https://github.com/a/b"))["risk"] == "suppressed"
      and keep("alert", YEL, ctx("Zen", "x", "https://supabase.com/d"))["risk"] == "suppressed")
check("Stripe dashboard titles still suppressed", all(keep("alert", YEL, ctx("Zen", t))["risk"] == "suppressed" for t in ("Home – Stripe", "Payments - Stripe", "Dashboard | Stripe")))
check("EyeGuard's own report still ignored", is_ignored(ctx("Zen", "EyeGuard Activity Report"), IGN))

print("C. low-risk list follows the app name (was: any word 'mail'/'photos'/'notes' in app+title+url)")
check("Apple Mail app: still low risk", keep("alert", YEL, ctx("Mail", "Inbox"))["risk"] == "low")
check("Proton Mail app: no longer discounted as 'Mail' (neutral)", keep("alert", YEL, ctx("Proton Mail", "Inbox | Proton Mail"))["risk"] == "neutral")
check("'Beach photos' page title: neutral, not Photos-app low risk", keep("alert", YEL, ctx("Zen", "Beach photos"))["risk"] == "neutral")
check("Photos / Messages / Preview / Notes apps: low risk", all(keep("alert", YEL, ctx(a, "x"))["risk"] == "low" for a in ("Photos", "Messages", "Preview", "Notes")))
check("YouTube stays low risk by title (policy unchanged)", keep("alert", YEL, ctx("Zen", "30 Minute Workout - YouTube — Zen"))["risk"] == "low")
check("high-risk sites unchanged", keep("alert", YEL, ctx("Zen", "x", "https://www.instagram.com/"))["risk"] == "high")

print("D. a low-risk CLIP RED is demoted to YELLOW instead of dropped")
yt = ctx("Zen", "30 Minute Workout - YouTube — Zen")
a = keep("flagged", "clear -> clip-red:0.88:full:x", yt)
check("RED 0.88 on YouTube: kept, flagged for demotion to alert", a["keep"] and a.get("demote_to_alert") is True, str(a))
check("RED 0.93 on YouTube: stays RED (no demotion)", keep("flagged", "clear -> clip-red:0.94:full:x", yt)["keep"] and not keep("flagged", "clear -> clip-red:0.94:full:x", yt).get("demote_to_alert"))
check("RED 0.80 on YouTube: still dropped (below the yellow bar too)", not keep("flagged", "clear -> clip-red:0.80:full:x", yt)["keep"])
check("NudeNet RED is never discounted or demoted", (lambda r: r["keep"] and not r.get("demote_to_alert"))(keep("flagged", "nudenet:BUTTOCKS_EXPOSED=0.85", yt)))
check("neutral context: RED untouched, no demotion", (lambda r: r["keep"] and not r.get("demote_to_alert"))(keep("flagged", RED, ctx("Zen", "Gallery"))))
check("yellow rule unchanged: 0.80 yellow on YouTube dropped, 0.90 kept", not keep("alert", "clip-yellow:0.80:full:x", yt)["keep"] and keep("alert", "clip-yellow:0.90:full:x", yt)["keep"])
off = dict(R, low_risk_red_demote=False)
check("low_risk_red_demote: false restores the old drop", not keep("flagged", "clear -> clip-red:0.88:full:x", yt, off)["keep"])

print("E. pattern_hits basics")
check("plain entry = substring (as before)", pattern_hits("github.com", ctx("Zen", "x", "https://github.com/a"), "zen x https://github.com/a"))
check("'app:' entry = exact app name, case-insensitive", pattern_hits("app:Mail", ctx("mail"), "mail") and not pattern_hits("app:Mail", ctx("Proton Mail"), "proton mail"))
check("missing app name never matches an 'app:' entry", not pattern_hits("app:Code", {"window_title": "code"}, "code"))
print("FAILED: " + ", ".join(fails) if fails else "ALL OK"); sys.exit(1 if fails else 0)
