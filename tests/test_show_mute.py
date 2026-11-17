#!/usr/bin/env python3
"""show_mute: a muted show's CLIP flags are dropped; ONLY NudeNet's own detections still alert. Uses the real config.yaml
and real risk.assess. Run: python3 tests/test_show_mute.py"""
import sys
from pathlib import Path
import yaml
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eyeguard.risk import assess
CFG = yaml.safe_load((ROOT / "config.yaml").read_text())
R = CFG["context_risk"]
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + ("" if ok else f" -- {detail}"))
    if not ok: fails.append(name)
RED = "clear -> clip-red:0.99:full:a woman in only underwear"
TILE = "clear -> clip-red:0.97:tile:a woman in only underwear"
YEL = "clear -> clip-yellow:0.97:full:a woman in swimwear"
NN = "nudenet:FEMALE_BREAST_EXPOSED=0.91"
NN_LOW = "nudenet:BUTTOCKS_EXPOSED=0.62"
GG = {"app": "Zen", "window_title": "Gilmore Girls S5E17 — FrameXTV", "url": "https://framextv.example/gilmore-girls/s5e17"}
OTHER = {"app": "Zen", "window_title": "Some other page", "url": "https://example.org/"}
def a(v, r, c): return assess(v, r, c, R)

print("config")
check("show_mute lists gilmore girls", [x.lower() for x in R.get("show_mute", [])] == ["gilmore girls"], R.get("show_mute"))
print("muted show: CLIP flags are dropped")
for n, v, r in [("CLIP red", "flagged", RED), ("CLIP tile red", "flagged", TILE), ("CLIP yellow", "alert", YEL)]:
    x = a(v, r, GG); check(f"{n} dropped", x["keep"] is False and x["risk"] == "show-muted", x)
print("muted show: NudeNet still alerts, undiscounted")
for n, r in [("NudeNet 0.91", NN), ("NudeNet 0.62", NN_LOW)]:
    x = a("flagged", r, GG); check(f"{n} kept as RED/Likely", x["keep"] is True and x["grade"] == "Likely" and not x.get("demote_to_alert"), x)
print("matching is by title/url, case-insensitive; nothing else changes")
for t in ("GILMORE GIRLS s1e1", "gilmore girls"):
    check(f"title {t!r} muted", a("flagged", RED, {"app": "Zen", "window_title": t, "url": None})["keep"] is False)
check("URL-only match muted", a("flagged", RED, {"app": "Zen", "window_title": "", "url": "https://x.example/gilmore girls"})["keep"] is False)
check("other page: CLIP red still kept", a("flagged", RED, OTHER)["keep"] is True)
check("other page: CLIP yellow still kept", a("alert", YEL, OTHER)["keep"] is True)
check("other page: NudeNet kept", a("flagged", NN, OTHER)["keep"] is True)
check("'girls' or 'gilmore' alone is not muted", a("flagged", RED, {"app": "Zen", "window_title": "Gilmore pool party girls", "url": None})["keep"] is True)
check("rule absent => nothing muted (rollback)", a.__call__("flagged", RED, GG) is not None and
      assess("flagged", RED, GG, {k: v for k, v in R.items() if k != "show_mute"})["keep"] is True)
if fails: print("\nFAILED:", fails); sys.exit(1)
print("\nall ok")
