#!/usr/bin/env python3
"""FreeTube (a YouTube client whose title has no 'youtube') gets the same low-risk discount as YouTube, and nothing else changes.
Uses the real config.yaml and real risk.assess; synthetic reasons only. Run: python3 tests/test_freetube_context.py"""
import sys
from pathlib import Path
import yaml
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eyeguard.risk import assess
R = yaml.safe_load((ROOT / "config.yaml").read_text())["context_risk"]
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + ("" if ok else f" -- {detail}"))
    if not ok: fails.append(name)
def red(s): return f"clear -> clip-red:{s}:full:a person with bare skin"
NN = "nudenet:FEMALE_BREAST_EXPOSED=0.91"
FT = {"app": "FreeTube", "window_title": "Some video - FreeTube", "url": None}
YT = {"app": "Zen", "window_title": "Some video - YouTube", "url": "https://www.youtube.com/watch?v=x"}
OTHER = {"app": "Zen", "window_title": "Some page", "url": "https://example.org/"}
def a(v, r, c): return assess(v, r, c, R)
print("config")
check("freetube is in low_risk", "freetube" in [x.lower() for x in R["low_risk"]])
print("a CLIP red of 0.73 to 0.84 in FreeTube behaves exactly like the same score in YouTube")
for sc in ("0.73", "0.78", "0.84"):
    f, y = a("flagged", red(sc), FT), a("flagged", red(sc), YT)
    check(f"red {sc}: FreeTube == YouTube", (f["keep"], f.get("risk"), f.get("demote_to_alert")) == (y["keep"], y.get("risk"), y.get("demote_to_alert")), (f, y))
print("real events still alert in FreeTube")
check("CLIP red 0.95 (>= 0.93) still kept as RED", a("flagged", red("0.95"), FT)["keep"] is True and not a("flagged", red("0.95"), FT).get("demote_to_alert"))
check("NudeNet exposure still kept as RED", a("flagged", NN, FT)["keep"] is True and not a("flagged", NN, FT).get("demote_to_alert"))
print("nothing else changed")
check("other site: CLIP red 0.84 still kept", a("flagged", red("0.84"), OTHER)["keep"] is True)
check("'freetube' must appear in app, title or url to count", a("flagged", red("0.84"), {"app": "Zen", "window_title": "free tube", "url": None})["keep"] is True)
if fails: print("\nFAILED:", fails); sys.exit(1)
print("\nall ok")
