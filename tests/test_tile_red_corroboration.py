#!/usr/bin/env python3
"""A CLIP RED reached ONLY by a zoomed tile needs corroboration (NudeNet saw some exposure, or the
full frame reaches RED too); otherwise it is reported as YELLOW. Feature is OFF unless
arbiter.tile_red_nudenet_min is set. Stub CLIP (exact unit vectors), no models. Run: python3 tests/test_tile_red_corroboration.py"""
import sys
from pathlib import Path
import numpy as np
from PIL import Image
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from eyeguard.detector import ClipArbiter, Detection, Detector, Verdict

fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + ("" if ok else f" -- {detail}"))
    if not ok: fails.append(name)

E_RED, E_YEL, E_SAFE = np.eye(3, dtype=np.float32)      # one explicit, one suggestive, one safe concept
IMG = Image.fromarray((np.random.RandomState(0).rand(200, 200, 3) * 255).astype("uint8"))   # passes the content gate
def arbiter(per_crop, tile_red_nudenet_min):
    a = ClipArbiter(["red"], ["yel"], ["safe"], red_threshold=0.60, yellow_threshold=0.55, tile_grid=2,
                    tile_penalty=0.20, min_content_std=12.0, tile_red_nudenet_min=tile_red_nudenet_min)
    a.available = True; a._text_features = np.stack([E_RED, E_YEL, E_SAFE]); a._logit_scale = 100.0
    a._preprocess_images = lambda crops: np.zeros((len(crops), 1))
    class V:
        def run(self, _o, _i): return [np.stack(per_crop)]
    a._vis = V(); return a
# crop order: [full, tile1..tile4]
TILE_RED = [E_SAFE, E_RED, E_SAFE, E_SAFE, E_SAFE]       # only tile 1 looks explicit
FULL_RED = [E_RED, E_SAFE, E_SAFE, E_SAFE, E_SAFE]       # the whole frame looks explicit

v, r = arbiter(TILE_RED, None).arbitrate(IMG, nudenet_top=0.0)
check("OFF (default): a tile-only red is RED, exactly as before", v is Verdict.FLAGGED and r.startswith("clip-red") and "tile" in r)
v, r = arbiter(TILE_RED, 0.30).arbitrate(IMG, nudenet_top=0.0)
check("ON, NudeNet saw nothing: tile-only red is demoted to YELLOW", v is Verdict.ALERT and r.startswith("clip-yellow") and "(tile-red demoted)" in r, r)
v, r = arbiter(TILE_RED, 0.30).arbitrate(IMG, nudenet_top=0.29)
check("ON, NudeNet just under the bar: still demoted", v is Verdict.ALERT)
v, r = arbiter(TILE_RED, 0.30).arbitrate(IMG, nudenet_top=0.30)
check("ON, NudeNet at the bar: stays RED (corroborated)", v is Verdict.FLAGGED and "tile" in r)
v, r = arbiter(FULL_RED, 0.30).arbitrate(IMG, nudenet_top=0.0)
check("ON, full frame itself reaches RED: stays RED with NudeNet at 0", v is Verdict.FLAGGED and ":full:" in r)
both = [E_RED, E_RED, E_SAFE, E_SAFE, E_SAFE]
v, r = arbiter(both, 0.30).arbitrate(IMG, nudenet_top=0.0)
check("ON, full frame AND a tile reach RED: stays RED", v is Verdict.FLAGGED)
v, r = arbiter([E_SAFE] * 5, 0.30).arbitrate(IMG, nudenet_top=0.0)
check("ON, nothing suggestive: SAFE (rule never creates a flag)", v is Verdict.SAFE)
check("demoted reason keeps the 'clip-yellow:<mass>' shape risk.assess parses",
      __import__("re").search(r"clip-yellow:([0-9.]+)", arbiter(TILE_RED, 0.30).arbitrate(IMG, 0.0)[1]) is not None)

class Stage1:
    def __init__(self, top, verdict): self.t, self.v = top, verdict
    def detect(self, image): return Detection(self.v, "x", top_score=self.t)
d = Detector(Stage1(0.35, Verdict.SAFE), arbiter(TILE_RED, 0.30))
check("Detector passes NudeNet's own top score to the arbiter (0.35 >= 0.30 keeps RED)", d.analyze(IMG).verdict is Verdict.FLAGGED)
d = Detector(Stage1(0.10, Verdict.SAFE), arbiter(TILE_RED, 0.30))
check("Detector: NudeNet 0.10 -> demoted to YELLOW", d.analyze(IMG).verdict is Verdict.ALERT)
d = Detector(Stage1(0.90, Verdict.FLAGGED), arbiter(TILE_RED, 0.30))
check("NudeNet's own RED (>= flag_threshold) short-circuits before CLIP and is never touched", d.analyze(IMG).verdict is Verdict.FLAGGED)
print("FAILED: " + ", ".join(fails) if fails else "ALL OK"); sys.exit(1 if fails else 0)
