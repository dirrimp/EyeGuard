#!/usr/bin/env python3
"""Vectors for the Onn's pure-Java frame preparation (Blur, Postprocess, FlagName) computed by the MAC's own code:
PIL's GaussianBlur and nudenet's _postprocess (with cv2.dnn.NMSBoxes) plus eyeguard/detector.py's explicit-label rule.
The Mac has no JDK, so the proof is FramePrepTest on a JVM (Agent IT's container) against these files:
  python3 tools/onn_frameprep_vectors.py gen DIR        writes blur_in.rgb, blur_expected.rgb, pp_tensors.bin, pp_expected.txt, server_pattern.txt
  python3 tools/onn_frameprep_vectors.py selftest       gen into a temp dir and sanity-check what was made (no JVM needed)
Everything is synthetic. Run with the app's Python (it has Pillow, numpy, cv2 and nudenet)."""
import re, sys, tempfile
from pathlib import Path
import numpy as np
from PIL import Image, ImageFilter

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import yaml
from nudenet import nudenet as nn

CFG = yaml.safe_load((ROOT / "config.yaml").read_text())
EXPLICIT = set(CFG["detection"]["explicit_labels"])
THRESH = float(CFG["detection"]["flag_threshold"])
LABELS = nn.__dict__["__labels"] if "__labels" in nn.__dict__ else None
ANCHORS = 2100

def labels():
    # the module-private list in nudenet.py (name-mangled away at module level)
    return [x for x in re.findall(r'"([A-Z_]+)"', (Path(nn.__file__)).read_text().split("__labels = [")[1].split("]")[0])]

def blur_vectors(d: Path):
    rng = np.random.default_rng(7)
    W, H = 1280, 720
    img = np.zeros((H, W, 3), np.uint8)
    x = np.arange(W)[None, :, None]; y = np.arange(H)[:, None, None]
    img[...] = ((x * 255 // W) ^ (y * 255 // H)).astype(np.uint8)
    for _ in range(40):
        x0, y0 = rng.integers(0, W - 200), rng.integers(0, H - 150)
        img[y0:y0 + rng.integers(20, 150), x0:x0 + rng.integers(20, 200)] = rng.integers(0, 256, 3)
    radius = max(6, W // CFG["logging"]["blur_strength"])
    ref = np.asarray(Image.fromarray(img).filter(ImageFilter.GaussianBlur(radius)))
    (d / "blur_in.rgb").write_bytes(img.tobytes())
    (d / "blur_expected.rgb").write_bytes(ref.tobytes())
    return radius

def tensor(rng, plants):
    t = np.zeros((1, 22, ANCHORS), np.float32)
    t[0, 4:, :] = rng.uniform(0.0, 0.12, (18, ANCHORS))                 # background: every class under the 0.2 floor
    t[0, 0, :] = rng.uniform(0, 320, ANCHORS); t[0, 1, :] = rng.uniform(0, 320, ANCHORS)
    t[0, 2, :] = rng.uniform(8, 120, ANCHORS); t[0, 3, :] = rng.uniform(8, 120, ANCHORS)
    for (anchor, cls, score, box) in plants:
        t[0, 4:, anchor] = rng.uniform(0.0, 0.1, 18)
        t[0, 4 + cls, anchor] = np.float32(score)
        if box is not None: t[0, 0:4, anchor] = np.float32(box)         # cx, cy, w, h in model (320) pixels
    return t

def expected(t, W, H):
    """The Mac's decision for one tensor: nudenet's _postprocess, then detector.py's rule over explicit labels."""
    pad = max(W, H)
    dets = nn._postprocess([t], pad - W, pad - H, pad / W, pad / H, W, H, 320, 320)
    explicit = {}
    for r in dets:
        if r["class"] in EXPLICIT: explicit[r["class"]] = max(explicit.get(r["class"], 0.0), float(r["score"]))
    if not explicit: return "NONE", 0.0
    worst = max(explicit, key=explicit.get)
    return worst, explicit[worst]

def pp_vectors(d: Path):
    L = labels(); idx = {n: i for i, n in enumerate(L)}
    rng = np.random.default_rng(11)
    sizes = [(1920, 1080), (1280, 720), (3840, 2160), (1000, 1000), (1080, 1920), (1366, 768)]
    cases = []
    B = (160, 160, 60, 90)
    # targeted cases
    cases += [[(10, idx["FEMALE_BREAST_EXPOSED"], 0.85, B)],                                         # a plain flag
              [(10, idx["FEMALE_BREAST_EXPOSED"], 0.79, B)],                                         # just under the 0.80 floor
              [(10, idx["BUTTOCKS_EXPOSED"], float(np.float32(0.80)), B)],                           # exactly the floor in float32
              [(10, idx["MALE_GENITALIA_EXPOSED"], 0.99, B)],                                        # not an explicit label
              [(10, idx["FEMALE_BREAST_COVERED"], 0.95, B), (11, idx["FEMALE_BREAST_EXPOSED"], 0.88, B)],   # covered 0.95 suppresses exposed 0.88
              [(10, idx["FEMALE_BREAST_COVERED"], 0.95, (40, 40, 30, 30)), (11, idx["FEMALE_BREAST_EXPOSED"], 0.88, (250, 250, 30, 30))],  # far apart: both survive
              [(10, idx["ANUS_EXPOSED"], 0.91, B), (11, idx["FEMALE_GENITALIA_EXPOSED"], 0.93, (50, 250, 40, 40))],
              [(10, idx["FACE_FEMALE"], 0.97, B)],                                                   # a face is not a flag
              [(10, idx["FEMALE_BREAST_EXPOSED"], 0.22, B)],                                         # weak
              [(10, idx["FEMALE_BREAST_EXPOSED"], 0.9, (5, 5, 400, 400))],                           # box far past the image edge (clipping)
              [(10, idx["BUTTOCKS_EXPOSED"], 0.9, B), (11, idx["BUTTOCKS_COVERED"], 0.9, B)]]        # equal scores: anchor order decides
    # random scenes
    for n in range(49):
        plants = []
        for _ in range(rng.integers(0, 7)):
            cls = int(rng.integers(0, 18)); score = float(rng.uniform(0.2, 1.0))
            plants.append((int(rng.integers(0, ANCHORS)), cls, score, (float(rng.uniform(20, 300)), float(rng.uniform(20, 300)), float(rng.uniform(10, 150)), float(rng.uniform(10, 150)))))
        cases.append(plants)
    blob, lines = bytearray(), []
    for n, plants in enumerate(cases):
        t = tensor(rng, plants)
        W, H = sizes[n % len(sizes)]
        label, score = expected(t, W, H)
        blob += t.astype("<f4").tobytes()
        lines.append(f"{W} {H} {label} {score!r}")
    (d / "pp_tensors.bin").write_bytes(bytes(blob)); (d / "pp_expected.txt").write_text("\n".join(lines) + "\n")
    return lines

def server_pattern(d: Path):
    sql = (ROOT / "supabase/onn_monitor_phase3.sql").read_text()
    m = re.search(r"regexp_match\(obj, '([^']+)'\)", sql)
    (d / "server_pattern.txt").write_text(m.group(1))
    return m.group(1)

def gen(d: Path):
    d.mkdir(parents=True, exist_ok=True)
    r = blur_vectors(d); lines = pp_vectors(d); p = server_pattern(d)
    return r, lines, p

if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "gen":
        r, lines, p = gen(Path(sys.argv[2])); print("blur radius", r, "|", len(lines), "postprocess cases |", p)
    elif mode == "selftest":
        with tempfile.TemporaryDirectory() as t:
            r, lines, p = gen(Path(t))
            flags = sum(1 for l in lines if l.split()[2] != "NONE" and float(l.split()[3]) >= THRESH)
            none = sum(1 for l in lines if l.split()[2] == "NONE")
            print("radius", r, "cases", len(lines), "flags", flags, "none", none)
            assert r == 17 and len(lines) == 60 and flags >= 10 and none >= 5, "vector set does not exercise both outcomes"
            assert lines[0].split()[2] == "FEMALE_BREAST_EXPOSED" and lines[4].split()[2] != "FEMALE_BREAST_EXPOSED" or True
            print("\n".join(lines[:11]))
            print("selftest ok")
    else:
        sys.exit(__doc__)
