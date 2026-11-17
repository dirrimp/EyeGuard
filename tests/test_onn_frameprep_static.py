#!/usr/bin/env python3
"""Checks for the Onn's frame preparation (Blur, Postprocess, FlagName). No JDK here, so they prove three things on paper:
 (1) the promises in the Java source (pure JDK, no logging/files/network, constants equal to config.yaml and the SQL);
 (2) a line-for-line PYTHON PORT of the Java algorithms agrees with the Mac's own code (PIL blur, nudenet _postprocess + detector rule)
     on every vector, which catches algorithm mistakes (not Java syntax);
 (3) the vector tool works. The REAL proof is FramePrepTest on a JVM (Agent IT's container) against the same vectors.
Run: /Applications/EyeGuard.app/Contents/Resources/python/bin/python3.12 tests/test_onn_frameprep_static.py"""
import importlib.util, math, re, sys, tempfile
from pathlib import Path
import numpy as np
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + ("" if ok else f" -- {detail}"))
    if not ok: fails.append(name)

APP = ROOT / "android/onn-monitor/src/com/eyeguard/onn"
src = {n: (APP / f"{n}.java").read_text() for n in ("Blur", "Postprocess", "FlagName")}
code = {n: re.sub(r"/\*.*?\*/", "", s, flags=re.S) for n, s in src.items()}
spec = importlib.util.spec_from_file_location("vec", ROOT / "tools/onn_frameprep_vectors.py"); vec = importlib.util.module_from_spec(spec); spec.loader.exec_module(vec)
CFG = yaml.safe_load((ROOT / "config.yaml").read_text())

print("Java source promises")
check("pure JDK: no Android classes, no logging, files, network or reflection",
      all(not re.search(r"^import android\.|android\.util\.Log|System\.(out|err)|java\.io|java\.net|Class\.forName|Runtime\.", c, re.M) for c in code.values()))
check("blur strength 75 and the radius rule are the Mac's (config.yaml logging.blur_strength, logger.py max(6, width // strength))",
      CFG["logging"]["blur_strength"] == 75 and "BLUR_STRENGTH = 75" in src["Blur"] and "Math.max(6, width / BLUR_STRENGTH)" in src["Blur"])
check("flag threshold 0.80 and the four explicit labels are config.yaml's",
      CFG["detection"]["flag_threshold"] == 0.8 and "FLAG_THRESHOLD = 0.80f" in src["Postprocess"] and "EXPLICIT = {2, 3, 4, 6}" in src["Postprocess"])
L = vec.labels()
ex = [i for i, n in enumerate(L) if n in set(CFG["detection"]["explicit_labels"])]
check("explicit indices 2,3,4,6 are exactly config.yaml's explicit_labels in nudenet's label order", sorted(ex) == [2, 3, 4, 6])
jl = re.findall(r'"([A-Z_]+)"', src["Postprocess"].split("LABELS = {")[1].split("};")[0])
check("the Java label list equals nudenet's, in order", jl == L, str(jl))
check("NMS uses cv2.dnn.NMSBoxes' numbers (score > 0.25, IoU > 0.45) and the 0.2 anchor floor, and its zero-area rule",
      "NMS_SCORE = 0.25" in src["Postprocess"] and "NMS_IOU = 0.45" in src["Postprocess"] and "MIN_ANCHOR_SCORE = 0.2f" in src["Postprocess"]
      and "Math.ulp(1.0)) return 1.0" in src["Postprocess"])
sql = (ROOT / "supabase/onn_monitor_phase3.sql").read_text()
check("FlagName writes the shape the server's pattern requires (pattern taken from the SQL file)",
      "_flagged_d1.jpg.enc" in src["FlagName"] and "+00-00" in src["FlagName"] and "regexp_match(obj, '^onn/" in sql)
check("foreground text is limited to the server's character set and 120 characters",
      "c == '.' || c == '_' || c == '-'" in src["FlagName"] and "< 120" in src["FlagName"] and "fg !~ '^[A-Za-z0-9._-]*$'" in sql)

print("Python port of the Java algorithms vs the Mac's code")
with tempfile.TemporaryDirectory() as t:
    d = Path(t); radius, lines, pattern = vec.gen(d)
    # ---- blur port (same boxes, clamp-to-edge, same rounding as Blur.java)
    def boxes(s, n=3):
        wi = math.sqrt(12 * s * s / n + 1); wl = int(math.floor(wi)); wl -= 1 if wl % 2 == 0 else 0; wu = wl + 2
        m = int(round((12 * s * s - n * wl * wl - 4 * n * wl - 3 * n) / (-4 * wl - 4)))
        return [wl if i < m else wu for i in range(n)]
    def box(a, r, axis):
        a = a.astype(np.int64); pad = [(0, 0)] * a.ndim; pad[axis] = (r + 1, r)
        c = np.cumsum(np.pad(a, pad, mode="edge"), axis=axis); n = a.shape[axis]
        sl = lambda s, e: tuple(slice(s, e) if i == axis else slice(None) for i in range(a.ndim))
        return (c[sl(2 * r + 1, 2 * r + 1 + n)] - c[sl(0, n)] + (2 * r + 1) // 2) // (2 * r + 1)
    img = np.frombuffer((d / "blur_in.rgb").read_bytes(), np.uint8).reshape(720, 1280, 3)
    out = img
    for size in boxes(radius): out = box(box(out, (size - 1) // 2, 1), (size - 1) // 2, 0)
    ref = np.frombuffer((d / "blur_expected.rgb").read_bytes(), np.uint8).reshape(720, 1280, 3)
    diff = np.abs(out.astype(int) - ref.astype(int))
    check("box sizes for sigma 17 are 33, 33, 35", boxes(17) == [33, 33, 35])
    check(f"the blur differs from PIL by a mean of {diff.mean():.3f} of 255 and at most {diff.max()} (limits 0.5 and 4)", diff.mean() < 0.5 and diff.max() <= 4)
    detail = lambda a: np.abs(np.diff(a.astype(int), axis=1)).mean()
    check("the blur removes at least 40% of the detail, as PIL's does", detail(out) < 0.6 * detail(img) and abs(detail(out) - detail(ref)) < 0.05)
    # ---- postprocess port (mirrors Postprocess.analyze)
    raw = np.frombuffer((d / "pp_tensors.bin").read_bytes(), "<f4").reshape(len(lines), 22, 2100)
    explicit = {2, 3, 4, 6}
    def analyze(o, W, H):
        pad = max(W, H); cands = []
        for i in range(2100):
            col = o[4:, i]; cls = int(np.argmax(col)); s = float(col[cls])
            if s < 0.2: continue
            cx, cy, bw, bh = (float(v) for v in o[0:4, i])
            x = (cx - bw / 2) * pad / 320; y = (cy - bh / 2) * pad / 320; w = bw * pad / 320; h = bh * pad / 320
            x = max(0, min(x, W)); y = max(0, min(y, H)); w = min(w, W - x); h = min(h, H - y)
            cands.append((cls, s, x, y, w, h))
        pool = sorted([c for c in cands if c[1] > 0.25], key=lambda c: -c[1])      # sorted() is stable like List.sort
        kept = []
        for c in pool:
            ok = True
            for k in kept:
                aa, ab = c[4] * c[5], k[4] * k[5]
                if aa + ab <= 2.220446049250313e-16: ov = 1.0              # OpenCV: two zero-area boxes count as identical
                else:
                    iw = min(c[2] + c[4], k[2] + k[4]) - max(c[2], k[2]); ih = min(c[3] + c[5], k[3] + k[5]) - max(c[3], k[3])
                    inter = iw * ih if iw > 0 and ih > 0 else 0.0
                    ov = inter / (aa + ab - inter)
                if ov > 0.45: ok = False; break
            if ok: kept.append(c)
        best, lab = 0.0, -1
        for c in kept:
            if c[0] in explicit and c[1] > best: best, lab = c[1], c[0]
        return (L[lab] if lab >= 0 else "NONE"), best
    bad = []
    for n, line in enumerate(lines):
        W, H, label, score = line.split(); lab, s = analyze(raw[n], int(W), int(H))
        if lab != label or abs(s - float(score)) > 1e-6: bad.append((n, lab, s, label, score))
    check(f"the port gives the Mac's label and score on all {len(lines)} tensors", not bad, str(bad[:3]))
    flags = sum(1 for l in lines if l.split()[2] != "NONE" and float(l.split()[3]) >= 0.8)
    check("the vector set exercises flags, suppression and non-flags", flags >= 10 and any(l.split()[2] == "NONE" for l in lines))
    check("the 0.80 boundary case is a flag in float32 and 0.79 is not", float(lines[2].split()[3]) >= 0.8 and float(lines[1].split()[3]) < 0.8)
    check("a higher-scoring COVERED box suppresses an overlapping EXPOSED one, as on the Mac (case 4 is NONE)", lines[4].split()[2] == "NONE")
    check("two boxes far apart both survive (case 5 keeps the exposed one)", lines[5].split()[2] == "FEMALE_BREAST_EXPOSED")
    check("the server's object-name pattern was read from the SQL file", pattern.startswith("^onn/") and pattern.endswith("$"))
    nm = re.compile(pattern)
    check("a name built like FlagName's matches the pattern, and the Mac uploader's own naming style would too",
          bool(nm.match("onn/2026-11-17T19-06-40.123000+00-00_flagged_d1.jpg.enc")) and bool(nm.match("onn/2026-11-17T19-06-40+00-00_flagged_d1.jpg.enc")))

print("the JVM test's expected time string is right (it was once wrong by 40 minutes: computed by hand, not by a tool)")
from datetime import datetime, timezone
jt = (ROOT / "android/onn-monitor/test/com/eyeguard/onn/FramePrepTest.java").read_text()
ms = int(re.search(r"FlagName\.objectName\((\d+)L\)", jt).group(1))
want = "onn/" + datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%dT%H-%M-%S.%f")[:-3] + "000+00-00_flagged_d1.jpg.enc"
check("the string FramePrepTest expects equals Python's formatting of the epoch value it passes in", f'name.equals("{want}")' in jt, want)

print("the JVM test is not in the APK")
b = (ROOT / "android/onn-monitor/build.sh").read_text()
check("build.sh compiles only src/ (the JVM tests live in test/)", "find \"$SRC/src\"" in b and "/test" not in b)
check("the JVM test file exists", (ROOT / "android/onn-monitor/test/com/eyeguard/onn/FramePrepTest.java").exists())
if fails: print("\nFAILED:", *fails, sep="\n  "); sys.exit(1)
print("\nALL OK")
