#!/usr/bin/env python3
"""OCR must run inside an Objective-C autorelease pool (the agent calls it from a plain thread, where
nothing drains the pool; unpooled, each call leaked ~0.6 MB and the memory guard kept restarting the agent).
Part 1 is offline (fake objc/Vision). Part 2 measures the real leak on macOS and is skipped elsewhere.
Synthetic image only: no screen content. Run: python3 tests/test_ocr_autorelease.py"""
import contextlib, io, os, re, subprocess, sys, types
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

# ---- part 1: offline wiring ------------------------------------------------
events = []
fake_objc = types.ModuleType("objc")
@contextlib.contextmanager
def fake_pool():
    events.append("enter"); 
    try: yield
    finally: events.append("exit")
fake_objc.autorelease_pool = fake_pool
sys.modules["objc"] = fake_objc

from eyeguard import textscan
calls = []
textscan._ocr = lambda img: (calls.append(1), events.append("ocr"), "hello")[2]
check("ocr() returns the text", textscan.ocr(object()) == "hello")
check("the OCR call happens inside the pool (enter, ocr, exit)", events == ["enter", "ocr", "exit"], str(events))
events.clear()
def boom(img): events.append("ocr"); raise RuntimeError("x")
textscan._ocr = boom
raised = False
try: textscan.ocr(object())
except RuntimeError: raised = True
check("the pool is released even if OCR raises", raised and events == ["enter", "ocr", "exit"], str(events))
sys.modules.pop("objc")
sys.modules["objc"] = None          # import objc -> ImportError
textscan._ocr = lambda img: "plain"
check("without PyObjC it still works (no pool)", textscan.ocr(object()) == "plain")
sys.modules.pop("objc")
import importlib; importlib.reload(textscan)
check("a bad image still returns '' (never raises)", textscan.ocr(None) == "")
check("match_terms is untouched", textscan.match_terms("a Foo b", ["foo", "bar"]) == ["foo"])

# ---- part 2: the real leak, macOS only -------------------------------------
def real():
    try:
        import Vision, objc  # noqa
        from PIL import Image, ImageDraw
    except Exception:
        print("  [skip] PyObjC Vision / Pillow not available: live leak check skipped"); return
    def mb():
        o = subprocess.run(["footprint", str(os.getpid())], capture_output=True, text=True).stdout
        return int(re.search(r"Footprint: (\d+) MB", o).group(1))
    img = Image.new("RGB", (1280, 720), "white"); d = ImageDraw.Draw(img)
    for i in range(30): d.text((20, 20 + i * 22), f"synthetic text line number {i} for the leak test", fill="black")
    textscan.ocr(img); base = mb()                    # warm-up call loads Vision
    for _ in range(150): textscan.ocr(img)
    grew = mb() - base
    check(f"150 real OCR calls grow the footprint by < 40 MB (was ~+90 MB unpooled): +{grew} MB", grew < 40, str(grew))
real()

print("\nFAILED: " + ", ".join(fails) if fails else "\nALL OK")
sys.exit(1 if fails else 0)
