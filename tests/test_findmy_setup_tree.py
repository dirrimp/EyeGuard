#!/usr/bin/env python3
"""--setup refuses to run from a stale copy of the code (2026-11-21: it saved a login but never cleared the back-off marker).
Synthetic paths only. Run: python3 tests/test_findmy_setup_tree.py"""
import subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

from eyeguard import findmy_watcher as fw
with tempfile.TemporaryDirectory() as t:
    t = Path(t)
    system = t / "Library" / "EyeGuard"; system.mkdir(parents=True)
    stale = t / "home" / "EyeGuard"; stale.mkdir(parents=True)
    check("running from the installed tree is allowed", fw._setup_tree_problem(system, system) is None)
    check("running from the installed tree through a symlink is allowed",
          (t / "link").symlink_to(system) is None and fw._setup_tree_problem(t / "link", system) is None)
    msg = fw._setup_tree_problem(stale, system)
    check("running from a different copy is refused", msg is not None)
    check("the message names both trees and the right command",
          msg and str(stale) in msg and str(system) in msg and "-m eyeguard.findmy_watcher --setup" in msg and "cd " in msg)
    check("the message says nothing was changed and gives the override", msg and "Nothing was changed" in msg and "--allow-any-tree" in msg)
    check("no installed tree on this machine (a dev box) -> allowed",
          fw._setup_tree_problem(stale, t / "does-not-exist") is None)

src = (ROOT / "eyeguard/findmy_watcher.py").read_text()
main_src = src[src.index("def main():"):]
check("main() checks the tree before loading config or prompting for a password",
      main_src.index("_setup_tree_problem(_BASE)") < main_src.index("load_config(args.config)") < main_src.index("setup(cfg)"))
check("the override flag exists and defaults off", '"--allow-any-tree", action="store_true"' in main_src)
check("the check only applies to --setup, never to the cron --once run",
      "args.setup and not args.allow_any_tree" in main_src)
check("the refusal exits non-zero without touching credentials", "sys.exit(2)" in main_src)

print()
if fails:
    print("FAILED:"); [print("  " + f) for f in fails]; sys.exit(1)
print("ALL OK")
