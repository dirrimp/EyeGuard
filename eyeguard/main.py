"""EyeGuard entry point: the capture-and-detect loop (foreground / one-shot).

The always-on agent runs through eyeguard.menubar via run_agent.py; this
module is the plain loop used by run.sh and diagnose.py.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import yaml

from .capture import ScreenCapturer
from .context import capture_context, is_ignored
from .risk import assess
from .detector import ClipArbiter, Detector, NudeNetStage, Verdict
from .logger import FlagLogger

# ANSI colors for the live console readout.
_COLOR = {
    Verdict.SAFE: "\033[2m",       # dim
    Verdict.REVIEW: "\033[2;33m",  # dim yellow (arbiter unavailable)
    Verdict.ALERT: "\033[1;33m",   # bold yellow (suggestive)
    Verdict.FLAGGED: "\033[1;31m", # bold red (explicit)
}
_RESET = "\033[0m"


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def build_detector(cfg: dict, verbose: bool = True) -> Detector:
    d = cfg["detection"]
    stage1 = NudeNetStage(
        explicit_labels=d["explicit_labels"],
        flag_threshold=d["flag_threshold"],
    )
    arbiter = None
    a = cfg.get("arbiter", {})
    if a.get("enabled"):
        arbiter = ClipArbiter(
            explicit_prompts=a["explicit_prompts"],
            suggestive_prompts=a["suggestive_prompts"],
            safe_prompts=a["safe_prompts"],
            red_threshold=a.get("red_threshold", 0.40),
            yellow_threshold=a.get("yellow_threshold", 0.30),
            model_id=a.get("model_id"),
            tile_grid=a.get("tile_grid", 1),
            tile_penalty=a.get("tile_penalty", 0.12),
            min_content_std=a.get("min_content_std", 12.0),
        )
        if verbose:
            print("[arbiter] loading CLIP (onnxruntime, ~560MB resident)...")
        arbiter.load()
        if verbose:
            if arbiter.available:
                print("[arbiter] CLIP loaded — borderline frames will be arbitrated.")
            else:
                print(f"[arbiter] unavailable ({arbiter.load_error}); "
                      "borderline frames will be logged as 'review' (fail-open).")
    return Detector(stage1, arbiter)


def run(cfg: dict, interval: float | None, once: bool):
    cap_cfg = cfg["capture"]
    ignore_patterns = cfg.get("ignore", {}).get("window_title_contains", [])
    risk_cfg = cfg.get("context_risk", {})
    capturer = ScreenCapturer(
        displays=cap_cfg["displays"],
        max_width=cap_cfg["max_width"],
        change_threshold=cap_cfg["change_threshold"],
    )
    detector = build_detector(cfg)
    log_cfg = cfg["logging"]
    logger = FlagLogger(
        flag_log=log_cfg["flag_log"],
        save_flagged_frames=log_cfg.get("save_flagged_frames", False),
        flagged_frames_dir=log_cfg.get("flagged_frames_dir", "flagged_frames"),
        blur_red_frames=log_cfg.get("blur_red_frames", True),
        blur_strength=log_cfg.get("blur_strength", 50),
    )

    # Apply data retention before starting.
    from .retention import prune
    summary = prune(cfg)
    if summary["log_entries_dropped"] or summary["frames_deleted"]:
        print(f"[eyeguard] retention: dropped {summary['log_entries_dropped']} "
              f"old flags, {summary['frames_deleted']} frames "
              f"(>{summary['retention_days']}d)")

    interval = interval if interval is not None else cap_cfg["interval_seconds"]
    print(f"[eyeguard] watching (interval={interval}s, "
          f"flag>={cfg['detection']['flag_threshold']}, "
          f"review>={cfg['detection']['review_threshold']}). Ctrl-C to stop.\n")

    try:
        while True:
            analyzed_any = False
            for frame in capturer.capture(skip_unchanged=not once):
                analyzed_any = True
                result = detector.analyze(frame.image)
                ts = time.strftime("%H:%M:%S")
                color = _COLOR.get(result.verdict, "")
                print(f"{color}{ts} [d{frame.display_index}] "
                      f"{result.verdict.value.upper():8} {result.reason}{_RESET}")
                if result.verdict in (Verdict.FLAGGED, Verdict.ALERT,
                                      Verdict.REVIEW):
                    ctx = capture_context()
                    if is_ignored(ctx, ignore_patterns):
                        continue
                    grade = risk = None
                    if risk_cfg.get("enabled"):
                        a = assess(result.verdict.value, result.reason, ctx,
                                   risk_cfg)
                        if not a["keep"]:
                            continue
                        grade, risk = a["grade"], a["risk"]
                    logger.log(result, frame.display_index, frame.image,
                               context=ctx, grade=grade, risk=risk)
                    if ctx.get("app") or ctx.get("url") or ctx.get("window_title"):
                        loc = ctx.get("url") or ctx.get("window_title") or ""
                        print(f"           ↳ {ctx.get('app') or '?'}"
                              + (f" — {loc}" if loc else "")
                              + (f"  [{grade}]" if grade else ""))
            if once:
                if not analyzed_any:
                    print("[eyeguard] no frame captured (permission?).")
                return
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[eyeguard] stopped.")


def main(argv=None):
    p = argparse.ArgumentParser(prog="eyeguard",
                                description="EyeGuard capture-and-detect loop")
    p.add_argument("--config", default=str(Path(__file__).resolve().parent.parent
                                            / "config.yaml"))
    p.add_argument("--interval", type=float, default=None,
                   help="seconds between captures (overrides config)")
    p.add_argument("--once", action="store_true",
                   help="analyze one frame per display and exit")
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    run(cfg, interval=args.interval, once=args.once)


if __name__ == "__main__":
    sys.exit(main())
