"""Local flag logging.

Phase 1 writes flag events to a local JSONL file. No network, no partner
notification yet (that's Phase 2). Optionally saves the flagged frame to disk
for sensitivity tuning — off by default for privacy.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image, ImageFilter

from .detector import Detection, Verdict


class FlagLogger:
    def __init__(self, flag_log: str, save_flagged_frames: bool = False,
                 flagged_frames_dir: str = "flagged_frames",
                 blur_red_frames: bool = True, blur_strength: int = 50):
        self.flag_log = Path(flag_log)
        self.save_flagged_frames = save_flagged_frames
        self.flagged_frames_dir = Path(flagged_frames_dir)
        # RED-tier frames (nudity / very revealing) are saved BLURRED so a
        # partner can review the flag without being exposed to the content.
        self.blur_red_frames = blur_red_frames
        # Blur radius = image_width / blur_strength. HIGHER = LIGHTER blur.
        self.blur_strength = max(8, int(blur_strength))

    def log(self, detection: Detection, display_index: int,
            image: Image.Image | None = None,
            context: dict | None = None,
            grade: str | None = None, risk: str | None = None) -> dict:
        ts = datetime.now(timezone.utc).isoformat()
        record = {
            "timestamp": ts,
            "verdict": detection.verdict.value,
            "reason": detection.reason,
            "top_score": round(detection.top_score, 4),
            "labels": {k: round(v, 4) for k, v in detection.labels.items()},
            "arbiter_answer": detection.arbiter_answer,
            "display": display_index,
            # Local corroboration: what app/site/window was active at flag time.
            "app": (context or {}).get("app"),
            "url": (context or {}).get("url"),
            "window_title": (context or {}).get("window_title"),
            # Context-aware risk grade.
            "grade": grade,
            "risk": risk,
        }
        if (self.save_flagged_frames and image is not None
                and detection.verdict in (Verdict.FLAGGED, Verdict.ALERT)):
            self.flagged_frames_dir.mkdir(parents=True, exist_ok=True)
            fname = ts.replace(":", "-") + f"_{detection.verdict.value}_d{display_index}.jpg"
            path = self.flagged_frames_dir / fname
            out_img = image.convert("RGB")
            # Blur RED-tier (nudity/very revealing) frames for safe partner review:
            # body detail is obscured, but the scene/app stays recognizable enough
            # to confirm the flag isn't a false positive.
            if detection.verdict is Verdict.FLAGGED and self.blur_red_frames:
                radius = max(6, out_img.width // self.blur_strength)
                out_img = out_img.filter(ImageFilter.GaussianBlur(radius))
            out_img.save(path, "JPEG", quality=80)
            record["saved_frame"] = str(path)

        with self.flag_log.open("a") as f:
            f.write(json.dumps(record) + "\n")
        return record

    def log_text(self, matched: list[str], source: str,
                 context: dict | None = None, grade: str = "Possible",
                 risk: str = "neutral") -> dict:
        """Log an explicit-TEXT flag (YELLOW). `source` is 'screen' (OCR) or
        'url' (URL/search signal). Imageless — the matched terms + site are the
        signal; we don't save screenshots of private text."""
        ctx = context or {}
        if source == "url":
            reason = "signal: explicit term in URL/search — " + ", ".join(matched[:5])
        else:
            reason = "text: explicit text on screen — " + ", ".join(matched[:5])
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verdict": "alert",
            "reason": reason,
            "app": ctx.get("app"),
            "url": ctx.get("url"),
            "window_title": ctx.get("window_title"),
            "grade": grade,
            "risk": risk,
            "no_image": True,
        }
        with self.flag_log.open("a") as f:
            f.write(json.dumps(record) + "\n")
        return record

    def log_extension(self, name: str, browser: str,
                      questionable: bool) -> dict:
        """Log a newly-installed browser extension. Questionable ones (likely
        evasion tools) are RED and route to the tamper alert; others are a YELLOW
        review flag. Imageless."""
        if questionable:
            reason = f"tamper: questionable {browser} extension '{name}'"
            verdict, grade, risk = "flagged", "Likely", "high"
        else:
            reason = f"extension: new {browser} extension '{name}'"
            verdict, grade, risk = "alert", "Possible", "neutral"
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict,
            "reason": reason,
            "app": browser,
            "url": None,
            "window_title": f"{browser}: {name}",
            "grade": grade,
            "risk": risk,
            "no_image": True,
        }
        with self.flag_log.open("a") as f:
            f.write(json.dumps(record) + "\n")
        return record

    def log_vm_software(self, name: str, path: str) -> dict:
        """Log newly-detected virtualization software (UTM, VirtualBox, etc.) --
        a Standard user can install this without admin and browse inside its own
        network stack, bypassing router-level DNS filtering. Not itself proof of
        anything (legitimate dev tool use is common), so YELLOW review rather
        than an immediate red incident -- but it's now visible to the partner,
        matching the browser-extension monitor's tamper-evident philosophy.
        Imageless."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verdict": "alert",
            "reason": f"vm: new virtualization software '{name}' ({path})",
            "app": "EyeGuard",
            "url": None,
            "window_title": f"Virtualization software installed: {name}",
            "grade": "Possible",
            "risk": "neutral",
            "no_image": True,
        }
        with self.flag_log.open("a") as f:
            f.write(json.dumps(record) + "\n")
        return record

    def log_drm(self, context: dict | None = None,
                service: str | None = None) -> dict:
        """Log a YELLOW flag for DRM streaming video that macOS blanks to black —
        EyeGuard can't see the pixels, so we record the title instead. Imageless
        (the frame is black); the partner sees WHAT was watched, not the content."""
        ctx = context or {}
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verdict": "alert",
            "reason": f"drm:{service or 'streaming'}",
            "app": ctx.get("app"),
            "url": ctx.get("url"),
            "window_title": ctx.get("window_title"),
            "grade": "Possible",
            "risk": "neutral",
            "no_image": True,
        }
        with self.flag_log.open("a") as f:
            f.write(json.dumps(record) + "\n")
        return record

    _TITLE_TRIM = 60

    def log_activity(self, context: dict | None = None) -> dict:
        """Log a clean (GREEN) browsing record: what app/site is active, with a
        timestamp and no image. This builds the full activity trail so a reviewer
        sees everywhere the user went — not only frames the detector flagged.

        window_title is trimmed here specifically because this is the
        highest-volume, routine, never-itself-an-incident record type (sampled
        every ~20s by default) — a browser tab title can carry a full search
        query or article headline, well beyond "which app/site was active."
        When a URL is already present it's the real identifying signal, so the
        title is dropped entirely as redundant; for non-browser apps with no
        URL to fall back on, the title is kept (it's the only location signal
        those rows have) but capped short, rather than logged in full."""
        ctx = context or {}
        url = ctx.get("url")
        title = ctx.get("window_title")
        if url:
            trimmed_title = None
        elif title and len(title) > self._TITLE_TRIM:
            trimmed_title = title[: self._TITLE_TRIM] + "…"
        else:
            trimmed_title = title
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verdict": "clear",
            "reason": "activity",
            "app": ctx.get("app"),
            "url": url,
            "window_title": trimmed_title,
        }
        with self.flag_log.open("a") as f:
            f.write(json.dumps(record) + "\n")
        return record
