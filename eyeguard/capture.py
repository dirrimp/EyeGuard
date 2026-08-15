"""Screen capture + frame-change filtering.

Captures the literal screen framebuffer (via mss), so content is seen regardless
of which app/browser/VM/emulator it appears in. A cheap frame-change filter skips
near-identical consecutive frames so the detector isn't re-analyzing a static
screen thousands of times an hour.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from PIL import Image


@dataclass
class Frame:
    """A captured screen frame ready for analysis."""

    image: Image.Image          # RGB PIL image, possibly downscaled
    display_index: int          # which monitor it came from (1-based)
    changed_fraction: float     # fraction of pixels changed vs the previous frame


class ScreenCapturer:
    """Captures one or more displays and filters out unchanged frames."""

    def __init__(self, displays="all", max_width: int = 1280,
                 change_threshold: float = 0.02):
        self.displays = displays
        self.max_width = max_width
        self.change_threshold = change_threshold
        # Per-display downscaled grayscale signature of the last frame seen.
        self._last_signature: dict[int, np.ndarray] = {}
        self._last_monitor_count: int | None = None
        # Every successful raw grab, INCLUDING ones skipped for being unchanged
        # -- unlike a count of yielded/analyzed frames, this can't go stale just
        # because the screen is legitimately static for a while (reading, idle).
        self.frames_captured = 0

    def _monitors(self, sct):
        # mss.monitors[0] is the "all displays" virtual screen; 1..n are physical.
        # Re-read every call so a newly attached display (external monitor,
        # Sidecar, extended AirPlay) is picked up automatically.
        physical = sct.monitors[1:]
        d = self.displays
        if d in ("all", "*", "", None):
            return list(enumerate(physical, start=1))
        try:
            idx = int(d)
            if 1 <= idx <= len(physical):
                return [(idx, sct.monitors[idx])]
        except (ValueError, TypeError):
            pass
        # Unknown or now-out-of-range (e.g. that display was unplugged): capture
        # everything rather than nothing — never leave a screen unwatched.
        return list(enumerate(physical, start=1))

    def _downscale(self, img: Image.Image) -> Image.Image:
        if img.width <= self.max_width:
            return img
        ratio = self.max_width / img.width
        return img.resize((self.max_width, int(img.height * ratio)),
                          Image.BILINEAR)

    @staticmethod
    def _signature(img: Image.Image) -> np.ndarray:
        # Tiny grayscale thumbnail used only for cheap change detection.
        thumb = img.convert("L").resize((64, 64), Image.BILINEAR)
        return np.asarray(thumb, dtype=np.int16)

    def _changed_fraction(self, display_index: int, sig: np.ndarray) -> float:
        prev = self._last_signature.get(display_index)
        self._last_signature[display_index] = sig
        if prev is None:
            return 1.0  # first frame for this display always counts as changed
        # Fraction of thumbnail pixels whose brightness moved more than a hair.
        diff = np.abs(sig - prev) > 12
        return float(diff.mean())

    def capture(self, skip_unchanged: bool = True):
        """Yield Frames for each display that changed enough to be worth analyzing.

        Importing mss lazily keeps module import cheap and surfaces a clear error
        only when capture is actually attempted (e.g. missing permission).
        """
        import mss

        with mss.mss() as sct:
            monitors = self._monitors(sct)
            # Note (but don't alarm on) display hot-plugs — a new screen just
            # means one more thing to watch, and it's captured from now on.
            n = len(monitors)
            if n != self._last_monitor_count:
                if self._last_monitor_count is not None:
                    print(f"[capture] displays changed "
                          f"{self._last_monitor_count} -> {n}; capturing all {n}",
                          flush=True)
                self._last_monitor_count = n
            for display_index, monitor in monitors:
                try:
                    shot = sct.grab(monitor)
                except Exception:
                    continue  # one flaky display must not blind the others
                img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
                img = self._downscale(img)
                sig = self._signature(img)
                changed = self._changed_fraction(display_index, sig)
                self.frames_captured += 1
                if skip_unchanged and changed < self.change_threshold:
                    continue
                yield Frame(image=img, display_index=display_index,
                            changed_fraction=changed)
