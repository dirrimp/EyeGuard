"""Screen Recording permission check for the capture agent's blind probe.

Why: when macOS rejects the agent's Screen Recording grant (tccd: "Failed to match existing
code requirement"), screen capture does NOT go black. It silently returns the wallpaper with
every other app's windows missing. The old blind probe (brightness + frozen frames) passes on
that, so the agent reported screen_ok=true for ~38 h on 2026-11-10..12 while seeing nothing.

CGPreflightScreenCaptureAccess() answers "may this process capture other apps' windows?"
without capturing anything. It returns booleans only: no pixels, no window names, no content.
"""
from __future__ import annotations

# Consecutive probes (15 s apart) that must all say "denied" before the agent calls itself
# blind. One stray False must not raise a false alarm; 2 probes = about 30 s.
DENIED_PROBES_REQUIRED = 2


def screen_capture_permitted() -> bool | None:
    """True / False from macOS, or None when the check itself is unavailable (non-macOS, no
    Quartz). None is never treated as a denial: this only ADDS a blind signal, it never hides
    the existing ones."""
    try:
        from Quartz import CGPreflightScreenCaptureAccess
        return bool(CGPreflightScreenCaptureAccess())
    except Exception:
        return None


class PermissionWatch:
    """Debounced 'is the Screen Recording grant gone?' state for the probe loop."""

    def __init__(self, required: int = DENIED_PROBES_REQUIRED):
        self.required = required
        self.streak = 0

    def update(self, permitted: bool | None) -> bool:
        """Feed one probe result. Returns True when the agent should count itself blind."""
        if permitted is False:
            self.streak += 1
        else:                      # True, or unknown: the streak restarts
            self.streak = 0
        return self.streak >= self.required
