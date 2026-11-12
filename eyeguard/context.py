"""Local capture of what app/site was active at flag time.

Stamps each flag with the frontmost app, the active browser URL (where the
browser exposes it to automation), and the front window title. This corroborates
*what* was on screen with *where* it came from — entirely on-device, with no
dependency on any external service (e.g. Accountable2You).

Permissions: window-title capture uses System Events and needs Accessibility
permission for the host process; URL capture uses per-browser automation
(Automation permission). Both fail gracefully — if not granted, the field is
simply omitted rather than blocking a flag.
"""

from __future__ import annotations

import os
import subprocess

# Browsers whose active-tab URL is reachable via AppleScript, and the script to
# get it. Firefox is intentionally absent — it doesn't expose tab URLs to
# AppleScript; we fall back to its window title (which is the page title).
_BROWSER_URL_SCRIPTS = {
    "Safari": 'tell application "Safari" to return URL of front document',
    "Google Chrome":
        'tell application "Google Chrome" to return URL of active tab '
        'of front window',
    "Google Chrome Canary":
        'tell application "Google Chrome Canary" to return URL of active tab '
        'of front window',
    "Brave Browser":
        'tell application "Brave Browser" to return URL of active tab '
        'of front window',
    "Microsoft Edge":
        'tell application "Microsoft Edge" to return URL of active tab '
        'of front window',
    "Arc": 'tell application "Arc" to return URL of active tab of front window',
    "Vivaldi":
        'tell application "Vivaldi" to return URL of active tab of front window',
}


def _osascript(script: str, timeout: float = 2.0) -> str | None:
    try:
        out = subprocess.run(["osascript", "-e", script], capture_output=True,
                             text=True, timeout=timeout)
        val = out.stdout.strip()
        return val or None
    except Exception:
        return None


def frontmost_app() -> str | None:
    """Localized name of the frontmost application (e.g. 'Firefox')."""
    try:
        from AppKit import NSWorkspace
        app = NSWorkspace.sharedWorkspace().frontmostApplication()
        return app.localizedName() if app else None
    except Exception:
        # Fallback: ask System Events for the frontmost process name.
        return _osascript(
            'tell application "System Events" to get name of '
            '(first process whose frontmost is true)')


def frontmost_is_self() -> bool:
    """True if EyeGuard's own process is the frontmost app — so the activity
    trail doesn't log ourselves (e.g. the brief moment we're focused at launch)."""
    try:
        from AppKit import NSWorkspace
        app = NSWorkspace.sharedWorkspace().frontmostApplication()
        return bool(app and app.processIdentifier() == os.getpid())
    except Exception:
        return False


def front_window_title(app_name: str | None) -> str | None:
    """Title of the frontmost window (for browsers this is the page title).

    Primary path: CGWindowList, which exposes window names under the SCREEN
    RECORDING permission EyeGuard already has — no Accessibility grant needed.
    Falls back to System Events (needs Accessibility) if Quartz is unavailable.
    """
    try:
        from AppKit import NSWorkspace
        from Quartz import (CGWindowListCopyWindowInfo,
                            kCGWindowListOptionOnScreenOnly, kCGNullWindowID)
        front = NSWorkspace.sharedWorkspace().frontmostApplication()
        pid = front.processIdentifier() if front else None
        if pid is not None:
            windows = CGWindowListCopyWindowInfo(
                kCGWindowListOptionOnScreenOnly, kCGNullWindowID) or []
            # Windows come back front-to-back; first normal (layer 0) window of
            # the frontmost app is the active one.
            for w in windows:
                if (w.get("kCGWindowOwnerPID") == pid
                        and int(w.get("kCGWindowLayer", 0)) == 0):
                    name = w.get("kCGWindowName")
                    if name:
                        return str(name)
    except Exception:
        pass
    if app_name:
        return _osascript(
            f'tell application "System Events" to tell process "{app_name}" '
            'to get name of front window')
    return None


def active_url(app_name: str | None) -> str | None:
    if not app_name:
        return None
    script = _BROWSER_URL_SCRIPTS.get(app_name)
    return _osascript(script) if script else None


def capture_context() -> dict:
    """Best-effort {app, url, window_title}. Any field may be None."""
    app = frontmost_app()
    return {
        "app": app,
        "url": active_url(app),
        "window_title": front_window_title(app),
    }


def is_ignored(ctx: dict, patterns: list[str]) -> bool:
    """True if the active window/url matches an ignore pattern — used so EyeGuard
    doesn't flag its OWN report/log (which list suggestive descriptions as text)."""
    if not patterns:
        return False
    hay = ((ctx.get("window_title") or "") + " "
           + (ctx.get("url") or "") + " " + (ctx.get("app") or "")).lower()
    from .risk import pattern_hits
    return any(pattern_hits(p, ctx, hay) for p in patterns)
