"""Virtual-machine software monitoring.

A Standard user can install free virtualization software (UTM, VirtualBox,
etc.) without admin, then browse inside the VM's own network stack --
bypassing the router's AdGuard/DoH-block network-level protections, and
reducing the green trail's app/URL context (a VM's internal browser isn't
AppleScript-introspectable the way Safari/Chrome are). This can't PREVENT
that (the same tamper-EVIDENT tradeoff as extensions.py's browser-extension
monitoring), but the on-screen visual detector still sees whatever's
rendered in the VM's window regardless of what's happening inside it --
this just makes installing virtualization software itself visible to the
partner, the same way a new browser extension is.

scan() returns {name: path} of detected VM software: known app bundles in
/Applications + ~/Applications, and known CLI-only tools (installed e.g. via
Homebrew, no .app bundle) found on PATH.
"""

from __future__ import annotations

import shutil
from pathlib import Path

_APP_DIRS = [Path("/Applications"), Path.home() / "Applications"]

# Full-desktop-OS / mobile-emulator virtualization apps, as they appear in
# /Applications. Docker is included even though it's containers, not a full
# OS -- still a separate, non-AppleScript-introspectable environment.
_KNOWN_APPS = [
    "UTM.app",
    "Parallels Desktop.app",
    "Parallels Desktop Lite.app",
    "VMware Fusion.app",
    "VMware Horizon Client.app",
    "Oracle VM VirtualBox.app",
    "VirtualBox.app",
    "Genymotion.app",
    "BlueStacks.app",
    "BlueStacks X.app",
    "NoxPlayer.app",
    "Android Studio.app",
    "Docker.app",
    "QEMU.app",
]

# CLI-only tools (typically Homebrew-installed, no .app bundle) on PATH.
_KNOWN_CLI = [
    "qemu-system-x86_64", "qemu-system-aarch64", "VBoxManage", "vagrant",
    "limactl", "colima", "multipass", "emulator",  # Android SDK emulator
]


def scan() -> dict:
    """{name: path} of detected VM software, app bundles + CLI tools."""
    out: dict = {}
    try:
        for base in _APP_DIRS:
            if not base.exists():
                continue
            for name in _KNOWN_APPS:
                p = base / name
                if p.exists():
                    out[name] = str(p)
    except Exception:
        pass
    try:
        for tool in _KNOWN_CLI:
            path = shutil.which(tool)
            if path:
                out[tool] = path
    except Exception:
        pass
    return out
