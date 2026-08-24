#!/usr/bin/env python3
"""Launcher for the session agent.

The managed LaunchAgent runs THIS file by its absolute path:
    <python> /Library/Application Support/EyeGuard/run_agent.py

Launching via an absolute script path (not `-m`) puts this directory first on
sys.path, so the intended `eyeguard` package always wins over any
PYTHONPATH/cwd override. (Admin-trust-model pivot, 2026-08-24: there is no
more socket/peer-verification to pin an invocation to -- see
eyeguard/uploader.py's module docstring for the current trust model.)
"""
from eyeguard.menubar import main

if __name__ == "__main__":
    main()
