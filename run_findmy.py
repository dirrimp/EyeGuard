#!/usr/bin/env python3
"""Launcher for the Find My cross-check watcher.

Mirrors run_agent.py exactly: a direct absolute script path, not
`-m eyeguard.findmy_watcher`. Under the per-user GUI launchd domain that
matters -- a `-m module` LaunchAgent here crash-loops with exit 78/EX_CONFIG
and no log output at all (established 2026-09-02); the direct-path form every
other GUI-domain job in this project uses (com.eyeguard.monitor) works. `-m`
invocation is only proven under the root LaunchDaemons (session_watcher,
deploy_watcher), a different domain.
"""
from eyeguard.findmy_watcher import main

if __name__ == "__main__":
    main()
