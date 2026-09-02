#!/usr/bin/env python3
"""Launcher for the Find My cross-check watcher, mirroring run_agent.py's
own pattern exactly (direct script path, not `-m eyeguard.findmy_watcher`).

Diagnostic context (2026-09-02): every other per-user GUI-domain LaunchAgent
in this project (com.eyeguard.monitor) invokes a script directly this way;
`-m module` invocation has only ever been proven under root LaunchDaemons
(session_watcher, deploy_watcher, a different launchd domain entirely).
com.eyeguard.findmy3/findmy4 (both `-m eyeguard.findmy_watcher`) crash-loop
under the GUI domain with exit 78/EX_CONFIG and zero log output anywhere,
even before Python's own first print statement -- testing whether the
invocation style itself, not the code, is the actual variable.
"""
from eyeguard.findmy_watcher import main

if __name__ == "__main__":
    main()
