#!/bin/sh
# EyeGuard G11 event reporter -- thin wrapper. See eg_report.py for behavior.
# Usage:  eg-report.sh '<event-json>'    report one event (queue first, then send)
#         eg-report.sh --flush           retry anything still queued (cron/timer)
#         eg-report.sh --status          print queue depth
#         eg-report.sh --heartbeat JSON  liveness beat (not queued; see eg_report.py)
exec python3 "$(dirname "$0")/eg_report.py" "$@"
