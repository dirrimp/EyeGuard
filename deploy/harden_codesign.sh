#!/bin/bash
# EyeGuard hardened-runtime signing — run with sudo, from Dad's own session.
# Signs the actual interpreter the session agent and session watcher both
# run as, so lldb-attach / DYLD_INSERT_LIBRARIES neutering-in-place without
# a restart no longer works. Free (ad-hoc), no Apple Developer Program
# needed. Backs up first, verifies the app still runs, restarts both
# processes, and rolls back automatically if anything looks wrong after
# restart.
#
# Admin-trust-model pivot (2026-08-24): its relative importance has dropped
# now that the monitored user has full admin and can just as easily
# uninstall/replace the binary outright -- this still closes a real, DIFFERENT
# gap the file-integrity manifest check can't (in-memory patching of a
# RUNNING process without touching any file on disk, so the manifest stays
# clean), so it's kept, just not oversold as the primary defense it used to
# be when it was the one thing standing between a Standard user and a
# privileged process.
set -euo pipefail

PYBIN="/Applications/EyeGuard.app/Contents/Resources/python/bin/python3.12"
BACKUP="/Applications/EyeGuard.app/Contents/Resources/python/bin/python3.12.pre-hardening-backup"
ENT="/tmp/eyeguard-hardening-entitlements.plist"
MONITORED_UID="$(id -u jonahdirrim)"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo." >&2
  exit 1
fi

echo "== 1/6: backing up current binary =="
cp "$PYBIN" "$BACKUP"

echo "== 2/6: writing entitlements =="
cat > "$ENT" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.cs.disable-library-validation</key>
	<true/>
	<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
	<true/>
	<key>com.apple.security.cs.allow-jit</key>
	<true/>
</dict>
</plist>
PLIST

echo "== 3/6: signing (hardened runtime, no get-task-allow) =="
codesign -f --options runtime --entitlements "$ENT" --sign - "$PYBIN"
SIGN_OUTPUT="$(codesign -dv "$PYBIN" 2>&1)"
if ! echo "$SIGN_OUTPUT" | grep -q "flags=0x10002(adhoc,runtime)"; then
  echo "Signature verification failed -- restoring backup." >&2
  echo "$SIGN_OUTPUT" >&2
  cp "$BACKUP" "$PYBIN"
  exit 1
fi
echo "Signature OK: hardened runtime, no get-task-allow."

echo "== 4/6: smoke test (unsigned-of-daemon-context import check) =="
"$PYBIN" -c "import Quartz, onnxruntime, numpy, transformers, PIL, mss" || {
  echo "Import smoke test failed -- restoring backup." >&2
  cp "$BACKUP" "$PYBIN"
  exit 1
}
echo "Smoke test OK."

echo "== 5/6: restarting session agent + session watcher =="
launchctl kickstart -k "gui/${MONITORED_UID}/com.eyeguard.monitor"
launchctl kickstart -k system/com.eyeguard.sessionwatcher
sleep 5

echo "== 6/6: verifying both are up and not crash-looping =="
# launchctl print's "pid = " line for another user's GUI domain isn't
# reliably visible cross-session (confirmed live: even queried directly, no
# sudo, targeting jonahdirrim's domain from patrickdirrim's session returns
# no pid line despite the process genuinely running per `ps`) -- so verify
# via the process table instead, which is visible regardless of caller.
AGENT_PID="$(pgrep -f "run_agent\.py" | head -1 || true)"
WATCHER_PID="$(pgrep -f "eyeguard\.session_watcher" | head -1 || true)"
if [ -z "${AGENT_PID:-}" ] || [ -z "${WATCHER_PID:-}" ]; then
  echo "One or both processes did not come back up -- restoring backup and restarting again." >&2
  cp "$BACKUP" "$PYBIN"
  launchctl kickstart -k "gui/${MONITORED_UID}/com.eyeguard.monitor"
  launchctl kickstart -k system/com.eyeguard.sessionwatcher
  exit 1
fi
sleep 3
if ! ps -p "$AGENT_PID" > /dev/null || ! ps -p "$WATCHER_PID" > /dev/null; then
  echo "One or both processes died shortly after restart -- restoring backup and restarting again." >&2
  cp "$BACKUP" "$PYBIN"
  launchctl kickstart -k "gui/${MONITORED_UID}/com.eyeguard.monitor"
  launchctl kickstart -k system/com.eyeguard.sessionwatcher
  exit 1
fi

echo
echo "SUCCESS. agent pid=$AGENT_PID watcher pid=$WATCHER_PID, both stable."
echo "Backup kept at: $BACKUP (safe to delete once you've confirmed heartbeats/flags are still landing normally over the next day)."
echo "Next: check the Supabase device_status heartbeat (both last_heartbeat and watcher_last_heartbeat) is still advancing, and that flags still land normally."
