#!/bin/bash
# EyeGuard hardened-runtime signing — run with sudo, from Dad's own session.
# Signs the actual interpreter both the vault daemon and session agent run
# as, so lldb-attach / DYLD_INSERT_LIBRARIES neutering-in-place no longer
# works. Free (ad-hoc), no Apple Developer Program needed. Backs up first,
# verifies the app still runs, restarts both processes, and rolls back
# automatically if anything looks wrong after restart.
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

echo "== 5/6: restarting vault daemon + session agent =="
launchctl kickstart -k system/com.eyeguard.vault
launchctl kickstart -k "gui/${MONITORED_UID}/com.eyeguard.monitor"
sleep 5

echo "== 6/6: verifying both are up and not crash-looping =="
VAULT_INFO="$(launchctl print system/com.eyeguard.vault 2>/dev/null || true)"
AGENT_INFO="$(launchctl print "gui/${MONITORED_UID}/com.eyeguard.monitor" 2>/dev/null || true)"
VAULT_PID="$(awk '/pid = /{print $3; exit}' <<< "$VAULT_INFO")"
AGENT_PID="$(awk '/pid = /{print $3; exit}' <<< "$AGENT_INFO")"
if [ -z "${VAULT_PID:-}" ] || [ -z "${AGENT_PID:-}" ]; then
  echo "One or both processes did not come back up -- restoring backup and restarting again." >&2
  cp "$BACKUP" "$PYBIN"
  launchctl kickstart -k system/com.eyeguard.vault
  launchctl kickstart -k "gui/${MONITORED_UID}/com.eyeguard.monitor"
  exit 1
fi
sleep 3
if ! ps -p "$VAULT_PID" > /dev/null || ! ps -p "$AGENT_PID" > /dev/null; then
  echo "One or both processes died shortly after restart -- restoring backup and restarting again." >&2
  cp "$BACKUP" "$PYBIN"
  launchctl kickstart -k system/com.eyeguard.vault
  launchctl kickstart -k "gui/${MONITORED_UID}/com.eyeguard.monitor"
  exit 1
fi

echo
echo "SUCCESS. vault pid=$VAULT_PID agent pid=$AGENT_PID, both stable."
echo "Backup kept at: $BACKUP (safe to delete once you've confirmed heartbeats/flags are still landing normally over the next day)."
echo "Next: check the Supabase device_status heartbeat is still advancing, and that flags still land normally."
