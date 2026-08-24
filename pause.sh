#!/usr/bin/env bash
# Pause EyeGuard WITHOUT alerting the partner — requires the partner's password.
# Any other way of stopping it will trip the "monitoring went dark" alert.
set -euo pipefail
DIR="$HOME/Library/Application Support/EyeGuard"
LABEL="com.eyeguard.monitor"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
# shellcheck source=/dev/null
source "$DIR/eg_authorize.sh"

if eg_authorized_stop; then
  launchctl unload "$PLIST" 2>/dev/null || true
  echo "✅ EyeGuard paused (authorized). Run ./resume.sh to start it again."
else
  echo "❌ Wrong password — EyeGuard was NOT stopped."
  echo "   Stopping it any other way will alert your accountability partner."
  exit 1
fi
