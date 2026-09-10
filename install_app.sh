#!/usr/bin/env bash
# Deploy EyeGuard.app to /Applications (branded, in Launchpad/Finder) and point
# the login agent at it. The runtime (code + venv) stays in Application Support;
# this only places the app shell in /Applications. Run in Terminal (needs admin).
set -euo pipefail

RUNTIME="$HOME/Library/Application Support/EyeGuard"
SRC_APP="$RUNTIME/EyeGuard.app"
DST_APP="/Applications/EyeGuard.app"
EXE="$DST_APP/Contents/MacOS/EyeGuard"
LABEL="com.eyeguard.monitor"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

[ -d "$SRC_APP" ] || { echo "No app at $SRC_APP — run build_app.sh first." >&2; exit 1; }

echo "==> Copying EyeGuard.app to /Applications (admin password required)"
sudo rm -rf "$DST_APP"
sudo cp -R "$SRC_APP" "$DST_APP"
# root-owned + non-user-writable: the interpreter inside is hardened-runtime
# signed, and it lives outside the root-owned code tree / file-integrity
# manifest, so a user-writable bundle would let a Standard user swap it for an
# unhardened build. deploy_watcher re-asserts this on every deploy; session_
# watcher flags it per-cycle if it regresses.
sudo chown -R root:wheel "$DST_APP"
sudo chmod -R go-w "$DST_APP"

echo "==> Pointing the login agent at /Applications/EyeGuard.app"
mkdir -p "$RUNTIME/logs"
cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>            <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$EXE</string>
    </array>
    <key>WorkingDirectory</key> <string>$RUNTIME</string>
    <key>RunAtLoad</key>        <true/>
    <key>KeepAlive</key>        <true/>
    <key>StandardOutPath</key>  <string>$RUNTIME/logs/agent.out.log</string>
    <key>StandardErrorPath</key><string>$RUNTIME/logs/agent.err.log</string>
    <key>ProcessType</key>      <string>Interactive</string>
</dict>
</plist>
PLIST_EOF

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load -w "$PLIST"

# Register so Finder/Launchpad pick up the icon immediately.
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
  -f "$DST_APP" 2>/dev/null || true

echo
echo "Done. EyeGuard.app is now in /Applications and runs from there at login."
echo "Pin it to the Dock: open /Applications in Finder and drag EyeGuard onto the Dock."
