#!/usr/bin/env bash
# Build a SELF-CONTAINED EyeGuard.app with an embedded standalone Python (+ all
# deps). The running process is then a binary INSIDE the bundle at a stable path,
# so Screen Recording permission survives any Homebrew change, and EyeGuard no
# longer depends on the system Python at all.
#
# The app code + config + data stay in ~/Library/Application Support/EyeGuard
# (editable); only the Python interpreter + libraries live in the bundle.
set -euo pipefail
cd "$(dirname "$0")"
PROJECT_DIR="$(pwd)"
PY_SRC="$PROJECT_DIR/build_bundle/python"      # prepared standalone python + deps
RUNTIME="$HOME/Library/Application Support/EyeGuard"
APP="${1:-$RUNTIME/EyeGuard-bundled.app}"      # build target (test name by default)

[ -x "$PY_SRC/bin/python3.12" ] || { echo "Missing prepared python at $PY_SRC" >&2; exit 1; }
[ -f "$PROJECT_DIR/assets/EyeGuard.icns" ] || { echo "Missing icon — run build_icons.sh" >&2; exit 1; }

for bad in transformers torch huggingface_hub; do
  if [ -d "$PY_SRC"/lib/python3.12/site-packages/"$bad" ]; then
    echo "Refusing to bundle dev-only package '$bad' (see requirements-dev.txt). Rebuild with tools/prepare_bundle_python.sh" >&2; exit 1
  fi
done

echo "==> Creating bundle skeleton: $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$PROJECT_DIR/assets/EyeGuard.icns" "$APP/Contents/Resources/EyeGuard.icns"

echo "==> Copying embedded Python (~1.5GB)…"
cp -R "$PY_SRC" "$APP/Contents/Resources/python"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>            <string>EyeGuard</string>
    <key>CFBundleDisplayName</key>     <string>EyeGuard</string>
    <key>CFBundleIdentifier</key>      <string>com.eyeguard.monitor</string>
    <key>CFBundleExecutable</key>      <string>EyeGuard</string>
    <key>CFBundleIconFile</key>        <string>EyeGuard</string>
    <key>CFBundlePackageType</key>     <string>APPL</string>
    <key>CFBundleVersion</key>         <string>0.2.0</string>
    <key>CFBundleShortVersionString</key><string>0.2.0</string>
    <key>LSUIElement</key>             <true/>
    <key>NSHighResolutionCapable</key> <true/>
</dict>
</plist>
PLIST

# Launcher: cd to the editable runtime (code + config + data), then exec the
# embedded Python so the process executable lives inside the bundle (stable TCC
# identity). Paths are resolved at runtime so the .app is relocatable.
cat > "$APP/Contents/MacOS/EyeGuard" <<'LAUNCH'
#!/bin/bash
APP_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
RUNTIME="$HOME/Library/Application Support/EyeGuard"
cd "$RUNTIME" || exit 1
exec "$APP_DIR/Contents/Resources/python/bin/python3.12" -m eyeguard.menubar
LAUNCH
chmod +x "$APP/Contents/MacOS/EyeGuard"

/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
  -f "$APP" 2>/dev/null || true

echo "==> Built $APP"
du -sh "$APP" | awk '{print "    size: "$1}'
