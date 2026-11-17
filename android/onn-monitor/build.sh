#!/bin/sh
# Builds the UNSIGNED phase 2 APK with raw SDK tools (no Gradle, no network). Run inside IT's pinned, network-less build container.
#   inputs : /src (this folder, read-only), /sdk (build-tools r34 + platform-34 android.jar, hash-pinned by IT)
#   output : /out/onn-guard-unsigned.apk and /out/BUILD.txt (hashes)
# No keystore is ever present here: signing happens on Jonah's Mac (see README.md).
set -eu
SRC=${SRC:-/src}; SDK=${SDK:-/sdk}; OUT=${OUT:-/out}
BT=${BT:-$SDK/build-tools/34.0.0}; JAR=${ANDROID_JAR:-$SDK/platforms/android-34/android.jar}
VERSION_NAME=${VERSION_NAME:-0.1.0}; VERSION_CODE=${VERSION_CODE:-1}
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
mkdir -p "$W/classes" "$W/dex" "$OUT"
"$BT/aapt2" compile --dir "$SRC/res" -o "$W/res.zip"
"$BT/aapt2" link -o "$W/base.apk" -I "$JAR" --manifest "$SRC/AndroidManifest.xml" \
  --min-sdk-version 30 --target-sdk-version 34 --version-code "$VERSION_CODE" --version-name "$VERSION_NAME" "$W/res.zip"
javac --release 11 -Xlint:all -classpath "$JAR" -d "$W/classes" $(find "$SRC/src" -name '*.java')
"$BT/d8" --release --min-api 30 --lib "$JAR" --output "$W/dex" $(find "$W/classes" -name '*.class')
# --date pins the zip entry time so two builds of the same source are byte-identical (found by Agent IT 2026-11-17)
( cd "$W/dex" && jar --update --no-manifest --date 2026-01-01T00:00:00Z --file "$W/base.apk" classes.dex )
"$BT/zipalign" -f -p 4 "$W/base.apk" "$OUT/onn-guard-unsigned.apk"
{ echo "version $VERSION_NAME ($VERSION_CODE)"; sha256sum "$OUT/onn-guard-unsigned.apk"; "$BT/aapt2" dump permissions "$OUT/onn-guard-unsigned.apk"; } > "$OUT/BUILD.txt"
# fail the release on any extra permission or any native library (phase 2 is pure Java)
PERMS=$("$BT/aapt2" dump permissions "$OUT/onn-guard-unsigned.apk" | grep -c '^uses-permission')
[ "$PERMS" = "1" ] || { echo "FAIL: expected exactly 1 permission, found $PERMS"; exit 1; }
# list with jar (always present in the JDK image; unzip is not), and fail if the listing itself fails: a pipe's status comes from
# grep, so a missing lister used to let this check pass silently (found by Agent IT 2026-11-17)
LIST=$(jar tf "$OUT/onn-guard-unsigned.apk") || { echo "FAIL: cannot list the APK"; exit 1; }
case "$LIST" in *lib/*) echo "FAIL: native libraries present"; exit 1;; esac
cat "$OUT/BUILD.txt"
