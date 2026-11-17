#!/bin/sh
# Builds the UNSIGNED phase 3 FIT-TEST APK (throwaway) with raw SDK tools, in Agent IT's network-less, hash-pinned container.
#   inputs : /src (this folder, ro), /sdk (build-tools r34, platform-34), /pins (IT's pinned ONNX Runtime pieces + model, ro)
#   output : /out/onn-fit-unsigned.apk and /out/BUILD-FIT.txt
# Differences from the phase 2 build.sh (on purpose): it ADDS exactly two armeabi-v7a native libraries and the ORT jar, and
# its checks are the opposite of phase 2's lib/ check. No keystore is ever present; Jonah signs it on his Mac.
set -eu
SRC=${SRC:-/src}; SDK=${SDK:-/sdk}; OUT=${OUT:-/out}; PINS=${PINS:-/pins}
BT=${BT:-$SDK/build-tools/34.0.0}; JAR=${ANDROID_JAR:-$SDK/platforms/android-34/android.jar}
ORT=${ORT:-$PINS/ort-1.31.1-armeabi-v7a}
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
( cd "$PINS" && sha256sum -c SHA256SUMS ) || { echo "FAIL: pinned inputs do not verify"; exit 1; }
mkdir -p "$W/classes" "$W/dex" "$W/lib/armeabi-v7a" "$W/x" "$OUT"
"$BT/aapt2" compile --dir "$SRC/res" -o "$W/res.zip"
"$BT/aapt2" link -o "$W/base.apk" -I "$JAR" --manifest "$SRC/AndroidManifest.xml" \
  --min-sdk-version 30 --target-sdk-version 34 --version-code 1 --version-name fit-0.1.0 "$W/res.zip"
javac --release 11 -Xlint:all -classpath "$JAR:$ORT/classes.jar" -d "$W/classes" $(find "$SRC/src" -name '*.java')
"$BT/d8" --release --min-api 30 --lib "$JAR" --output "$W/dex" $(find "$W/classes" -name '*.class') "$ORT/classes.jar"
( cd "$W/dex" && jar --update --no-manifest --date 2026-01-01T00:00:00Z --file "$W/base.apk" classes.dex )
cp "$ORT/libonnxruntime.so" "$ORT/libonnxruntime4j_jni.so" "$W/lib/armeabi-v7a/"
# stored (not deflated) so zipalign can page-align them, whatever extractNativeLibs is
jar --update --no-manifest --no-compress --date 2026-01-01T00:00:00Z --file "$W/base.apk" -C "$W" lib
"$BT/zipalign" -f -p 4 "$W/base.apk" "$OUT/onn-fit-unsigned.apk"
"$BT/zipalign" -c -p 4 "$OUT/onn-fit-unsigned.apk" || { echo "FAIL: not aligned"; exit 1; }
# ---- checks: the fit-test app must have NO permission, NO provider and no telemetry, and exactly the two pinned libraries
PERMS=$("$BT/aapt2" dump permissions "$OUT/onn-fit-unsigned.apk" | grep -c '^uses-permission' || true)
[ "$PERMS" = "0" ] || { echo "FAIL: expected 0 permissions, found $PERMS"; exit 1; }
TREE=$("$BT/aapt2" dump xmltree --file AndroidManifest.xml "$OUT/onn-fit-unsigned.apk")
case "$TREE" in *TelemetryInitializer*|*provider*|*receiver*|*"E: service"*) echo "FAIL: unexpected component or telemetry in the manifest"; exit 1;; esac
# an activity started from adb (uid 2000) must be exported, or `am start` is refused on the box (found on the first real run)
printf '%s' "$TREE" | grep -q 'exported(0x01010010)=true' || { echo "FAIL: FitActivity is not exported, so adb cannot start it"; exit 1; }
printf '%s' "$TREE" | grep -q 'intent-filter' && { echo "FAIL: unexpected intent-filter (the activity must only be reachable by explicit component)"; exit 1; }
LIB=$(jar tf "$OUT/onn-fit-unsigned.apk" | grep '^lib/' | grep -v '/$' | sort) || { echo "FAIL: cannot list the APK"; exit 1; }
WANT=$(printf 'lib/armeabi-v7a/libonnxruntime.so\nlib/armeabi-v7a/libonnxruntime4j_jni.so\n')
[ "$LIB" = "$WANT" ] || { echo "FAIL: lib/ must be exactly the two pinned armeabi-v7a libraries; found: $LIB"; exit 1; }
( cd "$W/x" && jar xf "$OUT/onn-fit-unsigned.apk" lib/armeabi-v7a/libonnxruntime.so lib/armeabi-v7a/libonnxruntime4j_jni.so \
  && for f in libonnxruntime.so libonnxruntime4j_jni.so; do cmp "lib/armeabi-v7a/$f" "$ORT/$f" || { echo "FAIL: $f differs from its pin"; exit 1; }; done )
"$BT/aapt2" dump badging "$OUT/onn-fit-unsigned.apk" | grep -q "native-code: 'armeabi-v7a'$" || { echo "FAIL: native-code is not armeabi-v7a only"; exit 1; }
{ echo "fit-0.1.0"; sha256sum "$OUT/onn-fit-unsigned.apk"; "$BT/aapt2" dump badging "$OUT/onn-fit-unsigned.apk" | grep -E "^package|native-code|sdkVersion|targetSdk"; } > "$OUT/BUILD-FIT.txt"
cat "$OUT/BUILD-FIT.txt"
