#!/bin/sh
# Builds the UNSIGNED phase 3 (0.2.1) APK with raw SDK tools, in Agent IT's network-less, hash-pinned container.
#   inputs : /src (this folder, ro), /sdk (build-tools r34 + platform-34), /pins (pinned ONNX Runtime pieces + the NudeNet model, ro)
#   output : /out/onn-guard-unsigned.apk and /out/BUILD-PHASE3.txt (every hash)
# No keystore is ever present: Jonah signs on his Mac. Checks FAIL the build (see the end): one permission, one service, exactly the two
# pinned armeabi-v7a libraries, the pinned model bundled, and NO ONNX Runtime telemetry code anywhere in the result.
set -eu
SRC=${SRC:-/src}; SDK=${SDK:-/sdk}; OUT=${OUT:-/out}; PINS=${PINS:-/pins}
BT=${BT:-$SDK/build-tools/34.0.0}; JAR=${ANDROID_JAR:-$SDK/platforms/android-34/android.jar}
ORT=${ORT:-$PINS/ort-1.31.1-armeabi-v7a}; MODEL=${MODEL:-$PINS/nudenet-3.4.2/320n.onnx}
MODEL_SHA=c15d8273adad2d0a92f014cc69ab2d6c311a06777a55545f2c4eb46f51911f0f
VERSION_NAME=${VERSION_NAME:-0.2.1}; VERSION_CODE=${VERSION_CODE:-3}
DATE=2026-01-01T00:00:00Z
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
( cd "$PINS" && sha256sum -c SHA256SUMS ) || { echo "FAIL: pinned inputs do not verify"; exit 1; }
[ "$(sha256sum "$MODEL" | cut -d' ' -f1)" = "$MODEL_SHA" ] || { echo "FAIL: model is not the pinned NudeNet 320n"; exit 1; }
mkdir -p "$W/classes" "$W/dex" "$W/lib/armeabi-v7a" "$W/assets" "$W/x" "$W/ortjar" "$OUT"

# ---- ONNX Runtime's Java jar WITHOUT its telemetry: remove ai/onnxruntime/telemetry/** and TelemetryInitializer (the ContentProvider) and the
# Apache text that only covers that code. Agent IT's analysis (it-20261117-1413.md): no remaining class refers to a removed one.
( cd "$W/ortjar" && jar xf "$ORT/classes.jar" )
rm -rf "$W/ortjar/ai/onnxruntime/telemetry" "$W/ortjar/ai/onnxruntime/TelemetryInitializer.class" "$W/ortjar/META-INF/LICENSE-1DS"
( cd "$W/ortjar" && find . -type f | LC_ALL=C sort | sed 's|^\./||' > "$W/ortlist" && jar --create --no-manifest --date "$DATE" --file "$W/ort-stripped.jar" @"$W/ortlist" )
STRIPPED="$W/ort-stripped.jar"
if jar tf "$STRIPPED" | grep -i -q 'telemetry'; then echo "FAIL: the stripped ONNX Runtime jar still has a telemetry entry"; exit 1; fi

cp "$MODEL" "$W/assets/320n.onnx"
"$BT/aapt2" compile --dir "$SRC/res" -o "$W/res.zip"
# the AAR manifest is NEVER used: only ours (one permission, one service). -0 onnx stores the model uncompressed.
"$BT/aapt2" link -o "$W/base.apk" -I "$JAR" --manifest "$SRC/AndroidManifest.xml" -A "$W/assets" -0 onnx \
  --min-sdk-version 30 --target-sdk-version 34 --version-code "$VERSION_CODE" --version-name "$VERSION_NAME" "$W/res.zip"
javac --release 11 -Xlint:all -classpath "$JAR:$STRIPPED" -d "$W/classes" $(find "$SRC/src" -name '*.java')
"$BT/d8" --release --min-api 30 --lib "$JAR" --output "$W/dex" $(find "$W/classes" -name '*.class') "$STRIPPED"
( cd "$W/dex" && jar --update --no-manifest --date "$DATE" --file "$W/base.apk" classes.dex )
cp "$ORT/libonnxruntime.so" "$ORT/libonnxruntime4j_jni.so" "$W/lib/armeabi-v7a/"
jar --update --no-manifest --no-compress --date "$DATE" --file "$W/base.apk" -C "$W" lib      # stored, so zipalign can page-align them
"$BT/zipalign" -f -p 4 "$W/base.apk" "$OUT/onn-guard-unsigned.apk"
"$BT/zipalign" -c -p 4 "$OUT/onn-guard-unsigned.apk" || { echo "FAIL: not aligned"; exit 1; }

# ---- checks that FAIL the build
APK="$OUT/onn-guard-unsigned.apk"
PERMS=$("$BT/aapt2" dump permissions "$APK" | grep '^uses-permission' || true)
[ "$(printf '%s\n' "$PERMS" | grep -c .)" = "1" ] && printf '%s' "$PERMS" | grep -q 'android.permission.INTERNET' \
  || { echo "FAIL: permissions must be exactly INTERNET; found: $PERMS"; exit 1; }
TREE=$("$BT/aapt2" dump xmltree --file AndroidManifest.xml "$APK")
case "$TREE" in *TelemetryInitializer*|*provider*|*receiver*|*"E: activity"*|*WRITE_SECURE_SETTINGS*) echo "FAIL: unexpected component or permission in the manifest"; exit 1;; esac
[ "$(printf '%s' "$TREE" | grep -c 'E: service')" = "1" ] || { echo "FAIL: the manifest must declare exactly one service"; exit 1; }
LIST=$(jar tf "$APK") || { echo "FAIL: cannot list the APK"; exit 1; }
LIB=$(printf '%s\n' "$LIST" | grep '^lib/' | grep -v '/$' | sort)
WANT=$(printf 'lib/armeabi-v7a/libonnxruntime.so\nlib/armeabi-v7a/libonnxruntime4j_jni.so\n')
[ "$LIB" = "$WANT" ] || { echo "FAIL: lib/ must be exactly the two pinned armeabi-v7a libraries; found: $LIB"; exit 1; }
printf '%s\n' "$LIST" | grep -q '^assets/320n.onnx$' || { echo "FAIL: the model is not bundled"; exit 1; }
( cd "$W/x" && jar xf "$APK" lib/armeabi-v7a/libonnxruntime.so lib/armeabi-v7a/libonnxruntime4j_jni.so assets/320n.onnx classes.dex \
  && for f in libonnxruntime.so libonnxruntime4j_jni.so; do cmp "lib/armeabi-v7a/$f" "$ORT/$f" || { echo "FAIL: $f differs from its pin"; exit 1; }; done \
  && cmp assets/320n.onnx "$MODEL" || { echo "FAIL: the bundled model differs from the pin"; exit 1; } )
# NO telemetry code in the dex, by name (class descriptors are plain strings in the dex string table)
if grep -a -q 'ai/onnxruntime/telemetry' "$W/x/classes.dex" || grep -a -q 'TelemetryInitializer' "$W/x/classes.dex"; then
  echo "FAIL: ONNX Runtime telemetry code is present in classes.dex"; exit 1; fi
"$BT/aapt2" dump badging "$APK" | grep -q "native-code: 'armeabi-v7a'$" || { echo "FAIL: native-code is not armeabi-v7a only"; exit 1; }
{ echo "$VERSION_NAME ($VERSION_CODE)"; sha256sum "$APK" "$STRIPPED" "$W/x/classes.dex" "$W/x/assets/320n.onnx"
  "$BT/aapt2" dump badging "$APK" | grep -E "^package|native-code|sdkVersion|targetSdk"; } > "$OUT/BUILD-PHASE3.txt"
cat "$OUT/BUILD-PHASE3.txt"
