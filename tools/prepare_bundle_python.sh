#!/usr/bin/env bash
# Prepare build_bundle/python (consumed by build_bundled_app.sh) from a
# python-build-standalone 3.12 tree, installing ONLY the pinned runtime set.
# usage: tools/prepare_bundle_python.sh /path/to/standalone/python
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="${1:?path to an unpacked standalone python 3.12 tree}"
DST="build_bundle/python"
[ -x "$SRC/bin/python3.12" ] || { echo "no $SRC/bin/python3.12" >&2; exit 1; }
rm -rf "$DST"; mkdir -p build_bundle; cp -R "$SRC" "$DST"
PY="$DST/bin/python3.12"
"$PY" -m pip install --quiet pip==26.2
"$PY" -m pip install --quiet --only-binary=:all: -r requirements-bundle.lock.txt
"$PY" -m pip check
# Guard: dev-only packages must not ship.
for bad in transformers torch torchvision huggingface_hub tokenizers; do
  if "$PY" -m pip show "$bad" >/dev/null 2>&1; then echo "FORBIDDEN in bundle: $bad" >&2; exit 1; fi
done
echo "prepared $DST"
