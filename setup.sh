#!/usr/bin/env bash
# EyeGuard setup: create an isolated Python 3.12 venv and install dependencies.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-/opt/homebrew/bin/python3.12}"
if [ ! -x "$PYTHON" ]; then
  echo "Python 3.12 not found at $PYTHON. Install with: brew install python@3.12" >&2
  exit 1
fi

echo "==> Creating virtualenv (.venv) with $($PYTHON --version)"
"$PYTHON" -m venv .venv
source .venv/bin/activate

echo "==> Upgrading pip"
pip install --quiet --upgrade pip

echo "==> Installing core dependencies (this downloads onnxruntime/opencv; takes a bit)"
pip install -r requirements.txt

echo
echo "==> Done. Runtime deps installed (onnxruntime — no PyTorch, no transformers)."
echo
echo "Models:"
echo "  Stage 1 NudeNet pulls its own weights via the nudenet package on first run."
echo "  Stage 2 CLIP needs models/clip_vision.onnx + clip_meta.json — build with"
echo "  'python tools/export_clip_onnx.py' (needs transformers/torch), or use the"
echo "  packaged EyeGuard.app which bundles them. Prompt embeddings are committed"
echo "  (eyeguard/clip_assets/); rerun tools/build_text_features.py only if you"
echo "  edit the prompt lists in config.yaml."
echo
echo "  The CLIP arbiter is ON by default, resident ~560MB. If the model files are"
echo "  missing it logs 'arbiter unavailable' and borderline frames fall through as"
echo "  'review' — the rest of the pipeline still runs."
echo
echo "Next: grant Screen Recording permission to your terminal, then run ./run.sh --once"
