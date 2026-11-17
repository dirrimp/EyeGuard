#!/usr/bin/env python3
"""Reference numbers for the Onn fit test: runs the Mac's NudeNet 320n model on the SAME deterministic synthetic input as
android/onn-fit FitActivity.parityInput() and prints the same summary. Compare with fit-result.json's "parity" from the box.
Benign synthetic input only. Run with the app's Python (it has onnxruntime):
  /Applications/EyeGuard.app/Contents/Resources/python/bin/python3.12 tools/onn_fit_reference.py [model.onnx]"""
import hashlib, json, sys
import numpy as np
import onnxruntime as ort

SIDE = 320
EXPLICIT = (2, 3, 4, 6)   # BUTTOCKS_EXPOSED, FEMALE_BREAST_EXPOSED, FEMALE_GENITALIA_EXPOSED, ANUS_EXPOSED

def parity_input():
    n = 3 * SIDE * SIDE
    out = np.empty(n, dtype=np.float32)
    s = 12345
    for i in range(n):
        s = (s * 1103515245 + 12345) & 0x7fffffff
        out[i] = np.float32((s >> 8) & 0xFFFF) / np.float32(65535)
    return out.reshape(1, 3, SIDE, SIDE)

def main():
    model = sys.argv[1] if len(sys.argv) > 1 else \
        "/Applications/EyeGuard.app/Contents/Resources/python/lib/python3.12/site-packages/nudenet/320n.onnx"
    sha = hashlib.sha256(open(model, "rb").read()).hexdigest()
    sess = ort.InferenceSession(model, providers=["CPUExecutionProvider"])
    y = sess.run(None, {sess.get_inputs()[0].name: parity_input()})[0]
    flat = y.reshape(-1)
    anchors = flat.size // 22
    top = max(float(flat[(4 + c) * anchors:(5 + c) * anchors].max()) for c in EXPLICIT)
    print(json.dumps({"model_sha256": sha, "onnxruntime": ort.__version__, "shape": list(y.shape), "count": int(flat.size),
                      "sum": float(flat.astype(np.float64).sum()), "max": float(flat.max()), "argmax": int(flat.argmax()),
                      "first16": [float(v) for v in flat[:16]], "top_explicit_score": top}, indent=2))

if __name__ == "__main__":
    main()
