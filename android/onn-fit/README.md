# Onn fit test (phase 3, gate 1): throwaway

Answers one question on the real box: **does the Mac's NudeNet 320n model run on this 32-bit ARM TV, and how fast / how big?**
Design: `docs/ONN-PHASE3-DETECTION-DESIGN.md`. This app is deleted afterwards.

- **No permissions at all** (not even INTERNET), no service, no receiver, no provider. One non-exported activity started from adb. It cannot
  report anywhere and cannot reach the network, which also keeps ONNX Runtime's built-in telemetry (a ContentProvider in its AAR manifest,
  never merged by `build-fit.sh`) from ever running.
- Benign synthetic input only (gradient frames and a seeded pseudo-random tensor). No real images, no screenshots, no captured content.
- It verifies `320n.onnx` against the pinned sha256, then for 1, 2 and 4 threads measures load time, preprocess time (1080p to 320x320),
  inference time (min / median / p95 / max) and memory (VmRSS / VmHWM), and records the model's output on a deterministic input so
  `tools/onn_fit_reference.py` (run on the Mac) can be compared numerically (`reference-mac.json`).

## Run (Agent IT's runbook, Jonah present, temporary rule closed afterwards)
1. IT builds `onn-fit-unsigned.apk` with `build-fit.sh` (separate script from phase 2's; adds exactly two pinned armeabi-v7a libraries). Jonah signs it.
2. `adb install`, then `adb push 320n.onnx /sdcard/Android/data/com.eyeguard.onnfit/files/`.
3. `adb shell am start -n com.eyeguard.onnfit/.FitActivity` (optionally `--ei runs 40`). The screen says when it is done.
4. `adb pull /sdcard/Android/data/com.eyeguard.onnfit/files/fit-result.json`, then `adb uninstall com.eyeguard.onnfit`.

## Reading the result
- `ok` must be true and `model_sha256` must equal the pin. `device.abis` must start with `armeabi-v7a`.
- `parity`: shape `[1,22,2100]`; `sum`, `max`, `argmax`, `first16` should match `reference-mac.json` within float tolerance (different ONNX Runtime
  version and CPU: expect differences around 1e-4 relative, not exact). A different `argmax` or a large gap means the box computes something else.
- `by_threads[].inference_ms.median` and `preprocess_ms.median`: with one screenshot every 15 s the budget is generous; the real gate is CPU and
  frame drops during 4K Jellyfin play, measured later inside the phase 3 service, not here.
- `memory_after_runs.vmhwm` (kB) against the box's `avail_mem_mb`.
