# Onn detector: license notes for Dad (docs only, not legal advice)

Source: Agent IT's report `it-20261117-1313.md`, which read the files on the G11 on 2026-11-17 (hashes of every file are in IT's `BUILD-PINS.txt`). This page reports what the files say and lists what they do **not** answer. It decides nothing.

## What the Onn would run
- **NudeNet 3.4.2 `320n.onnx`** (the same 12,150,158-byte file the Mac runs, sha256 `c15d8273adad2d0a92f014cc69ab2d6c311a06777a55545f2c4eb46f51911f0f`). The repo's README names its base as "ultralytics yolov8n".
- **ONNX Runtime for Android 1.31.1** (the library that runs the model on the TV).

## ONNX Runtime: MIT
`LICENSE` is the MIT license, "Copyright (c) Microsoft Corporation". It grants use, copy and modify "without restriction", with one condition: the copyright and permission notice must be included "in all copies or substantial portions". Plain reading: bundling it in our private APK is fine, and the notice should travel with it. (Its AAR also carries Apache-2.0 text for bundled telemetry code. We do not run that code: see the telemetry note below.)

## NudeNet and its weights: the files contradict each other
- The GitHub repo's `LICENSE` and `LICENSE.md` are the **GNU Affero GPL v3** (no project-specific terms added). GitHub reports AGPL-3.0.
- The PyPI package metadata says **MIT** (`License: MIT`, `setup.py license="MIT"`), yet the same wheel ships the AGPL v3 text as its own `LICENSE` files. The metadata and the shipped license files disagree.
- The repo says nothing about the weights' license. Its upstream, `ultralytics/ultralytics`, is also AGPL-3.0.

Key lines of the AGPL text (from IT's quotes):
- "This License explicitly affirms your unlimited permission to run the unmodified Program."
- "You may make, run and propagate covered works that you do not convey, without conditions so long as your license otherwise remains in force."
- "Mere interaction with a user through a computer network, with no transfer of a copy, is not conveying."
- Section 13: a source-offer duty for a **modified** version that users interact with **remotely** over a network.

## Plain reading for us (family use, one TV, no redistribution)
We run the model unmodified, on our own devices, and give copies to nobody. On the text above that appears to be "running a work you do not convey", which the AGPL allows without conditions. Section 13 is stated for a *modified* version that users reach over a network; we do not modify the model.

## What the files do NOT answer (open questions, not conclusions)
1. Whether a weights file counts as "the Program" or a "covered work".
2. Whether the family watching the TV, or Dad's database receiving encrypted flagged frames, counts as "interacting remotely" or "conveying".
3. Whether the package's MIT claim has any effect next to the AGPL files shipped beside it.

## Decision needed
- **For the family deployment now:** none beyond Dad's awareness. Nothing here blocks the fit test or the monitor as long as we change nothing about the model and give it to nobody.
- **Before any shippable product (the long-term goal):** this must be decided first. An AGPL detector (and an AGPL upstream) is a poor fit for a closed or distributed product. Options at that point: ship under AGPL terms with source offered, obtain a different license from the authors, or switch to a detector whose weights have a clear permissive license. Settle it before more is built on this model.

## Telemetry note
The ONNX Runtime Android package registers a telemetry component and its native library contains a Microsoft collection address. Our builds never merge that manifest, the fit-test build **fails** if a provider or telemetry component appears, and the Onn's router rules would show any attempt as `onn-deny:` lines.
