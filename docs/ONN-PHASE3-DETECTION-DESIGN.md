# Onn monitor, phase 3: real detection (design, docs only)

Builds on `docs/ONN-SCREEN-MONITOR-REVIEW.md` (#162) and the live phase 1 SQL and phase 2 app. **Nothing here is built.** It lists what phase 3 does, the gates that must pass before each step, and the decisions Jonah and Dad must make.

## Goal and honest scope
Run a trained exposure detector on the Onn's screenshots, on the box, and send only an **encrypted** flagged frame plus a flag record when it finds exposure. This matches the Mac's *fast path* (NudeNet): it flags when an `explicit_labels` region scores at or above `flag_threshold` (today 0.80; labels `FEMALE_BREAST_EXPOSED`, `FEMALE_GENITALIA_EXPOSED`, `BUTTOCKS_EXPOSED`, `ANUS_EXPOSED`, as in `config.yaml`).

**What the Onn will NOT have, stated plainly:** the Mac also runs a CLIP pass that catches suggestive and borderline content (YELLOW tier) and a tile pass. A CLIP-class model (~560 MB resident) does not fit this box. So on the Onn: **exposure only, no suggestive tier.** That is a real coverage difference from the Mac, not a hidden one. It is new coverage (nothing today), so it reduces nothing, but Dad must know it is narrower than the Mac. A later phase may add a smaller second-stage model if the box can afford it.

## Gates (each must pass, in order)
1. **Fit gate (on the real box, before any detection code ships).** A throwaway test app runs the chosen model on the Onn and reports: load time, per-frame time, peak memory, and that it runs on 32-bit ARM (`armeabi-v7a`). Benign images only. If no NudeNet-class model runs at an acceptable interval, that is a finding for Jonah and Dad, never a reason to fall back to keywords or to skip frames quietly.
2. **Performance gate.** Measured CPU, RAM and dropped frames during 4K Jellyfin direct play, with the model and interval chosen from that data. The **interval floor is written into this document before launch** (default 15 s; the floor is the slowest value Dad accepts), so slowing it later is visibly a coverage cut.
3. **Pipeline gate.** An end-to-end self-test (below) passes on the box and proves encrypt, upload and display work, using a synthetic image.
4. **Soak.** About 7 days of real viewing with no unexplained silence, black-frame or variance alert (phase 4's gate, restated).

## Choices to settle (recommendations in bold)
| Question | Options | Recommendation |
|---|---|---|
| Model | NudeNet 320n (the Mac's detector; YOLOv8n-class, 320x320) | **Use the same model and labels as the Mac** so thresholds mean the same thing. Pin the file by sha256; the app reports its hash every beat and the server compares it with `onn_approved.model_sha256` (column already exists). |
| Runtime | ONNX Runtime for Android, or TFLite, or NCNN | **ONNX Runtime first** (same model format as the Mac, no conversion). Sources suggest its Android release covers `armeabi-v7a`, but this is **not verified**: the fit gate proves it. Fall back to a converted model only if the fit gate fails. |
| Model/runtime provenance | downloads at build time | **Hash-pinned downloads by Agent IT in the network-less build container, exactly as for the SDK.** Check each license first (NudeNet's package metadata says MIT, one third-party page says AGPL: unresolved, read the repo's LICENSE and the release page before pinning). |
| Frame handling | analyse in memory | **Unchanged from phase 2:** frame decoded, examined, discarded. Only a *flagged* frame is ever kept, in memory, long enough to encrypt and send. |
| Encryption | EGF2, same as the Mac | **EGF2 in Java**: RSA-OAEP (SHA-256) wraps a per-frame AES-256-GCM key for each recipient, AAD `"EGF2|"+object name`. Recipients are Dad's offline key (always #1) plus the browser keys in `config.yaml`, **compiled into the APK from the repo** so adding a recipient is a reviewed PR plus a rebuild. Interop is tested with synthetic frames against `deploy/decrypt_frame.py` and the dashboard viewer before launch. |
| Upload | Mac path (anon insert to `flags` and the `frames` bucket) or a token-checked path | **Token-checked flag record, constrained storage path.** A new RPC `eg_onn_flag(token, ...)` writes the flags row (reason `nudenet:LABEL=score`, device `onn`), so only the verified box can create a flag. Frames upload to an `onn/` path prefix, `.enc` only, size-capped by an insert-only storage policy. Junk uploads there cannot create a flag or show on a dashboard. Dad runs this SQL. |
| Volume | every hit | **Rate-limit per hour in the app AND on the server, and batch like the Mac's session digest**, so a film does not become 100 emails. A cap that *drops* flags would be a coverage cut, so the cap counts and the digest says how many were suppressed. |

## Self-test (carries the weight "is it still detecting?")
Once an hour the app runs the model on a built-in synthetic image and compares the raw output to a stored golden value. The heartbeat carries `detector_ok` and the model hash; the server alerts on `detector_ok=false` or a changed hash, like the Mac's detector self-test. A weekly end-to-end test sends one clearly-labelled synthetic test flag through the whole encrypt-upload path (Dad sees a tagged test row, never an alert email). **Real nudity is never used to test.** The positive detection path (threshold, label mapping, non-max suppression) is proven in unit tests with synthetic model outputs.

## Server work (phase 3 SQL, Dad runs; written after the fit gate passes)
`eg_onn_flag` RPC, a storage policy for `onn/`, heartbeat fields `detector_ok`, `model_ms`, `frames_flagged`, `flags_dropped`, and alerts for detector failure and model drift. Each alert follows the existing pattern: one email, an all-clear, a permanent incident row, with a signal / false-positive / false-negative line in the PR.

## What can still go wrong (read this)
- A modified app can lie about everything, including `detector_ok`. Detection, not proof.
- DRM video is blank to Android; the black-frame alert reports it. It stays a blind spot.
- The model misses things (recall on this box's content is unmeasured) and misreads films (false positives expected; any relaxation is its own "REDUCES COVERAGE" PR).
- 32-bit and a low-end SoC may force a slower interval than the Mac's. The floor above is the limit.

## Decisions needed (before the fit gate runs)
1. **Jonah, explicit yes:** encrypted flagged frames may leave the TV and go to Supabase (the Mac already does this, and the frames are unreadable server-side).
2. **Dad and Jonah:** accept an exposure-only detector on the Onn (no suggestive tier).
3. **Dad:** the interval floor (default 15 s) once the performance gate has numbers.
4. **Jonah:** a third ADB session (with Agent IT) for the fit test; same temporary-rule routine, closed afterwards.
