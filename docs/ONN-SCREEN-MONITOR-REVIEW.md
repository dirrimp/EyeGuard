# Onn screen monitor: Agent Sauron's design review

Reviews Agent IT's draft (`onn-screen-monitor-design.md`, 2026-11-17) for web browsing on the Onn box with an accessibility-service screen monitor. **Design only. No code, SQL or router change is in this PR.** Status: the draft's route (accessibility screenshots, on-box analysis) is approved in principle, with the conditions below.

## Verdict
The route is right: it is the only way to get real pixels on a TV box with no GMS, and it matches the long-term "remote product with true screen-pixel monitoring" direction. It must follow the same rules as the Mac. Web access on the Onn stays **closed until the monitor is installed, verified and alerting** (the draft already says this; it is a condition, not a preference).

## Conditions (each one is a hard requirement)
1. **Same detectors, not keywords alone.** Pixel monitoring means an on-device NudeNet-class model (ONNX Runtime for Android, CPU, no Google services) on each screenshot, plus the Mac's rule set for URLs and visible text from the node tree. Keyword-only would be a smaller net than the Mac's and may not be called "monitoring like the Mac". The model file ships inside the signed app, not downloaded at runtime.
2. **Captured content never leaves the box except as an encrypted flagged frame.** Screenshots are analysed in memory and discarded. A flagged frame is encrypted with the existing EGF2 format (`eyeguard/frame_crypto.py`, same recipients list as the Mac, Dad's offline key always #1) before upload. The app holds public keys only. No agent, including me, ever sees a frame.
3. **The server verifies the box, not the reverse.** Reuse the MDM pattern (`supabase/mdm_heartbeat.sql`, `g11_attest.sql`): a device token whose hash lives in the database, callable only for two RPCs (`report` and `heartbeat/attest`), no service-role key anywhere on the box. The heartbeat carries what the app actually observes: accessibility service enabled, app version and APK signing-cert hash, time of the last screenshot, last analysis time, model hash. The database alerts on: silence, service off, a screenshot gap while the TV is on, version or cert drift, model drift. "Heartbeat alive but no frames analysed" must alert, not only "heartbeat dead".
4. **Honest limit, written where partners read it.** A viewer with the remote can turn the accessibility service off in Settings. This is **detection, not prevention**: it must alert within minutes and say so. Not claimed: tamper-proof.
5. **Dark-screen and DRM frames are reported, not skipped.** FLAG_SECURE/DRM comes back black. A run of all-black frames while the TV is on and an app is in the foreground is itself a signal (same idea as the Mac's blind-probe), not a quiet case.
6. **Reporting path: Supabase directly**, not a new G11 relay. A relay is a second system that can silently fail and holds a token. The Onn needs one extra allowed host (the project host); that is Agent IT's router change and goes through them and Dad.
7. **Shared-device privacy.** Everyone who uses the TV is monitored. Dad's sign-off on that, and Jonah's, are required in writing in the PR that adds the Onn as a device type. Retention follows the Mac's (frames purge on the same schedule).
8. **No weakening.** Adding the Onn only adds coverage. Any rule that mutes a case on the Onn (like the Gilmore Girls mute) is its own "REDUCES COVERAGE" PR.

## Phases (each ships separately, each reviewed by Dad)
| # | What | Who | Gate |
|---|------|-----|------|
| 0 | This review merged; answers to the open questions below | Jonah, Dad | none |
| 1 | SQL: `onn_*` status table, token, report + attest RPCs, silence/drift alerts with all-clear emails | Sauron (writes), **Dad runs** | Dad runs SQL himself |
| 2 | Android app skeleton: service, screenshot loop, heartbeat/attest only (no detection) | Sauron + Agent IT build env | verify "service off" alert fires on the real box |
| 3 | On-device detection + EGF2 flagged-frame upload | Sauron | test phrase and a benign test image; real nudity is never tested with real content |
| 4 | Open web access (TV Bro, Proton tunnel, AdGuard blocklist) | Agent IT, Jonah per item | only after phase 3 verified |

The Mac-side deploy watcher does not apply here. The Onn app is updated by hand over ADB until a signed-update path exists (see below).

## Gaps in the draft
- **Android version: 14 (API 34), per Jonah 2026-11-17.** `canTakeScreenshot` needs API 30, so the route works. Still to confirm in the ADB session: the system WebView exists for TV Bro, and Android 14's accessibility restrictions for sideloaded apps ("restricted settings") do not block enabling the service via the one-time `WRITE_SECURE_SETTINGS` grant.
- **Self-update.** A manual ADB install cannot be fixed remotely. Decide: a pinned-manifest self-update (hash checked by the app, as the Mac's) or a manual-only app. Prefer the manifest.
- **Signing key.** The keystore is Jonah's, offline. The app must also verify its own signing-cert hash and report it, so a swapped APK is visible server-side.
- **WRITE_SECURE_SETTINGS** is powerful. Granting it once via ADB is fine, but the app must use it only to re-enable its own accessibility service, and the heartbeat reports when it had to.
- **TV Bro Incognito** bypasses history. History is not the signal here (pixels are), so this is acceptable, but the app must also monitor the TV Bro window like any other.
- **Both new router openings** (broad egress for the Onn, the tunnel choice, AdGuard mode switch) are Agent IT's lane. This design does not edit the router.

## Open questions (needed from Jonah / Dad)
1. ~~Android version~~ Answered: Android TV 14 (API 34). WebView and restricted-settings behaviour still to confirm in the ADB session.
2. ~~Retention~~ Answered by Jonah: same as the Mac.
3. Dad's sign-off on shared-TV monitoring.
4. Is a phase-1 SQL run by Dad acceptable now, ahead of any app?

## Out of scope for this PR
Code, SQL, router, DNS, Android toolchain, TV Bro install.
