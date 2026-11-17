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

### Added after Agent 01's challenge review (2026-11-17), all accepted
9. **Prove the screenshots are real, not just that the service is on.** The Mac lost capture for 38.5 h on 2026-11-12 while its health check passed (a permission-less capture returned the wallpaper). The Onn heartbeat therefore carries **counts**, not flags: screenshots attempted, succeeded and analysed since the last beat, plus a cheap content-variance figure (distinct frame hashes). The server alerts on "service on but 0 analysed" and on "N identical frames while the screen is on". This makes condition 5 measurable.
10. **Define "TV on" before any gap alert.** The Onn stays powered when the TV is off (HDMI) and runs a screensaver. The app logs screen state (`PowerManager.isInteractive`, display state, screensaver/daydream flag) on the real box for several days in phase 2 **before** gap thresholds are set. Gap alerts are armed from that data, not guessed, so they neither fire nightly nor get loosened later (a quiet coverage cut). The silence, service-off and drift alerts are live from day one.
11. **Performance budget on the real box.** The Onn 4K Pro is a low-end SoC. Phase 3 gate: measured CPU, RAM and dropped frames during 4K Jellyfin direct play, with the model chosen to fit (for example a 320 px variant). The interval is chosen from that data and the **floor is written down** here before launch, so nobody can later slow it down or skip Jellyfin as a quiet cut.
12. **Film false positives are planned on paper.** Movies and TV will trigger an image model more than the Mac does. Any Jellyfin or app-specific relaxation is its own REDUCES COVERAGE PR (condition 8). Dad and Jonah agree in phase 1 how Onn alerts are batched (the session digest pattern), so volume does not create pressure to mute.
13. **Everyone who uses the TV is told in writing, not only Jonah and Dad.** Jada and any regular household viewer are told before phase 2. A small persistent on-screen indicator is a phase 2 option for guests; Jonah and Dad decide. (Replaces the narrower wording of condition 7.)
14. **State the router cost of the direct path.** Allowing the Supabase host puts its Cloudflare edge IPs into the Onn's allow set, and those IPs serve unrelated sites. Agent IT pins the allow to 443/TCP and keeps the AdGuard deny rule. Routed to Agent IT when phase 2 is approved, not before. I do not edit the router.

## Phases (each ships separately, each reviewed by Dad)
| # | What | Who | Gate |
|---|------|-----|------|
| 0 | This review merged; answers to the open questions below | Jonah, Dad | none |
| 1 | SQL: `onn_*` status table, token, report + attest RPCs (counts and variance), silence/service-off/drift alerts with all-clear emails. Adds tables and alerts only; nothing reports yet, so it can run as soon as Dad merges it | Sauron (writes), **Dad runs** | Dad runs SQL himself; alert batching agreed (12) |
| 2 | Android app skeleton: service, screenshot loop, counts/variance heartbeat, screen-state logging (no detection) | Sauron + Agent IT build env | everyone who uses the TV told (13); Agent IT pins Supabase egress (14); verify alerts fire on the real box for service off, app force-stop, app disable, reboot and power pull; screen-state data collected before gap thresholds are armed (10) |
| 3 | On-device detection + EGF2 flagged-frame upload | Sauron | performance gate met during 4K direct play and the interval floor written down (11); Jonah's explicit yes to encrypted frames going to Supabase; test phrase and a benign test image (real nudity is never tested with real content) |
| 4 | Open web access (TV Bro, Proton tunnel, AdGuard blocklist) | Agent IT, Jonah per item | phase 3 verified **plus a soak of about 7 days of real viewing** with no unexplained missed-silence, black-frame or variance alert, the performance gate met, and Dad's sign-off on phase 4 specifically. Agent IT first tidies the duplicate udp 443/123 rules in `forwarding_iot_rule`. |

The Mac-side deploy watcher does not apply here. **Updates are manual over ADB, with no self-updater** (Agent 01's change, accepted): the 2026-10-29 lockdown blocks installs, and a self-updater would need `REQUEST_INSTALL_PACKAGES` and an install path, which reopens that and adds a remote-code path. The server-side drift alert (signing-cert hash and version) covers a swapped APK. Revisit only if updates become frequent. TV Bro may be installed and locked down in the ADB session while egress stays YouTube-only; ip-api.com and raw.githubusercontent.com stay blocked regardless.

## Gaps in the draft
- **Android version: 14 (API 34), per Jonah 2026-11-17.** `canTakeScreenshot` needs API 30, so the route works. Still to confirm in the ADB session: the system WebView exists for TV Bro, and Android 14's accessibility restrictions for sideloaded apps ("restricted settings") do not block enabling the service via the one-time `WRITE_SECURE_SETTINGS` grant.
- **Self-update: decided, manual only** (see Phases).
- **Signing key.** The keystore is Jonah's, offline. The app must also verify its own signing-cert hash and report it, so a swapped APK is visible server-side.
- **WRITE_SECURE_SETTINGS** is powerful. Granting it once via ADB is fine, but the app must use it only to re-enable its own accessibility service, and the heartbeat reports when it had to.
- **TV Bro Incognito** bypasses history. History is not the signal here (pixels are), so this is acceptable, but the app must also monitor the TV Bro window like any other.
- **Both new router openings** (broad egress for the Onn, the tunnel choice, AdGuard mode switch) are Agent IT's lane. This design does not edit the router.

## Open questions (needed from Jonah / Dad)
1. ~~Android version~~ Answered: Android TV 14 (API 34). WebView and restricted-settings behaviour still to confirm in the ADB session.
2. ~~Retention~~ Answered by Jonah: same as the Mac.
3. Dad's sign-off on shared-TV monitoring, and Jada's being told (13).
4. Phase 1 SQL by Dad: Agent 01 and I agree it can run as soon as it is written and merged (adds tables and alerts only). Jonah/Dad to confirm.
5. Jonah's explicit yes to EGF2-encrypted flagged frames going to Supabase (needed before phase 3).
6. Alert batching for film content (12) and an on-screen indicator yes/no (13).

## Out of scope for this PR
Code, SQL, router, DNS, Android toolchain, TV Bro install.
