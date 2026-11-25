# Onn: media-session addendum (option C) for YouTube TV

**Docs only. Nothing is built, installed or changed by this PR.**

## ⚠️ REDUCES COVERAGE (if approved)
It replaces one alert for one app: the "Onn monitor is only seeing black" alert is no longer raised for beats where **YouTube TV** is verifiably playing. In exchange, the title that is playing is recorded, encrypted to Dad. Needs approval from **Jonah and Dad**; Dad's GitHub review is the proof. A pull of this PR without Dad's review changes nothing.

## Why
YouTube TV video is DRM-protected, so screenshots come back black and the on-box detector sees nothing. Today that raises `onn_black` after about 30 minutes, every time anyone watches. Jonah's goal (his words, 2026-11-20): not alert on black frames, but see *what* is playing. Option A (accessibility text) failed: 0 or 1 events and no text in real playback (phase 5a, 0.2.2).

## What was measured (IT, read-only ADB, 2026-11-21 20:15 to 20:20; no titles read)
| Scenario | Session | State | Metadata present |
|---|---|---|---|
| YouTube TV playing | its own session, package `com.google.android.youtube.tvunplugged` | PLAYING | yes |
| SmartTube playing | `org.smarttube.stable` | PLAYING | yes |
| Home screen | none (only always-present Bluetooth sessions) | n/a | no |

The session disappeared within a minute of stopping. `enabled_notification_listeners` is empty today. Jellyfin was **not** tested (not DRM, so its frames are visible and it needs no exemption).
Format note: Android 14 prints `state=PLAYING(3)`, not `state=3`; app code reads the API, not dumpsys text.

## Design
1. **Same app, no second accessibility service.** `com.eyeguard.onn` declares a `NotificationListenerService` (needed only because Android requires a listener component to read media sessions via `MediaSessionManager.getActiveSessions`). It does not override `onNotificationPosted` or read any notification. A static test fails the build if it does.
2. **Only one package is read.** Only the session whose package is exactly `com.google.android.youtube.tvunplugged`. Any other session (including SmartTube and Jellyfin) is ignored: not read, not logged, not counted.
3. **Exemption rule (all must hold in the beat):** the foreground window package is YouTube TV (from the monitor's existing accessibility events), its media session is PLAYING, and the beat's frames are black. A beat that meets this is reported as `black_exempt` and does **not** add to `black_beats`. Everything else counts black exactly as today: SmartTube, Jellyfin, the browser, the home screen, any other app, and a YouTube TV beat with no PLAYING session.
4. **A package name cannot be faked by a sideloaded app** (Android ties it to the signing identity), and the foreground package comes from the accessibility service, so a second app cannot claim to be YouTube TV.
5. **Titles are captured content.** Title strings (length-capped, deduplicated per session) are encrypted with EGF2 to the same recipients as flagged frames (Dad's offline key first) **before they leave the box**. Never in a heartbeat, log, database column, alert email or chat. No agent sees them. Kept 30 days (Jonah's earlier answer), only while frames are black (his earlier answer).
6. **Server verifies the client.** Exempt beats are only honoured if an encrypted title record arrived for that window (a new `onn_titles` table, SQL for Dad to run, modeled on `eg_onn_flag`). Exempt claims with no matching record count as black. The heartbeat carries counts only: `black_exempt_beats`, `titles_sent`.
7. **Phase order (each needs the previous one verified):** (a) this proposal merged; (b) SQL, run by Dad; (c) app 0.3.0 plus Dad's `onn_approved` row; (d) IT install with the safeguards below; (e) a clean week of beats; (f) then arm the gap alert.

## Install risk and safeguards
The 2026-11-17 spike showed that enabling a second *accessibility* service made Android clear the enabled list, so the real monitor was unbound for 10 to 20 seconds. Enabling a notification listener is a different setting and may not do that, but **that is unproven**. So, at install, IT must:
- record `enabled_accessibility_services` before and read it back after, and confirm the monitor is bound;
- have the restore command ready and run it if the list changed;
- disclose any gap (the server heartbeat shows how long);
- keep the temporary ADB rule open until Dad confirms the first beats after install.
The listener is enabled by the ADB step at install (`cmd notification allow_listener`). After a reboot it must still be enabled: the server alerts if `listener_ok` goes false while the monitor is alive.

## Honest limits
- A title is what the app says is playing, not what is on screen. A mislabeled or title-less stream defeats it.
- Whoever holds the TV can switch the listener or the service off. This is detection, not prevention: silence, service off and `listener_ok=false` each alert.
- Exempt beats are self-reported by the box (tamper-evident, not tamper-proof); the matching encrypted title record is the server's check.
- The exemption hides a real case: non-DRM explicit video inside YouTube TV would be black only if protected, so ordinary unprotected video still gets analysed on-box. The residual risk is protected content, which only the title (reviewed by Dad) covers.

## Decisions needed
**Jonah / Dad**
1. SmartTube (`org.smarttube.stable`) is installed, plays YouTube content and is not allowlisted. Default here: **no exemption, alert as today**. Keep it installed, or remove it?
2. Everyone who watches this TV must know titles are recorded for Dad. Jada's sign-off, in writing?
3. Confirm: exemption for YouTube TV only; titles 30 days; encrypted to Dad plus partner keys.

**Dad:** read and merge this page; run the SQL later (separate PR).

## Not changed by this PR
No code, SQL, device, router or alert behaviour. The current `onn_black` alert stays exactly as it is until the later phases ship.
