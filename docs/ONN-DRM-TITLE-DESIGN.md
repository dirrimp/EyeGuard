# Onn: what is playing during protected (DRM) video (design proposal, docs only, nothing built)

**Verdict: approved in principle for a small spike only; the build waits for Dad and Jonah.** This page proposes; it changes no code, SQL, router or device.

## The problem (observed 2026-11-17)
While YouTube TV played, 20 of 20 screenshots in a 5-minute window were black with one distinct frame (Dad's `onn_beats` rows). Protected video comes back black from Android's screenshot call, so the on-box detector cannot see it. The router cannot help: it sees domain names (`googlevideo.com`), timing and volume, never the title, and the Proton tunnel adds another encryption layer. The only coverage today is the server's `onn_black` alert (about 30 minutes of mostly black frames with the screen on). That tells Dad that something was streaming, not what.

## The idea
DRM blocks pixels, not text. Ask the app on the box for *what is playing* (a title string) instead of the picture, and give it to Dad, who can judge it. The detector is not involved: nothing here classifies content.

## Options (cheapest and narrowest first)
- **A. Window title from accessibility events.** The service already receives `typeWindowStateChanged` events. They may carry the window title or activity label without any new capability. Unknown: whether YouTube TV sets a useful one. Cost: no new permission. **Test first.**
- **B. Read the on-screen text of the player (accessibility tree).** Needs `canRetrieveWindowContent="true"`, which today is explicitly **false** in the service declaration. Turning it on lets the service read the text of any screen, so it is a real privilege increase and must be fenced in code (see conditions). Unknown: whether the player overlay exposes the title, and whether Android 14 asks Jonah to re-enable the service after the update.
- **C. Media session metadata (title, artist, app).** Needs notification-listener access (a second privileged component that can read every notification). Broader than A and B in a different direction. Not recommended unless A and B fail.

## Recommended path
1. **Spike (Agent IT, one ADB session, Jonah's per-item OK):** on a throwaway debug build, log (locally, never uploaded) what option A delivers during a YouTube TV session and a Jellyfin session. Report only *whether a usable title string appears*, not the titles themselves. If A works, stop there.
2. Only if A fails: the same spike for B, as a separate approval.
3. Server side (Dad runs the SQL): a small `onn_titles` table and an RPC, modeled on `eg_onn_flag`.
4. App side: title capture, then encrypted upload, then a new approved build row (`onn_approved`) for the new version.

## Conditions for any build (each checkable)
1. **Titles are captured content.** They are encrypted with EGF2 to the same four recipients as flagged frames (Dad's offline key first) before they leave the box. No plaintext title in a heartbeat, in the database, in logs or in an alert email. No agent sees them.
2. **Narrow scope in code:** only an allowlist of media apps (YouTube TV first); only while the last screenshots were black (the DRM case), so ordinary browsing is never read; a title is a short string, length-capped, deduplicated per session. Static tests fail the build if the service reads any other package or sends any other text.
3. **No text classification on the box or in the cloud.** Titles go to Dad, not to a model. A local keyword alert is a possible later step and its own proposal.
4. **Coverage:** this adds coverage and removes none. The `onn_black` alert and its 30-minute threshold stay as they are. Loosening that alert for streaming would be a separate "⚠️ REDUCES COVERAGE" PR needing Dad's GitHub review.
5. **Privilege change is disclosed:** if option B is needed, the PR says so at the top, the service description shown to the user in Android settings is updated, and the server's approved-build check carries the new certificate/version row before install.
6. **Retention and who sees titles** are decided before the SQL is written.
7. **Everyone who uses the TV agrees in writing** (Jonah, Jada, and any regular user). Asked, not assumed.
8. Phase order: this comes after the current monitor is stable (gap alert armed, a clean week of beats), and after Dad merges this proposal.

## Honest limits
- A title is what the app *says* is playing, not what is on screen. A bad actor, a mislabeled stream or a title-less overlay defeats it.
- Whoever holds the TV can still switch the service off. This is detection, not prevention; the server alerts when the service goes silent or is turned off.
- Some players may expose nothing usable. The spike answers that before any build.

## Open questions for Jonah (yes/no or a value)
1. Do you want titles collected at all, knowing Dad (and Jada's key) can read them?
2. Only during black/protected video, or whenever YouTube TV is open? (Recommended: only during black.)
3. How many days should titles be kept? (Suggest 30, matching how frames are handled.)
4. OK to run the one-session spike with IT, reporting only yes/no?

## Needs
- **Dad:** read and merge this page, then the SQL later if the spike passes.
- **Jonah:** the four answers above.
- **IT:** the spike session, only after both of the above.
