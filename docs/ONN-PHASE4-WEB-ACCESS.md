# Onn monitor, phase 4: opening web access (decision record, docs only)

Builds on `docs/ONN-SCREEN-MONITOR-REVIEW.md` (#162) and `docs/ONN-PHASE3-DETECTION-DESIGN.md` (#166). **This PR changes no code and no database.** It records the decision to open web browsing on the Onn, what is waived, what is NOT, what Agent IT will change on the router (its lane, each item with Jonah's own OK), and how EyeGuard watches the first days. **Dad's approving review or merge of this PR is the proof of his sign-off.**

## The decision
- **Jonah (2026-11-17):** open web access on the Onn now (TV Bro), and deal with alerts as they come.
- **What is waived, explicitly:** the review's "about 7 days of real viewing" soak before web access (phase 4 gate). That soak existed to catch an unexplained missed-silence, black-frame or variance alert and a failed performance gate while only YouTube and Jellyfin were reachable. It is replaced by the watch plan below, not silently dropped.
- **What is NOT waived** (all met today, 2026-11-17): the detector is running on the box and its self-test is **verified by the server** (argmax 8355, max 319.69696, same as the Mac; 284 ms a frame); the approved build and model are in the database; the end-to-end test flag was encrypted on the TV, stored, recorded and **opened in Dad's dashboard**; the heartbeat, silence, service-off and detector alerts are live; Jada is informed and agrees; the router's network monitor is active on the Onn's network (`br-iot`, no exclusions).

## What changes, and whose lane it is
Everything below is **router, DNS or the Onn's own settings: Agent IT's lane, not EyeGuard code**. IT proposes each item; Jonah OKs each one in the session; nothing here is done by this PR.
1. Web egress for the Onn's MAC (TCP 80/443, UDP 443) through the standard Proton tunnel (`wgclient1`), replacing the YouTube-only allow list for that device.
2. AdGuard for the Onn client: switch from allow-only (`denyallow=...`) to a blocklist plus a family-safe filter; keep Google callback names, `ip-api.com` and `raw.githubusercontent.com` blocked; Android's captive-portal check turned off by setting rather than broken by DNS.
3. TV Bro stays locked down as installed (camera, microphone and location revoked). The monitor's own heartbeat path (one host, TCP 443) is unchanged.
4. Rollback is one step: restore the allow-only AdGuard rule and remove the web egress rule (IT keeps the backups and the exact commands from the earlier changes).

## What EyeGuard watches on the Onn once web is open
- **Pixels:** the on-box detector (exposure only, the same threshold and labels as the Mac) on every screenshot while the TV is on, with flagged frames blurred, encrypted and uploaded. This is the main protection on web content.
- **Network:** the router monitor (`eyeguard-dnsnet`) sees the Onn's DNS names and flags explicit names, DoH/DoT, VPN and Tor bypass attempts as before; an explicit lookup is seen even when AdGuard blocks it.
- **Health:** heartbeat silence, service switched off, "on but not seeing the screen", all-black frames (DRM sites will look like this), identical frames, detector self-test, unapproved build. All live since phase 1 and 3.
- **TV Bro's incognito mode** hides history, not pixels or DNS, so neither of the two signals above depends on history.

## Honest limits (read this)
- **Exposure only.** There is no suggestive tier on the Onn (the Mac's CLIP pass does not fit this box). Web content is far more varied than YouTube and Jellyfin: expect false positives (the first one in a ten-minute window emails, the rest are yellow rows), and some real content below the 0.80 threshold will not be flagged.
- **DRM and protected pages come back black** (reported by the black-frame alert; they are a blind spot, not a pass).
- **Screenshots every 15 seconds** can miss a short event; that is the same cadence as the phase 3 design.
- **A person with the remote can switch the monitor off** or use a different device on the network. This is detection, not prevention; the silence and service-off alerts say so.
- **Not yet measured on this box:** CPU and dropped frames while playing 4K video with the detector running (gate 2). The fit test showed the detector needs about 270 ms of two cores every 15 seconds; Agent IT and Jonah can check playback on day one, and the interval floor can be raised if playback suffers (a slower interval is a coverage change and needs Dad).

## Day-one and first-week watch (what I will check, and when)
- After the egress change: a heartbeat arrives within 5 minutes; no `onn-deny:` lines toward the monitor's host; the router counters for the new rule; the Onn's DNS names in the AdGuard log.
- Dad's read-only queries on `onn_status`, `onn_beats` (`model_ms`, `succeeded`/`analysed`, `black`, `distinct_hashes`, `flags_dropped`) and `onn_flag_log` after the first browsing session, and again after day one.
- **The screenshot-gap alert is still OFF.** It is armed only after reading real screen-on data (`update public.onn_status set gap_armed = true`); with web browsing the data will exist within a day and I will propose the numbers.
- Any alert email: Jonah tells me the subject line and I diagnose it; a false alarm is fixed at its root, not muted. Any relaxation for the Onn (for example a site or app) is its own PR with "⚠️ REDUCES COVERAGE" at the top and Dad's review.

## Coverage impact
**No monitoring is removed or reduced by this decision.** It adds capability to the TV (web browsing), so it adds exposure to content the detector may or may not catch. That is why the limits above are written down, and why the watch plan exists.

## Needs
- **Dad:** approve this page (review or merge on GitHub).
- **Jonah:** per-item OK for each router/AdGuard change IT proposes; a ten-minute 4K playback test on day one.
- **IT:** the four items above, with backups, verification and the rollback commands.
