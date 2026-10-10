# iPhone app-install events (G11 MDM) -- 2026-10-03

**Coverage impact: UP. Nothing existing is changed or removed.**

## Why
Ask to Buy does not catch redownloads of previously-approved apps. The G11's
NanoMDM can list what is installed, so a check every 5 min catches them.

## Data flow
G11 poller -> `eg-report.sh '<event-json>'` -> queue file (fsync) -> HTTPS POST
`/rest/v1/rpc/eg_report_mdm_event` -> `mdm_events` (append-only) -> trigger ->
`eg_send_email_mdm()` -> Resend -> Jada + Dad.

## Event JSON
`{"type":"app_installed|app_removed|device_unreachable|device_reachable_again",
"detected_at":ISO8601,"window_start":ISO8601,"device":"...","name":"...",
"bundle_id":"...","version":"..."}` (name/bundle_id/version only for `app_*`;
`bundle_id` required for them).

## Alert policy
| Event | Result |
|-------|--------|
| app_installed | email immediately (name, bundle id, version, detected_at, "installed some time between window_start and detected_at") |
| device_unreachable | email once per outage; repeats logged only until `device_reachable_again` re-arms it |
| app_removed, device_reachable_again | logged in `mdm_events` only |

## Auth (least privilege)
The G11 holds the public anon key plus a random device token. The server stores
only the token's SHA-256 (`mdm_auth`, unreadable by every API role). The
credential can do exactly one thing: call `eg_report_mdm_event`, which returns
`{ok,duplicate}` and no data. Events are de-duplicated on
(type, bundle_id, detected_at), so retries are idempotent. received_at is the
server's clock.

## Poller, webhook and heartbeat (second PR)
`g11/mdm/hook.py` (container `mdm-hook`, receives NanoMDM check-ins/acks, diffs the
installed-app list, writes events to `outbox/`) and `g11/mdm/poll.py` (cron `*/5`,
asks the phone for its app list, delivers the outbox through `eg-report.sh`) were
already running on the G11. They are now in the repo; commit 1 of the PR is the
live code byte-for-byte, commit 2 is the change.

**Server-verified liveness.** After each completed run the poller sends
`eg-report.sh --heartbeat '{enrolled, unlisted, stalest_apps_age_s, outbox_pending}'`
(counts only; no app names, bundle ids or device ids). `supabase/mdm_heartbeat.sql`
adds `eg_mdm_heartbeat()` (same device token as the event RPC) and a cron check
every 5 minutes. Each email is sent once per condition and re-arms when it clears:

| Condition (server clock / figures) | Email |
|---|---|
| phone silent > 30 min (was 2 h; poller emits `device_unreachable`) | "cannot reach the phone" email, then an all-clear when it answers again |
| MDM profile installed again on a phone already enrolled | "MDM was removed and installed again" email at once (any gap length), plus a permanent incident |
| no heartbeat for > 15 min (poller runs every 5 min = 3 misses; checked every minute) | "app monitoring STOPPED reporting" |
| `enrolled = 0` or an enrolled phone never returned a list, for > 2 h | "no iPhone is being watched by MDM" |
| newest app list > 3 h old, and the poller's own unreachable alert is not active | "iPhone app list is stale" |

A poller that crashes sends no heartbeat, so a crash is itself the alert.
Heartbeats are not queued: a backfilled late beat would hide an outage.
Exit codes for `--heartbeat`: 0 accepted, 3 credential/config problem, 4 transient.

**Bug fixed in `hook.py`.** On profile removal (`CheckOut`) the hook emitted
`device_unreachable` but did not mark the device unreachable, so after re-enrolment
it never emitted `device_reachable_again`. The server's once-per-outage debounce
then stayed armed forever and the NEXT real outage was logged but not emailed.
`tests/test_mdm_system.py` reproduces this against the original code and proves the fix.

## Official app list, approve / deny (third PR)
The SERVER owns the list of approved apps (`mdm_apps`). The G11 only relays a raw
snapshot of what is installed (`app_snapshot`, one per InstalledApplicationList); the
server compares it with the list. (Previously the G11 held the baseline in files, and
losing them re-baselined silently.)

| Event | What happens |
|---|---|
| first snapshot (>= 1 app) | everything on the phone is **auto-trusted once** as the official list; the baseline then closes. Nothing the G11 sends can approve an app afterwards. Re-opening is Dad-only SQL. |
| app not on the list | `pending`; ONE email to Dad + Jada (one email per snapshot even for several apps); partners decide in the **Partner Dashboard -> Apps** |
| Approve | joins the official list (logged: who, when); both partners are emailed |
| Deny | flagged, reminded daily while installed, MDM **remove** queued, bundle id added to the **block list** the G11 pushes. Both partners emailed, with a plain statement of what is and is not possible |
| Revoke | approved -> pending |
| pending > 24 h | one reminder per day |

Who can decide: only the two partner accounts (`eg_mdm_decide`, checked with `auth.uid()`
on the server). Not the G11, not anon, not Jonah. Decisions are in an append-only log.
Approval is in the dashboard on purpose: an emailed "approve" link can be forwarded or
auto-clicked by a mail scanner.

### What deny can actually do (read this)
- **Detection works on any enrolled iPhone.** Profile enrolment is enough to list all apps.
- **Block needs a SUPERVISED phone** (restriction keys are ignored otherwise). The poller
  asks the phone `IsSupervised` each cycle and pushes the block list ONLY when it is
  true; otherwise it reports "not enforced" (emailed once) instead of pretending.
  The key names (`blockedAppBundleIDs`, plus the older `blacklistedAppBundleIDs`) follow
  Apple's docs but are **unverified until tried on the real supervised phone**.
- **Remove only works on apps MDM installed itself**, even on a supervised phone. For
  apps installed from the App Store by the user, block is the control that works.
  Failures are retried 3 times, then emailed with the phone's reason.
- **Supervising means erasing the iPhone** (Apple Configurator). The phone is currently
  neither supervised nor enrolled, so nothing is being watched yet.

### Baseline caveat (chosen: auto-trust)
Whatever is on the phone at the first snapshot is approved without review, including an
app that came back with a restored backup. Safer order: supervise, enrol, glance through
the list in the dashboard (approved list, Revoke) right after the first snapshot.

### Rollout order (matters)
1. Dad: review + merge #114, then this PR. Run `supabase/mdm_heartbeat.sql`, THEN
   `supabase/mdm_approvals.sql` (no placeholders in either; do NOT re-run
   `mdm_app_events.sql`). Dashboard updates itself via GitHub Pages after merge.
2. Jonah, on the G11, only AFTER the SQL is in: copy `g11/eg_report.py`, `g11/eg-report.sh`,
   `g11/mdm/poll.py` -> `/opt/kev/mdm/`, `g11/mdm/hook.py` -> `/opt/stack/mdm/hook/hook.py`,
   `docker restart mdm-hook`. (Before the SQL exists, snapshots can't be delivered; the
   reporter keeps only the newest one queued.)
3. Decide on supervision; enrol the phone; review the first list; test deny on a harmless app.

### Residuals
- Auto-trusted baseline (above). Anyone with root on the G11 can suppress snapshots (the
  heartbeat/stale alerts notice silence, not a lying G11).
- A pending app stays pending: it is NOT blocked until a partner decides.
- One monitored phone: `mdm_apps` is keyed by bundle id only.

## Rollout order (heartbeat PR)
1. Dad: review + merge this PR.
2. Dad: run `supabase/mdm_heartbeat.sql` (no placeholders; do NOT re-run
   `mdm_app_events.sql` after it: that file still holds the recipient placeholder).
   First-run grace: the "stopped" check is held off 2 h so the G11 can be updated.
3. Jonah, on the G11, from a checkout of `main`: `deploy/g11_install.sh --dry-run`, then
   `deploy/g11_install.sh`. It backs up replaced files, installs them with the right modes, sets
   the poller to every 5 minutes, restarts the hook only if it changed, and refuses to run if the
   credential file is missing, not mode 600, or its token is not 64 hex characters. Do this within
   2 hours of Dad running the SQL (the first-run grace); after that the silence alert is real.
4. Jonah: enrol the iPhone (`/opt/stack/mdm/enroll/enroll.mobileconfig`). Until a phone
   is enrolled nothing is being watched; the "no iPhone is being watched" email
   fires after 2 h of heartbeats with `enrolled = 0` and will keep that visible.

## One sender for every alert email (2026-10-09)
Every EyeGuard email goes through exactly three SQL functions (`eg_send_email`, `eg_send_email_jada`,
`eg_send_email_mdm`); no Python or shell code sends mail. Each used to carry its own hand-typed `From`,
they drifted apart, and when `orthanc.me` was not yet verified in Resend every alert was refused (HTTP 403)
with nobody told.

- `supabase/central_mail_sender.sql` puts the sender in ONE row (`eg_mail_config`), pinned by a CHECK
  constraint to `Name <...@orthanc.me>`, and points all three functions at it. Change it later with one
  statement (Dad only); nothing can be pointed at another domain by accident.
- `tests/test_mail_sender_guard.py` runs in the `guardrail` CI check and fails any PR that adds another
  Resend call, hand-types another sender, mentions another `alerts@` domain, or adds mail-sending code.
- Run order: verify `orthanc.me` in Resend (records at deSEC, NOT Hostinger: Hostinger is only the
  registrar, the zone is served by `ns1.desec.io` / `ns2.desec.org`), confirm a test returns `200` in
  `net._http_response`, then run `central_mail_sender.sql`.
- Also check, in Dad's Supabase dashboard: **Authentication > SMTP / Emails**. The partner dashboard's
  magic-link login emails are sent by Supabase Auth, not by these functions; if custom SMTP is configured
  there with an unverified sender, partners cannot log in.

## Removing the MDM profile (what is and is not possible)
- **The enrollment profile cannot be made non-removable.** iOS refuses to install an MDM profile
  marked `PayloadRemovalDisallowed` ("A profile containing an MDM payload must be removable"),
  supervised or not. An earlier version of this setup assumed supervision would make it
  non-removable; that was wrong. The profile in `/opt/stack/mdm/enroll/` was corrected on 2026-10-07.
- **What catches removal instead:**
  1. Removed while the phone is online: `CheckOutWhenRemoved` makes the phone tell the server,
     so the removal alert is immediate.
  2. Removed while offline (airplane mode, away from home), then reinstalled: no check-out is
     sent, so the hook reports every re-enrolment of a known phone and the database emails at once.
  3. Removed and NOT reinstalled: the phone goes silent and the unreachable alert fires after 30 min.
  4. Phone erased and re-enrolled: same as 2.
- Only a device in Apple Business Manager can be made impossible to unenroll. That needs an ABM
  account and is not part of this setup.

## Dad-owned integrity watch over the G11 (fourth PR)
`deploy/G11_ATTESTATION.md` explains it fully. In short: merging to `main` publishes the approved
hashes of the G11 code into Dad's database (CI, Dad's secret, insert-only); the G11 reports what
it has every 5 minutes; the DATABASE compares. Unapproved code is emailed at once, an old-but-approved
deploy after 24 h, a missing report after 15 min; each has an all-clear and a permanent incident.
It is evidence, not proof, against someone with root on the G11; the TPM layer that would be proof is
documented there with what it needs.

## Residuals (accepted, stated plainly)
- The hook's port (:8080) is unauthenticated inside the private docker network
  (never published). A container on that network could forge check-ins. Same trust
  class as the G11 itself; a signed-webhook follow-up would close it.
- A lost baseline file (`apps-<udid>.json` deleted) re-baselines silently: installs
  during that gap are missed. Needs root on the G11; the server cannot see it.
- Heartbeat counts come from the G11; the server verifies timing (its own clock) but
  cannot verify a lying client. Anyone with root on the G11 can fake them.
- The G11 is Jonah's machine. Anyone with root there can suppress or skip
  reports (same class as any client-side signal). The poller dying silently IS
  now covered server-side (see heartbeat above).
- A removed MDM profile surfaces only as `device_unreachable`.
- MDM has no install timestamp; the email says so.

## G11 install (Jonah, after Dad applies the SQL)
1. Copy `g11/eg-report.sh` and `g11/eg_report.py` to `/opt/kev/mdm/` (0755).
2. Create `/opt/kev/mdm/eg-report.json`, mode 0600:
   `{"supabase_url":"https://<ref>.supabase.co","anon_key":"<public anon key>","device_token":"<token from Dad>"}`
3. Optional retry timer: cron `*/5 * * * * /opt/kev/mdm/eg-report.sh --flush` (the poller now flushes each run).
Exit codes: 0 delivered or queued; 2 bad input (not recorded); 3 queued but a
human must act (token rejected, or config missing / wrong mode).
