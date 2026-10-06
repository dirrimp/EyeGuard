# iPhone app-install events (G11 MDM) -- 2026-10-03

**Coverage impact: UP. Nothing existing is changed or removed.**

## Why
Ask to Buy does not catch redownloads of previously-approved apps. The G11's
NanoMDM can list what is installed, so a diff every 15 min catches them.

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
installed-app list, writes events to `outbox/`) and `g11/mdm/poll.py` (cron `*/15`,
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
| no heartbeat for > 45 min | "app monitoring STOPPED reporting" |
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

## Rollout order
1. Dad: review + merge this PR.
2. Dad: run `supabase/mdm_heartbeat.sql` (no placeholders; do NOT re-run
   `mdm_app_events.sql` after it: that file still holds the recipient placeholder).
   First-run grace: the "stopped" check is held off 2 h so the G11 can be updated.
3. Jonah, on the G11: copy `g11/eg_report.py` and `g11/eg-report.sh` to `/opt/kev/mdm/`,
   `g11/mdm/poll.py` to `/opt/kev/mdm/poll.py`, `g11/mdm/hook.py` to
   `/opt/stack/mdm/hook/hook.py`, then `docker restart mdm-hook`.
4. Jonah: enrol the iPhone (`/opt/stack/mdm/enroll/enroll.mobileconfig`). Until a phone
   is enrolled nothing is being watched; the "no iPhone is being watched" email
   fires after 2 h of heartbeats with `enrolled = 0` and will keep that visible.

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
3. Optional retry timer: cron `*/5 * * * * /opt/kev/mdm/eg-report.sh --flush`.
Exit codes: 0 delivered or queued; 2 bad input (not recorded); 3 queued but a
human must act (token rejected, or config missing / wrong mode).
