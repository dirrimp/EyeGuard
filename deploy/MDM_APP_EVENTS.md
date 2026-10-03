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

## Residuals (accepted, stated plainly)
- The G11 is Jonah's machine. Anyone with root there can suppress or skip
  reports (same class as any client-side signal). Server-side backstop for the
  poller itself dying silently is NOT in this PR (follow-up: a heartbeat RPC +
  gone-quiet check like `eg_check_phone_jada`).
- A removed MDM profile surfaces only as `device_unreachable`.
- MDM has no install timestamp; the email says so.

## G11 install (Jonah, after Dad applies the SQL)
1. Copy `g11/eg-report.sh` and `g11/eg_report.py` to `/opt/kev/mdm/` (0755).
2. Create `/opt/kev/mdm/eg-report.json`, mode 0600:
   `{"supabase_url":"https://<ref>.supabase.co","anon_key":"<public anon key>","device_token":"<token from Dad>"}`
3. Optional retry timer: cron `*/5 * * * * /opt/kev/mdm/eg-report.sh --flush`.
Exit codes: 0 delivered or queued; 2 bad input (not recorded); 3 queued but a
human must act (token rejected, or config missing / wrong mode).
