# EyeGuard context map (for the review agent)

Read this before judging a diff. Source of truth is the repo; deploy/STATUS.md and README.md
are longer. If this file disagrees with the code, the code wins and this file gets a fix PR.

## Trust model
- Jonah is monitored. Dad is accountability partner, repo owner, Supabase Owner, Resend owner,
  CODEOWNER for `*`. Every merge to main needs Dad's approval; branch protection requires the `guardrail` check.
- Since the admin-trust pivot (2026-08-24) the Mac holds NO secret. `config.yaml` carries only the public anon key.
  Server-side RPCs and RLS make each call unabusable (server-stamped heartbeat, append-only flag insert).
  The service_role key exists only in Dad's Supabase console and a GitHub Actions secret.
- Tamper-evident, not tamper-proof. Accepted residuals are listed in deploy/STATUS.md.

## Components (where to look)
| Component | Path | Runs as | Notes |
|---|---|---|---|
| Capture + detect | eyeguard/main.py, capture.py, detector.py, textscan.py, context.py, risk.py | user LaunchAgent (com.eyeguard.monitor) | CLIP + text; thresholds in config.yaml |
| Upload / frames | eyeguard/uploader.py, frame_crypto.py | user | review frames encrypted to Dad's public key; never read them |
| Menu bar / viewer | eyeguard/menubar.py, viewer.py | user | self-diagnosis, frozen-frame check |
| Session watcher | eyeguard/session_watcher.py | root LaunchDaemon | independent liveness; sleep/power corroboration |
| Deploy watcher | eyeguard/deploy_watcher.py, deploy/update.sh | root LaunchDaemon | polls GitHub main every ~5 min, hard-resets the root-owned tree, restarts |
| Integrity | eyeguard/integrity.py, deploy/gen_*manifest.py | root | manifest fetched fresh from Supabase |
| Find My | eyeguard/findmy_watcher.py, run_findmy.py | user/cron | phone location/liveness backstop |
| Router phone monitor | router/eyeguard-phone*.py, eyeguard-router-watcher.py, eyeguard-dnsnet.py, connlog.sh | root on GL.iNet router | separate processes so editing one is caught |
| G11 / MDM | g11/mdm/**, g11/eg_report.py, deploy/g11_install.sh | G11 server | app-appearance alerts via EyeGuard |
| Backend | supabase/*.sql | Supabase (Dad runs SQL himself) | functions, cron, RLS, mail senders |
| CI | .github/workflows/*.yml, tests/ | GitHub | guardrail + manifest publishers |

## Data flows and boundaries
1. Screen -> capture (Mac) -> detect locally -> flag metadata + encrypted frame -> Supabase (anon key, RLS insert only).
2. Heartbeats (Mac, session watcher, router, G11, MDM) -> Supabase RPC; pg_cron checks silence -> SQL sender -> Resend -> both partners.
3. Merge to main -> deploy_watcher -> root-owned tree reset -> restart -> Dad emailed.
4. Captured content never leaves the Mac except as encrypted frames for Dad. It never goes to any API, including Claude.

## Where state lives
- Code tree: /Library/Application Support/EyeGuard (root:wheel, reset on deploy). Never write state here.
- Mutable state: outside the tree (flags.jsonl, pending queue, EyeGuard-data/). Off limits to the review agent (denylist.txt).

## Approved outbound hosts (EG-SEC-03)
Supabase project (anon RPC/REST/Storage), Resend (via Supabase SQL only), GitHub API (deploy_watcher poll,
public), the G11 on the LAN, the router on the LAN. Anything else needs a line here and Jonah's OK.

## Things that look like bugs but are not
- The anon key in config.yaml is public by design.
- A powered-off phone going dark and alerting is accepted behaviour (iOS gives no shutdown signal).
- The Mac and phone are different WireGuard peers; mixing them up caused real phone-dark false alarms (6c67e15).
