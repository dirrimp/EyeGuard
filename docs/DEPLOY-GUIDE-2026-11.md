# Deployment guide for Dad: open EyeGuard PRs (2026-11-03)

Written by Agent Sauron for Dad's review. It contains no secrets: keys are referenced by where they live, never pasted. Nothing here has been run; every command is for Dad (or Jonah, where stated).

State when written: `main` is at `f0e5cae` (merge of PR #137). The live Mac checkout (`/Library/Application Support/EyeGuard`) is at the same commit. The router runs release `2026-10-21a`.

Note from Jonah: on 2026-11-03 he turned off Proton VPN AutoConnect on the Mac. That app's auto-connect after every wake caused the Mac alerts to `185.159.158.x:51820` and `185.159.159.x`. No EyeGuard change is needed for it and none of the PRs below touches it. Those alerts should stop. If they come back, that is a real signal, not a false alarm.

## 1. The open PRs at a glance

| PR | What it does | Coverage | SQL | Where it deploys |
|---|---|---|---|---|
| #138 | Network alerts get their own email wording (today they say "Very revealing content / review image on the dashboard", which is false) | SAME | `supabase/network_alert_title.sql` | Supabase only |
| #141 | Context rules match app names, not words in titles; low-risk REDs demote to yellow instead of being dropped | **UP** | none | Mac (auto) |
| #140 | A tile-only CLIP RED becomes YELLOW unless NudeNet also saw at least 0.30 exposure | **REDUCES COVERAGE** | none | Mac (auto) |
| #142 | Bundle: pin runtime dependencies, drop dev-only transformers (117 advisories down to 2) | SAME | none | Only when Jonah rebuilds the app bundle |
| #139 | `mask-api.icloud.com` TLS connection becomes observe-only (counted, no email) | **REDUCES COVERAGE** | none | Router |
| #143 | G11 gluetun to Proton (one /32, UDP 51820) is an expected tunnel; off until configured | **REDUCES COVERAGE (narrow)** | none | Router, plus a phone.json entry |

Already merged, listed only because they were on the request: #131 (Find My session-age heads-up, merged 2026-10-20, no SQL), #132, #129, #126. There is no other open PR besides this guide.

Approval: #139, #140 and #143 reduce coverage and need Jonah's AND Dad's approval. Your GitHub review is the record. This guide does not replace it.

## 2. Merge order

1. **#138** first (wording only; its SQL is independent of everything else).
2. **#141**, then **#140**. Strict: #140's description depends on #141 landing first, because #141 surfaces detections that #140 then re-tiers.
3. **#142** any time (packaging only).
4. **#139**, then **#143** (both edit `router/eyeguard-dnsnet.py`; the second may need a trivial rebase, which the PR author will do).
5. Then ONE router rollout for #139 and #143 together (section 5).

Reason to keep #140 and #141 close together: #141 raises coverage and #140 lowers one slice of it. Merging only #140 would leave the context-layer drops that Jonah reported (underwear marketing in Proton Mail, workout videos on YouTube in Zen) in place.

## 3. Supabase SQL (Dad runs it himself; Supabase SQL Editor)

Run in this order. Nothing here uses a key Claude or Jonah holds; you are signed in as Owner.

0. **Before anything: confirm `supabase/mdm_requeue_removal.sql` (from merged #132) was run.** This is UNCONFIRMED. Check that `eg_mdm_sync` has the requeue block and the 8-removals-per-24h limit. If you are not sure, run the file; it is a `create or replace` generated from the committed definition (the PR's test asserts every original line survives). This is not part of the open PRs, but the Mac/G11 enforcement behaves differently without it.
1. **`supabase/network_alert_title.sql` (PR #138).** Run after merging #138 (the file only exists on `main` after the merge; before that it is on branch `fix/network-alert-title`).
   - STOP first if you have hand-edited `eg_on_red()` in the live database since 2026-10-01. The file rebuilds the whole function; tell Jonah and the new branch will be re-applied on top of your version.
   - Expect ONE result row: `true, true`.
   - Verify (read-only, no side effects): `select pg_get_functiondef('public.eg_on_red()'::regprocedure) like '%net-bypass%';` returns `true`. The next real network alert's email subject should read "network bypass signal" (or "explicit site on the home network" for `net-signal:`), not "Very revealing content".
   - Rollback: re-run `supabase/explicit_search_red_and_digest_fix.sql` (the previous committed `eg_on_red()`). Wording only; no data is changed either way.
   - Optional (also in #138's description): the two false `mask-api` rows from 2026-10-20 are append-only and expire by the hourly retention job after 7 days; do not edit them.

No other SQL is needed for #139, #140, #141, #142 or #143. Confirm after merging each that the PR still lists no `supabase/` file.

## 4. Mac-side PRs: #141, #140, #142

### How the Mac deploys
`eyeguard/deploy_watcher.py` (root daemon) pulls merged `main` within about 5 minutes, restarts the components and emails Dad what shipped. Fallback: `deploy/update.sh` with sudo on the Mac.

The file-integrity manifest must match the new code or the integrity check raises tamper alerts (it did on 2026-09-02). #140 and #141 touch `eyeguard/*.py`, so after each merge:
- The workflow `.github/workflows/publish-manifest.yml` republishes it automatically, if the repo Actions secret `SUPABASE_SERVICE_ROLE_KEY` is set (Settings, Secrets and variables, Actions; the value comes from Supabase, Project Settings, API, `service_role`; it lives only there).
- Verify: Actions tab shows a green "Publish release manifest" run on the merge commit. If it is red or absent, use the manual fallback in `deploy/RELEASE_CHECKLIST.md` from your own machine (`./deploy/publish_manifest.sh <version>`, with `<version>` equal to `file_integrity.version` in `config.yaml`, currently `0.3.0`). Never run it on the monitored Mac.

### #141 (coverage UP)
- What: `app:Name` entries in `config.yaml` match only when the frontmost app name is exactly that name (fixes words like "code", "stripe", "terminal", "mail", "photos" suppressing or discounting detections). `low_risk_red_demote: true` makes a CLIP RED between 0.85 and 0.93 in a low-risk context a YELLOW instead of dropping it.
- Expect more alerts: Proton Mail is no longer low-risk (Apple Mail still is), so underwear newsletters there can now produce RED emails to you and Jada. That is the intent.
- Verify after deploy: (1) the Mac checkout is at the merge commit: `git -C "/Library/Application Support/EyeGuard" log -1 --format=%h`; (2) no new `tamper:` rows in `flags` (anon select on `flags`, `reason like 'tamper%'`, recent); (3) `python3 tests/test_context_matching.py` and `python3 tests/test_guardrail.py` pass on the merged checkout; (4) the heartbeat stays green on the dashboard for 15 minutes.
- Rollback: set `low_risk_red_demote: false` for the demotion only, or revert the merge commit on `main` (deploy_watcher redeploys the previous sha). Coverage goes back to the old, weaker behaviour.

### #140 (REDUCES COVERAGE; merge only after #141)
- What: a RED that only a zoomed tile produced (the full frame is not RED) is recorded YELLOW unless NudeNet's top score is at least `tile_red_nudenet_min: 0.30`. The frame is still flagged (dashboard, daily digest) but there is no instant RED email for it. Full-frame REDs and NudeNet REDs of 0.80 and up are untouched.
- Lost coverage: if a real explicit image appears only in a small tile and NudeNet misses it, you get a yellow dashboard item instead of an instant email. Explicit-tier recall is unmeasured (the offline test used 624 non-explicit photos, RED 31 down to 11). Plan your own red test before approving.
- Control test: `tests/test_tile_red_corroboration.py` (11 checks): NudeNet 0.29 demotes, 0.30 keeps RED, full-frame RED never demotes, NudeNet's own RED passes, the rule never creates a flag, off switch restores old behaviour.
- Verify after deploy: a planned red test on the Mac that you control (it must still produce an instant RED email); then watch the ratio of `verdict = flagged` red rows over the following days. Demoted frames have reason ending `(tile-red demoted)`.
- Rollback: delete the single `tile_red_nudenet_min: 0.30` line from `config.yaml` (default is off), or revert the merge.

### #142 (packaging only)
- What: `requirements-bundle.lock.txt` pins 41 runtime packages, `tools/prepare_bundle_python.sh` builds the bundle Python from it and refuses transformers/torch/huggingface_hub/tokenizers, `build_bundled_app.sh` refuses them too.
- Merge does nothing to the live app. It takes effect only when Jonah rebuilds the bundle and you deploy it. Remaining advisory: certifi (fixed in 2026.10.19; bump the one lock-file line on or after 2026-10-27).
- Verify when rebuilt: `pip check` clean; guardrail, `test_findmy_hardening.py` and `test_dnsnet.py` pass; the detector gives the same result on a synthetic image as before (the PR reports identical output with Pillow 10.4.0 and 13.0.0); the integrity manifest still matches (no tamper rows).
- Rollback: keep running the previous bundle; do not deploy the new one.

## 5. Router rollout for #139 and #143 (one sitting)

Both change only `router/eyeguard-dnsnet.py` (and `deploy/DNSNET.md`). The monitor is a manifest-covered file, so the router manifest is republished and the install script run back to back. If the manifest is published more than about 5 minutes before the install, the old watcher reports "script modified". Do it in this order, in one sitting, and tell Jonah beforehand.

1. Merge #139, then #143 (after your review of each).
2. On your own machine, from an up-to-date clone of `main`, with `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` in your own shell (never in a file, never on the router): `./deploy/publish_router_manifest.sh 2026-11-04a`. Choose a version string different from `2026-10-21a`. Expected last line: `Published router manifest for version 2026-11-04a.`
3. Immediately tell Jonah. He runs, from a checkout equal to merged `main`: `./deploy/dnsnet_install.sh 2026-11-04a`. The script:
   - refuses unless the manifest lists the monitor files and every staged file matches it, and the files already installed also match;
   - backs up what it replaces (`*.bak-<date>-dnsnet`), sets `router_script_version` in `/etc/eyeguard/phone.json` (the only config change), restarts the monitor, waits for the status file, and stops and disables the monitor again if it is not healthy;
   - leaves the phone monitors alone.
   If it says the manifest carries a newer phone connector, run `./deploy/router_release_install.sh 2026-11-04a` first. Today's files already match `2026-10-21a`, so this is not expected.
4. Verify: `ssh router 'cat /tmp/dnsnet-stats.json'` shows `captures` 20 / 20 and a fresh timestamp; `ssh router "logread | grep eyeguard-dnsnet"` shows no repeated errors; `grep router_script_version /etc/eyeguard/phone.json` shows `2026-11-04a`; no "script modified" or "network monitor not running" rows in `flags` (anon select, `reason like 'tamper%'`).

### #139 effect to verify
- `mask-api.icloud.com` stops producing `net-bypass: connection to iCloud Private Relay` emails and appears under `observed.private-relay-api` in the stats file.
- Control (alerts still fire): do not test with a real relay name on a family device. The PR's tests show `mask.icloud.com`, `mask-h2.icloud.com` and `mask.apple-dns.net` still alert, and the 7-day simulation (`tests/sim_dnsnet_traffic.py --days 7`) alerts on 49 of 49 injected bad events with 0 false alarms. Run both on the merged checkout.
- Rollback: restore the backup (`/usr/bin/eyeguard-dnsnet.py.bak-<date>-dnsnet`) or reinstall the previous version; or set `dnsnet_alert_classes` to include `private-relay-api` to alert on it again (the PR notes this switch).

### #143 post-merge configuration (the /32 entry)
`dnsnet_expected_tunnels` is empty by default. With it empty, behaviour is identical to today. After you approve the range, add this entry on the router. Use the exact /32 the router's own bypass rule uses (`CLAUDE_GLUETUN_BYPASS`), not the /24 mentioned in the PR description:

```
"dnsnet_expected_tunnels": [{"src": "192.168.8.231", "dst": "217.138.198.246/32", "port": 51820}]
```

Before adding it, confirm the endpoint is still current: on the router, `grep 'src=192.168.8.231' /proc/net/nf_conntrack | grep 'dport=51820'` should show `dst=217.138.198.246`. As of 2026-11-03 it did (about 174 GB carried), and alerts for that destination were still firing until 19:01Z, so the exemption is still needed after the 2026-10-30 direct-WAN change.

How to apply (Jonah has root; this edits only the EyeGuard file, no network config): back up first, then merge the key with a small script so nothing else in `phone.json` is touched, then restart the monitor so it re-reads the config:

```
ssh router 'cp /etc/eyeguard/phone.json /etc/eyeguard/phone.json.bak-$(date +%F)-tunnel && python3 - <<PY
import json
p="/etc/eyeguard/phone.json"; c=json.load(open(p))
c["dnsnet_expected_tunnels"]=[{"src":"192.168.8.231","dst":"217.138.198.246/32","port":51820}]
json.dump(c,open(p+".new","w"),indent=2)
import os; os.replace(p+".new",p)
PY
/etc/init.d/eyeguard-dnsnet restart'
```

Verify:
- Within an hour or two there are no new `net-bypass: ... 217.138.198.246 ... from g11` rows (anon select on `flags`, newest first).
- `logread | grep eyeguard-dnsnet` has no "ignoring bad dnsnet_expected_tunnels entry" line (that line means the entry was rejected and it still alerts).
- Control: the same destination from any other device still alerts, and a different Proton server from the G11 still alerts. The PR's `tests/test_dnsnet_expected_tunnel.py` proves this (default config alerts on identical packets; every non-matching variant alerts; /8, /0, bad octet and port 0 are ignored and logged, never widened). Run it on the merged checkout.
- If gluetun reconnects to a different Proton server, the alert returns until this entry is updated. That is the intended fail-safe.
- Rollback: remove the `dnsnet_expected_tunnels` key (or restore `phone.json.bak-<date>-tunnel`) and restart `eyeguard-dnsnet`.

### Router rollback for the whole rollout
`/etc/init.d/eyeguard-dnsnet stop; /etc/init.d/eyeguard-dnsnet disable`, restore the `*.bak-<date>-dnsnet` files, restart `eyeguard-router-watcher`. Warning from the installer: the manifest lists the monitor as REQUIRED, so disabling it makes the watcher alert. Roll back together with a manifest for the previous file set, with Jonah told first.

## 6. Emails this rollout itself will cause (so they are not mistaken for incidents)
- Mac deploy: Dad's "what shipped" email from `deploy_watcher` after each Mac merge.
- A tamper or "script modified" alert if the router manifest is published long before the install, or the Mac manifest workflow did not run.
- "network monitor not running" if the monitor is disabled while the manifest lists it.
- More Proton Mail RED emails after #141 (intended). Fewer `mask-api` and G11 Proton emails after #139 and #143 (intended).

## 7. Final checklist for Dad
1. Review and approve #138, #141, #140, #142, #139, #143 (the three marked REDUCES COVERAGE together with Jonah).
2. Run `supabase/mdm_requeue_removal.sql` if unconfirmed, then `supabase/network_alert_title.sql`.
3. Confirm the Mac manifest workflow ran green after #141 and #140.
4. Router: publish manifest, then Jonah installs, then the /32 entry.
5. Watch `flags` for three days: expect the false-alarm classes above to disappear and real signals (a different VPN server, DoT, Tor, a real Private Relay name) to keep alerting.

Where keys live: the Supabase anon key is in the router's and the Mac's own `phone.json` / config and is read-only for `flags`; the `service_role` key exists only in your Supabase dashboard and the repo Actions secret; the frame-decryption private key is yours alone. None appears in this document.
