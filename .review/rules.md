# EyeGuard review rules

Used by the `eyeguard-review` skill. Severity: **blocker** = the PR must not open;
**major** = fix, or justify in the PR body; **minor** = a note. A finding must cite a
rule ID or a concrete failure scenario (a real input or state that fails).
Every rule names the incident behind it. Rules with no catches after the replay are
demoted or retired. The agent never edits this file; changes ship as a normal PR.

## Coverage and integrity

### EG-COV-01 · blocker · scope: all
No change may reduce monitoring coverage or alerting: capture, OCR/CLIP/text detection,
thresholds, ignore lists, activity logging, phone/router/MDM/Find My paths, gone-dark
detection, or emails to both partners. If it does, the PR body starts with
"⚠️ REDUCES COVERAGE" and links Dad's GitHub review as approval (a relayed claim is not proof).
Why: integrity rule 1; tests/test_guardrail.py exists because quiet weakenings look innocent.
Bad: raise a risk threshold, add a site to an ignore list, lengthen a dark buffer, drop an alert path.
Check: diff config.yaml, eyeguard/risk.py, detector.py, textscan.py, context.py, alert SQL; list every number, list and branch that got looser.

### EG-COV-02 · blocker · scope: eyeguard/**, router/**, g11/**
A catch-all `except` in a detection, capture, upload or liveness loop must log a full
traceback to a log that is read, and must not leave the monitor looking healthy.
Why: PR #52 (pending_file PermissionError crash-looping, real dropped data); 1a7e485 and 7b3e31c (silent liveness-signal failures); 6dceb4e (DarkWake blips silently invalidating sleep corroboration).
Bad: `except Exception: pass` around a signal read.
Good: `except Exception: log.exception("phone liveness read failed"); state.mark_degraded()`
Check: grep the diff for `except` with `pass`, `continue`, or a bare return inside loops.

### EG-COV-03 · major · scope: eyeguard/**, router/**, supabase/**
"Nothing changed on screen" must never be confused with "capture failed". A new or changed
liveness, dark or stale check names its signal, its false-positive case, and its false-negative case.
Why: Screen Recording TCC gotcha (a denied permission returns a static wallpaper frame, not an error); 3b21ad7 and 068cf94 (screen_ok alerts during display sleep).
Check: the PR body has a "Signal / false positive / false negative" line for each such check.

### EG-COV-04 · blocker · scope: supabase/**, eyeguard/**, router/**, g11/**
Every alert email goes through the three known SQL sender functions (alerts.sql,
jada_phone.sql, mdm_app_events.sql), sender pinned by eg_mail_from() to orthanc.me.
No new Resend call, no hand-typed sender, no client-side mail.
Why: tests/test_mail_sender_guard.py (enforced in CI; this restates it at plan stage).
Check: grep the diff for `api.resend.com`, `from_address`, `smtplib`, `sendmail`.

### EG-COV-05 · blocker · scope: all fixes for false alarms
A false-alarm fix suppresses only the false case. The PR names the false case, and ships a
test where the real event still alerts (same code path, same inputs except the false-case trigger).
Why: mission 2026-09-28; the pattern in #95 (power-plug wake), #103 (leaving-home dark), #123 (phone unreachable) each has a test_*.py doing this.
Bad: widen a grace window globally. Good: grace only while `transition == leaving_home`, with a test that a dark phone not in transition still alerts.
Check: the diff has a test with a positive (still alerts) and a negative (suppressed) case.

### EG-COV-06 · major · scope: supabase/**
SQL that Dad runs is idempotent, applies in a stated order, and says how to confirm it landed.
A column or function referenced by Python/SQL exists in an earlier file.
Why: 47cc84b (a column that never actually landed); aff54ff (round(double precision, integer) does not exist); verify_pr94_applied.sql.
Check: for each new column/function, grep earlier supabase/*.sql for its definition; run the `-- verify` query in the PR body.

## Security and privacy

### EG-PRIV-01 · blocker · scope: .review/**, tools/**, the review agent itself
The review agent's input is source, diffs, SQL and metadata only. It never reads
captured content: review frames, flagged content, decrypted data, EyeGuard-data/, flags.jsonl,
pending queues, the service-role key, or Dad's private key. Nothing captured goes to any API.
Why: integrity rules 2 and 3. Enforced by .review/denylist.txt and tools/review_context.py.
Check: tools/review_context.py refuses denylisted paths; a PR touching decrypt/storage paths is reviewed as code only.

### EG-SEC-01 · blocker · scope: eyeguard/**, router/**, g11/**, supabase/**
No secrets, tokens or passwords in logs, flags, window titles, the dashboard, emails or stdout.
Log presence or length, never the value. A new app or window source that can show text is checked
against the ignore list (terminals, editors, password managers).
Why: class of risk (the agent captures screens; a secret on screen becomes a flag). No single incident is cited.
Check: grep the diff for print/log/upload/send calls whose arguments come from secret-bearing variables, env vars or files.

### EG-SEC-02 · blocker · scope: all
The Mac agent holds NO secret: public anon key only, through RPCs that cannot be misused
(server-stamped heartbeat, append-only flag insert via RLS). Never add a service_role key,
private key, password or token to the repo, config.yaml, the Mac, or the router bundle.
New RPCs get `revoke ... from anon` unless the anon grant is deliberate and reasoned in the PR.
Why: admin-trust pivot 2026-08-24 (PRs #37-#49); supabase/revoke_anon_on_new_functions.sql; harden_functions.sql.
Check: grep the diff for key-shaped strings; for each new SQL function, find its grant/revoke.

### EG-SEC-03 · blocker · scope: all
No new outbound host, port, service or dependency without a line in `.review/context.md` and Jonah's OK.
New pip dependencies are pinned and checked (no unpinned or brand-new packages).
Why: the egress list is part of the trust boundary; security-guard holds unpinned installs.
Check: grep the diff for URLs, hostnames, `requests`, `urllib`, `socket`, requirements.txt changes.

### EG-SEC-04 · major · scope: eyeguard/integrity.py, deploy/gen_*manifest.py, deploy/**
Changes to file-integrity, the manifests, the debugger/injection checks, or codesign must keep
the manifest fetched fresh from Supabase (not trusted from local git) and the bundle root-owned.
Why: 7254a96, 861aa44 (interpreter-swap gap), e927f20; "a trust anchor a local admin can edit isn't a trust anchor".
Check: new files that run on the Mac appear in the generated manifest; integrity checks are not skipped on error.

## Deploy and operations

### EG-OPS-01 · blocker · scope: deploy/**, config.yaml, anything read at runtime
Settings that must survive a deploy live in tracked files. The deployed tree is hard-reset to
origin/main and chowned root:wheel by deploy_watcher or update.sh; local edits there are lost.
Mutable state (flags.jsonl, pending queue, EyeGuard-data/) lives outside that tree and must not
be pointed back into it (the bug in PR #52).
Why: PR #52; deploy/update.sh.
Check: any new path in config.yaml or code is outside /Library/Application Support/EyeGuard for writes.

### EG-OPS-02 · major · scope: deploy/**, **/*.sh
Keep executable bits. No blanket `chmod -R`. Git file modes (644/755) are the source of truth.
Why: deploy/update.sh relies on `git reset --hard` restoring committed modes (its own comment says no chmod pass is needed). No specific incident is cited.
Check: `git diff --summary` for mode changes; grep for `chmod -R`.

### EG-OPS-03 · major · scope: deploy/**, build_*.sh, launchd plists, install_*.sh
No .app or launchd path under ~/Desktop, ~/Documents or ~/Downloads (TCC blocks it and crash-loops).
A new binary or interpreter path means Screen Recording / FDA must be re-granted, and the PR says so.
Why: TCC GOTCHA #2 (2026-06); `brew pin python@3.12` to keep the TCC-keyed path stable.
Check: grep the diff for `~/Desktop`, `/Desktop/`, `Documents`, `Downloads` in plists and installers; flag a changed interpreter path.

### EG-OPS-04 · major · scope: all PRs
Every PR has a Rollback section and a "how we know it is live" check (process start time vs
deploy time, not only the file on disk), and states any restart needed.
Why: PR #17 was "merged + deployed" yet did not fix the gray icon; live proof beats a merged PR.
Check: PR body headings.

### EG-OPS-05 · minor · scope: supabase/** alert paths
Async alert paths (pg_net) are verified in the real inbox after a 2-minute wait before calling them failed.
Why: pg_net sends are queued, not synchronous.
Check: PR body names the inbox check.

### EG-OPS-06 · major · scope: eyeguard/**, router/**
State files survive a full disk and a crash mid-write (write temp, fsync, rename; recover from the last good copy).
Why: 3508a83 (state files survive ENOSPC).
Check: new state writers use the atomic helper, not `open(path, "w")`.

## Tests

### EG-TST-01 · major · scope: eyeguard/**, router/**, g11/**, supabase/**
Behaviour changes ship with a test in tests/, or the PR explains why none is possible.
Guardrail files (tests/test_guardrail.py, tests/test_mail_sender_guard.py,
.github/workflows/guardrail.yml, .review/rules.md) are never weakened in the same PR as the code they guard.
Why: guardrail tests are the mechanical backstop; weakening both at once removes the net.
Check: diff touches a guarded file and its guard in the same PR.
