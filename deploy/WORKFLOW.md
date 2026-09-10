# Developing EyeGuard After the Lockdown

The Mac is locked down and the repo belongs to Dad (see `deploy/STATUS.md`), so
`/Library/Application Support/EyeGuard` is root-owned — you can't edit it
directly, on purpose. This is how you keep improving EyeGuard anyway, without
reopening the hole the lockdown just closed.

**The shape of it:** you propose, Dad reviews & merges, then it ships.

```
you edit on a branch  →  PR to main  →  Dad reviews & approves & merges
                                              │
                                              ▼
                          deploy_watcher (root daemon) pulls within ~5 min
                          — or Dad runs deploy/update.sh (sudo) manually
                                              │
                                              ▼
                         root-owned install updated + restarted,
                         Dad emailed what shipped
```

No code reaches the running agent without Dad's review and merge — that's
the gate. Deployment after merge is automatic (`deploy_watcher`); the
manual `update.sh` path is a fallback.

## One-time setup (Dad, in his GitHub repo)

1. **Settings → Collaborators** → add you as a collaborator with **Write**
   access (not Admin). Write lets you push branches and open PRs — not push to
   `main`.
2. **Settings → Branches → Branch protection rule** for `main`:
   - ✅ Require a pull request before merging
   - ✅ Require approvals — **1**
   - ✅ Require review from Code Owners
   - ✅ **Require status checks to pass before merging** → select **`guardrail`**
     (the `.github/workflows/guardrail.yml` check). This makes the security
     guardrail *blocking* — a PR that weakens detection can't merge even if
     approved by accident.
   - ✅ Do not allow bypassing the above settings (applies even to admins)
   - ✅ Restrict who can push to matching branches → only Dad
3. Add a **`CODEOWNERS`** file (already in this repo, at `.github/CODEOWNERS`)
   naming Dad as the owner of everything — this is what makes his review
   mandatory on every PR, automatically.

After this, GitHub itself refuses to merge anything into `main` without Dad's
approval — it's not a social convention, it's enforced.

## Your normal dev loop

```bash
git clone <the repo>              # your own working copy, anywhere you like
git checkout -b fix-something
# ... edit, test ...
git push origin fix-something
gh pr create   # or open the PR on github.com
```

Dad gets notified, reviews the diff, and either approves + merges or asks for
changes. You can keep pushing to the same branch until it's approved.

## Getting an approved change onto the Mac

Once a PR is merged to `main`, **`deploy_watcher` (a root LaunchDaemon) ships
it automatically** — it polls GitHub, and within ~5 minutes it does exactly
what `deploy/update.sh` does by hand: hard-reset the deployed tree to
`origin/main`, `chown -R root:wheel`, and restart the session agent, session
watcher, and deploy watcher. It then emails Dad what shipped (visibility, not
a gate). The merge *is* the deploy trigger; there is no separate deploy
approval, because getting a commit onto `main` already required Dad's review.

`deploy/update.sh` still exists for a manual deploy (Dad, `sudo`) if the
watcher is down or you need it immediately:

```bash
cd "/Library/Application Support/EyeGuard"
sudo ./deploy/update.sh
```

It prints the incoming commits, asks for confirmation, then does the same
reset + restart.

## Why this is safe

- You can never push to `main` — GitHub blocks it, not just etiquette.
- A PR you open is just a *proposal* sitting on GitHub; it has zero effect on
  the Mac until Dad **reviews and merges** it. That review is the only gate,
  and it's mandatory (branch protection + `CODEOWNERS`).
- The deployed tree is root-owned; you can't edit it directly, and
  `update.sh` needs `sudo` (Dad's password).
- Monitoring data (`flags.jsonl`, the pending queue, `EyeGuard-data/`) lives
  outside the code tree a deploy resets, so shipping code never touches
  history. There is no secret key on the Mac to protect — the agent uses the
  public anon key only (admin-trust pivot, 2026-08-24).

If you ever want to move fast on something, the honest move is to just talk to
Dad — the workflow is designed to require his attention, not to be worked
around.

## Verified working (2026-08-04)
Full loop tested end-to-end: branch pushed by a Write collaborator, direct
push to `main` confirmed blocked by the ruleset, PR opened, Dad approved and
merged, `deploy/update.sh` deployed the change to the locked-down Mac. This
pipeline is proven, not just configured.
