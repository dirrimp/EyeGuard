# Developing EyeGuard After the Lockdown

Once the Mac is locked down and the repo belongs to Dad (`CONTROL_PLANES.md`),
`/Library/Application Support/EyeGuard` is root-owned — you can't edit it
directly, on purpose. This is how you keep improving EyeGuard anyway, without
reopening the hole the lockdown just closed.

**The shape of it:** you propose, Dad approves, only then does it run.

```
you edit on a branch  →  PR to main  →  Dad reviews & approves & merges
                                              │
                                              ▼
                              Dad runs deploy/update.sh (sudo)
                                              │
                                              ▼
                         root-owned install updated + restarted
```

No step lets code reach the running agent without Dad's approval *and* Dad's
own hands on the keyboard for the deploy.

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

Merging to `main` does **not** touch the running agent by itself — the
root-owned install only changes when Dad explicitly runs:

```bash
cd "/Library/Application Support/EyeGuard"
sudo ./deploy/update.sh
```

It shows exactly what's about to change (`git log` of the incoming commits),
asks for confirmation, then hard-resets the deployed code to `main` and
restarts the vault daemon + session agent. Takes 30 seconds.

## Why this is safe

- You can never push to `main` — GitHub blocks it, not just etiquette.
- You can never run `update.sh` — it requires `sudo`, which needs Dad's
  password.
- A PR you open is just a *proposal* sitting on GitHub; it has zero effect on
  the Mac until Dad merges it **and** separately chooses to deploy it.
- Monitoring data (`flags.jsonl`, the secret key, the pending queue) lives
  outside the code tree `update.sh` resets, so a deploy never touches history.

If you ever want to move fast on something, the honest move is to just talk to
Dad — the workflow is designed to require his attention, not to be worked
around.

## Verified working (2026-08-04)
Full loop tested end-to-end: branch pushed by a Write collaborator, direct
push to `main` confirmed blocked by the ruleset, PR opened, Dad approved and
merged, `deploy/update.sh` deployed the change to the locked-down Mac. This
pipeline is proven, not just configured.
