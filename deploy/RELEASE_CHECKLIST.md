# After merging a PR to `main`

The deployed Mac auto-pulls merged commits (`eyeguard/deploy_watcher.py`),
but that's only half of what "deployed" means for this project.

**Every time a PR touching any file under `eyeguard/` or `run_agent.py`
gets merged, the release manifest must be republished** — otherwise
`eyeguard/integrity.py`'s file-integrity check has no way to know the new
code is legitimate, and will flag every changed file as tampered (real
incident: 2026-09-02, dozens of tamper alerts fired for `uploader.py`,
`deploy_watcher.py`, `session_watcher.py` after a batch of merges because
this step was skipped).

## Now automatic (2026-09-04)

`.github/workflows/publish-manifest.yml` republishes the manifest on every
push to `main` that touches `eyeguard/**.py` or `run_agent.py` — no manual
step needed as long as the `SUPABASE_SERVICE_ROLE_KEY` repo secret is set.

**One-time setup (Dad only, requires repo admin access):** repo
Settings → Secrets and variables → Actions → New repository secret →
name it exactly `SUPABASE_SERVICE_ROLE_KEY`, value from the Supabase
dashboard (Project Settings → API → `service_role`, "reveal"). After
that, this file's manual steps below should never be needed again for as
long as the secret stays valid — check the Actions tab after a merge if
you want to confirm the workflow ran and succeeded.

If the secret is ever missing or wrong, the workflow fails loudly (an
`::error::` annotation, visible as a red X on the commit and in the
Actions tab) rather than silently doing nothing — that's the signal to
fall back to the manual steps below.

## Manual fallback (only if the workflow above isn't set up or failed)

Run on Dad's own machine, from an up-to-date clone of `main` (never on the
monitored Mac, never with the anon key):

```bash
export SUPABASE_URL=https://ucgldleacehxjjwwqomk.supabase.co
export SUPABASE_SERVICE_ROLE_KEY=<from Supabase dashboard -> Project Settings -> API>
git pull origin main
./deploy/publish_manifest.sh 0.3.0
```

`0.3.0` must match `config.yaml`'s `file_integrity.version` field currently
set in the deployed config — check that before running if unsure (the
workflow above reads this same field automatically, so it can't drift the
way a hardcoded manual command can).

The publish is an upsert (`Prefer: resolution=merge-duplicates`), so
re-running it for the same version safely overwrites the previous manifest
rather than erroring or duplicating.

If the version number in `config.yaml` is ever bumped, the NEW version
string is what gets published (both by the workflow and by this manual
command) — `_fetch_manifest` looks up an exact match, so a stale version
key just means "no manifest found" (a distinct, non-alarming warning), not
tamper — but a *wrong* one means the check is silently comparing against
nothing useful until it's fixed.
