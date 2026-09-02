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

Run on Dad's own machine, from an up-to-date clone of `main` (never on the
monitored Mac, never with the anon key):

```bash
export SUPABASE_URL=https://ucgldleacehxjjwwqomk.supabase.co
export SUPABASE_SERVICE_ROLE_KEY=<from Supabase dashboard -> Project Settings -> API>
git pull origin main
./deploy/publish_manifest.sh 0.3.0
```

`0.3.0` must match `findmy.version`/the top-level `version:` field currently
set in the deployed `config.yaml` — check that before running if unsure.
The publish is an upsert (`Prefer: resolution=merge-duplicates`), so
re-running it for the same version safely overwrites the previous manifest
rather than erroring or duplicating.

If the version number in `config.yaml` is ever bumped, publish under the
NEW version string, not the old one — `_fetch_manifest` looks up an exact
match, so a stale version key just means "no manifest found" (a distinct,
non-alarming warning), not tamper — but a *wrong* one means the check is
silently comparing against nothing useful until it's fixed.
