"""Auto-deploy watcher -- root LaunchDaemon, admin-trust-model pivot.

Polls GitHub's public API for main's latest commit. When it differs from
what's actually deployed (the local repo's own HEAD -- no separate state
needed, git already knows), pulls and restarts immediately, exactly what
deploy/update.sh already does by hand. The only gate is the one that
already existed: GitHub branch protection + Dad's own PR review to get a
commit onto main in the first place. Once merged, it ships -- no second
approval step, no password prompt.

The repo is public, so reading commit history needs no token/credential on
the monitored Mac at all -- nothing new to protect here.

After deploying, calls eg_report_deploy() (supabase/deploy_watcher.sql) so
Dad gets an email of what just shipped -- visibility, not a gate.

Tamper-EVIDENT, not tamper-proof: an admin can kill this daemon (shows up
as its own gone-dark condition, same mechanism as session_watcher.py) or
edit its code (caught by the file-integrity manifest check, since this
file is part of the covered eyeguard/*.py tree).
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

from .net import opener as _opener

_BASE = Path(__file__).resolve().parent.parent
_GITHUB_API = "https://api.github.com"
_TIMEOUT = 20


def _github_get(path: str) -> dict | list | None:
    """GET against the public GitHub API. Never raises -- a network hiccup
    or rate limit should skip this cycle, not crash the daemon."""
    try:
        req = urllib.request.Request(
            f"{_GITHUB_API}{path}",
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "eyeguard-deploy-watcher"})
        with _opener.open(req, timeout=_TIMEOUT) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print(f"[deploy_watcher] {datetime.now().isoformat()} GitHub API request failed: {e} -- "
              f"skipping this cycle", flush=True)
        return None


def _latest_main_sha(owner: str, repo: str) -> str | None:
    data = _github_get(f"/repos/{owner}/{repo}/commits/main")
    if not isinstance(data, dict):
        return None
    return data.get("sha")


def _commit_summary(owner: str, repo: str, base_sha: str, head_sha: str) -> str:
    """One line per commit between what's deployed and what's incoming --
    the same information update.sh's own `git log --oneline HEAD..origin/
    main` confirmation prompt already showed, just captured for the
    after-the-fact email instead of a terminal only Dad standing at the Mac
    would have seen."""
    data = _github_get(f"/repos/{owner}/{repo}/compare/{base_sha}...{head_sha}")
    if not isinstance(data, dict):
        return f"(commit list unavailable -- new commit is {head_sha[:9]})"
    lines = []
    for c in data.get("commits", []):
        sha = c.get("sha", "")[:9]
        msg = (c.get("commit", {}).get("message") or "").splitlines()[0]
        lines.append(f"{sha} {msg}")
    return "\n".join(lines) or f"(no listed commits -- new commit is {head_sha[:9]})"


def _deployed_sha(code_dir: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(code_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        return out.stdout.strip() if out.returncode == 0 else None
    except Exception:
        return None


class DeployWatcher:
    def __init__(self, url: str, api_key: str, owner: str, repo: str,
                 code_dir: str | Path, monitored_user: str,
                 check_seconds: int = 300):
        self.base = url.rstrip("/")
        self.api_key = api_key
        self.owner = owner
        self.repo = repo
        self.code_dir = Path(code_dir)
        self.monitored_user = monitored_user
        self.check_seconds = check_seconds

    def _rpc(self, name: str, params: dict):
        req = urllib.request.Request(
            f"{self.base}/rest/v1/rpc/{name}",
            data=json.dumps(params).encode(), method="POST",
            headers={"apikey": self.api_key,
                     "Authorization": f"Bearer {self.api_key}",
                     "Content-Type": "application/json"})
        with _opener.open(req, timeout=15) as r:
            r.read()

    def _deploy(self, sha: str, summary: str):
        """Exactly what deploy/update.sh does by hand -- git reset --hard,
        chown, restart the running components. Deploys to the exact sha
        that was `main`'s tip when this cycle started, not whatever main
        might have advanced to mid-deploy -- a merge landing in the middle
        of this just gets picked up cleanly on the NEXT poll cycle instead
        of being silently folded in."""
        print(f"[deploy_watcher] {datetime.now().isoformat()} deploying {sha[:9]}...", flush=True)
        subprocess.run(["git", "-C", str(self.code_dir), "fetch", "origin",
                        "main"], check=True, timeout=60)
        subprocess.run(["git", "-C", str(self.code_dir), "reset", "--hard",
                        sha], check=True, timeout=60)
        subprocess.run(["chown", "-R", "root:wheel", str(self.code_dir)],
                       check=True, timeout=60)
        try:
            uid = subprocess.run(["id", "-u", self.monitored_user],
                                 capture_output=True, text=True,
                                 timeout=10).stdout.strip()
            if uid:
                subprocess.run(["launchctl", "kickstart", "-k",
                                f"gui/{uid}/com.eyeguard.monitor"],
                               timeout=30)
        except Exception:
            pass
        subprocess.run(["launchctl", "kickstart", "-k",
                        "system/com.eyeguard.sessionwatcher"], timeout=30)
        self._rpc("eg_report_deploy", {"p_sha": sha, "p_summary": summary})
        print(f"[deploy_watcher] {datetime.now().isoformat()} deployed {sha[:9]}.", flush=True)
        # Restart this daemon too -- unconditionally, same as monitor/
        # sessionwatcher above, not gated on "did deploy_watcher.py itself
        # change" (a future deploy could touch a shared module this file
        # imports, e.g. net.py, with the same stale-code-in-memory problem).
        # Confirmed live (2026-08-25): this PR's own fix to this file would
        # otherwise never take effect on a running instance -- the process
        # keeps executing whatever was already loaded, indefinitely, until
        # something else restarts it. MUST be the last statement in this
        # method: `kickstart -k` on your own label stops the calling process
        # almost immediately, so everything above (deploy the code, restart
        # the other services, report the deploy) has to have already fully
        # completed. KeepAlive=true in the plist brings a fresh instance
        # straight back up running the code that was just deployed.
        subprocess.run(["launchctl", "kickstart", "-k",
                        "system/com.eyeguard.deploywatcher"], timeout=30)

    def _check_once(self):
        deployed = _deployed_sha(self.code_dir)
        latest = _latest_main_sha(self.owner, self.repo)
        if deployed is None or latest is None or latest == deployed:
            return
        summary = _commit_summary(self.owner, self.repo, deployed, latest)
        self._deploy(latest, summary)

    def run(self):
        print(f"[deploy_watcher] {datetime.now().isoformat()} active, checking every "
              f"{self.check_seconds}s against {self.owner}/{self.repo}",
              flush=True)
        while True:
            try:
                self._check_once()
            except urllib.error.URLError as e:
                print(f"[deploy_watcher] {datetime.now().isoformat()} network error: {e} -- will retry "
                      f"next cycle", flush=True)
            except subprocess.CalledProcessError as e:
                print(f"[deploy_watcher] {datetime.now().isoformat()} deploy step failed: {e} -- "
                      f"will retry next cycle", flush=True)
            except Exception as e:
                # A bad check must never kill this daemon -- same rule as
                # every other background watcher in this project.
                print(f"[deploy_watcher] {datetime.now().isoformat()} check raised {e!r} -- continuing",
                      flush=True)
            time.sleep(self.check_seconds)


def main():
    import argparse
    from .main import load_config
    p = argparse.ArgumentParser(prog="eyeguard-deploy-watcher")
    p.add_argument("--config", default=str(_BASE / "config.yaml"))
    args = p.parse_args()
    cfg = load_config(args.config)
    dw = cfg.get("deploy_watcher", {})
    sb = cfg.get("supabase", {})
    if not dw.get("enabled", True):
        print("[deploy_watcher] disabled in config, exiting", flush=True)
        return
    DeployWatcher(
        url=sb["url"], api_key=sb["api_key"],
        owner=dw["owner"], repo=dw["repo"],
        code_dir=dw.get("code_dir", str(_BASE)),
        monitored_user=dw["monitored_user"],
        check_seconds=int(dw.get("check_seconds", 300)),
    ).run()


if __name__ == "__main__":
    main()
