"""Deployed-code/config integrity watcher — root-daemon-side tamper evidence.

Runs inside the vault daemon (root, LaunchDaemon), independent of the
unprivileged session agent. Periodically confirms every git-tracked file in
the deployed tree still byte-matches what's actually committed at HEAD, and
reports drift via the SAME report_tamper() path already used by the agent's
own flags.jsonl / flagged-frame tamper checks (menubar.py) -- so it composes
with the existing "tamper: ..." -> dedicated alert-email routing, no new
Supabase wiring needed.

Why this needs to live here, not in menubar.py (the agent):
  * The agent is a killable, restartable, user-run process. If someone edits
    or deletes the agent's own code, a check running INSIDE the agent stops
    running too -- it can't detect its own removal. This daemon is a
    separate root process holding the network credentials directly; even a
    fully broken/deleted agent doesn't stop it from checking and reporting.
  * git itself is the baseline -- no separate baseline file to protect or
    keep in sync. Every check re-reads `git show HEAD:<path>` fresh, so it
    self-corrects across legitimate deploys (update.sh's `git reset --hard`
    moves HEAD; the very next check just compares against the new HEAD)
    without any manual reset step, unlike the log/frames tamper checks
    which need retention to explicitly clear their stored baseline.

What this does NOT claim: this is tamper-EVIDENT, not tamper-PROOF, the
same standing philosophy as everywhere else in this project. Someone with
root could, in principle, edit a file and this exact watcher in the same
sudo session before the next check cycle -- the mitigation is the same one
this project already relies on elsewhere: a code change to the running
daemon requires either a restart (loud, root-only, and independently
crash-loop / gone-dark-detectable via the existing heartbeat path) or an
in-place edit-without-restart (which this check WILL catch on its next
cycle, since the check re-reads the file from disk each time, not from any
cached/imported state).
"""

from __future__ import annotations

import hashlib
import subprocess
import threading
import time
from pathlib import Path


def _git(repo_dir: Path, *args: str) -> tuple[bool, bytes]:
    """Run git against repo_dir. (ok, stdout_bytes). Never raises."""
    try:
        p = subprocess.run(
            ["git", "-C", str(repo_dir), *args],
            capture_output=True, timeout=15, check=False,
        )
        return p.returncode == 0, p.stdout
    except Exception:
        return False, b""


def _tracked_files(repo_dir: Path, exclude: set[str]) -> list[str] | None:
    ok, out = _git(repo_dir, "ls-tree", "-r", "HEAD", "--name-only")
    if not ok:
        return None
    return [ln for ln in out.decode("utf-8", "replace").splitlines()
            if ln.strip() and ln.strip() not in exclude]


def _committed_hash(repo_dir: Path, rel_path: str) -> str | None:
    ok, out = _git(repo_dir, "show", f"HEAD:{rel_path}")
    if not ok:
        return None  # file deleted from HEAD, or path error -- not a live-file check
    return hashlib.sha256(out).hexdigest()


def _live_hash(repo_dir: Path, rel_path: str) -> str | None:
    p = repo_dir / rel_path
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return None  # missing / unreadable


class IntegrityWatcher:
    """Periodically diffs every git-tracked file in repo_dir against its
    HEAD-committed content. On drift, calls uploader.report_tamper() once
    the SAME drift has persisted for two consecutive checks (matching the
    existing 2-strikes debounce already used by menubar.py's log-tamper
    check, to rule out a transient read racing a legitimate in-progress
    deploy) -- and only once per path per drift episode, not every cycle.

    exclude: relative paths to skip (e.g. anything legitimately allowed to
    differ from git, none by design today -- config.yaml is meant to be
    byte-identical to what's committed, per this project's own standing
    lesson about untracked local-only config patches going stale).
    """

    def __init__(self, uploader, repo_dir: str | Path,
                 check_seconds: int = 300,
                 exclude: set[str] | None = None):
        self.uploader = uploader
        self.repo_dir = Path(repo_dir)
        self.check_seconds = check_seconds
        self.exclude = exclude or set()
        self._pending: dict[str, int] = {}   # path -> consecutive-mismatch count
        self._reported: set[str] = set()     # paths already alerted for THIS drift
        self._last_head: str | None = None

    def _check_once(self):
        ok, head_out = _git(self.repo_dir, "rev-parse", "HEAD")
        head = head_out.decode().strip() if ok else None
        if not ok or not head:
            # Can't even read the repo state -- report once per occurrence,
            # same debounce as everything else here, then stay quiet until
            # it resolves (avoids spamming if e.g. disk is briefly busy).
            self._note_mismatch("<repo>", "git repository unreadable "
                                 "(HEAD unresolvable) -- deployed code may "
                                 "have been removed or corrupted")
            return
        if head != self._last_head:
            # A legitimate deploy (or a HEAD-moving tamper attempt) -- either
            # way, start comparing against the NEW head from here on; no
            # manual reset needed, this is what makes git-as-baseline work.
            self._last_head = head

        files = _tracked_files(self.repo_dir, self.exclude)
        if files is None:
            self._note_mismatch("<repo>", "git ls-tree failed -- could not "
                                 "enumerate deployed files against HEAD")
            return

        seen_this_cycle = set()
        for rel in files:
            seen_this_cycle.add(rel)
            committed = _committed_hash(self.repo_dir, rel)
            live = _live_hash(self.repo_dir, rel)
            if committed is None:
                continue  # file legitimately not in HEAD at this path; skip
            if live is None:
                self._note_mismatch(rel, "deployed file is missing or "
                                     "unreadable but is tracked at HEAD")
            elif live != committed:
                self._note_mismatch(rel, "deployed file content differs "
                                     "from the committed/deployed version")
            else:
                self._clear(rel)

        # A tracked path that's now MISSING from ls-tree entirely (e.g. HEAD
        # itself was force-moved to an old commit that never had this file)
        # isn't caught by the loop above -- but the next cycle's committed
        # lookup already reflects the new HEAD, so nothing to add here; this
        # comment exists only to record that case was considered, not missed.
        _ = seen_this_cycle

    def _note_mismatch(self, path: str, detail: str):
        n = self._pending.get(path, 0) + 1
        self._pending[path] = n
        if n >= 2 and path not in self._reported:
            self._reported.add(path)
            msg = f"deployed-file integrity check: {path} -- {detail}"
            try:
                self.uploader.report_tamper(msg)
            except Exception:
                pass  # a failed report must never kill this thread
            print(f"[vault] [integrity] {msg} -- reported", flush=True)

    def _clear(self, path: str):
        if path in self._pending or path in self._reported:
            self._pending.pop(path, None)
            self._reported.discard(path)

    def run(self):
        """Blocks forever on its own daemon thread, same convention as
        SleepWatcher.run() in vault.py."""
        print(f"[vault] [integrity] watcher active, checking every "
              f"{self.check_seconds}s against {self.repo_dir}", flush=True)
        while True:
            try:
                self._check_once()
            except Exception as e:
                # A bad check must never kill this thread -- same rule as
                # every other background watcher in this project.
                print(f"[vault] [integrity] check raised {e!r} -- "
                      f"continuing", flush=True)
            time.sleep(self.check_seconds)
