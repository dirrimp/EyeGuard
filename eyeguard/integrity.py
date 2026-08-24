"""Deployed-code/config integrity watcher — packaged-app tamper evidence.

Admin-trust-model pivot (2026-08-24): the original version of this file
diffed every git-tracked file in the deployed tree against `git show
HEAD:<path>` in a live git repository -- correct for a git-clone-style
deployment, but it doesn't generalize to a packaged, distributed `.app` (no
git repo ships inside a bundle). This version instead fetches a PUBLISHED
manifest fresh from Supabase on every check
(supabase/anon_client_pivot.sql's `release_manifests` table, anon
SELECT-only -- populated only by a release script using the maintainer's own
key at build time, never the shipped app) and compares the running files'
hashes against it.

Why fetch fresh every time rather than trust a locally-shipped copy of the
manifest: a manifest sitting on disk next to the code has the exact same
"I'd have to protect this file too" problem a locally-shipped git repo
would -- a local admin could edit both the code AND the manifest to match.
Fetching the canonical copy fresh from a server the local admin doesn't
control is what makes this a real check rather than a check-yourself
tautology -- the same reasoning that motivated using live git HEAD over a
local baseline file in the original version.

What this does NOT claim: this is tamper-EVIDENT, not tamper-PROOF, same
standing philosophy as everywhere else in this project. A local admin could,
in principle, patch a running process in memory without touching any file on
disk at all (that's what deploy/harden_codesign.sh's hardened-runtime
signing exists to raise the bar against) -- this check only ever sees what's
actually on disk when it looks. And an admin who kills this process entirely
just shows up as gone-dark, same as killing the main app for any other
reason -- that's the design working as intended, not a gap.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

_MANIFEST_TIMEOUT = 15


def _fetch_manifest(url: str, api_key: str, version: str) -> dict | None:
    """{rel_path: "sha256:..."} for the given version, or None if the
    server has no manifest published for it, or on any network failure.
    Never raises -- a network hiccup should skip this cycle, not crash the
    watcher or read as tamper."""
    try:
        req = urllib.request.Request(
            f"{url.rstrip('/')}/rest/v1/release_manifests"
            f"?version=eq.{urllib.parse.quote(version)}&select=manifest",
            headers={"apikey": api_key, "Authorization": f"Bearer {api_key}"})
        with urllib.request.urlopen(req, timeout=_MANIFEST_TIMEOUT) as r:
            rows = json.loads(r.read().decode())
    except Exception:
        return None
    if not rows:
        return None  # no manifest published for this exact version
    manifest = rows[0].get("manifest") or {}
    return manifest.get("files")


def _local_hash(base_dir: Path, rel_path: str) -> str | None:
    try:
        return "sha256:" + hashlib.sha256(
            (base_dir / rel_path).read_bytes()).hexdigest()
    except OSError:
        return None  # missing / unreadable


class IntegrityWatcher:
    """Periodically fetches the published manifest for `version` and diffs
    every path it lists against the live file on disk. On drift, calls
    uploader.report_tamper() once the SAME drift has persisted for two
    consecutive checks (rules out a transient read racing a legitimate
    in-progress update), and only once per path per drift episode, not every
    cycle -- identical debounce shape to the original git-based version.

    If the server has no manifest for the locally-running `version` at all,
    that's treated as a distinct soft "unknown version" signal (logged
    locally, not reported as tamper) rather than conflated with genuine
    content drift -- an out-of-date install isn't the same thing as a
    tampered one.
    """

    def __init__(self, uploader, base_dir: str | Path, url: str,
                 api_key: str, version: str, check_seconds: int = 300):
        self.uploader = uploader
        self.base_dir = Path(base_dir)
        self.url = url
        self.api_key = api_key
        self.version = version
        self.check_seconds = check_seconds
        self._pending: dict[str, int] = {}   # path -> consecutive-mismatch count
        self._reported: set[str] = set()     # paths already alerted for THIS drift
        self._warned_unknown_version = False  # log the soft warning once, not every cycle

    def _check_once(self):
        manifest = _fetch_manifest(self.url, self.api_key, self.version)
        if manifest is None:
            if not self._warned_unknown_version:
                print(f"[integrity] no published manifest for version "
                      f"'{self.version}' (or the server is unreachable) -- "
                      f"integrity check paused, not treated as tamper",
                      flush=True)
                self._warned_unknown_version = True
            return
        if self._warned_unknown_version:
            print(f"[integrity] manifest for version '{self.version}' is "
                  f"available again -- resuming checks", flush=True)
            self._warned_unknown_version = False

        for rel_path, expected_hash in manifest.items():
            live_hash = _local_hash(self.base_dir, rel_path)
            if live_hash is None:
                self._note_mismatch(rel_path, "file is missing or "
                                     "unreadable but is listed in the "
                                     "published manifest")
            elif live_hash != expected_hash:
                self._note_mismatch(rel_path, "file content differs from "
                                     "the published known-good version")
            else:
                self._clear(rel_path)

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
            print(f"[integrity] {msg} -- reported", flush=True)

    def _clear(self, path: str):
        if path in self._pending or path in self._reported:
            self._pending.pop(path, None)
            self._reported.discard(path)

    def run(self):
        """Blocks forever on its own daemon thread."""
        print(f"[integrity] watcher active, checking every "
              f"{self.check_seconds}s against {self.base_dir} "
              f"(version {self.version})", flush=True)
        while True:
            try:
                self._check_once()
            except Exception as e:
                # A bad check must never kill this thread -- same rule as
                # every other background watcher in this project.
                print(f"[integrity] check raised {e!r} -- continuing",
                      flush=True)
            time.sleep(self.check_seconds)
