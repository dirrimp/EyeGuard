#!/usr/bin/env python3
"""Purge review frames older than the retention window, through the Storage API.

Why this exists: supabase/phase4b_hardening.sql schedules `eyeguard-image-retention`
as a plain `delete from storage.objects ...`. Supabase blocks that (trigger
storage.protect_delete: "Direct deletion from storage tables is not allowed. Use the
Storage API instead"), so the job failed on every run and old review frames were
never purged. Deleting through the Storage API is the supported way.

Where it runs: .github/workflows/purge-frames.yml, with the repo Actions secret
SUPABASE_SERVICE_ROLE_KEY (the same trust boundary as publish-manifest.yml: Dad's
secret, never in this repo, never on the monitored Mac, never in a coding session).

What it will and will not do:
  * touches only the 'frames' bucket;
  * deletes only objects whose NAME looks like an agent frame (timestamp-prefixed
    .jpg/.png/.enc), so placeholders and anything unexpected are left alone;
  * deletes only when BOTH the storage created_at and the timestamp in the file name
    (when present) are older than the cutoff, so a clock quirk can only keep a frame,
    never delete a young one;
  * refuses a retention shorter than 3 days;
  * deletes at most --max-delete objects per run (oldest first), so a bug or a bad
    clock cannot wipe the bucket in one go; any backlog drains on later runs;
  * defaults to --dry-run: it counts and deletes nothing;
  * prints COUNTS ONLY, never an object name and never the key (this repo is public,
    so Actions logs are public);
  * fails closed: any unexpected API response exits non-zero, which makes the
    workflow run red and GitHub emails Dad.

Stdlib only. Usage:  tools/purge_frames.py [--dry-run | --apply] [--days 7] [--max-delete 500]
Env:    SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.request

BUCKET = "frames"
MIN_RETENTION_DAYS = 3
DEFAULT_RETENTION_DAYS = 7
DEFAULT_MAX_DELETE = 500
PAGE = 100
DELETE_BATCH = 100

# Agent frames are named <ISO timestamp with ':' as '-'>_<reason>_d<N>.jpg[.enc], e.g.
# 2026-11-10T20-59-12.446472+00-00_alert_d1.jpg.enc (see eyeguard/uploader.py).
NAME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})[^/]*\.(?:jpe?g|png)(?:\.enc)?$")


class PurgeError(Exception):
    """Raised for any condition that must fail the run. Never carries object names."""


def name_time(name: str) -> dt.datetime | None:
    m = NAME_RE.match(name)
    if not m:
        return None
    try:
        return dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H-%M-%S").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def _parse_ts(value) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def is_old(entry: dict, cutoff: dt.datetime) -> bool:
    """True only if every timestamp we can read is older than the cutoff, and at
    least one is readable."""
    name = entry.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        return False
    stamps = [name_time(name), _parse_ts(entry.get("created_at"))]
    stamps = [s for s in stamps if s is not None]
    return bool(stamps) and all(s < cutoff for s in stamps)


def list_frames(api) -> list[dict]:
    """Every file entry in the bucket root (folders have id null and are skipped)."""
    out: list[dict] = []
    offset = 0
    while True:
        page = api("POST", f"/storage/v1/object/list/{BUCKET}", {
            "prefix": "", "limit": PAGE, "offset": offset,
            "sortBy": {"column": "created_at", "order": "asc"}})
        if not isinstance(page, list):
            raise PurgeError("list: unexpected response shape")
        out.extend(e for e in page if isinstance(e, dict) and e.get("id") is not None)
        if len(page) < PAGE:
            return out
        offset += PAGE
        if offset > 200_000:
            raise PurgeError("list: refusing to page past 200000 entries")


def run(api, now: dt.datetime, days: int, max_delete: int, apply: bool, say=print) -> int:
    if days < MIN_RETENTION_DAYS:
        raise PurgeError(f"retention {days}d is below the {MIN_RETENTION_DAYS}d minimum")
    if max_delete < 1:
        raise PurgeError("max-delete must be at least 1")
    cutoff = now - dt.timedelta(days=days)

    entries = list_frames(api)
    recognized = [e for e in entries if NAME_RE.match(e.get("name", ""))]
    old = sorted((e for e in recognized if is_old(e, cutoff)),
                 key=lambda e: min(t for t in (name_time(e["name"]), _parse_ts(e.get("created_at"))) if t))
    todo = old[:max_delete]
    oldest_days = ""
    if old:
        first = min(t for t in (name_time(old[0]["name"]), _parse_ts(old[0].get("created_at"))) if t)
        oldest_days = f", oldest is {(now - first).days} days old"
    say(f"mode: {'APPLY' if apply else 'DRY RUN'}; retention {days}d; cap {max_delete} per run")
    say(f"bucket '{BUCKET}': {len(entries)} files, {len(recognized)} recognized frames, "
        f"{len(old)} older than {days}d{oldest_days}")
    say(f"selected for deletion this run: {len(todo)}"
        + (f" ({len(old) - len(todo)} more remain for later runs)" if len(old) > len(todo) else ""))

    if not apply:
        say("DRY RUN: nothing was deleted. Re-run with --apply to delete.")
        return 0
    if not todo:
        say("nothing to delete.")
        return 0

    deleted = 0
    for i in range(0, len(todo), DELETE_BATCH):
        batch = [e["name"] for e in todo[i:i + DELETE_BATCH]]
        res = api("DELETE", f"/storage/v1/object/{BUCKET}", {"prefixes": batch})
        if not isinstance(res, list):
            raise PurgeError("delete: unexpected response shape")
        if len(res) != len(batch):
            raise PurgeError(f"delete: asked for {len(batch)}, API reports {len(res)} deleted")
        deleted += len(res)

    after = [e for e in list_frames(api) if is_old(e, cutoff)]
    say(f"deleted {deleted}; frames older than {days}d still present: {len(after)}")
    if len(after) > len(old) - deleted:
        raise PurgeError("post-check: more old frames remain than expected")
    return 0


def make_api(base: str, key: str):
    def api(method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            base.rstrip("/") + path, data=data, method=method,
            headers={"apikey": key, "Authorization": f"Bearer {key}",
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:      # status only: bodies can echo names
            raise PurgeError(f"{method} storage API: HTTP {e.code}") from None
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            raise PurgeError(f"{method}: {type(e).__name__}") from None
    return api


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="count only (default)")
    mode.add_argument("--apply", action="store_true", help="really delete")
    ap.add_argument("--days", type=int, default=DEFAULT_RETENTION_DAYS)
    ap.add_argument("--max-delete", type=int, default=DEFAULT_MAX_DELETE)
    args = ap.parse_args(argv)

    base, key = os.environ.get("SUPABASE_URL", ""), os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    if not base or not key:
        print("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set", file=sys.stderr)
        return 2
    try:
        return run(make_api(base, key), dt.datetime.now(dt.timezone.utc),
                   args.days, args.max_delete, apply=args.apply)
    except PurgeError as e:
        print(f"FAILED: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
