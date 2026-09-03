"""Reliable Supabase uploader for flags + frame images.

Design goals:
  * Never block the detection loop — uploads run on a background worker thread.
  * Survive offline — each flag is appended to a persistent pending queue; the
    worker retries the whole queue periodically, so a backlog auto-sends the
    moment the network is back (and across restarts).
  * "No alert without an image" — the flag row is only inserted after its image
    uploads; if the local image is gone (e.g. pruned), the flag is dropped.
  * Idempotent — a deterministic row id + upsert means a retry after a crash
    never creates a duplicate.

Admin-trust-model pivot (2026-08-24): the client holds ONLY the public anon
key from now on. There is no secret/service_role key anywhere in this file,
on disk, or in config -- once the monitored user has full admin on their own
Mac, no locally-held secret can be assumed hidden from them, so there's no
longer a meaningful distinction between "the powerful key" and "the public
key." Every write goes through one of two mechanisms, both safe to expose to
a fully-untrusted, fully-admin client:
  * `flags` and the `frames` storage bucket: explicit anon-scoped INSERT-only
    RLS policies (frames' policy predates this pivot -- Storage doesn't honor
    a REVOKE against service_role the same way table access does, a confirmed
    Supabase platform quirk, which is exactly why frames moved to anon+RLS
    first; flags now uses the identical pattern).
  * `device_status`: no direct table write exists for any role anymore.
    Every write is a SECURITY DEFINER RPC (`eg_heartbeat`, `eg_report_suspend`,
    `eg_authorized_stop`) that stamps `last_heartbeat = now()` itself -- the
    SERVER's clock, never anything the client submits -- so a local admin
    reading this key can't forge a future timestamp to silence gone-dark, or
    set `status='clean_shutdown'` without passing `eg_authorized_stop`'s
    password check.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .net import opener as _opener

_NS = uuid.UUID("e7e9f1c0-0000-4000-8000-eeeeeeeeeeee")  # stable namespace


def _score(reason: str) -> float | None:
    m = re.search(r"clip-(?:red|yellow):([0-9.]+)", reason or "")
    if m:
        return float(m.group(1))
    m = re.search(r"=([0-9.]+)", reason or "")
    return float(m.group(1)) if m else None


class SupabaseUploader:
    def __init__(self, url: str, api_key: str, pending_path: str,
                 retry_seconds: int = 60, heartbeat: bool = True,
                 encryption_public_key_pem: str | None = None):
        self.base = url.rstrip("/")
        self.api_key = api_key
        self.pending_path = Path(pending_path)
        self.retry_seconds = retry_seconds
        self.heartbeat = heartbeat
        # When set, review-frame bytes are encrypted (see frame_crypto.py)
        # before they ever leave this process -- what lands in Storage is
        # opaque ciphertext, viewable only by whoever holds the matching
        # private key (never this device). None = upload as plain JPEG,
        # same as before this existed.
        self.encryption_public_key_pem = encryption_public_key_pem
        self._suspended = False  # True between sleep/power-off and wake
        self._status_provider = None  # returns {screen_ok, frames_analyzed}
        self._heartbeat_failing = False  # logged on first failure + recovery only
        self._resumed_at = 0.0  # time.time() of the last resume() call
        self._display_asleep = False  # True for the WHOLE duration the display
        # is off (NSWorkspaceScreensDidSleepNotification -> DidWake), not just
        # the short post-wake grace window recently_resumed() covers -- see
        # note_screen_asleep()'s own docstring.
        self._lock = threading.Lock()          # guards the pending file
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---- public API ---------------------------------------------------------

    def start(self):
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def set_status_provider(self, fn):
        """fn() -> {"screen_ok": bool, "frames_analyzed": int}. Stamped onto each
        heartbeat so the server can alert if the agent goes blind or stalls."""
        self._status_provider = fn

    def enqueue(self, record: dict):
        """Append a flag record to the persistent queue and wake the worker."""
        with self._lock:
            with self.pending_path.open("a") as f:
                f.write(json.dumps(record) + "\n")
        self._wake.set()

    def report_tamper(self, detail: str):
        """Record a tamper/system event (e.g. the local log was deleted) as an
        imageless flag row. It's append-only so it can't be erased, and it fires
        the tamper alert email. Goes through the reliable queue (retries offline)."""
        self.enqueue({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verdict": "flagged",
            "reason": f"tamper: {detail}",
            "app": "EyeGuard",
            "url": None,
            "window_title": "local log tamper detected",
            "grade": "Likely",
            "risk": "high",
            "no_image": True,
        })

    # Cloud image retention runs SERVER-SIDE (pg_cron, as postgres -- outside
    # the API entirely). The agent itself never deletes cloud images: uploads
    # go through the anon key's insert-only Storage RLS policy (see
    # _put_image), which is what actually prevents deleting/overwriting them.

    # ---- worker -------------------------------------------------------------

    def _log_diag(self, msg: str):
        """Append a timestamped line to agent_diagnostic.log (same file
        menubar.py's own _log_diag() writes the screen-probe lines to, same
        directory pending_path already lives in post the 2026-08-27
        pending_file fix). Confirmed live (2026-08-31): the plist defines no
        stdout/stderr path at all -- like the frozen-probe gap this same
        file already closed once before -- so _heartbeat_ok()/_failed()'s
        bare print() calls below were going nowhere, making a real spike of
        'monitoring went dark' alerts undiagnosable after the fact (no way
        to tell DNS error vs timeout vs something else). Best-effort: a
        failure here must never break the heartbeat loop trying to report
        through it."""
        try:
            with (self.pending_path.parent / "agent_diagnostic.log").open("a") as f:
                f.write(f"{datetime.now().isoformat()} {msg}\n")
        except Exception:
            pass

    def _heartbeat_ok(self):
        if self._heartbeat_failing:
            self._log_diag("heartbeat recovered")
            print(f"[uploader] {datetime.now().isoformat()} heartbeat recovered",
                  flush=True)
            self._heartbeat_failing = False

    def _heartbeat_failed(self, e: Exception, context: str):
        # Logged only on the FIRST failure and again on recovery -- a sustained
        # outage would otherwise print once per retry_seconds forever. This is
        # the only local trail a missed heartbeat ("gone dark") leaves; before
        # this, the exception was swallowed entirely and a real outage was
        # indistinguishable, after the fact, from no attempt having been made.
        # Timestamped so a later alert email can actually be correlated to a
        # specific line here instead of just "somewhere in this log".
        if not self._heartbeat_failing:
            self._log_diag(f"heartbeat FAILING ({context}): "
                            f"{type(e).__name__}: {e} -- retrying every "
                            f"{self.retry_seconds}s, next line is on recovery")
            print(f"[uploader] {datetime.now().isoformat()} heartbeat FAILING "
                  f"({context}): {type(e).__name__}: {e} -- retrying every "
                  f"{self.retry_seconds}s, next log line is on recovery",
                  flush=True)
            self._heartbeat_failing = True

    def _worker(self):
        # Pulse once right away so "last seen" is fresh the moment we start.
        if self.heartbeat:
            try:
                self.send_heartbeat()
                self._heartbeat_ok()
            except Exception as e:
                self._heartbeat_failed(e, "startup pulse")
        while not self._stop.is_set():
            # Heartbeat FIRST, flush second -- confirmed live (2026-09-01):
            # each upload is its own fresh TCP+TLS connection (~1.3s, no
            # connection reuse), and _flush() processes the ENTIRE pending
            # backlog sequentially. With a real backlog of 270 records that's
            # ~5.7 minutes for one flush cycle -- comfortably longer than
            # eg_check_gone_dark()'s 3-minute threshold. Heartbeat used to
            # run AFTER flush, so a big backlog directly delayed the one
            # signal that keeps "monitoring went dark" from firing -- a real
            # structural bug, not network flakiness (zero heartbeat
            # exceptions were ever logged; the calls just weren't happening
            # in time). This reorder means the accountability signal is
            # never held hostage behind a backlog of ordinary activity
            # uploads -- _flush() itself is also now capped per cycle (see
            # its own docstring) as defense in depth.
            if self.heartbeat:
                try:
                    if self._suspended:
                        self._send_suspend_beacon()
                    else:
                        self.send_heartbeat()
                    self._heartbeat_ok()
                except Exception as e:
                    self._heartbeat_failed(e, "worker loop")
            try:
                self._flush()
            except Exception:
                pass  # never let the uploader crash the app
            self._wake.wait(self.retry_seconds)
            self._wake.clear()

    def suspend(self):
        """Mac going to sleep / shutting down normally: beacon a clean state so
        the gone-dark watchdog stays quiet, and keep pulses clean until resumed.
        (A MANUAL stop sends no beacon at all, so disabling the monitor still
        alerts — the clean beacon only fires on real sleep/power-off events.)
        Not password-gated (routine sleep shouldn't need a password prompt) --
        see supabase/anon_client_pivot.sql's eg_report_suspend() docstring for
        the accepted residual this implies."""
        self._suspended = True
        try:
            self._send_suspend_beacon()
            self._heartbeat_ok()
        except Exception as e:
            self._heartbeat_failed(e, "suspend beacon")

    def resume(self):
        """Mac woke: back to alive (also clears the gone-dark `alerted` flag)."""
        self._suspended = False
        self._resumed_at = time.time()
        try:
            self.send_heartbeat()
            self._heartbeat_ok()
        except Exception as e:
            self._heartbeat_failed(e, "resume beacon")

    def note_screen_resumed(self):
        """Display-only wake (NSWorkspaceScreensDidWakeNotification, not a
        full system resume) -- see menubar.py's _register_power_observers()
        docstring for the full reasoning. Confirmed live (2026-09-02): 4
        real 'lost view of the screen' false alarms in one night, none
        within recently_resumed()'s grace window of an actual SYSTEM wake
        (that part already confirmed working) -- these were the display
        blanking on its own idle timer while the Mac stayed fully awake,
        which NSWorkspaceWillSleep/DidWake never fire for at all.
        Deliberately does NOT set self._suspended or send any beacon -- the
        Mac was never actually offline, the normal heartbeat loop kept
        running the whole time; this only extends the same grace window
        recently_resumed() already uses for real wakes, so a capture
        briefly seeing a blank/black display during the display-sleep
        transition doesn't get misread as a real blind condition."""
        self._resumed_at = time.time()
        self._display_asleep = False

    def note_screen_asleep(self):
        """Display-only sleep start (NSWorkspaceScreensDidSleepNotification)
        -- the missing other half of note_screen_resumed()'s pair (2026-09-03).
        recently_resumed()'s grace window only covers the first ~2 minutes
        AFTER waking; it does nothing for the sleep itself, which routinely
        runs much longer (a real ~14-minute display sleep alerted 'lost view
        of the screen' after the 2026-09-02 debounce fix, confirmed via
        agent_diagnostic.log cross-referenced against the probe's own
        frozen-since-19:48/woke-at-20:02 timestamps). Nothing risky can
        happen on a screen that's off, same reasoning already applied to the
        phone (phone_unlock_active_use_signal.sql) and to session_watcher's
        own IOKit sleep-awareness -- so screen_ok=false is simply not
        reported at all for the whole sleep duration, reserving the alert
        for when the Mac is actually awake and in use but capture is
        genuinely broken, which is the only case that matters."""
        self._display_asleep = True

    def authorized_stop(self, password: str) -> bool:
        """Ask the server to verify `password` and, only if correct, set
        status='clean_shutdown' -- one atomic RPC call (eg_authorized_stop),
        replacing the old two-call check-then-beacon sequence, which had a
        real gap: nothing tied the two together, so a direct POST with the
        old secret key could set the clean-shutdown status without ever
        passing the password check. Returns True iff the password was
        correct and the beacon was set; False on a wrong password OR the
        server-side lockout (5 wrong attempts / 15 min, tracked in
        `settings`, immune to a local reset no matter what key you hold)."""
        req = urllib.request.Request(
            f"{self.base}/rest/v1/rpc/eg_authorized_stop",
            data=json.dumps({"pw": password}).encode(), method="POST",
            headers=self._headers({"Content-Type": "application/json"}))
        with _opener.open(req, timeout=15) as r:
            return json.loads(r.read().decode()) is True

    def recently_resumed(self, grace_seconds: int = 120) -> bool:
        """True for a window after resume() -- the session agent is frozen
        for the ENTIRE sleep duration (unlike this daemon, which IOKit can
        wake right at the boundary), so its last-contact timestamp is stale
        by however long the sleep lasted the instant we wake. Without this,
        resume()'s own immediate "alive" heartbeat would carry a false
        screen_ok=false (the daemon's own staleness check has no way to tell
        "genuinely blind" from "just hasn't reconnected yet") -- confirmed
        live: this fired a real 'lost view of the screen' alert on ordinary
        wake, every time, since the agent's actual catch-up window
        (comfortably under agent_timeout once it resumes) is not
        distinguishable from the sleep-induced staleness that preceded it."""
        return time.time() - self._resumed_at < grace_seconds

    def send_heartbeat(self):
        """Calls eg_heartbeat() -- the ONLY way status='alive' +
        last_heartbeat gets set. The RPC signature has no timestamp
        parameter at all, so there is nothing for the client to forge; the
        server's own now() is the only value ever written."""
        params: dict = {}
        if self._status_provider is not None:
            try:
                extra = self._status_provider() or {}
                if "screen_ok" in extra:
                    screen_ok = bool(extra["screen_ok"])
                    # Confirmed live (2026-08-29): recently_resumed() was
                    # defined but never actually called anywhere -- dead
                    # code since the admin-trust pivot deleted the old
                    # vault.py this was originally written for. Result: a
                    # real 'lost view of the screen' alert fired on ordinary
                    # wake (timing matched agent_diagnostic.log's own frozen-
                    # probe recovery to the second). Omit the key entirely
                    # during the grace window rather than forcing True --
                    # eg_heartbeat()'s coalesce(p_screen_ok, screen_ok) then
                    # just keeps whatever was last reported (almost always
                    # True, from before sleep) instead of asserting a value
                    # this process doesn't actually know yet.
                    # Omit p_screen_ok entirely (rather than forcing True)
                    # during the post-wake grace window OR while the display
                    # is currently, legitimately asleep -- eg_heartbeat()'s
                    # coalesce(p_screen_ok, screen_ok) then just keeps
                    # whatever was last reported instead of asserting a
                    # value this process doesn't actually know yet, or
                    # reporting a "problem" that isn't one. See
                    # note_screen_asleep()'s docstring for why the sleep
                    # itself (not just the post-wake catch-up) needs this.
                    if not (screen_ok is False and
                            (self.recently_resumed() or self._display_asleep)):
                        params["p_screen_ok"] = screen_ok
                if "frames_analyzed" in extra:
                    params["p_frames_analyzed"] = int(extra["frames_analyzed"])
                if "detector_ok" in extra:
                    params["p_detector_ok"] = bool(extra["detector_ok"])
            except Exception:
                pass
        self._rpc("eg_heartbeat", params)

    def _send_suspend_beacon(self):
        self._rpc("eg_report_suspend", {})

    def _rpc(self, name: str, params: dict):
        req = urllib.request.Request(
            f"{self.base}/rest/v1/rpc/{name}", data=json.dumps(params).encode(),
            method="POST",
            headers=self._headers({"Content-Type": "application/json"}))
        with _opener.open(req, timeout=15) as r:
            r.read()

    # Each upload is its own fresh TCP+TLS connection (~1.3s, confirmed live
    # 2026-09-01 -- no connection reuse across calls) -- an unbounded flush
    # against a real backlog (270 records observed live) takes minutes in
    # one call. Heartbeat now runs before flush (see _worker()) so a slow
    # flush can no longer delay it, but a multi-minute-long single call is
    # still bad for responsiveness generally -- this caps how much one
    # _flush() call processes, so a big backlog drains gradually over
    # several retry_seconds-spaced cycles (each starting with a fresh
    # heartbeat) instead of in one long blocking pass.
    _MAX_PER_FLUSH = 25

    def _flush(self):
        with self._lock:
            if not self.pending_path.exists():
                return
            lines = [l for l in self.pending_path.read_text().splitlines()
                     if l.strip()]
        if not lines:
            return
        batch = lines[:self._MAX_PER_FLUSH]
        sent_lines: list[str] = []
        for line in batch:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                sent_lines.append(line)       # malformed -> drop, same as before
                continue
            try:
                sent = self._upload(rec)      # True = done (sent or dropped)
            except urllib.error.URLError:
                sent = False                  # offline -> keep for retry
            except Exception:
                sent = False                  # transient server error -> retry
            if sent:
                sent_lines.append(line)
        if not sent_lines:
            return
        # Re-read the CURRENT file rather than blindly overwriting with what
        # was in-memory before the (potentially slow) upload loop ran --
        # enqueue() may have appended new lines while this batch was
        # uploading (lock only held for the read above and the write below,
        # not across the network calls in between, so this window is real).
        # Removing exactly the sent lines from a fresh read means a record
        # enqueued mid-flush can never be silently dropped by this write-back.
        with self._lock:
            if not self.pending_path.exists():
                return
            current = [l for l in self.pending_path.read_text().splitlines()
                       if l.strip()]
            # Remove exactly len(sent_lines) copies of each distinct sent
            # line, not just "any line matching this content" -- two records
            # can legitimately be byte-identical (e.g. two "activity" pulses
            # for the same app in the same second), and removing without
            # counting could drop more of them than were actually sent.
            to_remove = Counter(sent_lines)
            remaining = []
            for l in current:
                if to_remove.get(l, 0) > 0:
                    to_remove[l] -= 1
                else:
                    remaining.append(l)
            tmp = self.pending_path.with_suffix(".tmp")
            tmp.write_text("\n".join(remaining) + ("\n" if remaining else ""))
            tmp.replace(self.pending_path)

    # ---- one record ---------------------------------------------------------

    def _upload(self, rec: dict) -> bool:
        """Upload one record. Returns True when done (or when it can never
        complete, so we stop retrying)."""
        # GREEN activity records + tamper/system events are intentionally
        # imageless — just insert the row. The "no alert without an image" rule
        # applies only to real detected FLAGS, which must carry a review frame.
        if rec.get("verdict") == "clear" or rec.get("no_image"):
            self._post_row(self._row(rec, None))             # raises on failure
            return True
        local = rec.get("saved_frame")
        if not local or not Path(local).exists():
            return True  # flag with no image -> no alert; drop from queue
        data = Path(local).read_bytes()
        remote = Path(local).name
        if self.encryption_public_key_pem:
            # Encrypt BEFORE this process ever hands the bytes to the network
            # -- what lands in Storage is opaque ciphertext, not a viewable
            # JPEG, so a data breach or anyone holding the anon key can't see
            # actual frame content, only whoever holds the private key
            # (never this device -- see eyeguard/frame_crypto.py).
            from .frame_crypto import encrypt_frame
            data = encrypt_frame(data, self.encryption_public_key_pem)
            remote += ".enc"
        self._put_image(remote, data)                         # raises on failure
        self._post_row(self._row(rec, remote))               # raises on failure
        return True

    def _row(self, rec: dict, remote_path: str) -> dict:
        seed = f"{rec.get('timestamp')}|{rec.get('reason')}|{rec.get('display')}"
        return {
            "id": str(uuid.uuid5(_NS, seed)),   # deterministic -> idempotent
            "flagged_at": rec.get("timestamp"),
            "verdict": rec.get("verdict"),
            "is_nudity": bool((rec.get("reason") or "").startswith("nudenet")),
            "grade": rec.get("grade"),
            "risk": rec.get("risk"),
            "app": rec.get("app"),
            "url": rec.get("url"),
            "window_title": rec.get("window_title"),
            "reason": rec.get("reason"),
            "score": _score(rec.get("reason", "")),
            "image_path": remote_path,
        }

    # ---- HTTP (urllib, no extra deps) ---------------------------------------

    def _headers(self, extra: dict | None = None) -> dict:
        h = {"apikey": self.api_key, "Authorization": f"Bearer {self.api_key}"}
        if extra:
            h.update(extra)
        return h

    def _put_image(self, remote_path: str, data: bytes):
        # Insert-only on the 'frames' bucket via RLS (no update/delete policy
        # exists for anon), so this key can create an image but never
        # overwrite or erase one. A 409 means it already exists (an earlier
        # attempt succeeded) -> fine.
        content_type = ("application/octet-stream"
                        if remote_path.endswith(".enc") else "image/jpeg")
        url = f"{self.base}/storage/v1/object/frames/{remote_path}"
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers=self._headers({"Content-Type": content_type}))
        try:
            with _opener.open(req, timeout=20) as r:
                r.read()
        except urllib.error.HTTPError as e:
            if e.code == 409:  # already uploaded on a previous attempt
                return
            raise

    def _post_row(self, row: dict):
        # ignore-duplicates (ON CONFLICT DO NOTHING) keeps retries idempotent
        # using only INSERT — no UPDATE — so the flags table can be locked
        # append-only (Phase 4): the agent can never alter or delete a flag.
        url = f"{self.base}/rest/v1/flags"
        req = urllib.request.Request(
            url, data=json.dumps(row).encode(), method="POST",
            headers=self._headers({
                "Content-Type": "application/json",
                "Prefer": "resolution=ignore-duplicates,return=minimal"}))
        with _opener.open(req, timeout=20) as r:
            r.read()
