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

The sb_secret key (read from a local file, never in code/config) is used for
the flags/device_status tables, where it bypasses RLS but a direct REVOKE on
those tables still holds (confirmed: append-only survives even service_role).

Image uploads are the one exception: Supabase's Storage API does NOT honor a
REVOKE against service_role the way /rest/v1/ table access does (confirmed
live 2026-08-05 — DELETE/UPDATE via the secret key still succeeded even after
`revoke delete, update on storage.objects from service_role`). So image
uploads instead use the PUBLIC anon/publishable key, for which Storage DOES
enforce RLS — an insert-only policy on the 'frames' bucket (no update/delete
policy exists for anon) means the key can create evidence but never alter or
erase it, closing the gap the secret key couldn't close for storage.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

_NS = uuid.UUID("e7e9f1c0-0000-4000-8000-eeeeeeeeeeee")  # stable namespace

# ---- route every HTTPS call off the system default route -----------------
# The default route is often an on-demand VPN tunnel (confirmed live
# 2026-08-17: scutil flags it "Transient Connection", and it was caught
# mid-DNS-resolution-failure during a real gone-dark investigation). This
# Mac's own network state shouldn't be able to interrupt the accountability
# channel, so every request below binds to the physical interface directly
# via IP_BOUND_IF, independent of whatever the tunnel is doing at that
# moment. IP_BOUND_IF=25, confirmed from this machine's own
# /usr/include/netinet/in.h (not guessed/copied from docs).
_IP_BOUND_IF = 25


def _physical_interface() -> str | None:
    """First non-tunnel interface in macOS's own priority order (scutil
    --nwi's own "Network interfaces:" line -- the same list macOS itself
    uses to pick the default route), or None if none found. Re-checked on
    every connection attempt (not cached) since the active interface can
    change -- Wi-Fi<->Ethernet, docking -- while this process runs for days.
    Never raises: a scutil hiccup should fall back to default routing, not
    break every request."""
    try:
        out = subprocess.run(["scutil", "--nwi"], capture_output=True,
                              text=True, timeout=5).stdout
    except Exception:
        return None
    for line in out.splitlines():
        if line.startswith("Network interfaces:"):
            for name in line.split(":", 1)[1].split():
                if not name.startswith(("utun", "ppp", "ipsec", "awdl")):
                    return name
    return None


class _BoundHTTPSConnection(http.client.HTTPSConnection):
    """Binds to the physical interface before connecting, so this request's
    route is independent of the system default route. Falls back to normal
    (default-route-following) behavior if no physical interface is found or
    the bind/connect itself fails -- this can only ever ADD a more reliable
    path, never remove the one that already existed before this."""

    def connect(self):
        iface = _physical_interface()
        if not iface:
            super().connect()
            return
        try:
            ifindex = socket.if_nametoindex(iface)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_IP, _IP_BOUND_IF, ifindex)
            if self.timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except OSError:
            super().connect()  # bind/connect on the physical interface failed


class _BoundHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_BoundHTTPSConnection, req)


_opener = urllib.request.build_opener(_BoundHTTPSHandler)


def _score(reason: str) -> float | None:
    m = re.search(r"clip-(?:red|yellow):([0-9.]+)", reason or "")
    if m:
        return float(m.group(1))
    m = re.search(r"=([0-9.]+)", reason or "")
    return float(m.group(1)) if m else None


class SupabaseUploader:
    def __init__(self, url: str, secret: str, pending_path: str,
                 retry_seconds: int = 60, heartbeat: bool = True,
                 publishable_key: str | None = None):
        self.base = url.rstrip("/")
        self.secret = secret
        # Falls back to the secret key if no publishable key is configured
        # (old configs) -- logs so a missing key doesn't silently reopen the
        # storage-deletion gap without anyone noticing.
        self.publishable_key = publishable_key or secret
        if not publishable_key:
            print("[uploader] WARNING: no supabase.publishable_key configured "
                  "-- image uploads are falling back to the secret key, which "
                  "reopens the storage delete/overwrite gap. Set "
                  "publishable_key in config.yaml.", flush=True)
        self.pending_path = Path(pending_path)
        self.retry_seconds = retry_seconds
        self.heartbeat = heartbeat
        self._suspended = False  # True between sleep/power-off and wake
        self._status_provider = None  # returns {screen_ok, frames_analyzed}
        self._heartbeat_failing = False  # logged on first failure + recovery only
        self._resumed_at = 0.0  # time.time() of the last resume() call
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
    # the API entirely, so it's unaffected by the anon/secret key distinction
    # above). The agent itself never deletes cloud images: uploads go through
    # the anon key's insert-only Storage RLS policy (see _put_image), which is
    # what actually prevents the agent from deleting/overwriting them -- the
    # secret key alone was NOT sufficient for this (see module docstring).

    # ---- worker -------------------------------------------------------------

    def _heartbeat_ok(self):
        if self._heartbeat_failing:
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
            print(f"[uploader] {datetime.now().isoformat()} heartbeat FAILING "
                  f"({context}): {type(e).__name__}: {e} -- retrying every "
                  f"{self.retry_seconds}s, next log line is on recovery",
                  flush=True)
            self._heartbeat_failing = True

    def _worker(self):
        # Pulse once right away so "last seen" is fresh the moment we start.
        if self.heartbeat:
            try:
                self.send_heartbeat("alive")
                self._heartbeat_ok()
            except Exception as e:
                self._heartbeat_failed(e, "startup pulse")
        while not self._stop.is_set():
            try:
                self._flush()
            except Exception:
                pass  # never let the uploader crash the app
            if self.heartbeat:
                try:
                    self.send_heartbeat(
                        "clean_shutdown" if self._suspended else "alive")
                    self._heartbeat_ok()
                except Exception as e:
                    self._heartbeat_failed(e, "worker loop")
            self._wake.wait(self.retry_seconds)
            self._wake.clear()

    def suspend(self):
        """Mac going to sleep / shutting down normally: beacon a clean state so
        the gone-dark watchdog stays quiet, and keep pulses clean until resumed.
        (A MANUAL stop sends no beacon at all, so disabling the monitor still
        alerts — the clean beacon only fires on real sleep/power-off events.)"""
        self._suspended = True
        try:
            self.send_heartbeat("clean_shutdown")
            self._heartbeat_ok()
        except Exception as e:
            self._heartbeat_failed(e, "suspend beacon")

    def resume(self):
        """Mac woke: back to alive (also clears the gone-dark `alerted` flag)."""
        self._suspended = False
        self._resumed_at = time.time()
        try:
            self.send_heartbeat("alive")
            self._heartbeat_ok()
        except Exception as e:
            self._heartbeat_failed(e, "resume beacon")

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

    def send_heartbeat(self, status: str = "alive"):
        """Upsert the single device_status row. status='alive' also clears the
        `alerted` flag so a future outage can fire a fresh alert; a clean
        shutdown sets status='clean_shutdown' so it doesn't false-alarm."""
        now = datetime.now(timezone.utc).isoformat()
        core = {"id": 1, "last_heartbeat": now, "status": status,
                "updated_at": now}
        if status == "alive":
            core["alerted"] = False
        row = dict(core)
        if self._status_provider is not None:
            try:
                extra = self._status_provider() or {}
                if "screen_ok" in extra:
                    row["screen_ok"] = bool(extra["screen_ok"])
                if "frames_analyzed" in extra:
                    row["frames_analyzed"] = int(extra["frames_analyzed"])
                if "detector_ok" in extra:
                    row["detector_ok"] = bool(extra["detector_ok"])
            except Exception:
                pass
        try:
            self._post_status(row)
        except urllib.error.HTTPError:
            # A missing optional column (schema not migrated yet) must never
            # break the heartbeat — retry with just the core fields, so a fresh
            # deploy can't false-trip gone-dark before its SQL is run.
            self._post_status(core)

    def _post_status(self, row: dict):
        req = urllib.request.Request(
            f"{self.base}/rest/v1/device_status", data=json.dumps(row).encode(),
            method="POST",
            headers=self._headers({
                "Content-Type": "application/json",
                "Prefer": "resolution=merge-duplicates,return=minimal"}))
        with _opener.open(req, timeout=15) as r:
            r.read()

    def _flush(self):
        with self._lock:
            if not self.pending_path.exists():
                return
            lines = [l for l in self.pending_path.read_text().splitlines()
                     if l.strip()]
        if not lines:
            return
        remaining: list[str] = []
        for line in lines:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue  # drop malformed
            try:
                sent = self._upload(rec)      # True = done (sent or dropped)
            except urllib.error.URLError:
                sent = False                  # offline -> keep for retry
            except Exception:
                sent = False                  # transient server error -> retry
            if not sent:
                remaining.append(line)
        with self._lock:
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
        remote = Path(local).name
        self._put_image(remote, Path(local).read_bytes())    # raises on failure
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
        h = {"apikey": self.secret, "Authorization": f"Bearer {self.secret}"}
        if extra:
            h.update(extra)
        return h

    def _anon_headers(self, extra: dict | None = None) -> dict:
        h = {"apikey": self.publishable_key,
             "Authorization": f"Bearer {self.publishable_key}"}
        if extra:
            h.update(extra)
        return h

    def _put_image(self, remote_path: str, data: bytes):
        # Anon key, not the secret: Storage RLS grants anon INSERT-only on the
        # 'frames' bucket (no update/delete policy exists for anon), so this
        # key can create an image but never overwrite or erase one -- unlike
        # the secret key, which Storage lets bypass a REVOKE entirely (see
        # module docstring). A 409 means it already exists (an earlier attempt
        # succeeded) -> fine.
        url = f"{self.base}/storage/v1/object/frames/{remote_path}"
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers=self._anon_headers({"Content-Type": "image/jpeg"}))
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
