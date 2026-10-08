#!/usr/bin/env python3
"""NanoMDM webhook receiver for the app-install notifier (2026-10-03).

NanoMDM POSTs every check-in and command result here. This keeps:
  state/devices.json   enrolled devices (udid -> name, enrolled/checked-out, last_seen)
  state/results/<uuid>.json  outcome of commands the poller sent (pending-cmds.json)
and writes one JSON file per event into state/outbox/ for poll.py to deliver to EyeGuard.
Each app list becomes ONE app_snapshot event; the server diffs it against the official
list (no baseline is kept here).
Stdlib only. Listens on :8080 inside the private docker network (never published).
"""
import base64, json, os, plistlib, sys, time, uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock

STATE = os.environ.get("HOOK_STATE", "/state")
OUTBOX = os.path.join(STATE, "outbox")
LOCK = Lock()


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load(name, default):
    p = os.path.join(STATE, name)
    for cand in (p, p + ".bak"):        # fall back to the last good copy if the file is empty/corrupt
        try:
            with open(cand) as f:
                data = json.load(f)
            if cand != p:
                print(f"[hook] WARNING {name} was unreadable; using the last good copy", flush=True)
            return data
        except FileNotFoundError:
            continue
        except json.JSONDecodeError:
            print(f"[hook] ERROR {os.path.basename(cand)} is empty or corrupt", flush=True)
            continue
    return default


def save(name, data):
    p = os.path.join(STATE, name)
    try:                                # keep the previous good copy for recovery
        if os.path.getsize(p) > 0:
            import shutil
            shutil.copyfile(p, p + ".bak")
    except OSError:
        pass
    tmp = p + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(data, f, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def emit(event):
    os.makedirs(OUTBOX, exist_ok=True)
    name = f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}.json"
    with open(os.path.join(OUTBOX, name + ".tmp"), "w") as f:
        json.dump(event, f)
    os.replace(os.path.join(OUTBOX, name + ".tmp"), os.path.join(OUTBOX, name))
    print(f"[hook] {now_iso()} event {event['type']} {event.get('bundle_id', '')}", flush=True)


def touch_device(udid, **fields):
    devices = load("devices.json", {})
    d = devices.setdefault(udid, {"name": "Jonah iPhone", "enrolled": True})
    d.update(fields)
    d["last_seen"] = now_iso()
    save("devices.json", devices)
    return d


def handle_checkin(ev):
    udid = ev.get("udid")
    mt = ev.get("message_type") or ev.get("topic", "")
    if not udid:
        return
    if "CheckOut" in mt:
        # unreachable_reported=True so the first ack after re-enrolment emits
        # device_reachable_again; without it the server's once-per-outage debounce
        # (mdm_status.unreachable_alerted) is never re-armed and the NEXT real
        # outage would be logged but not emailed.
        touch_device(udid, enrolled=False, checked_out_at=now_iso(), unreachable_reported=True)
        emit({"type": "device_unreachable", "detected_at": now_iso(), "device": "Jonah iPhone",
              "reason": "MDM profile removed from the device (CheckOut)"})
    elif "Authenticate" in mt:
        # Authenticate is sent only when the MDM profile is (re)installed. If this phone is
        # already known, the profile was removed (or the phone erased) and put back. Going
        # offline first means no CheckOut was ever sent, so this is the only signal there is,
        # however short the gap was.
        known = load("devices.json", {}).get(udid)
        d = touch_device(udid, enrolled=True)
        if known:
            emit({"type": "device_reenrolled", "detected_at": now_iso(), "device": d["name"],
                  "reason": "MDM profile installed again on a phone that was already enrolled"})
    elif "TokenUpdate" in mt:
        touch_device(udid, enrolled=True)


def record_result(cmd_uuid, status, pl):
    """Outcome of a command the POLLER sent (it lists them in pending-cmds.json).
    Written to results/<uuid>.json for the poller to report. NotNow/Idle are not
    outcomes (the device was busy; MDM redelivers). No app data is stored."""
    if not cmd_uuid or status not in ("Acknowledged", "Error", "CommandFormatError"):
        return
    if cmd_uuid not in load("pending-cmds.json", {}):
        return
    parts = []
    for e in (pl.get("ErrorChain") or [])[:3]:
        parts.append(f"{e.get('ErrorCode', '?')}: {str(e.get('USEnglishDescription') or e.get('LocalizedDescription') or '')[:100]}")
    os.makedirs(os.path.join(STATE, "results"), exist_ok=True)
    save(os.path.join("results", f"{cmd_uuid}.json"),
         {"uuid": cmd_uuid, "status": status, "error": "; ".join(parts)[:300]})


def handle_ack(ev):
    udid = ev.get("udid")
    raw = ev.get("raw_payload")
    if not udid or not raw:
        return
    try:
        pl = plistlib.loads(base64.b64decode(raw))
    except Exception as e:
        print(f"[hook] bad payload: {e}", flush=True)
        return
    devices = load("devices.json", {})
    was_unreachable = devices.get(udid, {}).get("unreachable_reported")
    d = touch_device(udid)
    if was_unreachable:
        d = touch_device(udid, unreachable_reported=False)
        emit({"type": "device_reachable_again", "detected_at": now_iso(), "device": d["name"]})
    status = pl.get("Status") or ev.get("status")
    record_result(ev.get("command_uuid") or pl.get("CommandUUID"), status, pl)
    qr = pl.get("QueryResponses")
    if isinstance(qr, dict) and "IsSupervised" in qr:
        d = touch_device(udid, supervised=bool(qr["IsSupervised"]))
    if pl.get("Status") != "Acknowledged" or "InstalledApplicationList" not in pl:
        return
    apps = []
    for a in pl["InstalledApplicationList"]:
        bid = a.get("Identifier")
        if bid:
            apps.append({"bundle_id": bid, "name": a.get("Name") or bid,
                         "version": a.get("ShortVersion") or a.get("Version") or ""})
    if not apps:          # a real phone always has apps; never send (or trust) an empty list
        print(f"[hook] {now_iso()} empty app list ignored", flush=True)
        return
    t = now_iso()
    # The SERVER owns the official list and does the diff; the G11 only relays what
    # is installed. (Previously the baseline lived in apps-<udid>.json here, and
    # losing that file silently re-baselined.)
    emit({"type": "app_snapshot", "detected_at": t, "device": d["name"],
          "supervised": d.get("supervised"), "apps": apps})
    touch_device(udid, last_apps_at=t, app_count=len(apps))


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(n, 8 * 1024 * 1024))
        self.send_response(200)
        self.end_headers()
        try:
            ev = json.loads(body)
        except json.JSONDecodeError:
            return
        with LOCK:
            try:
                if ev.get("checkin_event"):
                    c = ev["checkin_event"]
                    c.setdefault("message_type", ev.get("topic", ""))
                    handle_checkin(c)
                if ev.get("acknowledge_event"):
                    handle_ack(ev["acknowledge_event"])
            except Exception as e:
                print(f"[hook] error: {e!r}", file=sys.stderr, flush=True)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    os.makedirs(OUTBOX, exist_ok=True)
    print(f"[hook] {now_iso()} listening on :8080", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
