#!/usr/bin/env python3
"""NanoMDM webhook receiver for the app-install notifier (2026-10-03).

NanoMDM POSTs every check-in and command result here. This keeps:
  state/devices.json   enrolled devices (udid -> name, enrolled/checked-out, last_seen)
  state/apps-<udid>.json  last known installed-app list
and writes one JSON file per event into state/outbox/ for poll.sh to deliver to EyeGuard.
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
    try:
        with open(os.path.join(STATE, name)) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save(name, data):
    p = os.path.join(STATE, name)
    with open(p + ".tmp", "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.replace(p + ".tmp", p)


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
        touch_device(udid, enrolled=False, checked_out_at=now_iso())
        emit({"type": "device_unreachable", "detected_at": now_iso(), "device": "Jonah iPhone",
              "reason": "MDM profile removed from the device (CheckOut)"})
    elif "Authenticate" in mt or "TokenUpdate" in mt:
        touch_device(udid, enrolled=True)


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
    prev_seen = devices.get(udid, {}).get("last_apps_at")
    was_unreachable = devices.get(udid, {}).get("unreachable_reported")
    d = touch_device(udid)
    if was_unreachable:
        d = touch_device(udid, unreachable_reported=False)
        emit({"type": "device_reachable_again", "detected_at": now_iso(), "device": d["name"]})
    if pl.get("Status") != "Acknowledged" or "InstalledApplicationList" not in pl:
        return
    apps = {}
    for a in pl["InstalledApplicationList"]:
        bid = a.get("Identifier")
        if bid:
            apps[bid] = {"name": a.get("Name") or bid,
                         "version": a.get("ShortVersion") or a.get("Version") or ""}
    key = f"apps-{udid}.json"
    old = load(key, None)
    t = now_iso()
    if old is None:
        print(f"[hook] {t} baseline: {len(apps)} apps", flush=True)
    else:
        for bid in sorted(set(apps) - set(old)):
            emit({"type": "app_installed", "detected_at": t, "window_start": prev_seen or t,
                  "device": d["name"], "name": apps[bid]["name"], "bundle_id": bid,
                  "version": apps[bid]["version"]})
        for bid in sorted(set(old) - set(apps)):
            emit({"type": "app_removed", "detected_at": t, "window_start": prev_seen or t,
                  "device": d["name"], "name": old[bid]["name"], "bundle_id": bid,
                  "version": old[bid]["version"]})
    save(key, apps)
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
