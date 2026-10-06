#!/usr/bin/env python3
"""App-install notifier poller (cron */15 on the G11, 2026-10-03).

1. Asks every enrolled device for InstalledApplicationList via the NanoMDM API (with push).
   Results come back through the webhook (hook.py), which diffs and writes events.
2. Reports a device as unreachable once if no app list arrived for UNREACHABLE_AFTER.
3. Delivers queued events to EyeGuard via SENDER (defined by the EyeGuard repo).
   Until SENDER exists, events stay queued in outbox/ and nothing is lost.
"""
import json, os, ssl, subprocess, sys, time, urllib.request, uuid, base64
from datetime import datetime, timezone, timedelta

STATE = "/opt/stack/mdm/hook-state"
OUTBOX = os.path.join(STATE, "outbox")
SENT = os.path.join(STATE, "sent")
SENDER = "/opt/kev/mdm/eg-report.sh"
API = "https://mdm.orthanc.me/v1"
UNREACHABLE_AFTER = timedelta(hours=2)
LOG = "/opt/kev/mdm/poll.log"


def log(msg):
    with open(LOG, "a") as f:
        f.write(f"{datetime.now().isoformat(timespec='seconds')} {msg}\n")


def api_key():
    for line in open("/opt/stack/.env"):
        if line.startswith("NANOMDM_API_KEY="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("no API key")


def enqueue(udid, key):
    cmd = (b'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
           b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>'
           b'<key>Command</key><dict><key>RequestType</key><string>InstalledApplicationList</string>'
           b'<key>ManagedAppsOnly</key><false/></dict><key>CommandUUID</key><string>'
           + str(uuid.uuid4()).encode() + b'</string></dict></plist>')
    req = urllib.request.Request(f"{API}/enqueue/{udid}", data=cmd, method="PUT")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"nanomdm:{key}".encode()).decode())
    # the vhost resolves to the G11 itself; connect via the published port
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return r.status


def load(name, default):
    try:
        return json.load(open(os.path.join(STATE, name)))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save(name, data):
    p = os.path.join(STATE, name)
    json.dump(data, open(p + ".tmp", "w"), indent=1, sort_keys=True)
    os.replace(p + ".tmp", p)


def emit(event):
    os.makedirs(OUTBOX, exist_ok=True)
    p = os.path.join(OUTBOX, f"{int(time.time()*1000)}-{uuid.uuid4().hex[:8]}.json")
    json.dump(event, open(p + ".tmp", "w"))
    os.replace(p + ".tmp", p)


def main():
    key = api_key()
    devices = load("devices.json", {})
    now = datetime.now(timezone.utc)
    for udid, d in devices.items():
        if not d.get("enrolled"):
            continue
        try:
            log(f"enqueue {udid[:8]}… -> {enqueue(udid, key)}")
        except Exception as e:
            log(f"enqueue {udid[:8]}… FAILED {e}")
        last = d.get("last_apps_at") or d.get("last_seen")
        if last and not d.get("unreachable_reported"):
            if now - datetime.fromisoformat(last) > UNREACHABLE_AFTER:
                emit({"type": "device_unreachable", "detected_at": now.replace(microsecond=0).isoformat(),
                      "window_start": last, "device": d.get("name", "Jonah iPhone"),
                      "reason": f"no app list received since {last}"})
                d["unreachable_reported"] = True
                save("devices.json", devices)
                log(f"device {udid[:8]}… unreachable since {last}")
    # deliver queued events in order
    os.makedirs(SENT, exist_ok=True)
    queued = sorted(f for f in os.listdir(OUTBOX) if f.endswith(".json")) if os.path.isdir(OUTBOX) else []
    if queued and not os.access(SENDER, os.X_OK):
        log(f"{len(queued)} event(s) queued; sender {SENDER} not installed yet")
        return
    for f in queued:
        p = os.path.join(OUTBOX, f)
        r = subprocess.run([SENDER, open(p).read()], capture_output=True, text=True, timeout=60)
        if r.returncode in (0, 3):   # 0 delivered/queued by sender; 3 queued, needs a human (logged)
            os.replace(p, os.path.join(SENT, f))
            log(f"handed to sender {f} rc={r.returncode} {r.stdout.strip()[:80]} {r.stderr.strip()[:160]}")
        elif r.returncode == 2:      # sender rejected the event as malformed: park it, keep going
            os.makedirs(os.path.join(STATE, "bad"), exist_ok=True)
            os.replace(p, os.path.join(STATE, "bad", f))
            log(f"BAD event parked {f}: {r.stderr.strip()[:200]}")
        else:
            log(f"send FAILED {f} rc={r.returncode} {r.stderr.strip()[:200]}")
            break  # keep order; retry next run


if __name__ == "__main__":
    main()
