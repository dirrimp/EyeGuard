#!/usr/bin/env python3
"""App-install notifier poller (cron */5 on the G11; was */15 until 2026-10-07).

1. Asks every enrolled device for InstalledApplicationList via the NanoMDM API (with push).
   Results come back through the webhook (hook.py), which diffs and writes events.
2. Reports a device as unreachable once if no app list arrived for UNREACHABLE_AFTER.
3. Delivers queued events to EyeGuard via SENDER (defined by the EyeGuard repo).
   Until SENDER exists, events stay queued in outbox/ and nothing is lost.
4. After a COMPLETED run, sends a heartbeat (counts only, no app data). The
   server alerts if heartbeats stop, if no phone is enrolled, or if app lists
   go stale -- so this script dying, cron stopping or the G11 going dark is
   caught by the server, not trusted to this script. A run that crashes
   (e.g. missing API key) deliberately sends no heartbeat.
"""
import base64, fcntl, hashlib, json, os, plistlib, re, ssl, subprocess, sys, time, urllib.request, uuid
from datetime import datetime, timezone, timedelta

STATE = os.environ.get("MDM_STATE", "/opt/stack/mdm/hook-state")
OUTBOX = os.path.join(STATE, "outbox")
SENT = os.path.join(STATE, "sent")
SENDER = os.environ.get("MDM_SENDER", "/opt/kev/mdm/eg-report.sh")
API = "https://mdm.orthanc.me/v1"
UNREACHABLE_AFTER = timedelta(minutes=30)   # was 2 h; 6 missed 5-minute checks. The server also sends an all-clear when it answers again
POLL_STATE = "poll-state.json"          # poller-owned (the hook owns devices.json: no write races)
AWAIT_REPOLL = timedelta(minutes=30)    # don't stack commands for a phone that has not answered
CMDS = "pending-cmds.json"          # commands this poller sent; hook records their outcome
RESULTS = os.path.join(STATE, "results")
BUNDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
CMD_STALE = timedelta(minutes=20)    # an unanswered command is re-sent after this
BLOCK_REFRESH = timedelta(hours=6)
LOG = os.environ.get("MDM_LOG", "/opt/kev/mdm/poll.log")


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


def sender(*args):
    r = subprocess.run([SENDER, *args], capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def enqueue_command(udid, key, request):
    """Queue an MDM command for the phone; returns its CommandUUID."""
    cid = str(uuid.uuid4())
    body = plistlib.dumps({"Command": request, "CommandUUID": cid})
    req = urllib.request.Request(f"{API}/enqueue/{udid}", data=body, method="PUT")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"nanomdm:{key}".encode()).decode())
    with urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context()):
        pass
    return cid


def track(cid, info):
    cmds = load(CMDS, {})
    cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    cmds = {k: v for k, v in cmds.items() if v.get("at", "") > cutoff}
    cmds[cid] = dict(info, at=datetime.now(timezone.utc).isoformat())
    save(CMDS, cmds)


def pending(kind, ident=None):
    """Is there a recent unanswered command of this kind (and action id)?"""
    cutoff = (datetime.now(timezone.utc) - CMD_STALE).isoformat()
    return any(v.get("kind") == kind and v.get("at", "") > cutoff and (ident is None or v.get("id") == ident)
               for v in load(CMDS, {}).values())


def block_profile(ids):
    """Restrictions profile blocking the given bundle ids. SUPERVISED phones only
    (Apple ignores these keys elsewhere), so the caller refuses to push it otherwise.
    Both key names are sent: blockedAppBundleIDs is the current one, the older
    blacklistedAppBundleIDs is kept for older iOS. Unverified until tested on the
    real phone."""
    ids = sorted(set(ids))
    inner = {"PayloadType": "com.apple.applicationaccess", "PayloadVersion": 1,
             "PayloadIdentifier": "me.orthanc.eyeguard.blocklist.restrictions",
             "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_DNS, "eyeguard-blocklist-restrictions")),
             "PayloadDisplayName": "EyeGuard blocked apps",
             "blockedAppBundleIDs": ids, "blacklistedAppBundleIDs": ids}
    outer = {"PayloadType": "Configuration", "PayloadVersion": 1,
             "PayloadIdentifier": "me.orthanc.eyeguard.blocklist",
             "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_DNS, "eyeguard-blocklist")),
             "PayloadDisplayName": "EyeGuard app block list", "PayloadOrganization": "EyeGuard",
             "PayloadContent": [inner]}
    return plistlib.dumps(outer)


def report_results():
    """Send the phone's answers for earlier removals / block pushes to the server."""
    if not os.path.isdir(RESULTS):
        return
    cmds = load(CMDS, {})
    for f in sorted(os.listdir(RESULTS)):
        path = os.path.join(RESULTS, f)
        try:
            res = json.load(open(path))
            info = cmds.get(res["uuid"])
        except Exception:
            os.remove(path)
            continue
        if not info:
            os.remove(path)
            continue
        ok = res.get("status") == "Acknowledged"
        detail = res.get("error") or res.get("status") or ""
        if info["kind"] == "remove":
            rc, _, err = sender("--action-result", str(info["id"]), "ok" if ok else "fail", detail)
        else:
            rc, _, err = sender("--block-result", "ok" if ok else "fail", str(info.get("count", 0)), detail)
            if rc == 0:
                save("block-state.json", {"hash": info["hash"] if ok else None,
                                          "applied_at": datetime.now(timezone.utc).isoformat()})
        log(f"result {info['kind']} {info.get('id', '')} ok={ok} rc={rc} {err[:120]}")
        if rc == 0:                       # else keep the file; retried next run
            os.remove(path)
            cmds.pop(res["uuid"], None)
            save(CMDS, cmds)


def approvals(devices, key):
    """Enforce partner decisions. The server decides; this only carries them out and
    reports what the phone said. Never raises into main()."""
    enrolled = [u for u, d in devices.items() if d.get("enrolled")]
    if not enrolled:
        return
    udid = enrolled[0]
    d = devices[udid]
    try:
        enqueue_command(udid, key, {"RequestType": "DeviceInformation", "Queries": ["IsSupervised"]})
    except Exception as e:
        log(f"DeviceInformation FAILED {e}")
    report_results()
    rc, out, err = sender("--sync")
    if rc != 0:
        log(f"sync FAILED rc={rc} {err[:160]}")
        return
    try:
        sync = json.loads(out)
        blocked = [b for b in sync.get("blocked", []) if isinstance(b, str) and BUNDLE_RE.match(b)]
        actions = [a for a in sync.get("actions", []) if a.get("action") == "remove"
                   and isinstance(a.get("id"), int) and BUNDLE_RE.match(str(a.get("bundle_id", "")))]
    except Exception as e:
        log(f"sync response unreadable: {e}")
        return
    for a in actions:
        if pending("remove", a["id"]):
            continue
        try:
            cid = enqueue_command(udid, key, {"RequestType": "RemoveApplication", "Identifier": a["bundle_id"]})
            track(cid, {"kind": "remove", "id": a["id"]})
            log(f"remove queued for action {a['id']}")
        except Exception as e:
            log(f"remove action {a['id']} FAILED {e}")
    h = hashlib.sha256("\n".join(sorted(blocked)).encode()).hexdigest()
    bs = load("block-state.json", {})
    fresh = bs.get("applied_at") and datetime.now(timezone.utc) - datetime.fromisoformat(bs["applied_at"]) < BLOCK_REFRESH
    if bs.get("hash") == h and fresh:
        return
    if not blocked and not bs.get("hash"):
        return                              # nothing blocked, nothing ever applied
    if d.get("supervised") is not True:     # the profile would install but enforce nothing
        why = "phone is not supervised: block list not enforced" if d.get("supervised") is False \
              else "supervision state unknown yet: block list not applied"
        rc, _, err = sender("--block-result", "fail", str(len(blocked)), why)   # server emails once
        log(f"block list not applied ({why}) rc={rc}")
        return
    if pending("block"):
        return
    try:
        cid = enqueue_command(udid, key, {"RequestType": "InstallProfile", "Payload": block_profile(blocked)})
        track(cid, {"kind": "block", "count": len(blocked), "hash": h})
        log(f"block list queued ({len(blocked)} apps)")
    except Exception as e:
        log(f"block list FAILED {e}")


def coalesce_snapshots():
    """Only the newest queued app_snapshot matters (the server diffs the latest list)."""
    if not os.path.isdir(OUTBOX):
        return
    snaps = []
    for f in sorted(os.listdir(OUTBOX)):
        if f.endswith(".json"):
            try:
                if json.load(open(os.path.join(OUTBOX, f))).get("type") == "app_snapshot":
                    snaps.append(f)
            except Exception:
                pass
    for f in snaps[:-1]:
        os.remove(os.path.join(OUTBOX, f))


def prune_sent(days=2):
    cutoff = time.time() - days * 86400
    if os.path.isdir(SENT):
        for f in os.listdir(SENT):
            p = os.path.join(SENT, f)
            if os.path.getmtime(p) < cutoff:
                os.remove(p)


def main():
    key = api_key()
    devices = load("devices.json", {})
    now = datetime.now(timezone.utc)
    for udid, d in devices.items():
        if not d.get("enrolled"):
            continue
        # With a 5-minute cadence an offline phone would otherwise collect hundreds of
        # queued commands (and answer them all at once when it returns). Ask again only
        # once the last request was answered, or after AWAIT_REPOLL.
        ps = load(POLL_STATE, {})
        sent_at = ps.get(udid, {}).get("last_enqueue_at")
        answered = d.get("last_apps_at")
        awaiting = bool(sent_at) and now - datetime.fromisoformat(sent_at) < AWAIT_REPOLL and (
            not answered or datetime.fromisoformat(answered) < datetime.fromisoformat(sent_at))
        if awaiting:
            log(f"enqueue {udid[:8]}… skipped: previous request not answered yet")
        else:
            try:
                log(f"enqueue {udid[:8]}… -> {enqueue(udid, key)}")
                ps[udid] = dict(ps.get(udid, {}), last_enqueue_at=now.isoformat())
                save(POLL_STATE, ps)
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
    coalesce_snapshots()
    prune_sent()
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
    if os.access(SENDER, os.X_OK):
        rc, _, err = sender("--flush")      # anything the sender queued on an earlier blip
        if rc not in (0, 3):
            log(f"flush rc={rc} {err[:120]}")
    try:
        approvals(load("devices.json", {}), key)
    except Exception as e:
        log(f"approvals ERROR {e!r}")


def heartbeat():
    """Counts only. Server compares against its own clock (gone-quiet) and these
    figures (no phone enrolled / stale app lists)."""
    devices = load("devices.json", {})
    now = datetime.now(timezone.utc)
    enrolled = [d for d in devices.values() if d.get("enrolled")]
    ages, unlisted = [], 0
    for d in enrolled:
        t = d.get("last_apps_at")
        if t:
            ages.append(int((now - datetime.fromisoformat(t)).total_seconds()))
        else:
            unlisted += 1
    pending = len([f for f in os.listdir(OUTBOX) if f.endswith(".json")]) if os.path.isdir(OUTBOX) else 0
    info = {"enrolled": len(enrolled), "unlisted": unlisted,
            "stalest_apps_age_s": max(ages) if ages else None, "outbox_pending": pending}
    if not os.access(SENDER, os.X_OK):
        log("heartbeat skipped: sender not installed")
        return info
    r = subprocess.run([SENDER, "--heartbeat", json.dumps(info)], capture_output=True, text=True, timeout=60)
    log(f"heartbeat rc={r.returncode} {json.dumps(info)} {r.stderr.strip()[:160]}")
    return info


def lock():
    """One run at a time. A run that is still going when the next fires (slow network)
    makes the newer one exit quietly; the running one sends the heartbeat when done. A run
    that HANGS for 15 minutes is exactly what the server's silence alert is for."""
    os.makedirs(STATE, exist_ok=True)
    f = open(os.path.join(STATE, ".poll.lock"), "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return None
    return f


if __name__ == "__main__":
    _lock = lock()
    if _lock is None:
        log("previous run still active; skipping")
        sys.exit(0)
    main()
    heartbeat()
