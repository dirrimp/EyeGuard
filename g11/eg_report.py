#!/usr/bin/env python3
"""EyeGuard G11 -> Supabase event reporter (iPhone MDM app events).

Durable-first: every event is written to a queue file (fsync + atomic rename)
BEFORE any network attempt, so a crash or offline moment never loses it.
Then the queue is flushed oldest-first. Delivery is idempotent server-side
(dedupe on type|bundle_id|detected_at), so a retry after an ambiguous failure
cannot double-email.

Credential file (JSON, must be mode 0600, owned by the running user):
  /opt/kev/mdm/eg-report.json  (override: EG_REPORT_CONF)
  {"supabase_url": "https://<ref>.supabase.co", "anon_key": "<public anon key>",
   "device_token": "<64 hex chars given by Dad>"}
Queue: /opt/kev/mdm/eg-queue/ (override: EG_REPORT_QUEUE), mode 0700.
Dead letters (malformed events the server rejects with 400): eg-queue/dead/.

Exit codes:  0 event delivered OR safely queued for retry
             2 bad input / config problem (event NOT recorded)  -- see stderr
             3 queued, but a human must act (credential rejected 401, or config missing/wrong mode)
--sync | --action-result ID ok|fail [detail] | --block-result ok|fail COUNT [detail]
             (NOT queued; poller retries) 0 ok  2 bad input  3 credential/config  4 transient
--heartbeat '<json>' (NOT queued: a late beat would hide an outage, so a miss is a miss):
             0 beat accepted   3 credential/config problem   4 transient failure (next run retries)
Nothing but fixed status words is printed to stdout; the token is never logged.
"""
import fcntl, hashlib, json, os, stat, sys, time, urllib.error, urllib.request
from datetime import datetime

CONF = os.environ.get("EG_REPORT_CONF", "/opt/kev/mdm/eg-report.json")
QDIR = os.environ.get("EG_REPORT_QUEUE", "/opt/kev/mdm/eg-queue")
TYPES = {"app_installed", "app_removed", "device_unreachable", "device_reachable_again", "device_reenrolled", "app_snapshot"}
TIMEOUT = float(os.environ.get("EG_REPORT_TIMEOUT", "10"))
ATTEMPTS = int(os.environ.get("EG_REPORT_ATTEMPTS", "3"))


def err(msg):
    print("eg-report: " + msg, file=sys.stderr)


def load_conf():
    st = os.stat(CONF)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError(f"{CONF} must be mode 0600 (is {oct(st.st_mode & 0o777)})")
    c = json.load(open(CONF))
    for k in ("supabase_url", "anon_key", "device_token"):
        if not isinstance(c.get(k), str) or not c[k]:
            raise ValueError(f"{CONF} missing {k}")
    c["supabase_url"] = c["supabase_url"].rstrip("/")
    if not c["supabase_url"].startswith("https://"):
        raise ValueError("supabase_url must be https")
    return c


def parse_ts(v):
    datetime.fromisoformat(v.replace("Z", "+00:00"))


def validate(ev):
    if not isinstance(ev, dict):
        raise ValueError("event must be a JSON object")
    if ev.get("type") not in TYPES:
        raise ValueError("type must be one of " + ",".join(sorted(TYPES)))
    if not ev.get("detected_at"):
        raise ValueError("detected_at required")
    parse_ts(ev["detected_at"])
    if ev.get("window_start"):
        parse_ts(ev["window_start"])
    if ev["type"] == "app_snapshot":
        apps = ev.get("apps")
        if not isinstance(apps, list) or not 0 < len(apps) <= 2000:
            raise ValueError("app_snapshot needs 1..2000 apps")
        if not all(isinstance(a, dict) and isinstance(a.get("bundle_id"), str) and a["bundle_id"] for a in apps):
            raise ValueError("every app needs a bundle_id")
    elif ev["type"].startswith("app_") and not ev.get("bundle_id"):
        raise ValueError("bundle_id required for app_* events")


def drop_superseded_snapshots():
    """Only the newest app_snapshot matters (the server diffs the latest list), so
    older queued ones are deleted rather than stacking up while the server is
    unreachable or its SQL is not installed yet."""
    for name in queued():
        path = os.path.join(QDIR, name)
        try:
            if json.load(open(path)).get("type") == "app_snapshot":
                os.unlink(path)
        except Exception:
            pass


def enqueue(ev):
    os.makedirs(QDIR, mode=0o700, exist_ok=True)
    if ev.get("type") == "app_snapshot":
        drop_superseded_snapshots()
    body = json.dumps(ev, sort_keys=True)
    h = hashlib.sha256(body.encode()).hexdigest()[:12]
    name = f"{time.strftime('%Y%m%dT%H%M%S')}-{time.time_ns() % 10**9:09d}-{h}.json"
    tmp = os.path.join(QDIR, "." + name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(body)
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp, os.path.join(QDIR, name))
    dfd = os.open(QDIR, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def queued():
    if not os.path.isdir(QDIR):
        return []
    return sorted(f for f in os.listdir(QDIR) if f.endswith(".json") and not f.startswith("."))


def post(conf, ev):
    """Returns ('ok'|'retry'|'auth'|'dead', detail). Never raises on network errors."""
    if ev.get("type") == "app_snapshot":      # the server diffs it against the official list
        rpc, payload = "eg_mdm_snapshot", {"p_token": conf["device_token"], "p_snapshot": ev}
    else:
        rpc, payload = "eg_report_mdm_event", {"p_token": conf["device_token"], "p_event": ev}
    req = urllib.request.Request(
        conf["supabase_url"] + "/rest/v1/rpc/" + rpc,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"apikey": conf["anon_key"], "Authorization": "Bearer " + conf["anon_key"],
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return ("ok", str(r.status))
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return ("auth", "401")
        if e.code in (400, 422):
            return ("dead", str(e.code))
        return ("retry", f"http {e.code}")          # 403/404/429/5xx: server-side issue, keep
    except Exception as e:                          # DNS, timeout, TLS, reset
        return ("retry", type(e).__name__)


def heartbeat(conf, info):
    """One attempt, no queue. Returns 'ok' | 'auth' | 'retry'."""
    req = urllib.request.Request(
        conf["supabase_url"] + "/rest/v1/rpc/eg_mdm_heartbeat",
        data=json.dumps({"p_token": conf["device_token"], "p_info": info}).encode(),
        method="POST",
        headers={"apikey": conf["anon_key"], "Authorization": "Bearer " + conf["anon_key"],
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT):
            return "ok"
    except urllib.error.HTTPError as e:
        return "auth" if e.code == 401 else "retry"
    except Exception:
        return "retry"


def rpc_once(conf, fn, payload):
    """One attempt, no queue. Returns ('ok', body) | ('auth', '') | ('retry', '')."""
    req = urllib.request.Request(
        conf["supabase_url"] + "/rest/v1/rpc/" + fn,
        data=json.dumps({"p_token": conf["device_token"], **payload}).encode(), method="POST",
        headers={"apikey": conf["anon_key"], "Authorization": "Bearer " + conf["anon_key"],
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return "ok", r.read().decode()
    except urllib.error.HTTPError as e:
        return ("auth", "") if e.code == 401 else ("retry", "")
    except Exception:
        return "retry", ""


def main_oneshot(cmd, args):
    """--sync | --action-result <id> ok|fail [detail] | --block-result ok|fail <count> [detail]
    Not queued: the poller retries on its next run. 0 ok, 2 bad input, 3 credential/config, 4 transient."""
    try:
        if cmd == "--sync" and not args:
            fn, payload = "eg_mdm_sync", {}
        elif cmd == "--action-result" and len(args) >= 2 and args[1] in ("ok", "fail"):
            fn, payload = "eg_mdm_action_result", {"p_id": int(args[0]), "p_ok": args[1] == "ok",
                                                   "p_detail": " ".join(args[2:])[:300]}
        elif cmd == "--block-result" and len(args) >= 2 and args[0] in ("ok", "fail"):
            fn, payload = "eg_mdm_block_result", {"p_ok": args[0] == "ok", "p_count": int(args[1]),
                                                  "p_detail": " ".join(args[2:])[:300]}
        else:
            raise ValueError("bad arguments")
    except Exception as e:
        err(f"invalid {cmd} arguments: {e}")
        return 2
    try:
        conf = load_conf()
    except Exception as e:
        err(f"config error: {e}")
        return 3
    r, body = rpc_once(conf, fn, payload)
    if r == "ok":
        print(body.strip() if cmd == "--sync" else "ok")
        return 0
    if r == "auth":
        err("server rejected the device token (401)")
        return 3
    err(f"{cmd} not delivered (transient)")
    return 4


def flush(conf):
    """Send queued events oldest-first. Stops at the first transient failure to
    preserve order. Returns (delivered, remaining, auth_failed)."""
    delivered, auth_failed = 0, False
    for name in queued():
        path = os.path.join(QDIR, name)
        try:
            ev = json.load(open(path))
        except Exception:
            _dead(path)
            continue
        status = "retry"
        for i in range(ATTEMPTS):
            status, detail = post(conf, ev)
            if status != "retry":
                break
            time.sleep(min(2 ** i, 8))
        if status == "ok":
            os.unlink(path)
            delivered += 1
        elif status == "dead":
            err(f"server rejected {name} as malformed ({detail}); moved to dead/")
            _dead(path)
        elif status == "auth":
            err("server rejected the device token (401); events stay queued")
            auth_failed = True
            break
        else:
            err(f"delivery failed ({detail}); {len(queued())} event(s) queued for retry")
            break
    return delivered, len(queued()), auth_failed


def _dead(path):
    d = os.path.join(QDIR, "dead")
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.rename(path, os.path.join(d, os.path.basename(path)))


def main_heartbeat(raw):
    try:
        info = json.loads(raw)
        if not isinstance(info, dict):
            raise ValueError("heartbeat info must be a JSON object")
    except Exception as e:
        err(f"invalid heartbeat info: {e}")
        return 2
    try:
        conf = load_conf()
    except Exception as e:
        err(f"config error: {e}")
        return 3
    r = heartbeat(conf, info)
    if r == "ok":
        print("ok")
        return 0
    if r == "auth":
        err("server rejected the device token (401)")
        return 3
    err("heartbeat not delivered (transient); the next run will try again")
    return 4


def main(argv):
    if len(argv) == 3 and argv[1] == "--heartbeat":
        return main_heartbeat(argv[2])
    if len(argv) >= 2 and argv[1] in ("--sync", "--action-result", "--block-result"):
        return main_oneshot(argv[1], argv[2:])
    if len(argv) != 2:
        err("usage: eg-report.sh '<event-json>' | --flush | --status | --heartbeat '<json>' | --sync | --action-result | --block-result")
        return 2
    arg = argv[1]
    if arg == "--status":
        print(f"queued={len(queued())}")
        return 0
    os.makedirs(QDIR, mode=0o700, exist_ok=True)
    lock = open(os.path.join(QDIR, ".lock"), "a")
    fcntl.flock(lock, fcntl.LOCK_EX)               # serialize concurrent callers
    ev = None
    if arg != "--flush":
        try:
            ev = json.loads(arg)
            validate(ev)
        except Exception as e:
            err(f"invalid event: {e}")
            return 2
    try:
        conf = load_conf()
    except Exception as e:
        err(f"config error: {e}")
        if ev is not None:                          # still never lose the event
            enqueue(ev)
            err("event queued anyway; fix the config and run --flush")
            print("queued")
            return 3
        return 2
    if ev is not None:
        enqueue(ev)
    delivered, remaining, auth_failed = flush(conf)
    if auth_failed:
        print("queued")
        return 3
    print("delivered" if remaining == 0 else "queued")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
