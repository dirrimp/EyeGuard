#!/usr/bin/env python3
"""MDM wake-poke listener (G11). The router sends ONE UDP datagram when Jonah's phone has been
silent ~75 s (see router/eyeguard-phone.py, _should_poke); this sends the phone an MDM push so a
merely-idle iPhone wakes and talks over the tunnel before the 150 s dark threshold.

What this can and cannot do
  * It only WAKES the phone. It reports nothing, suppresses nothing, and never touches the
    router's liveness math: a dead phone ignores the push and is flagged on schedule.
  * The phone's answer is MDM traffic over the WireGuard tunnel, so the router's own rx counter
    sees it. That, not anything this script says, is what counts as "alive".
  * Reuses poll.py's API helpers (same key file, same endpoint); holds no secret of its own except
    the shared poke token in poke.json (0600), which only authenticates the datagram.

Run: cron starts it every minute; a flock keeps exactly one copy alive (see deploy/g11-poke.cron).
Config /opt/kev/mdm/poke.json (0600, not in the repo): {"token": "<random>", "bind": "192.168.8.231",
"port": 51902}. Missing or unreadable config = exit quietly (nothing to listen for).
"""
import fcntl, hmac, json, os, socket, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poll                                    # noqa: E402  (API helpers, state, log)

CONF = os.environ.get("MDM_POKE_CONF", "/opt/kev/mdm/poke.json")
MIN_GAP = 20          # seconds between pushes, however many datagrams arrive
CMD_GAP = 300         # a fresh command at most this often; between, push-only (the queued one is still waiting)
CMD_PER_HOUR = 12     # hard cap on queued commands, so an unreachable phone cannot build an unbounded queue


def load_conf(path=None):
    path = path or CONF
    try:
        st = os.stat(path)
        if st.st_mode & 0o077:
            poll.log(f"poke: {path} is group/world accessible; refusing to start")
            return None
        c = json.load(open(path))
        if not isinstance(c.get("token"), str) or len(c["token"]) < 16:
            poll.log("poke: token missing or shorter than 16 characters; refusing to start")
            return None
        return {"token": c["token"], "bind": c.get("bind", "0.0.0.0"), "port": int(c.get("port", 51902))}
    except FileNotFoundError:
        return None
    except Exception as e:
        poll.log(f"poke: config unreadable: {e!r}")
        return None


def authentic(data, token):
    """Datagram is JSON with the shared token (constant-time compare). Anything else is ignored."""
    try:
        msg = json.loads(data.decode())
        return isinstance(msg, dict) and hmac.compare_digest(str(msg.get("token", "")), token)
    except Exception:
        return False


class Poker:
    """Decides, from timestamps only, what one authenticated datagram should do."""

    def __init__(self):
        self.last_push = 0.0
        self.last_cmd = 0.0
        self.cmd_times = []

    def decide(self, now):
        if now - self.last_push < MIN_GAP:
            return "ignore"
        self.cmd_times = [t for t in self.cmd_times if now - t < 3600]
        if now - self.last_cmd >= CMD_GAP and len(self.cmd_times) < CMD_PER_HOUR:
            return "command+push"
        return "push"

    def record(self, now, action):
        self.last_push = now
        if action == "command+push":
            self.last_cmd = now
            self.cmd_times.append(now)


def enrolled_udid():
    devs = poll.load("devices.json", {})
    ids = [u for u, d in devs.items() if d.get("enrolled")]
    return ids[0] if ids else None


class QuietLog:
    """One line per kind of failure per window (plus a recovery line), so a backend outage
    that lasts hours is a few log lines, not one every 45 seconds."""

    def __init__(self, window=600, log=None):
        self.window, self.log = window, log or poll.log
        self.last = {}       # kind -> last time logged
        self.skipped = {}    # kind -> suppressed count
        self.failing = set()

    def fail(self, kind, detail, now):
        self.failing.add(kind)
        if now - self.last.get(kind, -1e9) >= self.window:
            n = self.skipped.pop(kind, 0)
            self.log(f"poke: {kind} FAILED {detail}" + (f" ({n} similar suppressed)" if n else ""))
            self.last[kind] = now
        else:
            self.skipped[kind] = self.skipped.get(kind, 0) + 1

    def ok(self, kind):
        if kind in self.failing:
            self.failing.discard(kind)
            self.log(f"poke: {kind} recovered")
            self.last.pop(kind, None)


QUIET = QuietLog()


def do_poke(action, key, now=None):
    """The push IS the wake; the queued DeviceInformation command is only the cheapest thing for the
    phone to answer. So a failed enqueue (e.g. the API answering 500 during an APNs outage) must
    never stop the push, and a failed push is the only thing that raises."""
    now = time.time() if now is None else now
    udid = enrolled_udid()
    if not udid:
        poll.log("poke: no enrolled phone")
        return False
    if action == "command+push":
        try:
            poll.enqueue_command(udid, key, {"RequestType": "DeviceInformation", "Queries": ["IsSupervised"]})
            QUIET.ok("enqueue")
        except Exception as e:
            QUIET.fail("enqueue", repr(e), now)       # keep going: still push
    try:
        poll.push(udid, key)
    except Exception as e:
        QUIET.fail("push", repr(e), now)
        raise
    QUIET.ok("push")
    return True


def serve(conf, sock=None, poker=None, clock=time.time, poke=do_poke, keyfn=poll.api_key, once=False):
    sock = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if sock.getsockname()[1] == 0:
        sock.bind((conf["bind"], conf["port"]))
    poker = poker or Poker()
    poll.log(f"poke: listening on {conf['bind']}:{conf['port']}")
    while True:
        data, addr = sock.recvfrom(512)
        if not authentic(data, conf["token"]):
            if once:
                return "rejected"
            continue
        now = clock()
        action = poker.decide(now)
        if action == "ignore":
            if once:
                return "ignored"
            continue
        try:
            ok = poke(action, keyfn())
            poker.record(now, action)
            QUIET.ok("poke")
            poll.log(f"poke: {action} from {addr[0]} ok={ok}")
        except Exception as e:
            poker.record(now, action)        # a failed attempt still counts toward the gaps and the hourly cap
            QUIET.fail("poke", repr(e), now)
        if once:
            return action


def single_instance():
    os.makedirs(poll.STATE, exist_ok=True)
    f = open(os.path.join(poll.STATE, ".poke.lock"), "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return None
    return f


if __name__ == "__main__":
    lock = single_instance()
    if lock is None:
        sys.exit(0)                           # the running copy is the listener
    conf = load_conf()
    if conf is None:
        sys.exit(0)
    try:
        serve(conf)
    except OSError as e:                      # port busy / bad bind address: log and let cron retry
        poll.log(f"poke: cannot listen: {e!r}")
        sys.exit(1)
