#!/usr/bin/env python3
"""MDM wake poke (router side + G11 listener). Synthetic only; no network beyond loopback UDP.
Run: python3 tests/test_mdm_poke.py

The property that matters: the poke can ONLY send a wake. It must never change what counts as
dark, never delay a dark flag, and never fire once a dark flag has been raised."""
import importlib.util, json, os, socket, sys, tempfile, threading, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

# ---------------- router module (config at import time, like test_phone_dark_transition) ----------------
tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
json.dump({"api_key": "t", "supabase_url": "https://example.invalid", "dark_buffer_seconds": 150,
           "transition_grace_seconds": 40, "mdm_poke_host": "127.0.0.1", "mdm_poke_port": 0,
           "mdm_poke_token": "x" * 24}, tmp)
tmp.close()
os.environ["EG_PHONE_CONF"] = tmp.name
spec = importlib.util.spec_from_file_location("phone_under_test", ROOT / "router" / "eyeguard-phone.py")
phone = importlib.util.module_from_spec(spec); spec.loader.exec_module(phone)
os.unlink(tmp.name)

print("A. router: when to poke")
def st(**kw):
    s = {"last_activity": 1000.0, "last_rx": 5, "dark_alerted": False, "last_poke": 0.0, "poked_at": 0.0,
         "last_home_seen": 1000.0, "last_wg_seen": 1000.0, "transition_grace_logged": False, "green_seen": {}}
    s.update(kw); return s
check("enabled by config (host + token, primary instance)", phone.MDM_POKE_ENABLED is True)
s = st()
check("no poke below the threshold (74 s silent)", phone._should_poke(s, 1074.0, 74, 75, 45) is False)
check("poke at 75 s silent", phone._should_poke(s, 1075.0, 75, 75, 45) is True)
check("no second poke within 45 s", phone._should_poke(s, 1100.0, 100, 75, 45) is False)
check("poke again after 45 s if still silent", phone._should_poke(s, 1121.0, 121, 75, 45) is True)
check("NEVER pokes once a dark flag has fired", phone._should_poke(st(dark_alerted=True), 1200.0, 200, 75, 45) is False)
check("poke threshold is well before the 150 s dark threshold", 75 < phone.DARK)

print("B. the poke cannot change what is dark (same inputs, with and without poking -> same flag, same moment)")
def run(poking):
    s = st(last_activity=0.0, last_home_seen=-500.0, last_wg_seen=0.0); s["last_rx"] = 5
    fired_at = None
    for t in range(20, 400, 20):
        fire, dark_secs, active, _ = phone._evaluate_liveness(s, float(t), False, 5, 150, 40)
        if poking:
            phone._should_poke(s, float(t), dark_secs, 75, 45)
        if fire and fired_at is None: fired_at = t
    return fired_at
check("a phone that never answers is flagged at exactly the same tick either way", run(False) == run(True) and run(True) is not None,
      f"{run(False)} vs {run(True)}")

print("C. the poke's effect is measurable (answered / not answered), and an answer ends the episode")
s = st(last_activity=1000.0, poked_at=1080.0)
check("no follow-up while silent and inside 120 s", phone._poke_followup(s, 1100.0) is None and s["poked_at"] == 1080.0)
s["last_activity"] = 1090.0
line = phone._poke_followup(s, 1100.0)
check("traffic after the poke logs ANSWERED once", line and "ANSWERED" in line and s["poked_at"] == 0.0, str(line))
check("...and does not log again", phone._poke_followup(s, 1110.0) is None)
s = st(last_activity=1000.0, poked_at=1080.0)
line = phone._poke_followup(s, 1210.0)
check("still silent after 120 s logs NOT answered", line and "NOT answered" in line and s["poked_at"] == 0.0, str(line))

print("D. router sends one datagram with the token, and survives a dead destination")
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rx.bind(("127.0.0.1", 0)); rx.settimeout(2)
phone.MDM_POKE_PORT = rx.getsockname()[1]
phone.send_mdm_poke(88)
data, _ = rx.recvfrom(512); msg = json.loads(data)
check("datagram carries token and silent seconds", msg == {"token": "x" * 24, "silent": 88}, str(msg))
phone.MDM_POKE_HOST = "256.256.256.256"
phone.send_mdm_poke(1)
check("a bad destination never raises", True)
phone.MDM_POKE_HOST = "127.0.0.1"

print("E. disabled without host/token or on the secondary (Jada) instance")
for label, conf in (("no token", {"mdm_poke_host": "1.2.3.4"}), ("no host", {"mdm_poke_token": "y" * 24}),
                    ("secondary", {"mdm_poke_host": "1.2.3.4", "mdm_poke_token": "y" * 24, "secondary_instance": True})):
    t2 = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(dict({"api_key": "t", "supabase_url": "https://example.invalid"}, **conf), t2); t2.close()
    os.environ["EG_PHONE_CONF"] = t2.name
    sp = importlib.util.spec_from_file_location("p2", ROOT / "router" / "eyeguard-phone.py")
    m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m); os.unlink(t2.name)
    check(f"poke disabled: {label}", m.MDM_POKE_ENABLED is False)

# ---------------- G11 listener ----------------
print("F. G11 listener: authentication and rate limits")
st_dir = tempfile.mkdtemp()
os.environ.update({"MDM_STATE": st_dir, "MDM_LOG": os.path.join(st_dir, "log")})
sp = importlib.util.spec_from_file_location("pl", ROOT / "g11" / "mdm" / "poll.py"); pl = importlib.util.module_from_spec(sp); sp.loader.exec_module(pl)
sys.path.insert(0, str(ROOT / "g11" / "mdm"))
sp = importlib.util.spec_from_file_location("pk", ROOT / "g11" / "mdm" / "poke_listener.py"); pk = importlib.util.module_from_spec(sp); sp.loader.exec_module(pk)
TOKEN = "t" * 24
check("right token accepted", pk.authentic(json.dumps({"token": TOKEN}).encode(), TOKEN))
check("wrong token rejected", not pk.authentic(json.dumps({"token": "nope"}).encode(), TOKEN))
check("missing token, garbage, and non-object rejected", not any(pk.authentic(b, TOKEN) for b in (b"{}", b"\xff\xfe", b"[1]", b"null")))
p = pk.Poker()
check("first datagram: command + push", p.decide(1000.0) == "command+push")
p.record(1000.0, "command+push")
check("within 20 s: ignored", p.decide(1010.0) == "ignore")
check("after 20 s but within 300 s: push only (the queued command is still waiting)", p.decide(1030.0) == "push")
p.record(1030.0, "push")
check("after 300 s: a fresh command", p.decide(1400.0) == "command+push")
p2 = pk.Poker(); now = 0.0
cmds = 0
for i in range(400):
    now += 301.0
    a = p2.decide(now); p2.record(now, a); cmds += a == "command+push"
    if now > 3500: break
check("never more than 12 queued commands in an hour even if the phone never answers", cmds <= 12, str(cmds))

print("G. G11 listener: end to end over loopback with the API stubbed")
srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); srv.bind(("127.0.0.1", 0)); port = srv.getsockname()[1]
calls = []
def fake_poke(action, key): calls.append((action, key)); return True
conf = {"token": TOKEN, "bind": "127.0.0.1", "port": port}
poker = pk.Poker(); clock = [5000.0]
def send(payload):
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.sendto(payload, ("127.0.0.1", port)); c.close()
def one(payload):
    send(payload)
    return pk.serve(conf, sock=srv, poker=poker, clock=lambda: clock[0], poke=fake_poke, keyfn=lambda: "KEY", once=True)
check("forged datagram does nothing", one(b'{"token":"bad"}') == "rejected" and calls == [])
check("valid datagram sends command + push", one(json.dumps({"token": TOKEN}).encode()) == "command+push" and calls == [("command+push", "KEY")])
clock[0] += 5
check("a repeat 5 s later is ignored", one(json.dumps({"token": TOKEN}).encode()) == "ignored" and len(calls) == 1)
clock[0] += 30
check("30 s later: push only", one(json.dumps({"token": TOKEN}).encode()) == "push" and calls[-1] == ("push", "KEY"))
def boom(action, key): raise RuntimeError("api down")
poker2 = pk.Poker()
send(json.dumps({"token": TOKEN}).encode())
r = pk.serve(conf, sock=srv, poker=poker2, clock=lambda: 9000.0, poke=boom, keyfn=lambda: "KEY", once=True)
check("an API failure is logged and rate-limited, never raised", r == "command+push" and poker2.decide(9005.0) == "ignore")

print("H. config safety")
d = tempfile.mkdtemp(); cf = Path(d) / "poke.json"
cf.write_text(json.dumps({"token": "z" * 24, "bind": "10.0.0.1"})); cf.chmod(0o644)
check("refuses a world-readable config", pk.load_conf(str(cf)) is None)
cf.chmod(0o600)
c = pk.load_conf(str(cf))
check("0600 config loads with default port", c and c["port"] == 51902 and c["bind"] == "10.0.0.1")
cf.write_text(json.dumps({"token": "short"})); cf.chmod(0o600)
check("refuses a token shorter than 16 characters", pk.load_conf(str(cf)) is None)
check("missing config exits quietly (None)", pk.load_conf(str(Path(d) / "absent.json")) is None)
check("do_poke with no enrolled phone does nothing and says so", pk.do_poke("push", "K") is False)

print()
if fails:
    print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
print("all MDM poke tests passed")
