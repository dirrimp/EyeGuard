#!/usr/bin/env python3
"""Tests for the second phone instance (Jada's iPhone, 2026-10-01): per-device
identity in router/eyeguard-phone.py, instance separation in
router/eyeguard-router-watcher.py, and consistency between the installer, the
SQL and the code. Synthetic data only. Run: `python3 tests/test_jada_instance.py`."""
import importlib.util, json, os, re, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = {"api_key": "t", "supabase_url": "https://example.invalid",
        "explicit_terms": ["porn"], "wg_interface": "wgserver"}
JONAH = dict(BASE, home_ip="192.168.8.153", wg_ip="10.1.0.3",
             connlog_devices={"phone": ["192.168.8.153", "10.1.0.3", "10.1.0.5"]})
JADA = dict(BASE, home_ip="192.168.8.113", wg_ip="10.1.0.5",
            device_app="Jada's iPhone", reason_prefix="jada-",
            heartbeat_rpc="eg_phone_heartbeat_jada", dark_verdict="alert",
            secondary_instance=True, sleep_relay_token="",
            connlog_devices={"jada_phone": ["192.168.8.113", "10.1.0.5"]},
            connlog_excluded_ips=[])

def load(name, file, conf, argv_conf=False):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(conf, f); f.close()
    old_argv, old_env = sys.argv, os.environ.get("EG_PHONE_CONF")
    try:
        if argv_conf:
            os.environ["EG_PHONE_CONF"] = "/nonexistent/phone.json"   # argv must win
            sys.argv = ["eyeguard-phone.py", "--conf", f.name]
        else:
            os.environ["EG_PHONE_CONF"] = f.name
        sp = importlib.util.spec_from_file_location(name, ROOT / "router" / file)
        m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
        return m
    finally:
        sys.argv = old_argv
        if old_env is None: os.environ.pop("EG_PHONE_CONF", None)
        else: os.environ["EG_PHONE_CONF"] = old_env
        os.unlink(f.name)

fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

def capture(m):
    rows, rpcs = [], []
    m.sb_post = lambda path, row, prefer="return=minimal": rows.append(row) or True
    m.sb_rpc = lambda name, params: rpcs.append((name, params)) or True
    return rows, rpcs

def emit_all(m):
    m._handle_query("www.pornhub.com")
    m._handle_doh_attempt("1.1.1.1")
    m._handle_tor_attempt("9.9.9.9")
    m.sb_phone_heartbeat(True)

jonah = load("jonah", "eyeguard-phone.py", JONAH)
jada = load("jada", "eyeguard-phone.py", JADA, argv_conf=True)
wt = load("wt", "eyeguard-router-watcher.py", JONAH)

print("— primary (Jonah's phone): rows are exactly what they were —")
rows, rpcs = capture(jonah); emit_all(jonah)
check("3 device rows emitted", len(rows) == 3, str(rows))
check("app is still 'iPhone' on every row", all(r["app"] == "iPhone" for r in rows), str(rows))
check("reasons are byte-for-byte the pre-change strings",
      [r["reason"] for r in rows] == ["phone: pornhub.com",
          "phone-signal: DNS-over-HTTPS bypass attempt to 1.1.1.1",
          "phone-signal: Tor connection to guard relay 9.9.9.9"],
      str([r["reason"] for r in rows]))
check("heartbeat RPC is still eg_phone_heartbeat", rpcs == [("eg_phone_heartbeat", {"p_active": True})], str(rpcs))
check("dark verdict default is still 'flagged', not secondary",
      jonah.DARK_VERDICT == "flagged" and jonah.SECONDARY is False and jonah.REASON_PREFIX == "")
check("primary still refuses Jada's tunnel IP even when its config lists it",
      "10.1.0.5" not in jonah.CONNLOG_IPMAP and jonah._CONNLOG_DROPPED == ["10.1.0.5"])

print("— secondary (Jada's phone): own label, own prefix, own RPC —")
check("--conf on argv wins over EG_PHONE_CONF", jada.HOME_IP == "192.168.8.113")
rows, rpcs = capture(jada); emit_all(jada)
check("3 device rows emitted", len(rows) == 3, str(rows))
check("app is \"Jada's iPhone\" on every row", all(r["app"] == "Jada's iPhone" for r in rows), str(rows))
check("every reason is the primary's string with the jada- prefix",
      [r["reason"] for r in rows] == ["jada-phone: pornhub.com",
          "jada-phone-signal: DNS-over-HTTPS bypass attempt to 1.1.1.1",
          "jada-phone-signal: Tor connection to guard relay 9.9.9.9"],
      str([r["reason"] for r in rows]))
check("no reason starts with 'phone' (eg_on_red's Jonah-phone branches all key on a phone-... prefix)",
      not any(r["reason"].startswith("phone") for r in rows))
check("heartbeat goes to eg_phone_heartbeat_jada", rpcs == [("eg_phone_heartbeat_jada", {"p_active": True})], str(rpcs))
check("her connlog map holds only her device", set(jada.CONNLOG_IPMAP.values()) == {"jada_phone"}
      and set(jada.CONNLOG_IPMAP) == {"192.168.8.113", "10.1.0.5"}, str(jada.CONNLOG_IPMAP))
check("Jonah's connlog line is not read by her instance",
      jada.parse_connlog_line(b"1790000000 N tcp 10.1.0.3 1.2.3.4 443 0", jada.CONNLOG_IPMAP) is None)

print("— phone-dark row (heartbeat_loop, one iteration) —")
class _Stop(Exception): pass
def one_dark(m):
    rows, _ = capture(m)
    m.wg_rx_bytes = lambda: 0
    m.home_ping_alive = lambda: False
    m._evaluate_liveness = lambda *a, **k: (True, 200, False, None)
    def stop(_): raise _Stop()
    m.time.sleep = stop
    try: m.heartbeat_loop()
    except _Stop: pass
    finally: m.time.sleep = __import__("time").sleep
    return rows
r = one_dark(jonah)
check("Jonah: dark row unchanged (flagged, iPhone, reason starts phone-dark)",
      len(r) == 1 and r[0]["verdict"] == "flagged" and r[0]["app"] == "iPhone"
      and r[0]["reason"].startswith("phone-dark: silent for 200s"), str(r))
r = one_dark(jada)
check("Jada: dark row is verdict=alert, her app, reason starts jada-phone-dark",
      len(r) == 1 and r[0]["verdict"] == "alert" and r[0]["app"] == "Jada's iPhone"
      and r[0]["reason"].startswith("jada-phone-dark: silent for 200s"), str(r))

print("— main(): which loops each instance starts —")
def started(m):
    names = []
    class T:
        def __init__(self, target=None, args=(), daemon=None): self.t = target
        def start(self): names.append(self.t.__name__)
    real = m.threading.Thread
    m.threading.Thread = T; m.heartbeat_loop = lambda: None
    try: m.main()
    finally: m.threading.Thread = real
    return names
pj, sj = started(jonah), started(jada)
check("primary runs router_check_loop", "router_check_loop" in pj, str(pj))
check("secondary does NOT run router_check_loop or sleep_relay_loop",
      "router_check_loop" not in sj and "sleep_relay_loop" not in sj, str(sj))
per_device = {"capture_loop", "doh_syn_loop", "tor_syn_loop", "querylog_loop",
              "querylog_watch_loop", "connlog_loop", "wire_answers_loop", "tor_refresh_loop"}
check("secondary runs every per-device detector the primary runs",
      per_device <= set(sj) and per_device <= set(pj), str(sorted(per_device - set(sj))))
check("secondary captures on both home and tunnel (2 of each)",
      all(sj.count(n) == 2 for n in ("capture_loop", "doh_syn_loop", "tor_syn_loop")), str(sj))

print("— watcher: a live secondary can never mask a dead primary —")
P = "  901 root  12m S  /usr/bin/python3 /usr/bin/eyeguard-phone.py\n"
J = "  955 root  12m S  /usr/bin/python3 /usr/bin/eyeguard-phone.py --conf /etc/eyeguard/phone-jada.json\n"
W = "  700 root   9m S  /usr/bin/python3 /usr/bin/eyeguard-router-watcher.py\n"
check("both up", wt.phone_instances(W + P + J) == (True, True))
check("only primary up", wt.phone_instances(W + P) == (True, False))
check("only Jada's up -> primary reads DOWN", wt.phone_instances(W + J) == (False, True))
check("neither", wt.phone_instances(W) == (False, False))
wt._ps = lambda: W + J
check("_phone_process_running() is False when only the secondary is alive", wt._phone_process_running() is False)
wt._ps = lambda: None
check("ps failure is None (not a signal)", wt._phone_process_running() is None)
check("evaluate_jada: healthy", wt.evaluate_jada(True, True, 9999) == [])
check("evaluate_jada: not running", len(wt.evaluate_jada(False, True, 9999)) == 1)
check("evaluate_jada: not enabled at boot", len(wt.evaluate_jada(True, False, 9999)) == 1)
check("evaluate_jada: boot grace", wt.evaluate_jada(False, False, 30) == [])
check("evaluate_jada: ps failure is not a problem", wt.evaluate_jada(None, True, 9999) == [])
posted = []
wt._post_flag = lambda detail, what="", title="": posted.append((what, detail)) or True
wt._ps = lambda: W + P
check("not required when the manifest doesn't list the init", wt._check_jada({"eyeguard-phone.py": "x"}) is False and not posted)
wt._file_hash = lambda p: "sha256:good"
wt._JADA_BAD[0] = 0; wt._JADA_ALERTED[0] = False
man = {"eyeguard-phone-jada.init": "sha256:good"}
orig_up = wt.evaluate_jada
wt.evaluate_jada = lambda running, init_enabled, uptime: orig_up(running, True, 9999)
wt._check_jada(man)
check("required + down: no alert on the first check (debounce)", not posted)
wt._check_jada(man); wt._check_jada(man)
check("required + down: exactly one alert after 2 checks", len(posted) == 1 and posted[0][0] == "Jada's phone monitor", str(posted))
wt._ps = lambda: W + P + J
wt._check_jada(man)
check("recovery re-arms", wt._JADA_BAD[0] == 0 and wt._JADA_ALERTED[0] is False)
wt._file_hash = lambda p: "sha256:edited"
check("edited init script -> tampered", wt._check_jada(man) is True)

print("— manifest, installer and SQL agree with the code —")
gm = (ROOT / "deploy" / "gen_router_manifest.py").read_text()
check("manifest lists eyeguard-phone-jada.init", '"eyeguard-phone-jada.init"' in gm)
init = (ROOT / "router" / "eyeguard-phone-jada.init").read_text()
check("init starts the script with --conf " + wt.JADA_CONF, f"eyeguard-phone.py --conf {wt.JADA_CONF}" in init)
inst = (ROOT / "deploy" / "jada_phone_install.sh").read_text()
sql = (ROOT / "supabase" / "jada_phone.sql").read_text()
for k, v in (("device_app", "Jada's iPhone"), ("reason_prefix", "jada-"),
             ("heartbeat_rpc", "eg_phone_heartbeat_jada"), ("dark_verdict", "alert")):
    check(f"installer writes {k}={v!r}", f'"{k}": "{v}"' in inst)
check("installer sets secondary_instance", '"secondary_instance": True' in inst)
check("installer changes only router_script_version in Jonah's phone.json",
      len(re.findall(r'^src\[', inst, re.M)) == 1 and 'src["router_script_version"]' in inst)
check("SQL trigger WHEN matches the app label", "NEW.app = 'Jada''s iPhone'" in sql)
check("SQL keys dark on the same prefix", "like 'jada-phone-dark%'" in sql)
check("SQL defines the heartbeat RPC the config names", "function public.eg_phone_heartbeat_jada(" in sql)
code_sql = "\n".join(l for l in sql.splitlines() if not l.strip().startswith("--"))
for forbidden in ("function public.eg_on_red", "function public.eg_send_email(", "function public.eg_check_phone(",
                  "function public.eg_phone_heartbeat(", "public.phone_status ", "eg_red_alert"):
    check(f"SQL never touches existing object: {forbidden.strip()}", forbidden not in code_sql)

print()
if fails:
    print(f"FAILED: {len(fails)} — {fails}"); sys.exit(1)
print("all passed")
