#!/usr/bin/env python3
"""eyeguard-phone.py must not leave tcpdump captures behind.

1. reap_orphan_captures(): against a fake /proc tree -- kills ONLY tcpdump captures with
   this script's own filter shapes whose parent is init; never a live child, never a foreign
   tcpdump, never another program.
2. A real process: the SIGTERM handler takes every spawned tcpdump down with it
   (mutation-checked: without the handler the children are orphaned).
SIGKILL cannot be caught, so its leftovers are covered by the sweep (1), not by a handler.
Run: python3 tests/test_phone_reap.py
"""
import importlib.util, json, os, signal, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
fails = []


def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        fails.append(name)


d = Path(tempfile.mkdtemp())
(d / "phone.json").write_text(json.dumps({"api_key": "k", "supabase_url": "https://e.invalid"}))
os.environ["EG_PHONE_CONF"] = str(d / "phone.json")
spec = importlib.util.spec_from_file_location("phone_reap_under_test", ROOT / "router" / "eyeguard-phone.py")
ph = importlib.util.module_from_spec(spec); spec.loader.exec_module(ph)

print("-- orphan sweep against a fake /proc --")
fake = d / "proc"; fake.mkdir()


def entry(pid, comm, ppid, argv):
    p = fake / str(pid); p.mkdir()
    (p / "stat").write_text(f"{pid} ({comm}) S {ppid} 1 1 0 -1\n")
    (p / "cmdline").write_text("\0".join(argv) + "\0")


T = "tcpdump"
entry(101, T, 1, [T, "-i", "br-lan", "-l", "-nn", "udp src port 53 and dst host 192.168.8.153"])   # ours, orphan (answers)
entry(102, T, 1, [T, "-i", "wgserver", "-l", "-nn", "udp dst port 53 and src host 10.1.0.3"])       # ours, orphan (queries)
entry(103, T, 1, [T, "-i", "br-lan", "-l", "-nn", "tcp and src host 192.168.8.153 and dst port 443"])  # ours, orphan (syn)
entry(104, T, 4242, [T, "-i", "br-lan", "-l", "-nn", "udp dst port 53 and src host 192.168.8.153"])  # live child
entry(105, T, 1, [T, "-i", "eth1", "-w", "/tmp/x.pcap", "port 80"])                                  # foreign tcpdump, orphan
entry(106, T, 1, [T, "-i", "br-lan", "-l", "-nn", "port 80"])                                        # foreign, same flags
entry(107, "sleep", 1, ["sleep", "600"])                                                             # not tcpdump
entry(108, "tcp)dump (x", 1, ["/usr/sbin/tcpdump", "-i", "br-lan", "-l", "-nn", "tcp and src host 10.1.0.5 and dst port 443"])  # odd comm
(fake / "notapid").mkdir(); (fake / "109").mkdir()                                                    # garbage
sent = []
killed = ph.reap_orphan_captures(str(fake), kill=lambda pid, sig: sent.append((pid, sig)))
check("kills exactly the three orphaned captures of this script (+ the odd-comm one)", sorted(killed) == [101, 102, 103, 108], str(killed))
check("sends SIGTERM", all(s == signal.SIGTERM for _, s in sent))
check("never touches a live child, a foreign tcpdump, or another program",
      not ({104, 105, 106, 107} & set(killed)))
check("missing /proc is harmless", ph.reap_orphan_captures(str(d / "nope")) == [])

print("-- real process: SIGTERM takes the children down --")
(d / "bin").mkdir()
fk = d / "bin" / "tcpdump"
fk.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(600)\n"); fk.chmod(0o755)
harness = d / "harness.py"
HARNESS = '''
import importlib.util, os, signal, sys, time
spec = importlib.util.spec_from_file_location("ph", sys.argv[1]); ph = importlib.util.module_from_spec(spec); spec.loader.exec_module(ph)
if len(sys.argv) > 2 and sys.argv[2] == "handler":
    signal.signal(signal.SIGTERM, ph._terminate_children)
for i in range(3):
    ph._spawn_tcpdump("x%d" % i, "udp dst port 53 and src host 1.2.3.%d" % i)
print("ready", flush=True)
time.sleep(600)
'''
harness.write_text(HARNESS)
env = dict(os.environ, PATH=f"{d / 'bin'}:{os.environ['PATH']}", PYTHONDONTWRITEBYTECODE="1")


def kids():
    return subprocess.run(["pgrep", "-f", str(fk)], capture_output=True, text=True).stdout.split()


def run(mode, sig):
    p = subprocess.Popen([sys.executable, str(harness), str(ROOT / "router" / "eyeguard-phone.py"), mode],
                         env=env, stdout=subprocess.PIPE, text=True)
    p.stdout.readline(); time.sleep(0.5)
    n = len(kids()); p.send_signal(sig)
    try: p.wait(timeout=10)
    except subprocess.TimeoutExpired: p.kill()
    time.sleep(1)
    return n, kids()


n, left = run("handler", signal.SIGTERM)
check("3 captures running, SIGTERM leaves none", n == 3 and left == [], f"{n} {left}")
n, left = run("nohandler", signal.SIGTERM)            # the old behaviour
check("control: WITHOUT the handler SIGTERM leaves all 3 orphaned (proves the test can fail)", n == 3 and len(left) == 3, f"{n} {left}")
subprocess.run(["pkill", "-f", str(fk)]); time.sleep(0.5)

print("-- wiring --")
src = (ROOT / "router" / "eyeguard-phone.py").read_text()
check("every capture goes through _spawn_tcpdump (no raw Popen left)", src.count("subprocess.Popen") == 1 and src.count("_spawn_tcpdump(") >= 5)
check("main() installs the SIGTERM handler and sweeps first",
      "signal.signal(signal.SIGTERM, _terminate_children)" in src and "reap_orphan_captures()" in src)

print()
if fails:
    print(f"{len(fails)} FAILED: {fails}"); sys.exit(1)
print("all reap checks passed")
