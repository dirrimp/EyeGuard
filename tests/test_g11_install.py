#!/usr/bin/env python3
"""deploy/g11_install.sh against temp dirs with a fake crontab and fake docker.
Synthetic only. Run: python3 tests/test_g11_install.py"""
import json, os, shutil, stat, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "deploy" / "g11_install.sh"
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

def setup(token="ab" * 32, mode=0o600, cron="MAILTO=x\n0 3 * * * /usr/bin/backup.sh\n*/15 * * * * /usr/bin/python3 {mdm}/poll.py >/dev/null 2>&1\n"):
    t = Path(tempfile.mkdtemp()); mdm = t / "mdm"; hook = t / "hook"; mdm.mkdir(); hook.mkdir()
    cf = mdm / "eg-report.json"; cf.write_text(json.dumps({"supabase_url": "https://x", "anon_key": "k", "device_token": token})); cf.chmod(mode)
    store = t / "cron.txt"; store.write_text(cron.format(mdm=mdm))
    (t / "crontab").write_text(f'#!/bin/sh\nif [ "$1" = "-l" ]; then cat {store}; else cat > {store}; fi\n'); (t / "crontab").chmod(0o755)
    (t / "docker").write_text(f'#!/bin/sh\necho "$@" >> {t}/docker.log\n'); (t / "docker").chmod(0o755)
    env = dict(os.environ, MDM_DIR=str(mdm), HOOK_DIR=str(hook), CRONTAB_CMD=str(t / "crontab"), DOCKER_CMD=str(t / "docker"))
    return t, mdm, hook, store, env
def run(env, *a): return subprocess.run(["bash", str(SCRIPT), *a], capture_output=True, text=True, env=env)

t, mdm, hook, store, env = setup()
before = store.read_text()
r = run(env, "--dry-run")
check("dry run succeeds and reports NEW files and the cron change", r.returncode == 0 and "NEW" in r.stdout and "CHANGE" in r.stdout and "dry run" in r.stdout, r.stdout + r.stderr)
check("dry run changes nothing", store.read_text() == before and not (mdm / "poll.py").exists() and not (t / "docker.log").exists())
r = run(env)
check("install succeeds", r.returncode == 0, r.stdout + r.stderr)
for f, dest, mode in (("g11/eg_report.py", mdm / "eg_report.py", 0o755), ("g11/eg-report.sh", mdm / "eg-report.sh", 0o755),
                      ("g11/mdm/poll.py", mdm / "poll.py", 0o755), ("g11/mdm/hook.py", hook / "hook.py", 0o644)):
    check(f"{f} installed byte-identical with mode {oct(mode)}", dest.read_bytes() == (ROOT / f).read_bytes() and stat.S_IMODE(dest.stat().st_mode) == mode)
cron = store.read_text()
check("poller cron line is every 5 minutes, exactly once", cron.count("poll.py") == 1 and "*/5 * * * *" in cron and "*/15" not in cron, cron)
check("other cron lines are untouched", "MAILTO=x" in cron and "0 3 * * * /usr/bin/backup.sh" in cron)
check("hook container restarted (hook.py was new)", "restart mdm-hook" in (t / "docker.log").read_text())
check("a backup directory was created", any(p.name.startswith("backup-") for p in mdm.iterdir()))
check("the credential file was not touched", json.load(open(mdm / "eg-report.json"))["device_token"] == "ab" * 32 and stat.S_IMODE((mdm / "eg-report.json").stat().st_mode) == 0o600)

(t / "docker.log").unlink(); c1 = store.read_text()
r = run(env)
check("re-run is idempotent: cron identical, no hook restart", store.read_text() == c1 and not (t / "docker.log").exists() and "same" in r.stdout and r.returncode == 0)
(hook / "hook.py").write_text("# someone edited the live copy\n")
r = run(env)
check("a hand-edited live file is detected and restored from the repo",
      "CHANGED" in r.stdout and (hook / "hook.py").read_bytes() == (ROOT / "g11/mdm/hook.py").read_bytes() and (t / "docker.log").exists())
check("...and the edited version was kept in the backup", any("someone edited" in (b / "hook.py").read_text() for b in mdm.iterdir() if b.name.startswith("backup-") and (b / "hook.py").exists()))

for label, kw, msg in (("placeholder token", dict(token="PASTE_TOKEN_HERE"), "64 hex"),
                       ("token with stray characters", dict(token="ab" * 30 + "okay" + "cd"), "64 hex"),
                       ("credential file mode 0644", dict(mode=0o644), "mode 600")):
    t2, mdm2, hook2, store2, env2 = setup(**kw)
    r = run(env2)
    check(f"refuses to install with a {label}", r.returncode != 0 and msg in r.stderr and not (mdm2 / "poll.py").exists(), r.stderr)
t3, mdm3, hook3, store3, env3 = setup(); (mdm3 / "eg-report.json").unlink()
r = run(env3); check("refuses to install without a credential file", r.returncode != 0 and "missing" in r.stderr)

print()
if fails: print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
print("all g11_install tests passed")
