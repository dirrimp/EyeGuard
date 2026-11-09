#!/usr/bin/env python3
"""Offline test for the review agent's mechanical layer: planted violations are caught, a clean diff passes,
denylisted paths are withheld (EG-PRIV-01), and every rule has the required fields.
No docker, no network, no model. Run: python3 tests/test_review_agent.py"""
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import review_context as rc

fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

def diff(path, *lines):
    return f"--- a/{path}\n+++ b/{path}\n@@ -0,0 +1 @@\n" + "".join(f"+{l}\n" for l in lines)

def ids(d):
    files, _ = rc.split_diff(d)
    return {h[0] for h in rc.mechanical(files)}

# planted violations -> expected rule
check("EG-COV-02 swallowed except", "EG-COV-02" in ids(diff("eyeguard/x.py", "    except Exception: pass")))
check("EG-COV-04 resend call", "EG-COV-04" in ids(diff("eyeguard/x.py", "requests.post('https://api.resend.com/emails')")))
check("EG-OPS-02 chmod -R", "EG-OPS-02" in ids(diff("deploy/x.sh", "chmod -R 755 /opt/x")))
check("EG-OPS-03 Desktop path", "EG-OPS-03" in ids(diff("deploy/x.plist", "<string>/Users/jonah/Desktop/EyeGuard/run.sh</string>")))
check("EG-SEC-02 service_role", "EG-SEC-02" in ids(diff("config.yaml", "key: service_role_abc")))
check("EG-SEC-01 secret logged", "EG-SEC-01" in ids(diff("eyeguard/x.py", "log.info(f'auth with {password}')")))
# clean diff passes
clean = diff("eyeguard/x.py", "def add(a, b):", "    return a + b")
check("clean diff has no hits", not ids(clean))
check("clean diff exit-code path: no blockers", not [h for h in rc.mechanical(rc.split_diff(clean)[0]) if h[1] == "blocker"])
# false-positive guard: a logged non-secret and a reviewed exception
check("log of a harmless value is not flagged", "EG-SEC-01" not in ids(diff("eyeguard/x.py", "log.info('heartbeat ok')")))
ex = rc.mechanical(rc.split_diff(diff("eyeguard/x.py", "    except Exception: pass  # review-ok: EG-COV-02 shutdown path"))[0])
check("review-ok marker annotates but never downgrades a blocker", ex and ex[0][1] == "blocker" and "review-ok" in ex[0][4])
# EG-PRIV-01
for p in ["EyeGuard-data/a.jpg", "flags.jsonl", "pending_queue.json", "x/frames/1.enc", "keys/service_role.txt"]:
    check(f"denylist withholds {p}", rc.denied(p))
files, withheld = rc.split_diff(diff("EyeGuard-data/secret.txt", "TOP SECRET CONTENT"))
check("denied file content never reaches the review input", not files and withheld == ["EyeGuard-data/secret.txt"]
      and "TOP SECRET" not in rc.build(diff("EyeGuard-data/secret.txt", "TOP SECRET CONTENT"))[0])
check("ignored paths are skipped", not rc.split_diff(diff("assets/logo.svg", "<svg/>"))[0])
check("source files are not denied", not rc.denied("eyeguard/frame_crypto.py") and not rc.denied("deploy/decrypt_frame.py"))
# rules.md structure
txt = (ROOT / ".review/rules.md").read_text()
blocks = re.split(r"\n### ", txt)[1:]
check("rules.md has rules", len(blocks) >= 12, str(len(blocks)))
for b in blocks:
    rid = b.split(" ", 1)[0]
    ok = re.match(r"EG-[A-Z]+-\d\d · (blocker|major|minor) · scope: ", b) and "\nWhy:" in b and "\nCheck:" in b
    check(f"{rid} has severity, scope, Why, Check", bool(ok))
check("rule IDs are unique", len({b.split(' ',1)[0] for b in blocks}) == len(blocks))
for need in ["EG-PRIV-01", "EG-COV-01", "EG-COV-05", "EG-SEC-02"]:
    check(f"{need} present", need in txt)
check("feedback.jsonl exists", (ROOT / ".review/feedback.jsonl").exists())

print("\nFAILED: " + ", ".join(fails) if fails else "\nALL OK")
sys.exit(1 if fails else 0)
