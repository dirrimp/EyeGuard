#!/usr/bin/env python3
"""Offline test for the review agent's mechanical layer: planted violations are caught, a clean diff passes,
denylisted paths are withheld (EG-PRIV-01), and every rule has the required fields.
No docker, no network, no model. Run: python3 tests/test_review_agent.py"""
import base64, json, re, sys
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
# EG-SEC-02: fires on KEY MATERIAL, never on the secret's name. Fakes are built at run time so this file
# holds no key-shaped text. (The old rule matched the bare word service_role: it flagged every env block that
# NAMED the secret, and it never matched a real legacy service_role JWT, whose payload is base64.)
def b64(o): return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
def fake_jwt(role): return "eyJ" + b64({"alg": "HS256"})[3:] + "." + b64({"iss": "supabase", "role": role}) + "." + "s" * 20
SRV = "service" + "_role"
planted = {
    "new-style secret key": "key = '" + "sb_" + "secret_" + "a1B2c3D4" * 3 + "'",
    "service_role JWT": "SUPABASE_KEY=" + fake_jwt(SRV),
    "service_role JWT in YAML": "  token: \"" + fake_jwt(SRV) + "\"",
    "PEM private key header": "-----BEGIN " + "PRIVATE KEY-----",
    "RSA private key header": "-----BEGIN RSA " + "PRIVATE KEY-----",
    "literal assigned to the setting": "supabase_" + SRV + "_key: " + "9f8e7d6c5b4a3" * 2,
    "literal in an env file": "SUPABASE_" + SRV.upper() + "_KEY=" + "Ab3dEf6hIj9lMn2pQr5tUv8x",
}
for name, line in planted.items():
    check(f"EG-SEC-02 catches {name}", "EG-SEC-02" in ids(diff("config.yaml", line)))
names_only = [
    "      SUPABASE_SERVICE_ROLE_KEY: ${{ secrets.SUPABASE_SERVICE_ROLE_KEY }}",
    "key = os.environ[\"SUPABASE_SERVICE_ROLE_KEY\"]",
    "# the service_role key stays with Dad; the Mac only holds the anon key",
    "needs SUPABASE_SERVICE_ROLE_KEY in env (never printed)",
    "SUPABASE_SERVICE_ROLE_KEY=your-service-role-key-here",
    "select * from pg_roles where rolname = 'service_role';",
    "grant execute on function public.eg_heartbeat to " + SRV + ";",
    "token = " + fake_jwt("anon"),
    "export SUPABASE_URL=https://example.supabase.co",
]
for line in names_only:
    check(f"EG-SEC-02 ignores a name/reference/anon key: {line[:48]!r}", "EG-SEC-02" not in ids(diff("deploy/x.sh", line)))
hit = rc.mechanical(rc.split_diff(diff("config.yaml", planted["service_role JWT"]))[0])
check("a key hit never echoes the line (redacted in the review input)",
      hit and all("eyJ" not in h[3] and "withheld" in h[3] for h in hit)
      and "eyJ" not in rc.build(diff("config.yaml", planted["service_role JWT"]))[0])
check("EG-SEC-02 still a blocker", all(h[1] == "blocker" for h in hit))
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
# EG-PRIV-01, narrowed (the old catch-all `*frames*` withheld code that merely had "frames" in its name)
captured = [
    "flagged_frames/2026-11-10T20-59-12.446472+00-00_alert_d1.jpg",
    "EyeGuard-data/flagged_frames/2026-11-10T20-59-12.446472+00-00_alert_d1.jpg.enc",
    "/Library/Application Support/EyeGuard/flagged_frames/a.bin",
    "frames/a.bin", "x/frames/b.bin", "review_dump/frames/c.dat",
    "2026-11-10T15-48-47.481549+00-00_flagged_d1.jpg", "x/shot.JPEG".lower(), "x/photo.heic", "x/photo.webp",
    "flags.jsonl", "flags.jsonl.locked-by-dad-2026-08-16", "flags_report.html", "x/flags_report_old.html",
    "pending_uploads.jsonl", "EyeGuard-data/anything.txt",
    "keys/dad_private_key.pem", "keys/service_role.txt", ".env", "x/.env",
]
for p in captured:
    check(f"denylist still withholds captured/secret path {p}", rc.denied(p))
source = [
    "tools/purge_frames.py", "tests/test_purge_frames.py", ".github/workflows/purge-frames.yml",
    "eyeguard/frame_crypto.py", "deploy/decrypt_frame.py", "eyeguard/uploader.py",
    "assets/menubar/eye_red.png", "supabase/image_retention_unschedule.sql", "docs/frames-retention.md",
]
for p in source:
    check(f"denylist does not withhold source/asset {p}", not rc.denied(p))
files, withheld = rc.split_diff(diff("tools/purge_frames.py", "x = 1"))
check("a diff of tools/purge_frames.py reaches the review input", len(files) == 1 and not withheld, str((files, withheld)))
files, withheld = rc.split_diff(diff("flagged_frames/a.jpg", "CAPTURED"))
check("a diff of a captured frame is still withheld", not files and withheld == ["flagged_frames/a.jpg"]
      and "CAPTURED" not in rc.build(diff("flagged_frames/a.jpg", "CAPTURED"))[0])
# the core entries cannot be removed quietly
required = ["EyeGuard-data/", "flagged_frames/", "frames/", "flags.jsonl*", "flags_report*", "pending*", "*.enc",
            "*.age", "*.jpg", "*.jpeg", "*private*key*", "*service_role*", ".supabase_secret", "*.pem", ".env"]
have = set(rc._patterns("denylist.txt"))
check("denylist keeps every required entry", all(r in have for r in required), str([r for r in required if r not in have]))
check("denylist has no catch-all that matches the word 'frames' anywhere",
      not any(p.startswith("*") and p.endswith("*") and "frames" in p for p in have))
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
