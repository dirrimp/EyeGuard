#!/usr/bin/env python3
"""EyeGuard security guardrail.

Runs on every pull request (see .github/workflows/guardrail.yml). It encodes the
invariants that must stay true for EyeGuard to still be doing its job, so a PR
that quietly weakens detection — raising a threshold, disabling a safety toggle,
smuggling a site into the ignore lists, or gutting the socket peer check — fails
CI with a red X and can't be merged, no matter how innocent the diff looks.

This is defense-in-depth, not a proof: it catches the mechanical weakenings, not
a subtle logic change. It does NOT replace the reviewer — it backs them up.

Exit 0 = all invariants hold. Exit 1 = at least one is violated.
"""
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
fails: list[str] = []


def check(name: str, ok: bool, detail: str = ""):
    tag = "ok  " if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        fails.append(name)


cfg = yaml.safe_load((ROOT / "config.yaml").read_text())
d, a = cfg["detection"], cfg["arbiter"]
cap, lg, sb = cfg["capture"], cfg["logging"], cfg["supabase"]
cr = cfg["context_risk"]


def between(name, val, lo, hi):
    check(name, lo <= float(val) <= hi, f"{val} not in [{lo},{hi}]")


print("— detection thresholds stay meaningful —")
between("detection.flag_threshold", d["flag_threshold"], 0.50, 0.85)
between("arbiter.red_threshold", a["red_threshold"], 0.50, 0.75)
between("arbiter.yellow_threshold", a["yellow_threshold"], 0.40, 0.65)
between("arbiter.tile_penalty", a["tile_penalty"], 0.08, 0.25)
check("arbiter.tile_grid >= 3", int(a["tile_grid"]) >= 3, str(a["tile_grid"]))
check("arbiter.min_content_std <= 15", float(a["min_content_std"]) <= 15,
      str(a["min_content_std"]))
check("detection.self_test_seconds <= 3600",
      int(d.get("self_test_seconds", 1800)) <= 3600,
      str(d.get("self_test_seconds")))

print("— capture stays complete —")
check("capture.interval_seconds <= 10", int(cap["interval_seconds"]) <= 10,
      str(cap["interval_seconds"]))
check("capture.change_threshold <= 0.05", float(cap["change_threshold"]) <= 0.05,
      str(cap["change_threshold"]))
check("capture.displays == all", str(cap["displays"]) == "all",
      str(cap["displays"]))

print("— safety toggles stay on —")
for path, val in [
        ("logging.save_flagged_frames", lg.get("save_flagged_frames")),
        ("logging.blur_red_frames", lg.get("blur_red_frames")),
        ("supabase.heartbeat", sb.get("heartbeat")),
        ("file_integrity.enabled", cfg.get("file_integrity", {}).get("enabled")),
        ("session_watcher.enabled", cfg.get("session_watcher", {}).get("enabled")),
        ("deploy_watcher.enabled", cfg.get("deploy_watcher", {}).get("enabled")),
        ("context_risk.enabled", cr.get("enabled")),
        ("activity_logging.enabled", cfg["activity_logging"].get("enabled")),
        ("drm.enabled", cfg["drm"].get("enabled")),
        ("extensions.enabled", cfg.get("extensions", {}).get("enabled")),
        ("vm_monitor.enabled", cfg.get("vm_monitor", {}).get("enabled")),
        ("text.ocr_enabled", cfg.get("text", {}).get("ocr_enabled")),
        ("text.signals_enabled", cfg.get("text", {}).get("signals_enabled"))]:
    check(f"{path} is true", val is True, repr(val))
check("logging.retention_days == 7", int(lg["retention_days"]) == 7,
      str(lg["retention_days"]))

print("— prompt banks aren't gutted —")
check("explicit_prompts >= 5", len(a.get("explicit_prompts", [])) >= 5)
check("suggestive_prompts >= 10", len(a.get("suggestive_prompts", [])) >= 10)
check("safe_prompts >= 100", len(a.get("safe_prompts", [])) >= 100)

print("— no risky site smuggled into the ignore lists —")
DENY = ["porn", "onlyfans", "xvideos", "xhamster", "xnxx", "redtube", "youporn",
        "chaturbate", "instagram", "facebook", "tiktok", "reddit", "twitter",
        "x.com", "snapchat"]
for listname in ("suppress", "low_risk"):
    entries = [str(e).lower() for e in cr.get(listname, [])]
    bad = [e for e in entries if any(term in e for term in DENY)]
    check(f"context_risk.{listname} has no risky sites", not bad, str(bad))

print("— security-critical code is still wired —")
menu = (ROOT / "eyeguard" / "menubar.py").read_text()
uploader_src = (ROOT / "eyeguard" / "uploader.py").read_text()
session_watcher_src = (ROOT / "eyeguard" / "session_watcher.py").read_text()
deploy_watcher_src = (ROOT / "eyeguard" / "deploy_watcher.py").read_text()
check("eyeguard/vault.py deleted (admin-trust-model pivot)",
      not (ROOT / "eyeguard" / "vault.py").exists())
check("no secret/service_role key anywhere in uploader.py",
      "self.secret" not in uploader_src and "secret_file" not in uploader_src)
check("uploader calls the server-stamped heartbeat RPC, not a raw table write",
      "eg_heartbeat" in uploader_src and "eg_report_suspend" in uploader_src
      and "eg_authorized_stop" in uploader_src)
check("menubar wires the (manifest-based) integrity watcher",
      "IntegrityWatcher" in menu)
check("session_watcher checks both new-account and wrong-user",
      "_local_user_accounts" in session_watcher_src
      and "_active_console_user" in session_watcher_src)
check("session_watcher checks for injected libraries in the monitor agent",
      "_untrusted_library" in session_watcher_src
      and "_TRUSTED_LIB_PREFIXES" in session_watcher_src)
check("deploy_watcher polls GitHub and actually deploys on change",
      "_latest_main_sha" in deploy_watcher_src
      and "_deploy" in deploy_watcher_src)
check("uploader encrypts review frames when encryption is configured",
      "encrypt_frame" in uploader_src
      and "encryption_public_key_pem" in uploader_src)
enc_cfg = cfg.get("encryption", {})
check("encryption.enabled=true always has a public_key_pem configured "
      "(prevents flipping it on with an empty key)",
      not enc_cfg.get("enabled") or bool(enc_cfg.get("public_key_pem")))
check("menubar applies context-risk", "assess(" in menu)
check("menubar log-tamper detection present", "report_tamper" in menu
      and "_check_log_tamper" in menu)
check("menubar DRM detection present", "_screen_is_black" in menu)
check("menubar extension monitoring present",
      "scan_extensions" in menu and "log_extension" in menu)
check("extensions.questionable non-empty",
      len(cfg.get("extensions", {}).get("questionable", [])) >= 5)
check("menubar VM-software monitoring present",
      "scan_vm" in menu and "log_vm_software" in menu)
check("menubar text/OCR + signal scanning present",
      "log_text" in menu and "match_terms" in menu)
check("text.terms non-empty (>= 15)",
      len(cfg.get("text", {}).get("terms", [])) >= 15)

print()
if fails:
    print(f"GUARDRAIL FAILED — {len(fails)} invariant(s) violated: {fails}")
    sys.exit(1)
print("GUARDRAIL PASSED — all invariants hold.")
