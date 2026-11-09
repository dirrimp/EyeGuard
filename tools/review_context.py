#!/usr/bin/env python3
"""Build the review agent's input for a diff: the diff itself, callers of every changed symbol,
and a mechanical pre-pass for the greppable rules in .review/rules.md. Stdlib only, offline.

EG-PRIV-01: paths matching .review/denylist.txt are WITHHELD (name only, no content, no grep hits).
Paths matching .review/ignore.txt are skipped. Nothing here reads captured data.

Usage: python3 tools/review_context.py [BASE_REF]      (default origin/main; diff is BASE...HEAD)
       python3 tools/review_context.py --diff-file F  (review a saved unified diff; used by tests)
"""
import fnmatch, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REV = ROOT / ".review"
SEARCH_DIRS = ["eyeguard", "router", "g11", "supabase", "deploy", "tests", "tools"]


def _patterns(name):
    p = REV / name
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]


def _match(path, pats):
    base = path.rsplit("/", 1)[-1]
    for pat in pats:
        if pat.endswith("/"):
            if path.startswith(pat) or f"/{pat}" in f"/{path}":
                return True
        elif fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(base, pat) or fnmatch.fnmatch(path, f"*/{pat}"):
            return True
    return False


def denied(path):  # EG-PRIV-01
    return _match(path, _patterns("denylist.txt"))


def ignored(path):
    return _match(path, _patterns("ignore.txt"))


def split_diff(diff):
    """-> {path: [added lines]} from a unified diff; denied/ignored paths are dropped, denied ones reported."""
    files, withheld, cur = {}, [], None
    for line in diff.splitlines():
        m = re.match(r"^\+\+\+ b/(.+)$", line)
        if m:
            p = m.group(1)
            if denied(p):
                withheld.append(p); cur = None
            elif ignored(p):
                cur = None
            else:
                cur = files.setdefault(p, [])
            continue
        if cur is not None and line.startswith("+") and not line.startswith("+++"):
            cur.append(line[1:])
    return files, withheld


SYMBOL_RES = [
    re.compile(r"^\s*(?:async\s+)?def\s+(\w+)"), re.compile(r"^\s*class\s+(\w+)"),
    re.compile(r"create\s+(?:or\s+replace\s+)?function\s+(?:\w+\.)?(\w+)", re.I),
    re.compile(r"^\s{0,8}([a-z_][a-z0-9_]{3,}):\s"),  # yaml-ish config key
]


def symbols(added):
    out = set()
    for l in added:
        for r in SYMBOL_RES:
            m = r.search(l)
            if m:
                out.add(m.group(1))
    return sorted(s for s in out if len(s) > 3)


# Built from fragments so this file does not itself trip tests/test_mail_sender_guard.py (we never edit that guard).
MAIL_RX = "|".join(["api\\.re" + "send\\.com", "smt" + "plib", "\\.send" + "mail\\(", "from_address\\s*[:=]\\s*['\"]"])

# (rule id, severity, file glob, regex on an ADDED line, message)
MECH = [
    ("EG-COV-02", "blocker", "*.py", r"except\b[^:]*:\s*(pass|continue)\s*(#.*)?$", "catch-all swallows errors; log a traceback and surface the state"),
    ("EG-COV-04", "blocker", "*", MAIL_RX, "mail path outside the three SQL senders"),
    ("EG-OPS-02", "major", "*.sh", r"chmod\s+-R", "blanket chmod; git modes are the source of truth"),
    ("EG-OPS-03", "major", "*", r"(~|/Users/[^/\s]+)/(Desktop|Documents|Downloads)/", "app/launchd path under a TCC-protected folder"),
    ("EG-SEC-02", "blocker", "*", r"service_role|BEGIN (RSA |EC |)PRIVATE KEY|sb_secret_", "secret/private key material in the repo"),
    ("EG-SEC-01", "blocker", "*.py", r"(print|log\w*\.\w+|logging\.\w+)\(.*\b(password|secret|token|api_key|private_key)\b", "possible secret value written to a log/stdout"),
]
ALLOW_MARK = "review-ok:"  # "review-ok: EG-XXX-NN <reason>" is ANNOTATED, never downgraded: severity stays, a human/PR body must justify it


def mechanical(files):
    hits = []
    for path, added in files.items():
        for l in added:
            for rid, sev, glob, rx, msg in MECH:
                if fnmatch.fnmatch(path.rsplit("/", 1)[-1], glob) and re.search(rx, l, re.I):
                    if ALLOW_MARK in l and rid in l:
                        msg += " (author marked review-ok; severity unchanged, justify in PR body)"
                    hits.append((rid, sev, path, l.strip()[:140], msg))
    return hits


def callers(sym):
    cmd = ["git", "grep", "-n", "-w", "-I", sym, "--"] + SEARCH_DIRS
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return [l for l in r.stdout.splitlines() if not denied(l.split(":", 1)[0]) and not ignored(l.split(":", 1)[0])][:12]


def build(diff):
    files, withheld = split_diff(diff)
    out = ["# Review input", ""]
    if withheld:
        out += ["## Withheld (EG-PRIV-01, name only)"] + [f"- {p}" for p in withheld] + [""]
    out += ["## Changed files"] + [f"- {p}" for p in files] + [""]
    out += ["## Mechanical pre-pass"]
    hits = mechanical(files)
    out += [f"- **{s}** {r} `{p}`: {m}  `{l}`" for r, s, p, l, m in hits] or ["- none"]
    out += ["", "## Callers of changed symbols (outside the diff)"]
    for path, added in files.items():
        for sym in symbols(added):
            c = callers(sym)
            if c:
                out += [f"### {sym}  ({path})"] + [f"- {x}" for x in c]
    return "\n".join(out) + "\n", hits


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["--diff-file"]:
        diff = Path(a[1]).read_text()
    else:
        base = a[0] if a else "origin/main"
        diff = subprocess.run(["git", "diff", f"{base}...HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    text, hits = build(diff)
    sys.stdout.write(text)
    sys.exit(1 if any(s == "blocker" for _, s, *_ in hits) else 0)
