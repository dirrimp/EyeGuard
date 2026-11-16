#!/usr/bin/env python3
"""The partner dashboard (docs/index.html) must keep its Content-Security-Policy honest.
Offline, stdlib only. Run: python3 tests/test_dashboard_csp.py        (check)
                           python3 tests/test_dashboard_csp.py --fix  (refresh the inline-script hash after an edit)"""
import base64, hashlib, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "docs" / "index.html"
HOST = "ucgldleacehxjjwwqomk.supabase.co"
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

def inline_hash(html):
    m = re.findall(r"<script>(.*?)</script>", html, re.S)
    assert len(m) == 1, f"expected exactly one inline script, found {len(m)}"
    return base64.b64encode(hashlib.sha256(m[0].encode()).digest()).decode()

html = PAGE.read_text()
if "--fix" in sys.argv:
    new = re.sub(r"'sha256-[A-Za-z0-9+/=]+'", f"'sha256-{inline_hash(html)}'", html, count=1)
    PAGE.write_text(new); print("CSP script hash refreshed"); sys.exit(0)

csp = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)"', html)
check("a Content-Security-Policy meta tag exists", bool(csp))
c = csp.group(1) if csp else ""
d = dict(x.strip().split(" ", 1) for x in c.split(";") if x.strip())
check("default-src is 'none'", d.get("default-src") == "'none'")
check("script-src is 'self' plus exactly one hash, no unsafe-inline / unsafe-eval / remote host",
      re.fullmatch(r"'self' 'sha256-[A-Za-z0-9+/=]+'", d.get("script-src", "")) is not None)
check("the script hash matches the inline script (re-run with --fix after editing it)",
      f"'sha256-{inline_hash(html)}'" in d.get("script-src", ""))
check("network only to the project host", d.get("connect-src") == f"https://{HOST} wss://{HOST}")
check("images only from this origin, data:, blob: and the project host", d.get("img-src") == f"'self' data: blob: https://{HOST}")
check("no objects, no base-uri, no form posts", d.get("object-src") == "'none'" and d.get("base-uri") == "'none'" and d.get("form-action") == "'none'")
check("no inline event handler attributes in the markup", not re.search(r"\son[a-z]+\s*=\s*[\"']", re.sub(r"<script>.*?</script>", "", html, flags=re.S)))
js = re.findall(r"<script>(.*?)</script>", html, re.S)[0]
check("no generated markup with an inline handler either", not re.search(r"""<[a-z]+[^>]*\son[a-z]+\s*=""", js))
check("no external script or stylesheet", not re.search(r"""<(script|link)[^>]+(src|href)=["']https?://""", html))
check("the Supabase client is vendored, version-pinned and has an integrity hash",
      re.search(r'<script src="vendor/supabase-js-(\d+\.\d+\.\d+)\.umd\.js" integrity="sha384-([A-Za-z0-9+/=]+)"></script>', html) is not None)
m = re.search(r'src="(vendor/supabase-js-[\d.]+\.umd\.js)" integrity="sha384-([A-Za-z0-9+/=]+)"', html)
if m:
    data = (ROOT / "docs" / m.group(1)).read_bytes()
    sri = base64.b64encode(hashlib.sha384(data).digest()).decode()
    check("the vendored file matches its integrity hash", sri == m.group(2))
    check("the vendored file has no eval / new Function (the CSP has no unsafe-eval)", not re.search(rb"\beval\(|new Function\(", data))
    readme = (ROOT / "docs" / "vendor" / "README.md").read_text()
    check("the vendor README records the same hashes", hashlib.sha256(data).hexdigest() in readme and sri in readme)
ign = (ROOT / ".review" / "ignore.txt").read_text().splitlines()
check("the review agent now reads docs/index.html (it handles keys); only vendor/ is skipped",
      "docs/index.html" not in ign and "docs/vendor/" in ign)

print("\nFAILED: " + ", ".join(fails) if fails else "\nALL OK")
sys.exit(1 if fails else 0)
