#!/usr/bin/env python3
"""Runs tests/title_viewer.test.js in real Firefox (WebCrypto) when node is not installed (the Mac has none).
Python makes the throwaway records (same block as the node test), a temp HTML page runs the same assertions, and Firefox is driven over Marionette.
Usage: /Applications/EyeGuard.app/Contents/Resources/python/bin/python3.12 tools/title_viewer_firefox_test.py   (needs /Applications/Firefox.app)"""
import json, os, re, socket, subprocess, sys, tempfile, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FF = os.environ.get("EG_FIREFOX", "/Applications/Firefox.app/Contents/MacOS/firefox")
t = open(ROOT + "/tests/title_viewer.test.js").read()
code = re.search(r"const vec = JSON.parse\(py\(`(.*?)`\)\);", t, flags=re.S).group(1).replace("\\\\", "\\")
r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True)
assert r.returncode == 0, r.stderr[-500:]
mid = t[t.index("let fails = 0;"):t.index("const py = ")]
body = t[t.index("(async () => {"):].replace("process.exit(fails === 0 ? 0 : 1);", "document.title = fails === 0 ? 'ALLOK' : 'FAILED';")
html = f'''<!doctype html><meta charset="utf-8"><pre id="o"></pre>
<script src="file://{ROOT}/docs/frame-viewer.js"></script>
<script>
const V = window.EGViewer; const process = {{exit(){{}}}};
const Buffer = {{ from: (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0)) }};
const _o = document.getElementById("o"); console.log = (...a) => {{ _o.textContent += a.join(" ") + "\\n"; }};
window.onerror = (m) => {{ _o.textContent += "ERROR " + m + "\\n"; document.title = "FAILED"; }};
{mid}
const vec = {r.stdout.strip()};
{body}
</script>'''
work = tempfile.mkdtemp(); page = work + "/t.html"; open(page, "w").write(html)
prof = work + "/prof"; os.makedirs(prof); open(prof + "/user.js", "w").write('user_pref("marionette.port", 2828);\n')
ff = subprocess.Popen([FF, "--headless", "--no-remote", "--marionette", "--profile", prof], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(60):
        try: s = socket.create_connection(("127.0.0.1", 2828), timeout=5); break
        except OSError: time.sleep(1)
    else: raise SystemExit("could not reach Firefox")
    buf = b""
    def recv():
        global buf
        while b":" not in buf: buf += s.recv(65536)
        n, rest = buf.split(b":", 1); n = int(n)
        while len(rest) < n: rest += s.recv(65536)
        msg, buf = rest[:n], rest[n:]; return json.loads(msg)
    recv(); i = [0]
    def call(cmd, params=None):
        i[0] += 1; m = json.dumps([0, i[0], cmd, params or {}]).encode(); s.sendall(str(len(m)).encode() + b":" + m)
        while True:
            x = recv()
            if x[0] == 1 and x[1] == i[0]: return x
    call("WebDriver:NewSession", {"capabilities": {}}); call("WebDriver:Navigate", {"url": "file://" + page})
    res = None
    for _ in range(120):
        v = (call("WebDriver:ExecuteScript", {"script": "return [document.title, document.getElementById('o').textContent];", "args": []})[3] or {}).get("value")
        if v and v[0] in ("ALLOK", "FAILED"): res = v; break
        time.sleep(1)
finally:
    ff.terminate()
if not res: print("TIMEOUT"); sys.exit(2)
print(res[1]); print("ALL OK" if res[0] == "ALLOK" else "FAILED"); sys.exit(0 if res[0] == "ALLOK" else 1)
