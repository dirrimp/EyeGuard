#!/usr/bin/env bash
# Router release install -- run by JONAH on his Mac, from the repo root, AFTER Dad has
# published the manifest for <version> (deploy/publish_router_manifest.sh <version>).
#
#   ./deploy/router_release_install.sh <version>
#
# Installs, from THIS checkout (must be the merged main Dad published the manifest from):
#   eyeguard-phone.py, eyeguard-router-watcher.py, connlog.sh, connlog.init
# It REFUSES to touch the router unless the sha256 of every file it is about to
# install matches the published manifest (so the integrity watcher can't false-alarm),
# backs up everything it replaces, restarts the services, verifies, and rolls the phone
# connector back automatically if it doesn't come up.
#
# Reviewed script, no secrets: the anon key is read from the router's own phone.json.
# Bundles PRs #102 #103 #106 + the connlog watcher. LOG-ONLY: nothing here adds an alert
# except the watcher's "connlog stopped/stale/edited" invariant.
set -euo pipefail
V="${1:?usage: $0 <manifest-version>}"
cd "$(dirname "$0")/.."
D=$(date +%F)
PHONE_WG_IP="10.1.0.3"            # JJPWS-Phone (Jonah's phone). Per uci wireguard_server 2026-10-01.
MAC_WG_IPS='["10.1.0.2","10.1.0.4"]'   # Jonahs-Mac, Jonahs-Mac-Remote
EXCLUDED='["10.1.0.5"]'           # Jadas-Phone: NEVER read (also hard-refused in code)
FILES="eyeguard-phone.py eyeguard-router-watcher.py connlog.sh connlog.init"
R="ssh router"

echo "== 1. local files =="
for f in $FILES; do test -f router/$f || { echo "missing router/$f"; exit 1; }; shasum -a 256 router/$f | cut -c1-16,65-; done
git status --porcelain router deploy | grep . && echo "WARNING: uncommitted changes under router/ or deploy/ -- must equal merged main" || true

echo "== 2. push to router staging (/tmp/eg-release) =="
$R 'rm -rf /tmp/eg-release && mkdir -p /tmp/eg-release'
for f in $FILES; do cat router/$f | $R "cat > /tmp/eg-release/$f"; done

echo "== 3. verify staged files against the PUBLISHED manifest (abort on any mismatch) =="
$R "V='$V' sh -s" <<'REMOTE'
set -e
cd /tmp/eg-release
KEY=$(python3 -c "import json;print(json.load(open('/etc/eyeguard/phone.json'))['api_key'])")
SB=$(python3 -c "import json;print(json.load(open('/etc/eyeguard/phone.json'))['supabase_url'].rstrip('/'))")
M=$(curl -s --max-time 20 "$SB/rest/v1/router_manifests?version=eq.$V&select=manifest" -H "apikey: $KEY" -H "Authorization: Bearer $KEY")
[ "$M" != "[]" ] && [ -n "$M" ] || { echo "ABORT: no manifest published for version $V (Dad must publish first)"; exit 1; }
ok=1
for pair in eyeguard-phone.py:eyeguard-phone.py connlog.sh:connlog.sh connlog.init:connlog.init; do
  name=${pair%%:*}; f=${pair##*:}
  live=$(sha256sum $f | cut -d' ' -f1)
  echo "$M" | grep -q "sha256:$live" && echo "  match  $name" || { echo "  MISMATCH $name (staged $live)"; ok=0; }
done
[ $ok = 1 ] || { echo "ABORT: staged files do not match manifest $V"; exit 1; }
REMOTE

echo "== 4. read-only preflight (device map) =="
$R "echo 'phone.json wg_ip: '\$(python3 -c \"import json;print(json.load(open('/etc/eyeguard/phone.json')).get('wg_ip'))\"), home_ip: \$(python3 -c \"import json;print(json.load(open('/etc/eyeguard/phone.json')).get('home_ip'))\")"
$R "uci show dhcp 2>/dev/null | grep -B3 -A2 \"ip='192.168.8.153'\" | grep -E \"name|ip=\" || echo 'NOTE: no DHCP reservation found for 192.168.8.153 -- verify the phone home IP'"
$R "awg show wgserver allowed-ips 2>/dev/null | awk '{print \$2}'"
echo "  ^ expect 10.1.0.2/.3/.4/.5 -- .3 must be the phone; .5 (Jada) is excluded below"
CUR_WG=$($R "python3 -c \"import json;print(json.load(open('/etc/eyeguard/phone.json')).get('wg_ip'))\"")
[ "$CUR_WG" = "$PHONE_WG_IP" ] || echo "WARNING: phone.json wg_ip=$CUR_WG but the phone's tunnel IP is $PHONE_WG_IP -- left unchanged; fix deliberately (see phone.config.example _wg note)"

echo "== 5. back up + install =="
$R "V='$V' D='$D' PHONE_WG_IP='$PHONE_WG_IP' MAC='$MAC_WG_IPS' EXCL='$EXCLUDED' sh -s" <<'REMOTE'
set -e
S=/tmp/eg-release
# Never overwrite an existing backup (a same-day re-run would replace the real "before" copy).
for p in /usr/bin/eyeguard-phone.py /usr/bin/eyeguard-router-watcher.py /usr/bin/connlog.sh /etc/init.d/connlog /etc/eyeguard/phone.json; do
  if [ -f $p ] && [ ! -f $p.bak-$D-release ]; then cp $p $p.bak-$D-release; fi
done
python3 - <<'PY'
import json, os
p = "/etc/eyeguard/phone.json"
c = json.load(open(p))
c["router_script_version"] = os.environ["V"]
home = c.get("home_ip")
c["connlog_devices"] = {"phone": [i for i in (home, os.environ["PHONE_WG_IP"]) if i],
                        "mac": json.loads(os.environ["MAC"])}
c["connlog_excluded_ips"] = json.loads(os.environ["EXCL"])
# AdGuard size_memory was lowered 1000 -> 10 on 2026-10-01 (log now lags ~1 min, verified
# live), so "the log stopped" can fire after 15 min instead of the 4 h pre-change default.
c["querylog_max_lag_seconds"] = 900
json.dump(c, open(p + ".new", "w"), indent=2)
os.replace(p + ".new", p)
print("phone.json: router_script_version=%s connlog_devices=%s" % (os.environ["V"], c["connlog_devices"]))
PY
cp $S/connlog.sh /usr/bin/connlog.sh && chmod 755 /usr/bin/connlog.sh
cp $S/connlog.init /etc/init.d/connlog && chmod 755 /etc/init.d/connlog
cp $S/eyeguard-router-watcher.py /usr/bin/eyeguard-router-watcher.py && chmod 755 /usr/bin/eyeguard-router-watcher.py
# keep the new files across firmware upgrades
for f in /usr/bin/connlog.sh /etc/init.d/connlog /usr/bin/eyeguard-phone.py /usr/bin/eyeguard-router-watcher.py /etc/eyeguard/phone.json; do
  grep -qxF "$f" /etc/sysupgrade.conf || echo "$f" >> /etc/sysupgrade.conf
done
/etc/init.d/connlog enable
REMOTE

echo "== 6. restart services (phone connector last; auto-rollback if it doesn't come up) =="
$R "D='$D' S=/tmp/eg-release sh -s" <<'REMOTE'
# BusyBox on this router has no `pkill` (the old `pkill -f 'tcpdump ...'` line failed
# silently), so stopped instances left their tcpdump children running, re-parented to
# init. Kill exactly those: tcpdump processes whose parent is pid 1. Live instances'
# captures (parent = the python process) are never touched.
reap_orphans() { for p in $(pidof tcpdump); do [ "$(awk '{print $4}' /proc/$p/stat 2>/dev/null)" = 1 ] && kill $p 2>/dev/null; done; return 0; }
/etc/init.d/connlog restart; sleep 3
/etc/init.d/eyeguard-phone stop 2>/dev/null; sleep 2; reap_orphans   # orphaned captures (PHONE.md)
cp $S/eyeguard-phone.py /usr/bin/eyeguard-phone.py && chmod 755 /usr/bin/eyeguard-phone.py
/etc/init.d/eyeguard-phone start; sleep 12
if ! ps w | grep -q '[e]yeguard-phone.py'; then
  echo "FAIL: eyeguard-phone not running -- ROLLING BACK"
  cp /usr/bin/eyeguard-phone.py.bak-$D-release /usr/bin/eyeguard-phone.py
  cp /etc/eyeguard/phone.json.bak-$D-release /etc/eyeguard/phone.json
  /etc/init.d/eyeguard-phone start; exit 1
fi
/etc/init.d/eyeguard-router-watcher restart; sleep 3
echo "--- verify ---"
echo "phone connector:  $(ps w | grep -c '[e]yeguard-phone.py') proc   router-watcher: $(ps w | grep -c '[e]yeguard-router-watcher.py') proc   connlog: $(ps w | grep -c '[c]onntrack -E') conntrack"
echo "connlog newest write age: $(( $(date +%s) - $(date -r $(ls -t /tmp/connlog/log.* | head -1) +%s) ))s (expect <60)"
logread | grep -E "eyeguard-phone\] (connlog|querylog)|router-watcher\]" | tail -8
echo "(connlog stats appear in logread hourly + /tmp/connlog-stats.json; LOG-ONLY, no alerts)"
echo "Rollback: for f in <file>; cp \$f.bak-$D-release \$f; restart the service."
REMOTE
