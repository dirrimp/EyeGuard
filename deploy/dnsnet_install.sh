#!/usr/bin/env bash
# Network DNS + bypass monitor: install -- run by JONAH on his Mac, from the repo root,
# AFTER Dad has (1) merged the PR and (2) published the router manifest for <version>
# from that merged main (deploy/publish_router_manifest.sh <version>).
#
#   ./deploy/dnsnet_install.sh <version>
#
# Installs, from THIS checkout (must be the merged main Dad published the manifest from):
#   eyeguard-dnsnet.py, eyeguard-dnsnet.init, eyeguard-router-watcher.py
# No new config file and no new secret: the daemon reads the router's existing phone.json
# (same terms / noise / app map, same anon key). phone.json changes in exactly one field:
# router_script_version.
#
# It REFUSES to touch the router unless
#   - the manifest lists eyeguard-dnsnet.init and every staged file matches it,
#   - the files ALREADY installed (phone connector, connlog, Jada init) match it too (if the
#     manifest carries a newer phone connector, run deploy/router_release_install.sh first),
#   - all four client interfaces exist and tcpdump is present.
# It backs up everything it replaces, starts the monitor, waits for its own status file to
# show every capture running, and otherwise stops and disables it again (leaving the phone
# monitors exactly as they were -- this script never restarts them).
#
# COVERAGE: UP. Nothing is removed or loosened. Adds network-wide DNS rules plus bypass
# (Tor / VPN / DoT / DoH / Private Relay) alerts, and makes the monitor itself REQUIRED.
set -euo pipefail
V="${1:?usage: $0 <manifest-version>}"
cd "$(dirname "$0")/.."
D=$(date +%F)
FILES="eyeguard-router-watcher.py eyeguard-dnsnet.py eyeguard-dnsnet.init"
R="ssh router"

echo "== 1. local files =="
for f in $FILES; do test -f router/$f || { echo "missing router/$f"; exit 1; }; shasum -a 256 router/$f | cut -c1-16,65-; done
git status --porcelain router deploy | grep . && echo "WARNING: uncommitted changes under router/ or deploy/ -- must equal merged main" || true

echo "== 2. push to router staging (/tmp/eg-dnsnet) =="
$R 'rm -rf /tmp/eg-dnsnet && mkdir -p /tmp/eg-dnsnet'
for f in $FILES; do cat router/$f | $R "cat > /tmp/eg-dnsnet/$f"; done

echo "== 3. verify staged + already-installed files against the PUBLISHED manifest =="
$R "V='$V' sh -s" <<'REMOTE'
set -e
cd /tmp/eg-dnsnet
KEY=$(python3 -c "import json;print(json.load(open('/etc/eyeguard/phone.json'))['api_key'])")
SB=$(python3 -c "import json;print(json.load(open('/etc/eyeguard/phone.json'))['supabase_url'].rstrip('/'))")
M=$(curl -s --max-time 20 "$SB/rest/v1/router_manifests?version=eq.$V&select=manifest" -H "apikey: $KEY" -H "Authorization: Bearer $KEY")
[ "$M" != "[]" ] && [ -n "$M" ] || { echo "ABORT: no manifest published for version $V (Dad must publish first)"; exit 1; }
echo "$M" | grep -q "eyeguard-dnsnet.init" || { echo "ABORT: manifest $V does not list eyeguard-dnsnet.init -- it was published from a checkout without this PR"; exit 1; }
ok=1
for f in eyeguard-dnsnet.py eyeguard-dnsnet.init; do
  live=$(sha256sum $f | cut -d' ' -f1)
  echo "$M" | grep -q "sha256:$live" && echo "  match  $f (staged)" || { echo "  MISMATCH $f (staged $live)"; ok=0; }
done
for p in /usr/bin/eyeguard-phone.py /usr/bin/connlog.sh /etc/init.d/connlog /etc/init.d/eyeguard-phone-jada; do
  live=$(sha256sum $p | cut -d' ' -f1)
  echo "$M" | grep -q "sha256:$live" && echo "  match  $p (already installed)" || { echo "  MISMATCH $p (installed $live) -- run deploy/router_release_install.sh first"; ok=0; }
done
[ $ok = 1 ] || { echo "ABORT: files do not match manifest $V"; exit 1; }
REMOTE

echo "== 4. read-only preflight =="
$R sh -s <<'REMOTE'
set -e
which tcpdump >/dev/null || { echo "ABORT: tcpdump missing"; exit 1; }
for i in br-lan br-guest br-iot wgserver; do
  ip link show $i >/dev/null 2>&1 && echo "  ok  interface $i" || { echo "ABORT: interface $i does not exist -- fix dnsnet_interfaces in phone.json first"; exit 1; }
  echo "      ipv6 disabled on $i: $(cat /proc/sys/net/ipv6/conf/$i/disable_ipv6 2>/dev/null)  (1 = good; the monitor is IPv4-only)"
done
python3 -c "import ast;ast.parse(open('/tmp/eg-dnsnet/eyeguard-dnsnet.py').read())" && echo "  ok  staged script compiles under the router's python"
python3 -c "
import json;c=json.load(open('/etc/eyeguard/phone.json'))
assert c.get('explicit_terms') and c.get('api_key') and c.get('supabase_url'); print('  ok  phone.json has terms, noise (%d), app map, key' % len(c.get('noise_domains',[])))"
python3 - <<'PY'
import socket, subprocess, re, json
c = json.load(open("/etc/eyeguard/phone.json"))
mine = set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/", subprocess.run(["ip", "-4", "addr", "show"], capture_output=True, text=True).stdout))
for name in c.get("dnsnet_trusted_hostnames", ["vpn.orthanc.me"]):
    try:
        ips = socket.gethostbyname_ex(name.encode("ascii"))[2]     # bytes: python3-light has no idna codec
        print("  %s  tunnel hostname %s -> %s (%s)" % ("ok " if set(ips) & mine else "WARN", name, ips,
              "is a router address" if set(ips) & mine else "NOT a router address right now: check the DDNS record"))
    except Exception as e:
        print("  WARN tunnel hostname %s does not resolve here: %s" % (name, type(e).__name__))
PY
echo "  memory free: $(awk '/MemAvailable/{print int($2/1024)" MB"}' /proc/meminfo)"
REMOTE

echo "== 5. back up + install =="
$R "V='$V' D='$D' sh -s" <<'REMOTE'
set -e
S=/tmp/eg-dnsnet
for p in /usr/bin/eyeguard-router-watcher.py /usr/bin/eyeguard-dnsnet.py /etc/init.d/eyeguard-dnsnet /etc/eyeguard/phone.json; do
  if [ -f $p ] && [ ! -f $p.bak-$D-dnsnet ]; then cp $p $p.bak-$D-dnsnet; fi
done
python3 - <<'PY'
import json, os
p = "/etc/eyeguard/phone.json"
c = json.load(open(p))
c["router_script_version"] = os.environ["V"]      # the ONLY change to the existing config
json.dump(c, open(p + ".new", "w"), indent=2)
os.replace(p + ".new", p)
print("phone.json: router_script_version=%s (nothing else changed)" % os.environ["V"])
PY
cp $S/eyeguard-dnsnet.py /usr/bin/eyeguard-dnsnet.py && chmod 755 /usr/bin/eyeguard-dnsnet.py
cp $S/eyeguard-dnsnet.init /etc/init.d/eyeguard-dnsnet && chmod 755 /etc/init.d/eyeguard-dnsnet
cp $S/eyeguard-router-watcher.py /usr/bin/eyeguard-router-watcher.py && chmod 755 /usr/bin/eyeguard-router-watcher.py
for f in /usr/bin/eyeguard-dnsnet.py /etc/init.d/eyeguard-dnsnet /usr/bin/eyeguard-router-watcher.py /etc/eyeguard/phone.json /etc/eyeguard/vpn_ranges.txt /etc/eyeguard/tor_bridges.json; do
  grep -qxF "$f" /etc/sysupgrade.conf || echo "$f" >> /etc/sysupgrade.conf
done
REMOTE

echo "== 6. start the monitor (phone monitors are NOT restarted), verify its captures =="
$R "D='$D' sh -s" <<'REMOTE'
/etc/init.d/eyeguard-dnsnet enable
/etc/init.d/eyeguard-dnsnet restart
up=0
for i in 1 2 3 4 5 6 7 8; do          # first status write is within 60 s
  sleep 10
  if [ -f /tmp/dnsnet-stats.json ] && [ $(( $(date +%s) - $(date -r /tmp/dnsnet-stats.json +%s) )) -lt 90 ]; then up=1; break; fi
done
CAP=$(python3 -c "import json;d=json.load(open('/tmp/dnsnet-stats.json'));print(d.get('captures'),'/',d.get('expected_captures'))" 2>/dev/null || echo "?")
if [ $up = 0 ] || [ "$CAP" != "20 / 20" ]; then
  echo "FAIL: network monitor not healthy (status: up=$up captures=$CAP) -- STOPPING and DISABLING it."
  echo "      Phone monitors were not touched. Last log lines:"; logread | grep eyeguard-dnsnet | tail -8
  /etc/init.d/eyeguard-dnsnet stop; /etc/init.d/eyeguard-dnsnet disable
  echo "      NOTE: the manifest lists this monitor as required, so the watcher will report it missing until"
  echo "      this is fixed or Dad publishes a manifest without it. Tell Agent Sauron."
  exit 1
fi
/etc/init.d/eyeguard-router-watcher restart; sleep 3
echo "--- verify ---"
echo "network monitor: $(ps w | grep -c '[e]yeguard-dnsnet.py') proc, captures $CAP, router-watcher: $(ps w | grep -c '[e]yeguard-router-watcher.py') proc"
echo "phone monitors (untouched): $(ps w | grep '[e]yeguard-phone.py' | wc -l) proc"
logread | grep -E "eyeguard-dnsnet\] active" | tail -2
echo "Rollback: /etc/init.d/eyeguard-dnsnet stop; /etc/init.d/eyeguard-dnsnet disable; restore *.bak-$D-dnsnet; restart the watcher."
echo "  (Disabling it while the manifest still lists it makes the watcher alert -- roll back WITH Dad.)"
REMOTE
echo "Done. Harmless test from your Mac (no email, observe-only): dig +time=2 +tries=1 @8.8.4.4 example.com"
echo "  then: ssh router 'cat /tmp/dnsnet-stats.json' and look for observed.dns-bypass.  See deploy/DNSNET.md."
