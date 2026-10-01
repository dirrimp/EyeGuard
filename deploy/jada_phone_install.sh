#!/usr/bin/env bash
# Jada's phone: second-instance install -- run by JONAH on his Mac, from the repo root,
# AFTER Dad has (1) run supabase/jada_phone.sql, (2) merged the PR, and (3) published the
# manifest for <version> from that merged main (deploy/publish_router_manifest.sh <version>).
#
#   ./deploy/jada_phone_install.sh <version>
#
# Installs, from THIS checkout (must be the merged main Dad published the manifest from):
#   eyeguard-phone.py, eyeguard-router-watcher.py, eyeguard-phone-jada.init
# and writes /etc/eyeguard/phone-jada.json (derived from the live phone.json).
#
# It REFUSES to touch the router unless
#   - every staged file matches the published manifest (no integrity false alarm),
#   - the manifest lists eyeguard-phone-jada.init,
#   - Jada's tunnel IP is a real peer and her home IP has a DHCP reservation,
#   - Dad's SQL is live (the eg_phone_heartbeat_jada RPC answers).
# It backs up everything it replaces and rolls the PRIMARY connector (Jonah's phone) back
# automatically if it doesn't come up. Jonah's phone.json is changed in exactly one field:
# router_script_version. His monitoring config is otherwise untouched.
#
# Reviewed script, no secrets: the anon key is read from the router's own phone.json.
# COVERAGE: UP (a second device gets the same detectors). Nothing is removed.
set -euo pipefail
V="${1:?usage: $0 <manifest-version>}"
cd "$(dirname "$0")/.."
D=$(date +%F)
JADA_WG_IP="10.1.0.5"             # Jadas-Phone. Per uci wireguard_server 2026-10-01.
JADA_HOME_IP="192.168.8.113"      # Jadas-iPhone DHCP reservation, 2026-10-01.
FILES="eyeguard-phone.py eyeguard-router-watcher.py eyeguard-phone-jada.init"
R="ssh router"

echo "== 1. local files =="
for f in $FILES; do test -f router/$f || { echo "missing router/$f"; exit 1; }; shasum -a 256 router/$f | cut -c1-16,65-; done
git status --porcelain router deploy | grep . && echo "WARNING: uncommitted changes under router/ or deploy/ -- must equal merged main" || true

echo "== 2. push to router staging (/tmp/eg-jada) =="
$R 'rm -rf /tmp/eg-jada && mkdir -p /tmp/eg-jada'
for f in $FILES; do cat router/$f | $R "cat > /tmp/eg-jada/$f"; done

echo "== 3. verify staged + live files against the PUBLISHED manifest (abort on any mismatch) =="
$R "V='$V' sh -s" <<'REMOTE'
set -e
cd /tmp/eg-jada
KEY=$(python3 -c "import json;print(json.load(open('/etc/eyeguard/phone.json'))['api_key'])")
SB=$(python3 -c "import json;print(json.load(open('/etc/eyeguard/phone.json'))['supabase_url'].rstrip('/'))")
M=$(curl -s --max-time 20 "$SB/rest/v1/router_manifests?version=eq.$V&select=manifest" -H "apikey: $KEY" -H "Authorization: Bearer $KEY")
[ "$M" != "[]" ] && [ -n "$M" ] || { echo "ABORT: no manifest published for version $V (Dad must publish first)"; exit 1; }
echo "$M" | grep -q "eyeguard-phone-jada.init" || { echo "ABORT: manifest $V does not list eyeguard-phone-jada.init -- it was published from a checkout without this PR"; exit 1; }
ok=1
for f in eyeguard-phone.py eyeguard-phone-jada.init; do
  live=$(sha256sum $f | cut -d' ' -f1)
  echo "$M" | grep -q "sha256:$live" && echo "  match  $f" || { echo "  MISMATCH $f (staged $live)"; ok=0; }
done
# connlog files are not reinstalled here, but the new manifest covers them too:
for p in /usr/bin/connlog.sh /etc/init.d/connlog; do
  live=$(sha256sum $p | cut -d' ' -f1)
  echo "$M" | grep -q "sha256:$live" && echo "  match  $p (already installed)" || { echo "  MISMATCH $p (installed $live) -- run deploy/router_release_install.sh first"; ok=0; }
done
[ $ok = 1 ] || { echo "ABORT: files do not match manifest $V"; exit 1; }
REMOTE

echo "== 4. read-only preflight (her device identity + Dad's SQL) =="
$R "JADA_WG_IP='$JADA_WG_IP' JADA_HOME_IP='$JADA_HOME_IP' sh -s" <<'REMOTE'
set -e
awg show wgserver allowed-ips 2>/dev/null | awk '{print $2}' | grep -qx "$JADA_WG_IP/32" \
  || { echo "ABORT: no WireGuard peer with allowed-ips $JADA_WG_IP/32 on wgserver -- check 'uci show wireguard_server' and fix JADA_WG_IP in this script"; exit 1; }
echo "  ok  tunnel peer $JADA_WG_IP exists"
uci show dhcp 2>/dev/null | grep -q "\.ip='$JADA_HOME_IP'" || {
  echo "ABORT: no DHCP reservation for $JADA_HOME_IP."
  echo "  Fix: on Jada's phone, Settings > Wi-Fi > (i) on the home network > Private Wi-Fi Address > Off."
  echo "  Then in the router's Clients page, reserve an IP for her phone, put that IP in JADA_HOME_IP"
  echo "  at the top of this script, and run it again. Without a fixed IP the home capture silently"
  echo "  stops matching her phone."
  exit 1; }
echo "  ok  DHCP reservation for $JADA_HOME_IP exists"
CUR=$(python3 -c "import json;c=json.load(open('/etc/eyeguard/phone.json'));print(c.get('home_ip'),c.get('wg_ip'))")
echo "  primary (Jonah's phone) stays: home_ip/wg_ip = $CUR"
case " $CUR " in *" $JADA_WG_IP "*|*" $JADA_HOME_IP "*) echo "ABORT: phone.json already points at one of Jada's IPs -- the two devices would be mixed up"; exit 1;; esac
KEY=$(python3 -c "import json;print(json.load(open('/etc/eyeguard/phone.json'))['api_key'])")
SB=$(python3 -c "import json;print(json.load(open('/etc/eyeguard/phone.json'))['supabase_url'].rstrip('/'))")
CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X POST "$SB/rest/v1/rpc/eg_phone_heartbeat_jada" \
  -H "apikey: $KEY" -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" -d '{"p_active": null}')
case "$CODE" in 2*) echo "  ok  Dad's SQL is live (eg_phone_heartbeat_jada answered $CODE)";;
  *) echo "ABORT: eg_phone_heartbeat_jada answered http $CODE -- Dad must run supabase/jada_phone.sql first"; exit 1;; esac
REMOTE

echo "== 5. back up + install files + write phone-jada.json =="
$R "V='$V' D='$D' JADA_WG_IP='$JADA_WG_IP' JADA_HOME_IP='$JADA_HOME_IP' sh -s" <<'REMOTE'
set -e
S=/tmp/eg-jada
for p in /usr/bin/eyeguard-phone.py /usr/bin/eyeguard-router-watcher.py /etc/eyeguard/phone.json /etc/eyeguard/phone-jada.json /etc/init.d/eyeguard-phone-jada; do
  [ -f $p ] && cp $p $p.bak-$D-jada
done
JADA_PEER=$(awg show wgserver allowed-ips | awk -v ip="$JADA_WG_IP/32" '$2==ip {print $1}')
[ -n "$JADA_PEER" ] || { echo "ABORT: could not read Jada's peer key"; exit 1; }
[ -f /etc/eyeguard/tor_relays.json ] && cp /etc/eyeguard/tor_relays.json /etc/eyeguard/tor_relays-jada.json   # seed, so she isn't Tor-blind until the first refresh
JADA_PEER="$JADA_PEER" python3 - <<'PY'
import json, os
src = json.load(open("/etc/eyeguard/phone.json"))
keep = ("supabase_url", "api_key", "home_interface", "wg_interface", "explicit_terms",
        "noise_domains", "app_map", "dark_buffer_seconds", "transition_grace_seconds",
        "green_repeat_seconds", "heartbeat_seconds", "report_seconds", "tor_refresh_seconds",
        "querylog_max_lag_seconds", "querylog_missing_alerts", "adguard_querylog_file")
c = {k: src[k] for k in keep if k in src}
home, wg = os.environ["JADA_HOME_IP"], os.environ["JADA_WG_IP"]
c.update({
    "_comment": "Second instance: Jada's iPhone. Written by deploy/jada_phone_install.sh.",
    "device_app": "Jada's iPhone", "reason_prefix": "jada-",
    "heartbeat_rpc": "eg_phone_heartbeat_jada", "dark_verdict": "alert",
    "secondary_instance": True,
    "home_ip": home, "wg_ip": wg, "wg_peer": os.environ["JADA_PEER"],
    "sleep_relay_token": "",
    "tor_relay_cache_file": "/etc/eyeguard/tor_relays-jada.json",
    "connlog_devices": {"jada_phone": [home, wg]}, "connlog_excluded_ips": [],
    "connlog_stats_file": "/tmp/connlog-stats-jada.json",
    "router_script_version": os.environ["V"],
})
json.dump(c, open("/etc/eyeguard/phone-jada.json.new", "w"), indent=2)
os.replace("/etc/eyeguard/phone-jada.json.new", "/etc/eyeguard/phone-jada.json")
p = "/etc/eyeguard/phone.json"
src["router_script_version"] = os.environ["V"]      # the ONLY change to Jonah's config
json.dump(src, open(p + ".new", "w"), indent=2)
os.replace(p + ".new", p)
print("phone-jada.json written: home_ip=%s wg_ip=%s; phone.json router_script_version=%s" % (home, wg, os.environ["V"]))
PY
chmod 600 /etc/eyeguard/phone-jada.json
cp $S/eyeguard-router-watcher.py /usr/bin/eyeguard-router-watcher.py && chmod 755 /usr/bin/eyeguard-router-watcher.py
cp $S/eyeguard-phone-jada.init /etc/init.d/eyeguard-phone-jada && chmod 755 /etc/init.d/eyeguard-phone-jada
for f in /etc/init.d/eyeguard-phone-jada /etc/eyeguard/phone-jada.json /etc/eyeguard/tor_relays-jada.json; do
  grep -qxF "$f" /etc/sysupgrade.conf || echo "$f" >> /etc/sysupgrade.conf
done
REMOTE

echo "== 6. restart: primary first (auto-rollback), then Jada's instance, then the watcher =="
$R "D='$D' S=/tmp/eg-jada sh -s" <<'REMOTE'
primary_up() { ps w | grep '[e]yeguard-phone.py' | grep -qv -- '--conf'; }
jada_up()    { ps w | grep '[e]yeguard-phone.py' | grep -q 'phone-jada.json'; }
/etc/init.d/eyeguard-phone-jada stop 2>/dev/null
/etc/init.d/eyeguard-phone stop 2>/dev/null; pkill -f 'tcpdump -i .* -l -nn' 2>/dev/null   # orphaned captures (PHONE.md)
cp $S/eyeguard-phone.py /usr/bin/eyeguard-phone.py && chmod 755 /usr/bin/eyeguard-phone.py
/etc/init.d/eyeguard-phone start; sleep 12
if ! primary_up; then
  echo "FAIL: primary eyeguard-phone (Jonah's phone) not running -- ROLLING BACK, Jada's instance NOT started"
  cp /usr/bin/eyeguard-phone.py.bak-$D-jada /usr/bin/eyeguard-phone.py
  cp /etc/eyeguard/phone.json.bak-$D-jada /etc/eyeguard/phone.json
  cp /usr/bin/eyeguard-router-watcher.py.bak-$D-jada /usr/bin/eyeguard-router-watcher.py
  /etc/init.d/eyeguard-phone start; /etc/init.d/eyeguard-router-watcher restart; exit 1
fi
/etc/init.d/eyeguard-phone-jada enable
/etc/init.d/eyeguard-phone-jada start; sleep 12
if ! jada_up; then
  echo "FAIL: Jada's instance did not stay up. Jonah's phone monitoring is running normally on the new script."
  echo "      Last log lines:"; logread | grep 'eyeguard-phone' | tail -8
  echo "      The watcher will report 'Jada's phone monitor is not running' until this is fixed. Tell Agent 01."
  /etc/init.d/eyeguard-router-watcher restart; exit 1
fi
/etc/init.d/eyeguard-router-watcher restart; sleep 3
echo "--- verify ---"
echo "primary: $(ps w | grep '[e]yeguard-phone.py' | grep -cv -- '--conf') proc   jada: $(ps w | grep '[e]yeguard-phone.py' | grep -c 'phone-jada.json') proc   router-watcher: $(ps w | grep -c '[e]yeguard-router-watcher.py') proc"
logread | grep -E "eyeguard-phone\] secondary instance|router-watcher\]" | tail -4
echo "Rollback: /etc/init.d/eyeguard-phone-jada stop; /etc/init.d/eyeguard-phone-jada disable; then cp <file>.bak-$D-jada <file> for"
echo "  /usr/bin/eyeguard-phone.py /usr/bin/eyeguard-router-watcher.py /etc/eyeguard/phone.json and restart both services."
echo "  (After a rollback the router runs the previous release; its manifest version is restored with phone.json.)"
REMOTE
echo "Done. Test: on Jada's phone (home Wi-Fi), open any normal site; a green 'Jada's iPhone' card should appear on the dashboard within a minute."
