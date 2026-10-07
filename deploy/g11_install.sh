#!/usr/bin/env bash
# Install / update the EyeGuard MDM files on the G11 from this repo checkout.
# Run it ON the G11 (or `ssh g11 'cd <checkout> && deploy/g11_install.sh'`) as the
# stack user, after Dad has merged the PR AND run its SQL (the poller reports to
# functions that SQL creates). Safe to re-run.
#
#   deploy/g11_install.sh --dry-run   show exactly what would change, change nothing
#   deploy/g11_install.sh             back up, copy, fix the cron line, restart the hook if it changed
#
# What it installs (and nothing else):
#   g11/eg_report.py, g11/eg-report.sh, g11/mdm/poll.py -> $MDM_DIR   (default /opt/kev/mdm)
#   g11/mdm/hook.py                                       -> $HOOK_DIR (default /opt/stack/mdm/hook)
#   cron: the poller runs every 5 minutes (a single line; other cron lines are untouched)
# It refuses to run if the credential file is missing, not mode 0600, or still holds
# the placeholder / a token that is not 64 hex characters. It never prints the token.
set -euo pipefail

DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MDM_DIR="${MDM_DIR:-/opt/kev/mdm}"
HOOK_DIR="${HOOK_DIR:-/opt/stack/mdm/hook}"
CRONTAB_CMD="${CRONTAB_CMD:-crontab}"
DOCKER_CMD="${DOCKER_CMD:-docker}"
CRON_LINE='*/5 * * * * /usr/bin/python3 '"$MDM_DIR"'/poll.py >/dev/null 2>&1  # MDM app-install notifier poller (every 5 min)'
TS="$(date +%Y%m%dT%H%M%S)"
say() { printf '%s\n' "$*"; }
die() { printf 'g11_install: %s\n' "$*" >&2; exit 1; }

# ---- preflight: never install on top of a broken credential ----
CONF="$MDM_DIR/eg-report.json"
[ -f "$CONF" ] || die "$CONF missing (create it first; see deploy/MDM_APP_EVENTS.md)"
MODE="$(stat -c '%a' "$CONF" 2>/dev/null || stat -f '%Lp' "$CONF")"
[ "$MODE" = "600" ] || die "$CONF must be mode 600 (is $MODE)"
python3 - "$CONF" <<'PY' || exit 1
import json, re, sys
t = json.load(open(sys.argv[1])).get("device_token", "")
if not re.fullmatch(r"[0-9a-f]{64}", t):
    sys.exit("g11_install: device_token is not 64 hex characters (placeholder, extra characters, or wrong value)")
PY
for f in g11/eg_report.py g11/eg-report.sh g11/mdm/poll.py g11/mdm/hook.py; do
  [ -f "$REPO/$f" ] || die "$f not found in $REPO (run from a full checkout)"
done

# ---- plan ----
changed=(); hook_changed=0
plan() {   # src dest mode
  local src="$REPO/$1" dest="$2" mode="$3" what=""
  if [ ! -f "$dest" ]; then what=NEW; elif ! cmp -s "$src" "$dest"; then what=CHANGED; fi
  if [ -n "$what" ]; then
    printf '  %-8s %s\n' "$what" "$dest"; changed+=("$src|$dest|$mode")
    if [ "$dest" = "$HOOK_DIR/hook.py" ]; then hook_changed=1; fi
  else printf '  %-8s %s\n' same "$dest"; fi
}
say "Files:"
plan g11/eg_report.py  "$MDM_DIR/eg_report.py"  0755
plan g11/eg-report.sh  "$MDM_DIR/eg-report.sh"  0755
plan g11/mdm/poll.py   "$MDM_DIR/poll.py"       0755
plan g11/mdm/hook.py   "$HOOK_DIR/hook.py"      0644

CUR="$($CRONTAB_CMD -l 2>/dev/null || true)"
NEWCRON="$(printf '%s\n' "$CUR" | grep -v "$MDM_DIR/poll.py" | sed '/^$/d' || true)"
NEWCRON="$(printf '%s\n%s\n' "$NEWCRON" "$CRON_LINE" | sed '/^$/d')"
say "Cron:"
if [ "$(printf '%s\n' "$CUR" | sed '/^$/d')" = "$NEWCRON" ]; then say "  same     poller every 5 minutes"
else say "  CHANGE   poller line -> every 5 minutes"; printf '%s\n' "$CUR" | grep "$MDM_DIR/poll.py" | sed 's/^/             was: /' || true; fi

if [ "$hook_changed" = 1 ]; then say "Hook: will restart container mdm-hook"; else say "Hook: unchanged, no restart"; fi

if [ "$DRY" = 1 ]; then say "(dry run: nothing changed)"; exit 0; fi

# ---- apply ----
if [ "${#changed[@]}" -gt 0 ]; then
  BK="$MDM_DIR/backup-$TS"; mkdir -p "$BK"; chmod 700 "$BK"
  for c in "${changed[@]}"; do
    IFS='|' read -r src dest mode <<<"$c"
    [ -f "$dest" ] && cp -p "$dest" "$BK/$(basename "$dest")"
    install -m "$mode" "$src" "$dest.new" && mv -f "$dest.new" "$dest"
  done
  say "Backed up replaced files to $BK"
fi
printf '%s\n' "$NEWCRON" | $CRONTAB_CMD -
if [ "$hook_changed" = 1 ]; then $DOCKER_CMD restart mdm-hook >/dev/null && say "Restarted mdm-hook"; fi
say "Done. Poller runs every 5 minutes; the server alerts after 15 minutes of silence."
