#!/usr/bin/env bash
# Shared helper: verify the partner's pause password against the cloud AND
# send the clean-shutdown beacon, atomically, so an AUTHORIZED stop doesn't
# trip a gone-dark alert. Sourced by pause.sh and uninstall_agent.sh.
#
# Admin-trust-model pivot (2026-08-24): the old version made two separate
# calls (eg_check_pause, THEN a raw device_status POST) with a real gap --
# nothing tied them together, so a direct POST with the old secret key could
# set status='clean_shutdown' without ever passing the password check. This
# now calls the single eg_authorized_stop(pw) RPC (supabase/
# anon_client_pivot.sql), which does both atomically server-side, using the
# same public api_key everything else in this app uses (no secret file
# exists anymore).

EG_URL="https://ucgldleacehxjjwwqomk.supabase.co"
EG_DIR="$HOME/Library/Application Support/EyeGuard"
EG_CONFIG="$EG_DIR/config.yaml"

# Config is YAML, but `api_key:` is a distinctive-enough key name to appear
# exactly once in the whole file (confirmed) -- a direct grep/sed avoids
# needing a YAML parser available to plain bash, and avoids the fragile
# "N lines after the supabase: header" approach breaking the moment a
# comment gets added/removed above this key.
_eg_api_key() {
  grep -E '^[[:space:]]*api_key:' "$EG_CONFIG" | head -1 \
    | sed -E 's/^[[:space:]]*api_key:[[:space:]]*//'
}

# Prompt for the partner password, verify it AND set the clean-shutdown
# beacon in one atomic server-side call. Returns 0 if authorized.
eg_authorized_stop() {
  local api_key pw body ok
  api_key=$(_eg_api_key) || return 1
  if [ -z "$api_key" ]; then
    echo "EyeGuard: could not read supabase.api_key from config.yaml." >&2
    return 1
  fi
  read -r -s -p "Partner pause password: " pw; echo
  body=$(printf '%s' "$pw" | python3 -c \
        'import json,sys;print(json.dumps({"pw":sys.stdin.read()}))')
  ok=$(curl -s -X POST "$EG_URL/rest/v1/rpc/eg_authorized_stop" \
        -H "apikey: $api_key" -H "Authorization: Bearer $api_key" \
        -H "Content-Type: application/json" -d "$body")
  [ "$ok" = "true" ]
}
