#!/usr/bin/env bash
# Publish a release manifest to public.release_manifests. Run this ONLY on
# your own build machine, using your own service_role key -- never on a
# monitored Mac, never with the anon key (release_manifests has no anon
# insert/update policy by design; see supabase/anon_client_pivot.sql).
#
# Usage:
#   SUPABASE_URL=https://xxxx.supabase.co \
#   SUPABASE_SERVICE_ROLE_KEY=eyJ... \
#   ./deploy/publish_manifest.sh 0.3.0
#
# Both env vars are read from your own shell, never hardcoded here or
# committed anywhere -- get the service_role key from the Supabase
# dashboard (Project Settings -> API), not from this repo.
set -euo pipefail

VERSION="${1:?usage: $0 <version> (reads SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY from env)}"
: "${SUPABASE_URL:?set SUPABASE_URL in your own shell first}"
: "${SUPABASE_SERVICE_ROLE_KEY:?set SUPABASE_SERVICE_ROLE_KEY in your own shell first}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_JSON="$(python3 "$SCRIPT_DIR/gen_manifest.py" "$VERSION")"

BODY="$(python3 -c '
import json, sys
version, manifest = sys.argv[1], json.loads(sys.argv[2])
print(json.dumps({"version": version, "manifest": manifest}))
' "$VERSION" "$MANIFEST_JSON")"

curl -sf -X POST "$SUPABASE_URL/rest/v1/release_manifests" \
  -H "apikey: $SUPABASE_SERVICE_ROLE_KEY" \
  -H "Authorization: Bearer $SUPABASE_SERVICE_ROLE_KEY" \
  -H "Content-Type: application/json" \
  -H "Prefer: resolution=merge-duplicates" \
  -d "$BODY"

echo "Published manifest for version $VERSION."
