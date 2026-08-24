#!/usr/bin/env bash
# Pull the latest approved code into the LOCKED (root-owned) install and restart.
# Run with sudo — Dad types the password. This is the ONLY way code in
# /Library/Application Support/EyeGuard ever changes after the lockdown.
#
# Safety: it only ever moves the deployed copy to origin/main — the branch
# GitHub's branch protection requires Dad's review to merge into (see
# WORKFLOW.md). There is no path from "Jonah's laptop" to this script that
# skips that review.
set -euo pipefail

CODE="/Library/Application Support/EyeGuard"

if [ "$EUID" -ne 0 ]; then
  echo "Run with sudo: sudo ./update.sh" >&2
  exit 1
fi

cd "$CODE"
echo "Current commit: $(git log --oneline -1)"

git fetch origin main
echo
echo "Incoming changes (origin/main vs deployed):"
git log --oneline HEAD..origin/main || true
echo
read -r -p "Deploy these changes? [y/N] " ans
[ "$ans" = "y" ] || [ "$ans" = "Y" ] || { echo "Aborted — nothing deployed."; exit 0; }

# Hard reset the CODE tree to exactly what's on main. Data (flags, pending
# queue) lives outside this tree (see LOCKDOWN.md layout) so a reset here
# never touches monitoring history. Admin-trust-model pivot (2026-08-24):
# there is no more secret key on disk at all -- config.yaml's api_key is the
# same public key that's already safe to commit, so nothing here needs the
# old .supabase_secret chmod step. git checkout also restores each file's
# committed mode (644/755), so scripts keep their executable bit -- no
# separate chmod pass needed.
git reset --hard origin/main

chown -R root:wheel "$CODE"

echo "Restarting session agent + session watcher..."
# Target the monitored user by name, not whoever's active on the console --
# Dad has to be his own active session to type the sudo password for this
# script, so "console user" resolves to HIM, not the monitored user, and the
# agent (tied to the monitored user's own GUI session) never actually
# restarts. Silently no-ops via 2>/dev/null, so this went unnoticed for a
# while: config/code changes landed on disk but never took effect on the
# running agent until it happened to restart some other way.
MONITORED_UID=$(id -u jonahdirrim)
launchctl kickstart -k "gui/$MONITORED_UID/com.eyeguard.monitor" 2>/dev/null || true
launchctl kickstart -k system/com.eyeguard.sessionwatcher
# || true: the first run after this daemon is introduced won't have it
# installed yet -- see deploy/com.eyeguard.deploywatcher.plist, needs a
# one-time `launchctl bootstrap system ...` + `install` first, same
# one-time bootstrap the session watcher itself needed.
launchctl kickstart -k system/com.eyeguard.deploywatcher 2>/dev/null || true

echo "Deployed $(git log --oneline -1)."
