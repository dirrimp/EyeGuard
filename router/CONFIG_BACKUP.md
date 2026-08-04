# Router security config — snapshot & rationale (Flint 2, 192.168.8.1)

Documents the router-side hardening done 2026-08-04, "full mirror of the Mac
lockdown" scope. This is a **reviewable reference for Dad**, mirroring how the
Mac's config lives in this git repo — it is NOT a restorable config export
(no secrets, private keys, or full UCI dumps are included here on purpose).

Honest limit, told to and accepted by the user upfront: physical access to the
Flint 2 = a 10-second factory-reset button press that wipes all of this. No
software config can prevent that. The phone connector's existing gone-dark
alert (`eg_check_phone()`, 5-min `monitor_beat` staleness → email) covers this
scenario once the connector is a persistent service (it now is — see
`deploy/PHONE.md`), since a factory reset kills the connector process and its
heartbeat goes stale.

## Remote management — DISABLED
GL.iNet GoodCloud remote-management was found live+enabled with a real
pairing token, linked to an account the user didn't recognize/control.
Disabled outright (`gl-cloud.@cloud[0].enable=0`, service stopped). This was
the single biggest finding of the night — an enabled remote-cloud channel
could have bypassed all local password/lockdown work entirely, from anywhere,
regardless of LAN/SSH/GUI hardening.

## SSH — key-only, Dad's key exclusively
`dropbear.main.PasswordAuth='off'`, `RootPasswordAuth='off'`. Only
`/etc/dropbear/authorized_keys` (Dad's `~/.ssh/eyeguard-router`, ed25519,
generated in Dad's own Mac account — private key never touched Jonah's
session) is accepted. Verified: password SSH gets immediate
`Permission denied (publickey)`. **Structural consequence: every router
command from here on necessarily requires Dad's key — Jonah cannot SSH in.**

## Admin GUI — HTTPS-only, not WAN-exposed
`uhttpd.main.listen_https` only (`0.0.0.0:8443`/`[::]:8443`),
`redirect_https='1'`. The plaintext `:8080` HTTP listener that shipped
enabled was removed. Separately, the router's *real* day-to-day admin UI is
actually served by **nginx** (`gl-ngx`, the Lua-based GL.iNet frontend) on
80/443, not uhttpd/LuCI on 8443 — confirmed via `/etc/nginx/conf.d/gl.conf`.
Both are covered: WAN zone firewall policy is `input='DROP'` by default with
no explicit rule opening 80/443/8443 from WAN (`firewall.@zone[1]`, `name=wan`,
`network='wan' 'wan6' 'wwan' 'secondwan'`).

## DNS — plaintext enforced, DoH/DoT blocked
Firewall rule `Block-DoT` (`dest_port=853`, `target=REJECT`, `src=lan`,
`dest=wan`) is durably persisted in the saved UCI config, not a runtime-only
rule that would vanish on reboot. This is what forces every device's DNS
(including the phone's, even bypass attempts) into the clear, which the phone
connector's wire-capture design depends on. Router-level DoH proxying
(`https-dns-proxy`) is not installed; the DoT client (`stubby`) is present but
`enabled='0'`.

## Confirmed dormant (checked, not just assumed)
Verified genuinely inactive, not merely "configured but who knows":
- **Tor** — not installed/configured (`uci get tor.tor.enable` → entry not
  found).
- **Zerotier** — not configured (`uci get zerotier.sample_config.enabled` →
  entry not found).
- **Tailscale** — no local state file; never joined a tailnet.
- **OpenVPN client (NordVPN + "FromApp")** — `/etc/config/ovpnclient` held
  only provider/group *stub* entries (provider name + a numeric group_id),
  auto-created just by opening the GL.iNet app's VPN-client screen and
  selecting a provider — **no credentials, certs, or profiles were ever
  uploaded** (`/etc/openvpn/profiles/` is empty; `/etc/config/openvpn`'s three
  sections are firmware-stock defaults, all `enabled=0`, unrelated to this).
  User confirmed: "in the admin UI but not activated." Removed as hygiene —
  dormant bypass-capable config left lying around is worth cleaning up even
  when confirmed inactive. *(Requires `uci delete`, which needs to be run
  directly by Dad — not something this session's tooling would auto-apply to
  live router config; see the exact commands in the PR/session history.)*
- **`samba4`** — disabled, confirmed not running.

## Disabled as hygiene (enabled-at-boot but not running)
- **`minidlna`** (DLNA media server) — was enabled, not running. Disabled.
- **`vsftpd`** (FTP server) — was enabled, not running. Disabled.

## Left running (needed)
- **`nginx`** — the real admin GUI backend (`gl-ngx`), confirmed not
  WAN-exposed (see above). Not touched.

## Explicitly NOT done here
- **Router admin/GUI password rotation** — saved for last per user's own
  request. SSH access no longer depends on it (key-only), but the **GUI
  login** still uses the original shared password Jonah knows. When this
  happens: same rule as the Mac lockdown — done by Dad alone, at a keyboard,
  Jonah not watching.
- **Full UCI export / secrets** — deliberately excluded from this file and
  from git entirely. `gl-cloud`'s pairing token, WireGuard private keys, and
  any other credential-shaped values live only on the router itself, never in
  this repo (the same lesson as the earlier Mac-side credential-leak
  incident — see session history, 2026-08-04).
