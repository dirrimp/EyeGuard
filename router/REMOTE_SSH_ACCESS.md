# Enabling remote SSH access over the WireGuard tunnel (Flint 2, 192.168.8.1)

Staged 2026-08-27, ready to apply next time someone has on-LAN or existing-
SSH access to the router. Not yet applied — see "Applying this" at the
bottom for why it can't be done remotely as a first step.

## The problem

`ssh -i ~/.ssh/router-admin root@192.168.8.1` gets an immediate
`Connection refused` whenever Jonah is off the home network (traffic routes
out over the AmneziaWG tunnel — `utun0` on the Mac — to reach `192.168.8.1`),
but works fine on the home LAN. "Refused" (not a timeout) means the router is
actively rejecting the connection attempt before authentication is even
tried — this is a reachability/firewall problem, not a credentials problem;
`~/.ssh/router-admin` (see the admin-trust-pivot notes) is a valid,
full-root key already in `authorized_keys` and works fine once traffic
actually reaches dropbear.

## Most likely cause

CONFIG_BACKUP.md documents the router's SSH hardening (`dropbear.main.
PasswordAuth='off'`, key-only) but doesn't document dropbear's *listen*
scope, and per that same doc, SSH access was originally scoped for Dad
connecting from the LAN only — the WireGuard-tunnel case (Jonah reaching the
router while away) was never part of that hardening pass. Two candidate
causes, not mutually exclusive:

1. **Firewall**: no `ACCEPT` rule exists for port 22 with `src=wgserver`
   (the WireGuard zone name — confirmed elsewhere in this file's config,
   e.g. `Block-DoT`'s `src=wgserver` rule, so the zone name itself isn't in
   question). The WAN zone defaults to `input=DROP`; if the `wgserver` zone's
   default input policy is also non-ACCEPT for undeclared ports, a REJECT
   target would produce exactly this "connection refused" (whereas a DROP
   target would instead just time out — worth checking on the router
   directly, since it changes which fix applies).
2. **dropbear listen address**: if `dropbear.main.Interface` (or equivalent)
   pins it to the LAN interface/IP only, no firewall rule would help --
   dropbear itself never accepts a connection arriving via `wgserver`.

## Diagnosing which one it is (run once, on-LAN or via Dad's key)

```bash
# 1) Is dropbear listening on the WG-side address at all?
ssh -i ~/.ssh/router-admin root@192.168.8.1 "netstat -tlnp | grep :22"
#    0.0.0.0:22 or :::22  -> listening on all interfaces, so it's (1) firewall.
#    only the LAN IP:22   -> it's (2), dropbear's own bind scope.

# 2) What's the WG zone's current firewall policy + any existing SSH rule?
ssh -i ~/.ssh/router-admin root@192.168.8.1 "uci show firewall | grep -B2 -A6 \"name='wgserver'\""
ssh -i ~/.ssh/router-admin root@192.168.8.1 "uci show firewall | grep -i 'ssh\|dest_port=.22.'"
```

## Fix A — firewall rule (if dropbear is already listening on all interfaces)

Opens SSH specifically to the WireGuard zone, not to WAN/the open internet.
Since reaching that zone at all requires a valid WireGuard peer key
(crypto-authenticated before a single SSH packet is even sent), this doesn't
create a new attack surface -- it extends "trusted enough to SSH" from
"physically on the LAN" to "already a keyed VPN peer," which CONFIG_BACKUP.md's
own invariants (WAN default-deny, SSH key-only auth) are unaffected by: WAN
stays closed, key-only auth is untouched, this only adds one more zone
allowed to *reach* dropbear at all.

```bash
uci add firewall rule
uci set firewall.@rule[-1].name='Allow-SSH-from-WG'
uci set firewall.@rule[-1].src='wgserver'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].dest_port='22'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall
/etc/init.d/firewall restart
```

## Fix B — dropbear bind scope (if it's only listening on the LAN IP)

```bash
uci show dropbear   # confirm the exact option name/current value first
uci delete dropbear.main.Interface   # or set it to include the WG interface,
                                      # depending on what's actually set --
                                      # confirm against the `uci show` output
                                      # above before changing anything
uci commit dropbear
/etc/init.d/dropbear restart
```

Fix B is written less precisely than Fix A on purpose -- the exact option
name/value depends on what `uci show dropbear` actually returns, which
requires the same on-LAN/Dad access this whole doc is working around, so
it couldn't be confirmed in advance. Read the live config before applying.

## Applying this

Both diagnosis and fix need one initial SSH session that already works --
i.e. from the home LAN, or via Dad's key -- same catch-22 as the phone-dark
buffer fix in this same PR. After whichever fix applies, Jonah's own
`~/.ssh/router-admin` key should work identically from anywhere, since the
key itself was never the problem.
