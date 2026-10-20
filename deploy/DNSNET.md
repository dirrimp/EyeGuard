# Network DNS + bypass monitor (router only)

`router/eyeguard-dnsnet.py`, installed by `deploy/dnsnet_install.sh`. Passive `tcpdump` on the
router's four client segments (`br-lan`, `br-guest`, `br-iot`, `wgserver`). Nothing runs on any
client, so a device cannot opt out by uninstalling something. It sees domain names and
destination IPs, never payload or screens.

## What it does

1. **Every DNS query from every device**, UDP and TCP, including queries aimed at an outside
   resolver (seen before the router's NAT redirect), gets the **same rules** as the phone and Mac
   monitors: `explicit_terms`, `noise_domains` and `app_map` are read from the same
   `/etc/eyeguard/phone.json`. An explicit domain is a red flag. (A test asserts the verdict is
   identical to `eyeguard-phone.py`'s `classify()`.)
2. **Masked or routed-around traffic** is alerted (the extra rule):

| Class | Signal | Default |
|---|---|---|
| `tor-guard` | new TCP connection to a current Tor guard relay, any port (Onionoo list, shared cache) | alert |
| `tor-domain` | lookup of torproject.org (updates, bridges, snowflake) | alert |
| `vpn-domain` | lookup of a VPN / proxy / anti-censorship provider (suffix match; proton.me mail is NOT listed, only Proton VPN endpoints) | alert |
| `private-relay` | lookup of `mask.icloud.com` / `mask-h2.icloud.com` (iCloud Private Relay) | alert |
| `dot-attempt` | any TCP/UDP 853 (DNS-over-TLS / QUIC) to a non-household address | alert |
| `doh-ip` | TCP 443 to a known DoH provider IP (same list as the firewall rules) | alert |
| `vpn-port` | OpenVPN 1194, PPTP 1723, L2TP 1701, WireGuard 51820 | alert |
| `wg-handshake` | a WireGuard handshake (148-byte, type 1) to a non-household address on ANY port | alert |
| `ipv6-enabled` | IPv6 switched on for a client segment (the capture is IPv4-only) | alert |
| `dns-bypass` | plain DNS sent to a resolver other than the router/G11 | observe |
| `doh-host` | lookup of a public DoH hostname | observe |
| `ike-ipsec` | UDP 500/4500 (also Wi-Fi Calling) | observe |
| `proxy-port` | SOCKS 1080, 3128, 8118, 9050/9150, 8388 | observe |

Observe-only classes are counted in `/tmp/dnsnet-stats.json` and an hourly log line, and never email
until promoted with `dnsnet_alert_classes` (new heuristics that could fire on innocent traffic are
measured first, the same way connlog was).

Traffic whose destination is the router or the G11 is never a bypass (the household's own tunnel
and its DoH on 8853).

## How an alert looks

An anon insert into `flags` (no SQL, no new secret), `app = "Network"`, reason `net-signal: ...`
(explicit domain) or `net-bypass: ...`, with the device named from DHCP / the tunnel map. Neither
prefix starts with `phone` or `jada`, so the server's phone-specific logic never evaluates it.
At most one alert per device + class + target every 30 minutes.

## Overlap with the phone monitors

For devices the phone monitors already cover, the three overlapping classes (`explicit-dns`,
`doh-ip`, `tor-guard`) are de-duplicated **only while that monitor's process is running**; if it is
dead, this monitor alerts instead. Every other class is never suppressed.

## It is required once Dad publishes it

`gen_router_manifest.py` lists the daemon and its init script. Once a manifest with them is
published, the router watcher alerts if the monitor stops, is not enabled at boot, goes silent
(status file older than 5 min), loses a capture (16 expected: 4 per interface), or either file
differs from the manifest. Same server-side-requirement rule as connlog and Jada's instance.

## Not covered (honest residuals)

obfs4 / meek / snowflake bridges and AmneziaWG-style obfuscated tunnels (built to defeat these
signatures); a VPN inside the household's own tunnel from outside the home (only the outer tunnel
is visible); DoH to an unlisted private server; IPv6 (disabled today, tripwire above).

## Decisions for Jonah and Dad

- **Jada's phone is never evaluated**: not her tunnel peer (10.1.0.5), not her home address
  (192.168.8.113 and whatever her own `phone-jada.json` says), and not whatever address her
  hardware MAC (84:0f:4c:65:75:6c) holds in the lease file or neighbor table, so a changed DHCP
  address cannot expose her. "Excluded" = her packets are dropped before any rule runs: no DNS
  check, no bypass check, no alert, no record. Her own phone monitor is the only thing that reads
  her DNS. Config can only ADD exclusions; including her is a code change (PR + Dad) and needs both
  of you.
- Alerts reach both partners through the existing sender.

## Install, test, tune

Order: merge, Dad publishes the router manifest (`deploy/publish_router_manifest.sh <version>`),
Jonah runs `./deploy/dnsnet_install.sh <version>` (it checks everything against the manifest first
and stops and disables the monitor if its captures do not all come up). If PR #129 is also merged,
run `deploy/router_release_install.sh <version>` first (the installer refuses otherwise).

Harmless test from the Mac (observe-only, no email): `dig +time=2 +tries=1 @8.8.4.4 example.com`,
then `ssh router 'cat /tmp/dnsnet-stats.json'` and look for `observed.dns-bypass`.
A test that DOES email both partners (tell Dad first): `curl -m3 https://1.1.1.1` raises a
`doh-ip` alert.

Tests: `python3 tests/test_dnsnet.py` and `python3 tests/test_dnsnet_process.py` (real process, fake tcpdump, local receiver). The BPF filters are evaluated by real `tcpdump` against
synthetic pcaps; skipped with a message if tcpdump is missing).
