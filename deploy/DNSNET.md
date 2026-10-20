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
| `tor-guard` | new TCP connection to a current Tor guard relay OR one of Tor Browser's published default bridges, any port | alert |
| `private-relay` | a real TLS connection to iCloud Private Relay (`mask.icloud.com` / `mask-h2.icloud.com` as the server name) | alert |
| `dot-attempt` | any TCP/UDP 853 (DNS-over-TLS / QUIC) to a non-household address | alert |
| `doh-ip` | TCP 443 to a known DoH provider IP (same list as the firewall rules) | alert |
| `vpn-port` | OpenVPN 1194, PPTP 1723, L2TP 1701, WireGuard 51820 | alert |
| `wg-handshake` | a WireGuard handshake (148-byte, type 1) to a non-household address on ANY port | alert |
| `ipv6-enabled` | IPv6 switched on for a client segment (the capture is IPv4-only) | alert |
| `explicit-sni` | the same explicit-site rule applied to the **TLS server name** of a new HTTPS connection, only when that device did NOT just look the name up in DNS (cached, encrypted or bypassed DNS) | alert |
| `vpn-ip` | a connection to a known VPN server address (public list, ~7,000 ranges, refreshed daily) | alert |
| `vpn-domain` / `tor-domain` / `private-relay-lookup` | a DNS **lookup** of a VPN/proxy provider, a Tor Project name, or `mask.icloud.com`. Lookups are not use: on this network Apple devices look up `mask.icloud.com` ~1,300 times a day (AdGuard blocks it and they keep retrying), the Mac's Proton VPN app polls its account API all day, and EyeGuard's own tooling reads torproject.org. Real use is caught by the connection-based classes above. | observe |
| `dns-bypass` | plain DNS sent to a resolver other than the router/G11 | observe |
| `doh-host` | lookup of a public DoH hostname | observe |
| `ike-ipsec` | UDP 500/4500 (also Wi-Fi Calling) | observe |
| `proxy-port` | SOCKS 1080, 3128, 8118, 9050/9150, 8388 | observe |
| `tls-no-sni` | a TLS hello with no server name (common for tunnels) | observe |
| `ech-hidden` | a site hiding its name behind a public Encrypted Client Hello name | observe |
| `dns-tunnel` | many distinct long/random sub-names under one domain from one device in a minute, or one very long random label (iodine/dnscat style) | observe |

Observe-only classes are counted in `/tmp/dnsnet-stats.json` and an hourly log line, and never email
until promoted with `dnsnet_alert_classes` (new heuristics that could fire on innocent traffic are
measured first, the same way connlog was).

Traffic whose destination is the router or the G11 is never a bypass (the household's own tunnel
and its DoH on 8853).

## What it reads, beyond DNS

- **TLS server names (SNI):** one extra capture per segment of TLS ClientHellos only (handshakes, low volume, snaplen 1500 so a late-placed name is still read). A name the device also just looked up in DNS is skipped so one visit is one alert. QUIC/HTTP3 hides the name and is not covered (blocking UDP/443 at the firewall would force TCP; that is a router change for Agent IT).
- **Public lists** (daily, via curl, last good copy kept, a tiny or garbled list is never written): VPN server ranges (`vpn_ranges.txt`) and Tor Browser's default bridges (`tor_bridges.json`). Private custom bridges cannot be listed.

## How an alert looks

An anon insert into `flags` (no SQL, no new secret), `app = "Network"`, reason `net-signal: ...`
(explicit domain) or `net-bypass: ...`. **Every alert names the device that caused it**: name (static
DHCP name, tunnel name, or lease hostname; `UNKNOWN device` if none), IP, MAC (marked when it is a
randomized "private" address) and network segment, e.g.
`net-signal: explicit domain example.com from Jonahs-iPhone: 192.168.8.153, MAC 6e:1c:.. (randomized address), home LAN`.
Neither prefix starts with `phone` or `jada`, so the server's phone-specific logic never evaluates it.
Explicit-content alerts: at most one per device + target every 30 minutes (a repeat visit is the signal, so no backoff). Bypass alerts describe a persistent state, so repeats of the same device + class + target back off: 30 min, 2 h, 8 h, then daily, each marked `[repeat #N]`; the first alert and any new device or target are immediate. Simulated worst case (a device hitting a DoH address every 5 minutes for a week): about 10 emails instead of ~330.

**A device merely appearing is not an alert.** A new phone, a visitor or a new gadget alerts only if it
does something one of the rules above catches, and then the alert describes it.

## Your always-on tunnels

Devices away from home reach the router over AmneziaWG. The monitor reads the tunnel's **decrypted**
side (`wgserver`), never the encrypted packets, and it exempts everything addressed to the router or
the G11 at any port, so a tunnel (away or at home, where the phone dials the router's own public
address) cannot trip a rule. Because the ISP can change that public address and a phone with stale DNS
keeps dialing the old one, every address the router held in the last 24 h stays exempt; tunnel
hostnames can also be listed in `dnsnet_trusted_hostnames`. Only packets that come FROM a household
address are evaluated, so inbound internet packets are never mistaken for a device. The monitor is
passive (tcpdump); it cannot change or interrupt a tunnel, and tunnel-down detection stays with the
phone monitors.

## Overlap with the phone monitors

For devices the phone monitors already cover, the three overlapping classes (`explicit-dns`,
`doh-ip`, `tor-guard`) are de-duplicated **only while that monitor's process is running**; if it is
dead, this monitor alerts instead. Every other class is never suppressed.

## It is required once Dad publishes it

`gen_router_manifest.py` lists the daemon and its init script. Once a manifest with them is
published, the router watcher alerts if the monitor stops, is not enabled at boot, goes silent
(status file older than 5 min), loses a capture (20 expected: 5 per interface), or either file
differs from the manifest. Same server-side-requirement rule as connlog and Jada's instance.

## Not covered (honest residuals)

obfs4 / meek / snowflake bridges and AmneziaWG-style obfuscated tunnels (built to defeat these
signatures); a VPN inside the household's own tunnel from outside the home (only the outer tunnel
is visible); DoH to an unlisted private server; IPv6 (disabled today, tripwire above).

## Scope

**Every device on every segment is evaluated, Jada's phone included** (Jonah's decision 2026-10-20;
Jada knows). Nobody is excluded by default. Exclusion exists only as an explicit config choice
(`dnsnet_excluded_ips` / `dnsnet_excluded_macs`). Alerts reach both partners through the existing sender.

## Will it spam? (traffic simulation)

`python3 tests/sim_dnsnet_traffic.py --days 7` replays a week of simulated household traffic (5 devices,
~320,000 events) through the real rule code on a simulated clock, with real public inputs: the Tranco
top-sites list, the real server IPs of those sites, the public VPN ranges and Tor guard list, and the
live rule config. It also replays what the live network was measured doing (Apple devices looking up
`mask.icloud.com` ~1,300 times a day; the Mac's Proton VPN app polling its API). Everything the
households do is innocent; known-bad events are injected, so any other alert is a false alarm.
Result: **0 false alarms in 7 days (three seeds) and in 30 days; all injected bad events alerted**
(explicit domain, explicit TLS name, Tor guard, DoT, WireGuard handshake, VPN server, Private Relay
connection). `--worst-case` adds a misbehaving TV hitting a DoH address every 5 minutes: about 1.4
emails/day in total (it was 47/day before repeat back-off). Running it also caught that lookup-based
VPN/Tor/Private-Relay alerts would have spammed (now observe-only).

Known limits of the test: synthetic devices, not your real traffic; a connection to an *arbitrary* IP
lands in the VPN list 0.085% of the time (only matters for P2P or odd hosts); one top-1500 site
(`ueiwsp.com`) resolves to `1.1.1.1`, so visiting it trips `doh-ip` by design.

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
