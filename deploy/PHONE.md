# EyeGuard — iPhone Monitoring (via the router)

iOS can't be monitored by an on-device app (sandbox + only one VPN, which your
WireGuard owns — the exact wall that made you turn A2Y off). So instead the
**router** does it, by watching the phone's DNS traffic directly off the wire
with `tcpdump`. The router's firewall already forces plaintext DNS (DoT/DoH
blocked), so every lookup the phone makes — on home wifi or away on the
WireGuard tunnel — crosses the router in the clear. `router/eyeguard-phone.py`
streams that capture in real time and mirrors it into EyeGuard's Supabase as
the same red/green feed the Mac produces.

> AdGuard Home's own query-log API was tried first and doesn't work here:
> GL.iNet's `--glinet` flag hijacks AdGuard's auth (no login, native or added,
> can read it), and its on-disk log only flushes on shutdown — unusably stale.
> Wire capture sidesteps both problems and, as a bonus, also sees bypass
> attempts (e.g. the phone querying `8.8.8.8` directly instead of the router).

**Status: deployed and running as a persistent `procd` service on the Flint 2
(2026-08-04)**, confirmed posting real green/dark/heartbeat rows end-to-end.

## What it delivers
- 🟢 **Browsing/app trail** — every meaningful domain, collapsed to app names
  (Instagram, TikTok…), throttled so it's browsing not telemetry.
- 🔴 **Explicit site hit** — the phone querying a domain on the explicit-term
  list → red flag + email. (Wire capture only sees the outgoing query, not
  whether AdGuard's filter subsequently blocked it, so a match is flagged red
  outright — the attempt itself is the signal that matters.)
- 📵 **Phone went dark** — no phone traffic (home DNS, home ARP reachability,
  *or* tunnel) for 60s → red flag + email (VPN off / phone off / no signal).
  *Enforced router-side.*
- ⚫ **Monitor offline** — if the router script itself stops (router down), a
  Supabase cron alerts after 5 min.
- 🚨 **Router config tamper-evidence** (added 2026-08-05, for whoever besides
  Dad has the router GUI login) — every 5 min, checks that AdGuard protection,
  the Block-DoT rule, WAN default-deny, SSH key-only auth, GoodCloud staying
  disabled, the admin GUI staying HTTPS-only, and the WireGuard peer set all
  still match the hardened state from the 2026-08-04 lockdown. Any drift → red
  tamper alert + email, same as the browser-extension/VM-software monitors'
  philosophy: can't prevent a local admin from changing these, but it's no
  longer silent. Baselines on first run (no flags then).
- 🔐 **DoH bypass detection** (added 2026-08-05) — DoH can't be network-blocked
  the clean way DoT was (it deliberately reuses port 443, identical to
  ordinary HTTPS). Three layers: AdGuard returns NXDOMAIN for Firefox's
  `use-application-dns.net` canary (auto-disables Firefox's own DoH) + known
  DoH provider hostnames; the firewall REJECTs TCP:443 to known DoH provider
  IPs (both `lan` and `wgserver` sources); this connector watches for the
  initial SYN to those same IPs even though the firewall should already be
  rejecting it — catches a gap (an unlisted provider, a reverted firewall
  rule) the other two layers might miss. Red flag + email, throttled 5 min
  per IP so retry bursts collapse into one alert. Known accepted residual: a
  self-hosted DoH server on an unlisted IP, or Encrypted Client Hello, isn't
  caught by any of this.
- 🧅 **Tor bypass detection** (added 2026-08-17) — DNS-based detection is
  blind to Tor by design: it resolves whatever's actually visited *inside*
  the encrypted circuit, so there's no plaintext DNS query for the green/red
  classifier to see. Instead this watches for the initial SYN of any
  outbound TCP:443 connection matching the phone's current destination
  against the public Guard-flagged relay IP set (Tor's own Onionoo directory
  API, `onionoo.torproject.org`) — a client's first hop must be
  Guard-flagged, so this is the precise signal, not just "any known Tor
  relay." Refreshed every `tor_refresh_seconds` (default 6h; guard relay
  churn means a static list would go stale) with a local cache so a router
  reboot isn't blind until the first live fetch succeeds, and a failed
  refresh keeps the last-known-good list rather than going blind. Red flag +
  email, throttled 5 min per IP. Known accepted residual: pluggable
  transports/bridges (obfs4, meek, snowflake) are specifically designed to
  look like ordinary HTTPS to exactly this kind of IP-list detection — this
  catches default Tor Browser / Onion Browser usage (no bridge configured),
  not a deliberately bridge-configured evasion attempt.

## Install (on the Flint 2, SSH in as root)

```sh
opkg update && opkg install python3-light python3-urllib curl ca-bundle tcpdump-mini

mkdir -p /etc/eyeguard
# 1. the Supabase SECRET key (Dad's project) — root only
printf 'sb_secret_...' > /etc/eyeguard/.supabase_secret && chmod 600 /etc/eyeguard/.supabase_secret
# 2. config — copy the example and fill in the CAPS values
cp phone.config.example /etc/eyeguard/phone.json && vi /etc/eyeguard/phone.json
# 3. the script
cp eyeguard-phone.py /usr/bin/eyeguard-phone.py && chmod 755 /usr/bin/eyeguard-phone.py
```

### Fill in `phone.json`
- `home_ip` — the phone's **Reserved IP** on home wifi (set this in the
  router's Clients page first, and turn OFF Private Wi-Fi Address on the phone
  for your home network — otherwise the IP/MAC drift and capture silently
  stops matching).
- `home_interface` — usually `br-lan` (the default).
- `wg_interface` — the phone's WireGuard interface. Find it with `wg show` —
  it's often **not** `wg0`; GL.iNet's Flint 2 names it e.g. `wgserver`.
- `wg_ip` — the phone's tunnel IP (the `allowed ips` shown for its peer in
  `wg show`, e.g. `10.1.0.2`).
- `wg_peer` — the phone's WireGuard public key (also from `wg show`). This is
  the **sleep-aware liveness signal** — see below.
- Leave `explicit_terms`, `noise_domains`, `app_map` as-is; **tune
  `noise_domains` after a day** — whatever junk shows up in the green trail,
  add its domain here. `.arpa`/`.local` reverse-DNS junk is always dropped.

### Parse out sleep (like the Mac does) — one WireGuard setting
The Mac knows the difference between "asleep" and "killed" because it runs *on*
the Mac and macOS warns it before sleeping. The router runs *off* the phone, so
by default a sleeping phone looks the same as a disabled VPN — both go quiet.

The fix: watch the **WireGuard tunnel**, not just DNS. In the Flint 2 GUI set
the phone's peer **Persistent Keepalive = 25** (seconds). The phone then sends
a tiny packet every 25s *even while asleep*, so its rx-byte counter keeps
climbing while the tunnel is up. The connector reads that
(`wg show <iface> transfer`) and only calls "dark" when the counter
**flatlines** — i.e. the tunnel is genuinely down (VPN off, phone off, or no
signal), not merely asleep. This covers the phone while it's *away* on the
tunnel.

At home, DNS packet activity alone is **not** a reliable liveness signal —
confirmed live (2026-08-04): a locked, idle iPhone on home wifi can go 30-60s+
without a single DNS query, which used to false-fire `phone-dark` during
completely ordinary use. Worse, the natural fallback (an ICMP ping to the
phone's `home_ip`) doesn't fix it either — the same idle phone answers ARP but
**silently drops ICMP echo requests** while its network stack is in a
power-save state, so ping reads it as gone too. The real fix is `home_ping_alive()` in
`eyeguard-phone.py`: it fires a ping only to *force* a fresh ARP probe as a
side effect (the ping's own result is ignored), then reads the kernel's
neighbor-cache state (`ip neigh show <home_ip>`) for `REACHABLE`/`DELAY` — real
L2 presence, not app-layer cooperation. All three signals (DNS, ARP, WG
rx-counter) are OR-combined, so any one being fresh counts as alive; only
silence on all three for `dark_buffer_seconds` (60s) trips phone-dark. The one
case none of them can separate is a real power-off vs tampering — both
flatline identically (iOS, unlike macOS, gives the router no clean-shutdown
signal) — but a monitored phone being *off* is worth knowing too.

### Run it as a service (so it restarts on boot / crash)
Copy `router/eyeguard-phone.init` to `/etc/init.d/eyeguard-phone` (matches this
firmware's actual `USE_PROCD=1`/`start_service()` convention, taken from the
router's own `/etc/init.d/minidlna` — the simpler bare-`start()` procd form
from earlier drafts of this doc is not this firmware's pattern):
```sh
cp router/eyeguard-phone.init /etc/init.d/eyeguard-phone
chmod 755 /etc/init.d/eyeguard-phone && /etc/init.d/eyeguard-phone enable && /etc/init.d/eyeguard-phone start
```
**Kill any foreground test runs first** (`ps | grep eyeguard-phone`) — a
leftover manually-started instance plus the new service means duplicate
tcpdump captures and duplicate/conflicting Supabase posts. Note: killing the
python process does not kill its tcpdump children (they're orphaned, not
tracked by procd) — `kill` those PIDs too, or they linger until their pipe
finally errors out (fast on busy `br-lan`, can take a long time on quiet
`wgserver`).

## Supabase side (one-time)
Run `supabase/phone.sql` in the SQL Editor — it adds the `phone_status`
heartbeat, the phone-specific alert emails, and the monitor-offline cron.
(Already run for this deployment.)

## Verify on-device
```sh
python3 /usr/bin/eyeguard-phone.py      # run in the foreground, watch the output
```
- Browse a normal site on the phone (on home wifi) → a green **iPhone** entry
  appears in the dashboard within seconds. If not: check `home_ip` matches the
  phone's actual current IP (`ip neigh` or the router's Clients page) and that
  Private Wi-Fi Address is off for that network.
- Take the phone off wifi (cellular/away) and browse → same check, this time
  verifying the `wg_interface`/`wg_ip` capture is matching.
- Toggle WireGuard **off** on the phone while away, wait 60s → a **📵 phone
  went dark** email. Toggle back on → entries resume.
- **Home sleep test**: on home wifi, lock the phone and leave it idle > 60s →
  should stay green (verified working 2026-08-04: ~5+ clean minutes through a
  real lock/idle cycle, zero dark flags). If it still goes dark, check
  `home_ip` is still current (`ip neigh show <home_ip>` should read
  `REACHABLE`/`DELAY` — `STALE`/`FAILED` means the reservation or Private Wifi
  Address setting has drifted).
- **Away sleep test** (only meaningful once keepalive is set): away from home,
  lock the phone and leave it idle > 60s with the VPN **on** → should stay
  green. If it still goes dark, keepalive isn't set on the peer, or
  `wg_interface`/`wg_peer` don't match `wg show`'s actual output — check
  `wg show <iface> transfer` climbs while the phone sits locked.
- Watch for green-trail noise (CDNs/telemetry) → add those domains to
  `noise_domains` and restart the service.

## Known limits (same as the Mac's, honestly)
- **DoH** would bypass this entirely — you've locked it down at the router
  (Block-DoT rule + forced plaintext DNS). Keep it so; without it, none of
  this sees anything.
- **App usage is inferred from domains**, not true foreground tracking (iOS
  forbids that to any third party). "Instagram" means the phone talked to
  Instagram's servers, which is the practical A2Y-equivalent.
- **Explicit hits are flagged red without a block/allow distinction** — wire
  capture only sees the query going out, not AdGuard's filtering decision on
  it. Reaching for the domain is treated as the event that matters.
- **60s dark buffer** — with WireGuard keepalive liveness (above), normal
  sleep no longer trips it while away; only a truly-down tunnel does. At home,
  liveness is DNS activity **or** ARP reachability (see above) — a phone idle
  at home with the screen off but connected to wifi stays green even through
  DNS lulls. The most robust form overall is an **MDM always-on VPN** so the
  phone *can't* leave the tunnel at all — then "dark" means only "phone
  genuinely off."
