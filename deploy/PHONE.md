# EyeGuard — iPhone Monitoring (via the router)

iOS can't be monitored by an on-device app (sandbox + only one VPN, which your
WireGuard owns — the exact wall that made you turn A2Y off). So instead the
**router** does it: the phone already tunnels through WireGuard → the Flint 2 →
AdGuard, which logs every domain it touches. `router/eyeguard-phone.py` reads
that log and mirrors it into EyeGuard's Supabase as the same red/yellow/green
feed the Mac produces.

> **Untested on-device.** This is a first draft — verify the AdGuard API auth,
> your phone's client name, and DNS-noise filtering on the actual router (below).

## What it delivers
- 🟢 **Browsing/app trail** — every meaningful domain, collapsed to app names
  (Instagram, TikTok…), throttled so it's browsing not telemetry.
- 🔴 **Explicit site hit** — the phone reaching a porn domain (blocked by AdGuard
  or matching the term list) → red flag + email.
- 📵 **Phone went dark** — no phone activity through AdGuard for 30s → red flag +
  email (VPN off / phone off / no signal). *Enforced router-side for the 30s.*
- ⚫ **Monitor offline** — if the router script itself stops (router down), a
  Supabase cron alerts after 5 min.

## Install (on the Flint 2, SSH in as root)

```sh
opkg update && opkg install python3-light curl ca-bundle

mkdir -p /etc/eyeguard
# 1. the Supabase SECRET key (Dad's project) — root only
printf 'sb_secret_...' > /etc/eyeguard/.supabase_secret && chmod 600 /etc/eyeguard/.supabase_secret
# 2. config — copy the example and fill in the CAPS values
cp phone.config.example /etc/eyeguard/phone.json && vi /etc/eyeguard/phone.json
# 3. the script
cp eyeguard-phone.py /usr/bin/eyeguard-phone.py && chmod 755 /usr/bin/eyeguard-phone.py
```

### Fill in `phone.json`
- `adguard_user` / `adguard_pass` — your AdGuard Home admin login.
- `phone_clients` — how the phone appears in **AdGuard → Settings → Client
  Settings** (a name), and/or its LAN / WireGuard IP. Add every form.
- `wg_interface` — the phone's WireGuard interface on the router (e.g. `wg0`).
  This is the **sleep-aware liveness signal** (see below). Leave empty to fall
  back to DNS-activity, which false-alarms on a normal sleeping phone.
- Leave `explicit_terms`, `noise_domains`, `app_map` as-is; **tune `noise_domains`
  after a day** — whatever junk shows up in the green trail, add its domain here.

### Parse out sleep (like the Mac does) — one WireGuard setting
The Mac knows the difference between "asleep" and "killed" because it runs *on*
the Mac and macOS warns it before sleeping. The router runs *off* the phone, so
by default a sleeping phone looks the same as a disabled VPN — both go quiet.

The fix: watch the **WireGuard tunnel**, not DNS. In the Flint 2 GUI set the
phone's peer **Persistent Keepalive = 25** (seconds). The phone then sends a tiny
packet every 25s *even while asleep*, so its rx-byte counter keeps climbing while
the tunnel is up. The connector reads that (`wg show <iface> transfer`) and only
calls "dark" when the counter **flatlines** — i.e. the tunnel is genuinely down
(VPN off, phone off, or no signal), not merely asleep. Set `wg_interface`
accordingly. The one case it still can't separate is a real power-off vs
tampering — both flatline identically (iOS, unlike macOS, gives the router no
clean-shutdown signal) — but a monitored phone being *off* is worth knowing too.

### Run it as a service (so it restarts on boot / crash)
Create `/etc/init.d/eyeguard-phone`:
```sh
#!/bin/sh /etc/rc.common
START=95
start() { procd_open_instance; procd_set_param command /usr/bin/python3 /usr/bin/eyeguard-phone.py; procd_set_param respawn; procd_close_instance; }
```
```sh
chmod 755 /etc/init.d/eyeguard-phone && /etc/init.d/eyeguard-phone enable && /etc/init.d/eyeguard-phone start
```

## Supabase side (one-time)
Run `supabase/phone.sql` in the SQL Editor — it adds the `phone_status`
heartbeat, the phone-specific alert emails, and the monitor-offline cron.

## Verify on-device
```sh
python3 /usr/bin/eyeguard-phone.py      # run in the foreground, watch the output
```
- Browse a normal site on the phone → a green **iPhone** entry appears in the
  dashboard within ~15s. If not: check `phone_clients` matches AdGuard's client.
- Toggle WireGuard **off** on the phone, wait 30s → a **📵 phone went dark**
  email. Toggle back on → entries resume.
- **Sleep test** (only meaningful once keepalive is set): lock the phone and
  leave it idle > 30s with the VPN **on** → it should stay green, *no* dark email.
  If it still goes dark, keepalive isn't set on the peer or `wg_interface` is
  wrong — check `wg show <iface> transfer` climbs while the phone sits locked.
- Watch for green-trail noise (CDNs/telemetry) → add those domains to
  `noise_domains` and restart the service.

## Known limits (same as the Mac's, honestly)
- **DoH** would bypass AdGuard — you've locked it down at the router. Keep it so.
- **App usage is inferred from domains**, not true foreground tracking (iOS
  forbids that to any third party). "Instagram" means the phone talked to
  Instagram's servers, which is the practical A2Y-equivalent.
- **30s dark buffer** — with WireGuard keepalive liveness (above), normal sleep
  no longer trips it; only a truly-down tunnel does. Without keepalive it falls
  back to DNS-activity and *will* fire on a sleeping phone — raise
  `dark_buffer_seconds` or set keepalive. The most robust form is an **MDM
  always-on VPN** so the phone *can't* leave the tunnel at all — then "dark"
  means only "phone genuinely off."
