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
- Leave `explicit_terms`, `noise_domains`, `app_map` as-is; **tune `noise_domains`
  after a day** — whatever junk shows up in the green trail, add its domain here.

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
- Watch for green-trail noise (CDNs/telemetry) → add those domains to
  `noise_domains` and restart the service.

## Known limits (same as the Mac's, honestly)
- **DoH** would bypass AdGuard — you've locked it down at the router. Keep it so.
- **App usage is inferred from domains**, not true foreground tracking (iOS
  forbids that to any third party). "Instagram" means the phone talked to
  Instagram's servers, which is the practical A2Y-equivalent.
- **30s dark buffer is aggressive** — a phone legitimately drops off (signal,
  sleep, airplane mode) and will fire this. If it's noisy, raise
  `dark_buffer_seconds`; the truly robust fix is an **MDM always-on VPN** so the
  phone *can't* leave the tunnel, making "dark" mean only "phone off."
