-- Sharper phone-dark alert logic using a real "actively in use" signal
-- (2026-09-01/02), not just Find My presence.
--
-- Reframing (Jonah's own insight, worth recording): the right question was
-- never "is the phone on" -- a phone locked and idle in a pocket for hours
-- is also "on" (has power, Find My sees it), but nothing risky can happen
-- on a locked screen either. The real distinction is "is the phone
-- ACTIVELY IN USE right now" vs. not. Both "genuinely powered off" and
-- "locked and idle, VPN backgrounded by iOS" belong on the SAME side of
-- that line -- no monitored activity is possible in either case, so no
-- alert is needed for either. The only case that actually warrants an
-- alert is: the phone is being actively used RIGHT NOW while its traffic
-- isn't flowing through the monitored path.
--
-- The existing findmy_cross_check.sql fix (20-min Find My freshness window)
-- already correctly suppresses the "idle, VPN backgrounded" false-alarm
-- case -- Find My shows the phone present via Bluetooth-mesh relay even
-- while locked, so it doesn't distinguish idle-but-present from off. But
-- that's ALSO its blind spot: Find My shows the exact same "recently seen"
-- result whether the phone is idle in a pocket or being actively browsed
-- with the VPN deliberately disabled -- so the existing fix, while it
-- correctly kills the noise, could ALSO silently suppress a real bypass.
--
-- Fix: a genuinely different signal for "actively in use" -- an iOS
-- Shortcuts "When I Unlock My iPhone" personal automation, which (unlike
-- time-based automations, unreliable when locked -- confirmed via Apple's
-- own forums earlier in this investigation) fires off the literal system
-- unlock event, which iOS delivers reliably regardless of background
-- suspension rules. Shortcuts' "Get Contents of URL" action calls the new
-- eg_report_phone_unlock() RPC directly -- no companion app, no new
-- background process on the phone at all, sidestepping the entire class of
-- iOS background-execution problems this investigation kept running into.
--
-- New truth table for the phone-dark branch:
--   recently unlocked (real activity signal)  -> ALERT, phone was actively
--     used while monitoring was down -- the actual bypass-risk case.
--   not recently unlocked, but Find My shows recent presence -> SUPPRESS,
--     idle/asleep, not actively used (same as before, just no longer the
--     ONLY signal -- now the fallback for "present but not proven active").
--   neither signal available -> ALERT with a note that cross-check data is
--     missing -- fail-safe default when we can't actually tell (matches
--     findmy_cross_check.sql's existing behavior for "not set up yet"),
--     deliberately NOT the same as "phone is truly off" -- if it can't be
--     confirmed off, err toward notifying, same reasoning as every other
--     fail-safe default in this project.

alter table public.phone_status add column if not exists last_unlock_at timestamptz;

-- Called by the iPhone's own "When I Unlock My iPhone" Shortcuts automation
-- via a raw HTTPS POST (Get Contents of URL action) -- no app, no
-- background process, so none of AmneziaWG's iOS background-suspension
-- problems apply to this signal at all. Anon-key callable, same reasoning
-- as every other routine heartbeat-style RPC in this project (routine
-- device activity shouldn't need a password prompt).
create or replace function public.eg_report_phone_unlock() returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.phone_status set last_unlock_at = now() where id = 1;
end $$;
revoke all on function public.eg_report_phone_unlock() from public;
grant execute on function public.eg_report_phone_unlock() to anon;

-- eg_on_red()'s phone-dark branch, refined per the truth table above.
-- EXTENDS findmy_cross_check.sql's version -- everything else in this
-- function (branches for phone-blocked/phone-signal, tampering, and the
-- generic flagged-content branch) is copied verbatim, unchanged.
create or replace function public.eg_on_red() returns trigger
language plpgsql security definer set search_path = public as $$
declare loc text; whenn text; kind text;
declare fm_last timestamptz; fm_recent boolean;
declare unlock_at timestamptz; recently_unlocked boolean;
begin
  whenn := to_char(NEW.flagged_at at time zone 'America/New_York',
                   'Mon DD, HH12:MI AM');
  if NEW.reason like 'phone-dark%' then
    select findmy_last_seen, last_unlock_at into fm_last, unlock_at
      from public.phone_status where id = 1;
    fm_recent := fm_last is not null and now() - fm_last <= interval '20 minutes';
    -- Same 20-minute window as the Find My check -- long enough to survive
    -- findmy_watcher's/Shortcuts' own reporting lag, short enough that an
    -- unlock from hours ago (long since locked back up, phone since gone
    -- properly idle) doesn't get misread as still-active-right-now.
    recently_unlocked := unlock_at is not null and now() - unlock_at <= interval '20 minutes';

    if recently_unlocked then
      perform public.eg_send_email('🚨 EyeGuard — phone actively used while unmonitored',
        format('<p><b>The iPhone was unlocked at %s, but is not currently '
            || 'routing through the monitored network.</b></p>'
            || '<p>Unlike a routine "phone went dark" (which can just mean '
            || 'the phone is asleep and iOS backgrounded the VPN app), this '
            || 'means the phone was ACTIVELY IN USE during this gap -- a real '
            || 'sign monitoring may have been bypassed, not just suspended by '
            || 'iOS. Check in.</p>',
            to_char(unlock_at at time zone 'America/New_York', 'Mon DD, HH12:MI AM')));
      return NEW;
    elsif fm_recent then
      -- Present (Find My) but no evidence of active use -- idle/asleep,
      -- iOS most likely just suspended the VPN app in the background.
      -- Recorded in flags already (the router's own insert, unconditional);
      -- not escalated to email.
      return NEW;
    end if;

    perform public.eg_send_email('📵 EyeGuard — phone went dark',
      format('<p><b>The iPhone stopped routing through the monitored network.</b></p>'
          || '<p>When: %s. The VPN may be off, the phone off, or out of signal. '
          || '%s If it wasn''t expected, it warrants a check-in.</p>', whenn,
          case when fm_last is not null
                 then format('Find My also hasn''t seen it since %s -- a '
                              'stronger signal something''s actually wrong, '
                              'not just iOS suspending the VPN app.',
                              to_char(fm_last at time zone 'America/New_York',
                                      'Mon DD, HH12:MI AM'))
               else 'Find My cross-check has no data yet (not set up, or the '
                    'session needs a fresh login).'
          end));
    return NEW;
  end if;
  if NEW.reason like 'phone-blocked%' or NEW.reason like 'phone-signal%' then
    perform public.eg_send_email('🔴 EyeGuard — phone hit an explicit site',
      format('<p><b>%s</b></p><p>When: %s</p>'
          || '<p>Seen on the iPhone via the network monitor.</p>',
          coalesce(NEW.reason, ''), whenn));
    return NEW;
  end if;
  if NEW.app = 'EyeGuard' or NEW.reason like 'tamper:%' then
    perform public.eg_send_email('🚨 EyeGuard — tampering detected',
      format('<p><b>EyeGuard detected local tampering.</b></p>'
          || '<p><b>When:</b> %s<br><b>Detail:</b> %s</p>'
          || '<p>The cloud record is append-only and cannot be erased.</p>',
          whenn, coalesce(NEW.reason, '')));
    return NEW;
  end if;
  loc := coalesce(NEW.app, 'an app')
       || coalesce(' — ' || nullif(coalesce(NEW.url, NEW.window_title), ''), '');
  kind := case when NEW.is_nudity then 'Explicit nudity'
               else 'Very revealing content' end;
  perform public.eg_send_email('🔴 EyeGuard alert — ' || kind,
    format('<p><b>%s was flagged.</b></p><p><b>When:</b> %s<br>'
        || '<b>Where:</b> %s</p><p>The review image is on the dashboard: '
        || '<a href="https://dirrimp.github.io/EyeGuard/">open dashboard</a></p>',
        kind, whenn, loc));
  return NEW;
end $$;
