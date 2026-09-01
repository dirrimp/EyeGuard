-- Find My cross-check for the phone-dark alert (2026-08-31).
--
-- See eyeguard/findmy_watcher.py's module docstring for the full research
-- and reasoning (why AmneziaWG itself can't be fixed, why Find My is a
-- genuinely independent signal, the accepted tradeoffs of using an
-- unofficial API). Short version: the router's phone-dark detection can
-- only see the WireGuard tunnel, and iOS suspending AmneziaWG's background
-- execution during ordinary idle periods is indistinguishable, from the
-- tunnel's own signals, from the phone actually being off. Find My reports
-- device status via a privileged background mechanism Apple grants only to
-- its own system process -- never to any third-party app -- so it stays
-- current through exactly the gaps that suspend AmneziaWG's keepalive.

alter table public.phone_status add column if not exists findmy_last_seen timestamptz;
alter table public.phone_status add column if not exists findmy_reported_at timestamptz;

-- Called by eyeguard/findmy_watcher.py every check_seconds (default 600s).
-- p_last_seen is Find My's OWN timestamp for the device (not this script's
-- clock) -- an honest signal about the phone, not something a compromised
-- client could favorably fake beyond what Apple's API actually returned.
-- findmy_reported_at (server-stamped, same principle as every other
-- heartbeat in this project) is separate from findmy_last_seen so a stale
-- watcher (this script itself down) is distinguishable from a stale phone.
create or replace function public.eg_report_findmy_status(
  p_last_seen timestamptz
) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.phone_status
     set findmy_last_seen = p_last_seen,
         findmy_reported_at = now()
   where id = 1;
end $$;
revoke all on function public.eg_report_findmy_status(timestamptz) from public;
grant execute on function public.eg_report_findmy_status(timestamptz) to anon;

-- eg_on_red()'s phone-dark branch: before escalating to an email, check
-- whether Find My has seen the phone recently (20 min -- generous enough to
-- absorb findmy_watcher's own 10-min check cadence plus Find My's own
-- reporting lag, tight enough that a REAL outage still alerts promptly).
-- The underlying flags-table row is untouched either way -- always
-- inserted by the router regardless of this function, so the dashboard's
-- activity trail is never missing anything; this only decides whether it
-- escalates to an email or not, exactly the alert-fatigue problem this
-- cross-check exists to fix.
create or replace function public.eg_on_red() returns trigger
language plpgsql security definer set search_path = public as $$
declare loc text; whenn text; kind text;
declare fm_last timestamptz; fm_recent boolean;
begin
  whenn := to_char(NEW.flagged_at at time zone 'America/New_York',
                   'Mon DD, HH12:MI AM');
  if NEW.reason like 'phone-dark%' then
    select findmy_last_seen into fm_last from public.phone_status where id = 1;
    fm_recent := fm_last is not null and now() - fm_last <= interval '20 minutes';
    if fm_recent then
      -- Find My shows real recent activity on the phone -- almost
      -- certainly iOS suspending AmneziaWG's background execution, not a
      -- real outage. Recorded in flags already; not escalated to email.
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
