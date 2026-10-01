-- EyeGuard: sustained phone-dark alert (2026-10-01). COVERAGE: UP.
--
-- The gap this closes
-- -------------------
-- When Jonah's phone stops routing through the monitored network, the router
-- inserts ONE "phone-dark" flag (after 150-190s) for the whole dark period.
-- eg_on_red() then skips the email if Find My saw the phone in the last 20
-- minutes ("present and idle"). Nothing re-checks afterwards. So a phone that
-- is switched ON, on cellular, with the VPN tunnel OFF -- i.e. browsing with
-- no monitoring at all -- is exactly the case where Find My has seen it
-- recently, and no email is ever sent, however long it lasts. Confirmed on
-- 2026-10-01: the dark flag was recorded at 12:52 EDT with the phone on
-- cellular and the tunnel off.
--
-- (drop_phone_unlock_escalation.sql, 2026-09-12, removed the previous attempt
-- at this on the reasoning that a phone "not routing through the monitored
-- path" can't do anything risky. That is true for a phone that is OFF; it is
-- not true for a phone that is on and using cellular directly.)
--
-- What this adds
-- --------------
-- A once-a-minute check: if the phone has been dark for more than 10 minutes
-- and has not been positively shown to be off, email once for that dark
-- period. "Positively shown to be off" = the Find My cross-check is healthy
-- and has NOT seen the phone since it went dark.
--
-- PURELY ADDITIVE: one new column, one new function, one new cron job. It
-- calls the existing eg_send_email() but does not redefine it, and does not
-- touch eg_on_red(), eg_check_phone() or eg_phone_heartbeat(). Safe to re-run.
--
-- Known cost: if iOS suspends the tunnel on an idle phone away from home for
-- more than 10 minutes, this emails even though nothing happened. The email
-- says it is unconfirmed. If that proves noisy, raise the interval below
-- (one line) rather than removing the check.
--
-- It can send a second email for a dark period that eg_on_red() already
-- emailed about (when Find My had not seen the phone at the moment of the
-- flag and then sees it later). That is the informative case, not a bug.

alter table public.phone_status
  add column if not exists sustained_dark_alerted boolean not null default false;

create or replace function public.eg_check_phone_sustained_dark() returns void
language plpgsql security definer set search_path = public as $$
declare p public.phone_status;
declare dark_for interval;
declare fm_healthy boolean;
declare fm_seen_since_dark boolean;
begin
  select * into p from public.phone_status where id = 1;

  -- Back alive: re-arm (only writes when there is something to clear).
  if p.phone_active is true then
    if p.sustained_dark_alerted then
      update public.phone_status set sustained_dark_alerted = false where id = 1;
    end if;
    return;
  end if;

  -- Only judge when the router monitor itself is reporting. If it isn't,
  -- eg_check_phone()'s "phone MONITOR offline" alert already covers that, and
  -- phone_active would be stale.
  if p.phone_active is null or p.monitor_beat is null or p.last_seen is null
     or now() - p.monitor_beat > interval '5 minutes' then
    return;
  end if;

  dark_for := now() - p.last_seen;      -- last_seen = last time confirmed alive
  if dark_for <= interval '10 minutes' or p.sustained_dark_alerted then   -- <-- threshold
    return;
  end if;

  fm_healthy := p.findmy_reported_at is not null
                and now() - p.findmy_reported_at <= interval '20 minutes';
  fm_seen_since_dark := p.findmy_last_seen is not null
                        and p.findmy_last_seen > p.last_seen;

  -- Find My is working and has not seen the phone since it went dark: it is
  -- most likely off or out of signal. Not this alert's case. (Not marked as
  -- alerted, so if Find My later sees it while still dark, this fires then.)
  if fm_healthy and not fm_seen_since_dark then
    return;
  end if;

  update public.phone_status set sustained_dark_alerted = true where id = 1;
  perform public.eg_send_email('📵 EyeGuard — phone on but unmonitored',
    format('<p><b>The iPhone has been off the monitored network for %s.</b></p><p>%s</p>'
        || '<p>Last confirmed on the monitored network: %s. One email is sent '
        || 'per dark period; it re-arms when the phone is back.</p>',
        to_char(dark_for, 'HH24"h" MI"m"'),
        case
          when fm_seen_since_dark then
            format('Find My saw the phone at %s, <b>after</b> it stopped routing '
                || 'through the monitor. So it is switched on and online, but '
                || 'its traffic is not going through the monitored tunnel '
                || '(tunnel off, or iOS suspended it). Anything browsed in this '
                || 'state is not seen. Worth a check-in.',
                to_char(p.findmy_last_seen at time zone 'America/New_York',
                        'Mon DD, HH12:MI AM'))
          else
            'The Find My cross-check is not reporting right now, so this '
            || 'can''t be confirmed either way: the phone may be off, or on '
            || 'and unmonitored. Treat it as unconfirmed.'
        end,
        to_char(p.last_seen at time zone 'America/New_York', 'Mon DD, HH12:MI AM')));
end $$;
revoke all on function public.eg_check_phone_sustained_dark() from public;

select cron.unschedule('eyeguard-phone-sustained-dark')
  where exists (select 1 from cron.job where jobname = 'eyeguard-phone-sustained-dark');
select cron.schedule('eyeguard-phone-sustained-dark', '* * * * *',
  $$ select public.eg_check_phone_sustained_dark(); $$);

-- ---- verify (read-only). Expect one row: true, true. The remaining columns
-- show what the check currently sees, so you can sanity-check it.
select
  exists (select 1 from cron.job where jobname = 'eyeguard-phone-sustained-dark') as cron_scheduled,
  exists (select 1 from information_schema.columns
           where table_schema = 'public' and table_name = 'phone_status'
             and column_name = 'sustained_dark_alerted')                          as column_added,
  p.phone_active, p.last_seen, p.findmy_last_seen, p.findmy_reported_at
from public.phone_status p where p.id = 1;
