-- EyeGuard: sustained phone-dark alert for JADA's phone.  COVERAGE: UP.  2026-10-18.
--
-- PARITY GAP THIS CLOSES
-- Jonah's phone has two dark alerts: an immediate one (eg_on_red) and, since
-- 2026-10-01, a "phone on but unmonitored" check (eg_check_phone_sustained_dark)
-- that re-checks a dark period after 10 minutes. Jada's phone only had the
-- immediate one, and that one is debounced to one email per 30 minutes
-- (eg_on_jada_flag). So: dark at 9:00 (email), back at 9:05, dark again at 9:20
-- (debounced, NO email) and still dark at midnight -> nothing is ever sent.
-- This adds the same re-check for her phone.
--
-- Differences from Jonah's version, on purpose:
--   * No Find My for this phone, so there is no "probably just off" suppression.
--     A phone dark for more than 10 minutes is reported as unconfirmed.
--   * Sends through eg_send_email_jada (her recipient list), never eg_send_email.
--
-- PURELY ADDITIVE: one column, one function, one cron job. Does not redefine any
-- existing function. Safe to re-run.
--
-- DAD, BEFORE RUNNING: if Jada's phone is dark at the moment you run this (its
-- tunnel is currently cut), she gets ONE email within a minute. That is correct,
-- not a fault. It re-arms when the phone is back on the monitored network.

alter table public.phone_status_jada
  add column if not exists sustained_dark_alerted boolean not null default false;

create or replace function public.eg_check_phone_jada_sustained_dark() returns void
language plpgsql security definer set search_path = public as $$
declare p public.phone_status_jada;
declare dark_for interval;
begin
  select * into p from public.phone_status_jada where id = 1;

  -- Back on the monitored network: re-arm (writes only when there is something to clear).
  if p.phone_active is true then
    if p.sustained_dark_alerted then
      update public.phone_status_jada set sustained_dark_alerted = false where id = 1;
    end if;
    return;
  end if;

  -- Only judge while her router monitor is reporting; otherwise phone_active is
  -- stale and eg_check_phone_jada() ("MONITOR offline") is the alert that applies.
  if p.phone_active is null or p.monitor_beat is null or p.last_seen is null
     or now() - p.monitor_beat > interval '5 minutes' then
    return;
  end if;

  dark_for := now() - p.last_seen;      -- last_seen = last time confirmed on the monitored network
  if dark_for <= interval '10 minutes' or p.sustained_dark_alerted then
    return;
  end if;

  update public.phone_status_jada set sustained_dark_alerted = true where id = 1;
  perform public.eg_send_email_jada('EyeGuard - Jada''s phone on but unmonitored',
    format('<p><b>Jada''s iPhone has been off the monitored network for %s.</b></p>'
        || '<p>Last confirmed on the monitored network: %s. There is no Find My '
        || 'cross-check for this phone, so this is unconfirmed: the phone may be '
        || 'off, or on and unmonitored (tunnel off, or iOS suspended it). Anything '
        || 'browsed in this state is not seen.</p>'
        || '<p>One email is sent per dark period; it re-arms when the phone is back.</p>',
        to_char(dark_for, 'HH24"h" MI"m"'),
        to_char(p.last_seen at time zone 'America/New_York', 'Mon DD, HH12:MI AM')));
end $$;
revoke execute on function public.eg_check_phone_jada_sustained_dark()
  from public, anon, authenticated, service_role;

select cron.unschedule('eyeguard-phone-sustained-dark-jada')
  where exists (select 1 from cron.job where jobname = 'eyeguard-phone-sustained-dark-jada');
select cron.schedule('eyeguard-phone-sustained-dark-jada', '* * * * *',
  $$ select public.eg_check_phone_jada_sustained_dark(); $$);

-- ---- verify (read-only) ------------------------------------------------------
select
  exists (select 1 from information_schema.columns
           where table_name = 'phone_status_jada' and column_name = 'sustained_dark_alerted') as column_added,
  exists (select 1 from cron.job where jobname = 'eyeguard-phone-sustained-dark-jada') as cron_scheduled,
  not has_function_privilege('anon', 'public.eg_check_phone_jada_sustained_dark()', 'execute') as anon_cannot_call;
