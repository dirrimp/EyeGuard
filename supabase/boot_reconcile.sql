-- EyeGuard: boot-time reconciliation. Tells a REBOOT from a KILLED watcher after a both-dark alert.
--
-- Why (2026-10-18): the "monitoring AND session watcher both went dark" email said "the whole Mac
-- lost network connectivity". The Mac had actually been power-cycled (no clean shutdown record,
-- nothing could beacon it). From the outside a reboot and "someone killed the watchers" look
-- identical at alert time, and cannot be told apart then. They CAN be told apart afterwards,
-- by the boot time: after a reboot the Mac's boot time is newer than the watcher's last
-- heartbeat; if the watcher comes back with the SAME boot time as before the gap, the Mac never
-- restarted, so the outage was not a power event (the processes were stopped, crashed or relaunched).
--
-- What this does (ADDITIVE ONLY, never lowers an alert):
--   * eg_report_boot(boot_at, prev_shutdown_clean): called once by the session watcher at start-up,
--     BEFORE its first heartbeat. Stores one row per call in mac_boots with a server-computed verdict.
--   * Sends ONE follow-up email only when a dark alert is still outstanding (device_status.alerted or
--     watcher_dark_alerted still true: they clear on the next heartbeat), so ordinary restarts and
--     deploys stay silent. The original dark alert is untouched and still fires on its own schedule.
--   * Does NOT redefine eg_check_gone_dark, eg_watcher_heartbeat or eg_send_email (live copies were
--     hand-edited). It only CALLS eg_send_email(subject, html).
--
-- Verdicts (the server decides; the client only reports two facts):
--   baseline             first report ever (rollout): recorded, no email
--   rebooted             new boot time, not older than the watcher's last heartbeat (minus 2 min skew)
--   restarted_no_reboot  boot time already seen, and the watcher was silent more than 3 minutes
--   same_boot            boot time already seen, short gap (deploy / relaunch): recorded only
--   late_report          new boot time but the watcher had already heartbeated after it: recorded only
--
-- Trust: the boot time and shutdown flag are reported by the Mac (anon key), so they are EVIDENCE, not
-- proof, like every other client report here. Worst a forged call can do: add a throttled row and,
-- while a dark alert is outstanding, one explanatory email. It cannot clear, delay or suppress any alert.
--
-- Run once in the Supabase SQL editor, as the project owner. Safe to re-run.

create table if not exists public.mac_boots (
  id                   bigserial primary key,
  boot_at              timestamptz not null,
  reported_at          timestamptz not null default now(),
  prev_shutdown_clean  boolean,
  last_seen_before     timestamptz,
  gap_seconds          integer,
  verdict              text not null check (verdict in
                         ('baseline','rebooted','restarted_no_reboot','same_boot','late_report'))
);
create index if not exists mac_boots_reported_idx on public.mac_boots (reported_at desc);
alter table public.mac_boots enable row level security;
-- no policies on purpose: only the SECURITY DEFINER function below touches it
revoke all on table public.mac_boots from public, anon, authenticated;
revoke all on sequence public.mac_boots_id_seq from public, anon, authenticated;

create or replace function public.eg_report_boot(
  p_boot_at timestamptz,
  p_prev_shutdown_clean boolean default null)
returns text
language plpgsql security definer
set search_path = public, pg_temp
as $$
declare
  d           public.device_status;
  pre         timestamptz;
  gap         interval;
  known       boolean;
  outstanding boolean;
  v           text;
  clean_txt   text;
begin
  if p_boot_at is null
     or p_boot_at > now() + interval '2 minutes'
     or p_boot_at < now() - interval '400 days' then
    raise exception 'bad boot time';
  end if;

  -- anon-callable, so bound the write rate and the table size
  if exists (select 1 from public.mac_boots where reported_at > now() - interval '60 seconds') then
    return 'throttled';
  end if;
  delete from public.mac_boots where reported_at < now() - interval '120 days';

  select * into d from public.device_status where id = 1;
  pre := d.watcher_last_heartbeat;          -- the watcher's own last heartbeat, before this start-up
  gap := case when pre is null then null else now() - pre end;
  outstanding := coalesce(d.alerted, false) or coalesce(d.watcher_dark_alerted, false);
  known := exists (select 1 from public.mac_boots
                    where abs(extract(epoch from (boot_at - p_boot_at))) < 5);

  if not exists (select 1 from public.mac_boots) then
    v := 'baseline';
  elsif known then
    v := case when gap is not null and gap > interval '3 minutes'
              then 'restarted_no_reboot' else 'same_boot' end;
  elsif pre is null or p_boot_at >= pre - interval '2 minutes' then
    v := 'rebooted';
  else
    v := 'late_report';
  end if;

  insert into public.mac_boots (boot_at, prev_shutdown_clean, last_seen_before, gap_seconds, verdict)
  values (p_boot_at, p_prev_shutdown_clean, pre,
          case when gap is null then null else extract(epoch from gap)::integer end, v);

  if outstanding and v in ('rebooted', 'restarted_no_reboot') then
    clean_txt := case p_prev_shutdown_clean
      when true  then 'The previous shutdown was clean, like a normal restart.'
      when false then 'No clean shutdown was recorded for it: a power loss, a forced power-off, or a crash.'
      else 'Whether the previous shutdown was clean is unknown.' end;
    begin
      if v = 'rebooted' then
        perform public.eg_send_email(
          'EyeGuard - the Mac restarted (this explains the earlier dark alert)',
          format('<p><b>The Mac restarted, which explains the earlier dark alert.</b></p>'
              || '<p>Last heard from the session watcher %s ago. The Mac booted at %s (UTC) and the '
              || 'watcher is back.</p><p>%s</p><p>This is reported by the Mac itself, so treat it as '
              || 'evidence, not proof. If you did not expect a restart, check in.</p>',
              age(now(), pre), to_char(p_boot_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI'), clean_txt));
      else
        perform public.eg_send_email(
          'EyeGuard - monitoring came back WITHOUT a reboot after going dark',
          format('<p><b>The Mac did NOT restart, yet monitoring stopped and then came back.</b></p>'
              || '<p>The session watcher was silent for %s and has now started again. The Mac booted at '
              || '%s (UTC), the same boot as before the gap, so this was not a power event or a reboot: '
              || 'the monitoring processes were stopped, crashed, or relaunched while the Mac stayed on.</p>'
              || '<p>If nobody stopped them on purpose, check in.</p>',
              age(now(), pre), to_char(p_boot_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI')));
      end if;
    exception when others then
      null;   -- the explanation email must never break the report itself
    end;
  end if;

  return v;
end;
$$;

revoke execute on function public.eg_report_boot(timestamptz, boolean)
  from public, anon, authenticated, service_role;
grant execute on function public.eg_report_boot(timestamptz, boolean) to anon;

-- verify (expect: t, t, t, f, f)
select
  has_function_privilege('anon', 'public.eg_report_boot(timestamptz, boolean)', 'execute')          as anon_can_report,
  exists (select 1 from pg_class where relname = 'mac_boots' and relrowsecurity)                       as rls_on,
  not has_table_privilege('anon', 'public.mac_boots', 'select')                                        as anon_cannot_read,
  has_function_privilege('authenticated', 'public.eg_report_boot(timestamptz, boolean)', 'execute')   as authenticated_can_call,
  has_function_privilege('service_role', 'public.eg_report_boot(timestamptz, boolean)', 'execute')    as service_role_can_call;
