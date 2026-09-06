-- Fix: DarkWake blips silently invalidate every sleep-corroboration check
-- (2026-09-06).
--
-- passive_sleep_corroboration.sql (2026-09-04) added three OR-corroborations
-- to branch (d) of eg_check_gone_dark(), all three written as "some anchor
-- timestamp is NEWER than d.watcher_last_heartbeat." That assumption broke
-- overnight 2026-09-05->06: a real Clamshell Sleep at 19:45:22 was followed
-- by 49 completely ordinary "Maintenance Sleep" DarkWake blips (confirmed
-- via `pmset -g log`), each lasting 5-10 seconds, one every 6-13 minutes,
-- all night. session_watcher.py runs as a root LaunchDaemon (System
-- domain), not a per-user LaunchAgent -- unlike the main app, it CAN get a
-- few seconds of scheduled CPU time during these blips. When its plain
-- `while True: heartbeat(); time.sleep(120)` loop happened to tick during
-- one, it called eg_watcher_heartbeat(), which unconditionally sets
-- watcher_last_heartbeat = now() with zero gating on whether this was a
-- real wake (confirmed via git log + direct read: the live definition in
-- debugger_attach_check.sql has no such gate). session_watcher's own log
-- confirms IOKit itself was NOT fooled -- exactly one WillSleep (19:45:18)
-- and one HasPoweredOn (07:53:21) all night, nothing in between. But every
-- one of last week's three corroborations compares against
-- watcher_last_heartbeat, which kept drifting forward on its own past every
-- frozen anchor (watcher_sleep_signaled_at, the main app's clean_shutdown
-- last_heartbeat) -- breaking all three orderings by sunrise, hence the
-- night of "session watcher went dark" / "possible fake asleep signal"
-- spam despite session_watcher never actually being wrong about anything.
--
-- Fix: stop anchoring corroboration to watcher_last_heartbeat at all -- it
-- is proven noisy (ticks on any scheduled DarkWake blip, not just real
-- wakes). Anchor instead to a NEW column, watcher_confirmed_awake_at, set
-- ONLY by session_watcher's IOKit HasPoweredOn handler (heartbeat_now(),
-- called from exactly one place: SleepWatcher's _K_HAS_POWERED_ON branch --
-- a genuine full-system wake, never fired for a DarkWake blip, per this
-- file's own header evidence). The regular check_seconds loop's ordinary
-- ticks -- DarkWake-triggered or not -- now have zero effect on
-- corroboration; only a confirmed real wake can invalidate a standing
-- sleep signal.
--
-- Full rebuild of eg_watcher_heartbeat() (signature: 4 args -> 5, new
-- p_confirmed_awake) and eg_check_gone_dark() (only branch (d) changes;
-- (a),(b),(c),(e),(f) copied verbatim from passive_sleep_corroboration.sql,
-- confirmed newest via git log).

alter table public.device_status
  add column if not exists watcher_confirmed_awake_at timestamptz;

drop function if exists public.eg_watcher_heartbeat(boolean, boolean, boolean, boolean);

create or replace function public.eg_watcher_heartbeat(
  p_new_account boolean default false,
  p_wrong_user  boolean default false,
  p_untrusted_library boolean default false,
  p_debugger_attached boolean default false,
  p_confirmed_awake boolean default false
) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.device_status
     set watcher_last_heartbeat = now(),
         watcher_confirmed_awake_at =
           case when p_confirmed_awake then now()
                else watcher_confirmed_awake_at end,
         watcher_new_account = p_new_account,
         watcher_wrong_user = p_wrong_user,
         watcher_untrusted_library = p_untrusted_library,
         watcher_debugger_attached = p_debugger_attached,
         watcher_alerted = case
           when not (p_new_account or p_wrong_user or p_untrusted_library
                      or p_debugger_attached)
             then false
           else watcher_alerted
         end
   where id = 1;
end $$;
revoke all on function public.eg_watcher_heartbeat(boolean, boolean, boolean, boolean, boolean) from public;
grant execute on function public.eg_watcher_heartbeat(boolean, boolean, boolean, boolean, boolean) to anon;

create or replace function public.eg_check_gone_dark() returns void
language plpgsql security definer set search_path = public as $$
declare d public.device_status;
begin
  select * into d from public.device_status where id = 1;
  if d.last_heartbeat is null then return; end if;

  -- (a) went dark: no heartbeat for 3+ minutes [unchanged]
  if d.status = 'alive' and not d.alerted
     and now() - d.last_heartbeat > interval '3 minutes' then
    perform public.eg_send_email(
      '⚫ EyeGuard — monitoring went dark',
      format('<p><b>EyeGuard stopped reporting.</b></p><p>Last seen %s ago. The Mac '
          || 'may be off, offline, or the monitor was stopped. If unexpected, '
          || 'check in.</p>', age(now(), d.last_heartbeat)));
    update public.device_status set alerted = true where id = 1;
  end if;

  -- only evaluate the "alive but unhealthy" checks on a fresh heartbeat [unchanged]
  if d.status = 'alive' and now() - d.last_heartbeat <= interval '3 minutes' then

    -- (b) went blind: can't see the screen -- debounced (2026-09-02): must
    -- persist 2+ minutes, not just the first heartbeat reporting false.
    if d.screen_ok is false and d.screen_dark_since is not null
       and now() - d.screen_dark_since >= interval '2 minutes'
       and not d.blind_alerted then
      perform public.eg_send_email(
        '🚨 EyeGuard — lost view of the screen',
        '<p><b>EyeGuard is running but can no longer see the screen.</b></p>'
        || '<p>Screen Recording may have been revoked, the display switched, or '
        || 'capture frozen. Detection is NOT working until this is resolved.</p>');
      update public.device_status set blind_alerted = true where id = 1;
    elsif d.screen_ok is not false and d.blind_alerted then
      update public.device_status set blind_alerted = false where id = 1;
    end if;

    -- (c) detector broken: running + seeing, but the self-test failed [unchanged]
    if d.detector_ok is false and not d.detector_alerted then
      perform public.eg_send_email(
        '🚨 EyeGuard — detection may be broken',
        '<p><b>EyeGuard is running and can see the screen, but its detector '
        || 'self-test is failing.</b></p><p>The analysis pipeline may have broken '
        || '(e.g. after a macOS update). A quiet feed right now should NOT be '
        || 'read as "all clear" until this is fixed.</p>');
      update public.device_status set detector_alerted = true where id = 1;
    elsif d.detector_ok is not false and d.detector_alerted then
      update public.device_status set detector_alerted = false where id = 1;
    end if;

  end if;

  -- (d) session watcher went dark -- corroboration REWORKED (2026-09-06):
  -- all three checks now anchor to watcher_confirmed_awake_at (set ONLY on
  -- a real IOKit HasPoweredOn wake) instead of watcher_last_heartbeat
  -- (proven noisy -- see this file's header). A standing sleep signal or
  -- clean_shutdown report is trusted UNLESS a confirmed real wake has
  -- happened since it was recorded -- ordinary DarkWake-triggered
  -- heartbeat ticks can no longer invalidate it.
  if d.watcher_last_heartbeat is not null then
    if now() - d.watcher_last_heartbeat > interval '3 minutes'
       and not d.watcher_dark_alerted
       and not (
         d.watcher_sleep_signaled_at is not null
         and now() - d.watcher_sleep_signaled_at <= interval '24 hours'
         and (d.watcher_confirmed_awake_at is null
              or d.watcher_sleep_signaled_at > d.watcher_confirmed_awake_at)
       )
       and not (
         d.status = 'clean_shutdown'
         and now() - d.last_heartbeat <= interval '24 hours'
         and (d.watcher_confirmed_awake_at is null
              or d.last_heartbeat > d.watcher_confirmed_awake_at)
       )
       and not (
         d.status = 'alive'
         and now() - d.last_heartbeat > interval '2 minutes'
       ) then
      perform public.eg_send_email(
        '⚫ EyeGuard — session watcher went dark',
        format('<p><b>The account/session watcher stopped reporting.</b></p>'
            || '<p>Last seen %s ago. It may have been disabled, or the Mac may '
            || 'be off. The main app''s own detection may still be running, '
            || 'but new-account/user-switch detection is NOT while this is '
            || 'down.</p>', age(now(), d.watcher_last_heartbeat)));
      update public.device_status set watcher_dark_alerted = true where id = 1;
    elsif now() - d.watcher_last_heartbeat <= interval '3 minutes'
          and d.watcher_dark_alerted then
      update public.device_status set watcher_dark_alerted = false where id = 1;
    end if;
  end if;

  -- (e) session watcher found a new account, wrong user, untrusted library,
  -- or attached debugger [unchanged]
  if (d.watcher_new_account or d.watcher_wrong_user
      or d.watcher_untrusted_library or d.watcher_debugger_attached)
     and not d.watcher_alerted
     and d.watcher_last_heartbeat is not null
     and now() - d.watcher_last_heartbeat <= interval '3 minutes' then
    perform public.eg_send_email(
      '🚨 EyeGuard — account/session/process anomaly detected',
      format('<p><b>%s</b></p><p>This may be an attempt to bypass monitoring. '
          || 'Check in.</p>',
          case when d.watcher_debugger_attached
                 then 'A debugger appears to be attached to the monitor '
                      || 'agent -- someone may be actively inspecting or '
                      || 'patching its running memory.'
               when d.watcher_untrusted_library
                 then 'The monitor agent has an unexpected library loaded '
                      || 'that did not come from the app itself or the '
                      || 'system -- a classic sign of code injection into a '
                      || 'running process.'
               when d.watcher_new_account and d.watcher_wrong_user
                 then 'A new macOS user account was created AND the active '
                      || 'session is not the monitored account.'
               when d.watcher_new_account
                 then 'A new macOS user account was created.'
               else 'The active console session is not the monitored account.'
          end));
    update public.device_status set watcher_alerted = true where id = 1;
  elsif not (d.watcher_new_account or d.watcher_wrong_user
             or d.watcher_untrusted_library or d.watcher_debugger_attached) then
    update public.device_status set watcher_alerted = false where id = 1;
  end if;

  -- (f) main app claims "clean shutdown" while the session watcher kept
  -- reporting well after -- REWORKED (2026-09-06), same root cause as (d):
  -- this branch used to compare raw watcher_last_heartbeat drift against a
  -- 10-minute threshold, but that drifts forward on its own during ordinary
  -- DarkWake blips (confirmed: this is exactly what tripped this branch at
  -- 20:21 on 2026-09-05, just 36 minutes after a real clean_shutdown, once
  -- a couple of harmless blips nudged watcher_last_heartbeat forward past
  -- the 10-minute mark). Now fires on a much stronger, non-noisy signal
  -- instead: a CONFIRMED real wake (watcher_confirmed_awake_at, set only by
  -- IOKit HasPoweredOn) recorded after the main app's own clean_shutdown
  -- timestamp -- i.e. session_watcher registered an actual full wake the
  -- main app doesn't know about, not just a few seconds of scheduled
  -- background CPU time.
  if d.status = 'clean_shutdown'
     and d.watcher_confirmed_awake_at is not null
     and d.watcher_confirmed_awake_at > d.last_heartbeat
     and not d.suspend_abuse_alerted then
    perform public.eg_send_email(
      '🚨 EyeGuard — possible fake "asleep" signal',
      format('<p><b>The main app reports being cleanly shut down (asleep), '
          || 'but the account/session watcher -- a separate process that '
          || 'cannot run at all while the Mac is genuinely asleep -- '
          || 'registered a real wake at %s, after the shutdown was '
          || 'reported.</b></p><p>This looks like the shutdown signal was '
          || 'sent without the Mac actually going to sleep. Check '
          || 'in.</p>', d.watcher_confirmed_awake_at));
    update public.device_status set suspend_abuse_alerted = true where id = 1;
  elsif d.status = 'alive' and d.suspend_abuse_alerted then
    update public.device_status set suspend_abuse_alerted = false where id = 1;
  end if;
end $$;
