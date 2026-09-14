-- Fix branch (f)'s false positive on a brief, power-plug-triggered FullWake
-- (2026-09-13).
--
-- Confirmed live via `pmset -g log`: at 00:24:20, the Mac (asleep since
-- 00:23:55) was plugged into power (Using BATT -> Using AC), which macOS
-- itself logs as "DarkWake to FullWake ... due to Notification" -- a
-- genuine, real full wake, NOT a maintenance-only DarkWake (that category
-- was already handled by passive_sleep_corroboration.sql). Display turned
-- on at 00:24:21, then macOS re-entered DarkWake at 00:24:23 and real sleep
-- resumed at 00:24:53 -- the whole cycle self-corrected in under 30 seconds.
--
-- session_watcher's IOKit registration correctly saw BOTH halves of this:
-- HasPoweredOn at 00:24:21 (setting watcher_confirmed_awake_at, exactly as
-- designed) AND a subsequent WillSleep at 00:24:46 (setting a fresh
-- watcher_sleep_signaled_at) for the resleep. The main app's own
-- NSWorkspaceDidWakeNotification -- confirmed registered correctly in
-- menubar.py, not a missing-code bug -- simply never fired for this
-- ~2-second promoted wake (a known-plausible Cocoa notification-timing gap
-- for very brief power transitions, same general category as the original
-- DarkWake research finding, different specific trigger). So the main app's
-- status stayed 'clean_shutdown' the whole time, accurately, while branch
-- (f) fired the instant watcher_confirmed_awake_at appeared -- with no way
-- to tell "a brief, self-corrected, externally-triggered blip" apart from
-- "the Mac has stayed genuinely awake since that confirmed wake," which is
-- the actual abuse case (f) exists to catch.
--
-- Fix: use the SAME anchor session_watcher already sends for exactly this
-- purpose. If watcher_sleep_signaled_at is ALSO newer than
-- watcher_confirmed_awake_at, the watcher itself corroborates it went back
-- to sleep after that wake -- a real, self-correcting blip, not sustained
-- wakefulness. Does not weaken the abuse case at all: if someone actually
-- fakes a clean-shutdown report while continuing to use the Mac,
-- session_watcher never sends another WillSleep (the Mac never actually
-- sleeps), so watcher_sleep_signaled_at stays at whatever it was before
-- (null or a stale prior value, not newer than the fresh
-- watcher_confirmed_awake_at) -- the alert still fires correctly.
--
-- Full rebuild, verified against agent_hardened_runtime_check.sql
-- (confirmed newest via git log). Only branch (f) changes; (a)-(e) copied
-- verbatim.

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

  -- (d) session watcher went dark [unchanged]
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
  -- attached debugger, or the agent running un-hardened [unchanged]
  if (d.watcher_new_account or d.watcher_wrong_user
      or d.watcher_untrusted_library or d.watcher_debugger_attached
      or d.watcher_agent_unhardened)
     and not d.watcher_alerted
     and d.watcher_last_heartbeat is not null
     and now() - d.watcher_last_heartbeat <= interval '3 minutes' then
    perform public.eg_send_email(
      '🚨 EyeGuard — account/session/process anomaly detected',
      format('<p><b>%s</b></p><p>This may be an attempt to bypass monitoring. '
          || 'Check in.</p>',
          case when d.watcher_agent_unhardened
                 then 'The monitor agent is running WITHOUT the hardened '
                      || 'runtime (or with debugger-attach permitted) -- the '
                      || 'shipped interpreter is hardened, so this means it '
                      || 'was replaced with a build that can be patched in '
                      || 'memory (lldb / DYLD_INSERT_LIBRARIES).'
               when d.watcher_debugger_attached
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
             or d.watcher_untrusted_library or d.watcher_debugger_attached
             or d.watcher_agent_unhardened) then
    update public.device_status set watcher_alerted = false where id = 1;
  end if;

  -- (f) main app claims "clean shutdown" while the session watcher stayed
  -- genuinely awake since a confirmed real wake -- REWORKED (2026-09-13):
  -- no longer fires on the confirmed wake alone. Suppressed when the
  -- watcher's OWN later sleep-signal corroborates it went back to sleep
  -- after that wake (a brief, self-correcting, externally-triggered blip --
  -- see this file's header) -- not suppressed if the watcher has stayed up
  -- since (the actual abuse case).
  if d.status = 'clean_shutdown'
     and d.watcher_confirmed_awake_at is not null
     and d.watcher_confirmed_awake_at > d.last_heartbeat
     and not (
       d.watcher_sleep_signaled_at is not null
       and d.watcher_sleep_signaled_at > d.watcher_confirmed_awake_at
     )
     and not d.suspend_abuse_alerted then
    perform public.eg_send_email(
      '🚨 EyeGuard — possible fake "asleep" signal',
      format('<p><b>The main app reports being cleanly shut down (asleep), '
          || 'but the account/session watcher -- a separate process that '
          || 'cannot run at all while the Mac is genuinely asleep -- '
          || 'registered a real wake at %s, after the shutdown was '
          || 'reported, and has not signaled going back to sleep since.</b></p>'
          || '<p>This looks like the shutdown signal was sent without the '
          || 'Mac actually going to sleep. Check in.</p>', d.watcher_confirmed_awake_at));
    update public.device_status set suspend_abuse_alerted = true where id = 1;
  elsif d.status = 'alive' and d.suspend_abuse_alerted then
    update public.device_status set suspend_abuse_alerted = false where id = 1;
  end if;
end $$;
