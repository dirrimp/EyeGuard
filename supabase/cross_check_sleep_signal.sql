-- Cross-check session_watcher's own sleep signal against the MAIN app's
-- independent suspend beacon (2026-09-04) -- a second, structurally
-- independent chance for real-sleep evidence to land, instead of trying to
-- make ONE risky pre-sleep network call more reliable (see
-- tighten-sleep-signal-timeout's PR -- that narrows the race, this widens
-- the number of ways to win it).
--
-- The main app ALSO races to report the exact same real system sleep,
-- independently: uploader.py's suspend() fires on the identical
-- NSWorkspaceWillSleepNotification session_watcher.py's IOKit handler
-- reacts to, and calls eg_report_suspend() (supabase/anon_client_pivot.sql),
-- which sets device_status.status='clean_shutdown' + last_heartbeat=now().
-- That's a SEPARATE process, SEPARATE code path, SEPARATE network call --
-- if session_watcher's own 3s-timeout WillSleep call loses the race but the
-- main app's succeeds (or vice versa), we now have two independent shots at
-- the same evidence instead of one. Reuses fully-existing infrastructure --
-- no new RPC, no new column, and no new residual risk: eg_report_suspend()
-- being anon-callable without a password was already an accepted,
-- documented residual (2026-08-24, "anyone holding the public anon key
-- could call this to suppress gone-dark ... low real-world value to an
-- outside attacker").
--
-- Full rebuild of eg_check_gone_dark(), verified against
-- fix_screen_and_phone_alert_debounce.sql (confirmed newest via git log).
-- Branches (a),(c),(e),(f) copied verbatim, unchanged. (b) unchanged from
-- that file's own debounce fix. Only (d) gains the new OR-corroboration.

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

  -- (d) session watcher went dark -- NOW checks TWO independent sources of
  -- "a real sleep explains this," either one sufficient: session_watcher's
  -- own IOKit signal (unchanged), OR the main app's independent suspend
  -- beacon (NEW -- see this file's header). Both are self-reported,
  -- lower-trust signals (same standing as everywhere else in this project),
  -- but two independent processes agreeing (or even just one succeeding
  -- where the other didn't) is real corroboration a single flaky network
  -- call during a tight pre-sleep window is not.
  if d.watcher_last_heartbeat is not null then
    if now() - d.watcher_last_heartbeat > interval '3 minutes'
       and not d.watcher_dark_alerted
       and not (
         d.watcher_sleep_signaled_at is not null
         and d.watcher_sleep_signaled_at > d.watcher_last_heartbeat
         and now() - d.watcher_sleep_signaled_at <= interval '24 hours'
       )
       and not (
         d.status = 'clean_shutdown'
         and d.last_heartbeat > d.watcher_last_heartbeat
         and now() - d.last_heartbeat <= interval '24 hours'
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
  -- reporting well after [unchanged]
  if d.status = 'clean_shutdown'
     and d.watcher_last_heartbeat is not null
     and now() - d.watcher_last_heartbeat <= interval '3 minutes'
     and d.watcher_last_heartbeat - d.last_heartbeat > interval '10 minutes'
     and not d.suspend_abuse_alerted then
    perform public.eg_send_email(
      '🚨 EyeGuard — possible fake "asleep" signal',
      format('<p><b>The main app reports being cleanly shut down (asleep), '
          || 'but the account/session watcher -- a separate process that '
          || 'cannot run at all while the Mac is genuinely asleep -- has '
          || 'kept reporting for %s since.</b></p><p>This looks like the '
          || 'shutdown signal was sent without the Mac actually going to '
          || 'sleep. Check in.</p>', age(d.watcher_last_heartbeat, d.last_heartbeat)));
    update public.device_status set suspend_abuse_alerted = true where id = 1;
  elsif d.status = 'alive' and d.suspend_abuse_alerted then
    update public.device_status set suspend_abuse_alerted = false where id = 1;
  end if;
end $$;
