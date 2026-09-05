-- Passive, notification-independent sleep corroboration (2026-09-04, part 2).
--
-- The 2026-09-04 cross-check (cross_check_sleep_signal.sql) assumed the
-- main app's NSWorkspaceWillSleepNotification might catch what
-- session_watcher's IOKit registration misses for "Maintenance Sleep."
-- Confirmed WRONG by direct research: a 19-minute flurry of six real
-- Maintenance Sleep/DarkWake transitions (18:10:07-18:29:25, via `pmset -g
-- log`) produced ZERO "power event" log lines from the main app either --
-- both APIs are silent for this sleep TYPE, not just one of them. Verified
-- against Apple's own Developer Forums (thread 770517): a DTS engineer's
-- direct answer is "we don't have any API for detecting DarkWake, so you
-- should file a bug asking for us to add one." Every suggested workaround
-- (IOServiceAddInterestNotification + kIOGeneralInterest,
-- IOPMCopyAssertionsByProcess, polling CurrentPowerState/DesiredPowerState)
-- is explicitly unsupported and unguaranteed -- not worth building this
-- project's alerting reliability on.
--
-- Fix: stop depending on ANY push notification for this specific
-- corroboration. Instead, check PASSIVELY at evaluation time whether the
-- main app's own regular heartbeat -- driven by a plain timer loop
-- (retry_seconds, currently 60s), not any OS sleep/wake API -- is ALSO
-- currently stale. This is guaranteed by physics, not by any vendor's API
-- surface: if the Mac is genuinely asleep (Maintenance Sleep, DarkWake, or
-- anything else, known API or not), EVERY user-space process's code stops
-- running, this app's heartbeat loop included. A co-stale main-app
-- heartbeat is real, direct evidence the whole machine is unresponsive
-- right now, not something specifically targeting session_watcher alone.
--
-- Cannot be abused to hide a targeted attack on session_watcher alone:
-- silencing the main app's heartbeat TOO (to fake this corroboration)
-- immediately satisfies branch (a)'s own "monitoring went dark" condition
-- instead, which this change does not touch or weaken in any way -- the
-- attacker just trips a different, equally real alert.
--
-- ACCEPTED RESIDUAL: someone who manages to delay/block BOTH processes'
-- heartbeat network calls simultaneously (without actually sleeping the
-- Mac) gets a brief window -- this branch's 2-minute threshold is lower
-- than branch (a)'s 3-minute one, so between minute 2 and minute 3
-- specifically, (d) stays quiet while (a) hasn't fired yet either. Bounded
-- to at most ~1 extra minute of delay, not indefinite silence -- branch
-- (a) still fires at the 3-minute mark regardless, using the exact same
-- d.last_heartbeat this corroboration reads. Same standing tradeoff
-- category as every other accepted residual in this project.
--
-- 2-minute threshold (slightly under branch (a)'s 3-minute own threshold,
-- matching this file's existing debounce thresholds like screen_dark_since)
-- so corroboration engages promptly once the main app is ALSO clearly
-- unresponsive, without being so loose it fires on ordinary jitter.
--
-- Full rebuild of eg_check_gone_dark(), verified against
-- cross_check_sleep_signal.sql (confirmed newest via git log). Branches
-- (a),(b),(c),(e),(f) copied verbatim, unchanged. Only (d) gains this one
-- new OR-corroboration alongside the two it already has.

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

  -- (d) session watcher went dark -- NOW checks THREE independent sources
  -- of "a real sleep explains this," any one sufficient: session_watcher's
  -- own IOKit signal, the main app's explicit clean_shutdown beacon (both
  -- unchanged from cross_check_sleep_signal.sql), OR passively -- the main
  -- app's own heartbeat ALSO currently stale (NEW, see this file's header
  -- for the full reasoning: confirmed neither push signal fires for
  -- Maintenance Sleep/DarkWake, so this corroboration must not depend on
  -- either one ever firing).
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
