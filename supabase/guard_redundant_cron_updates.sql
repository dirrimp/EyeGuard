-- Eliminate the two unconditional single-row UPDATEs in the every-minute
-- cron functions (2026-09-14).
--
-- Found by a full architecture audit prompted by recurring 504s. Measured on
-- the live database:
--   device_status : 1 live row,  74,988 lifetime UPDATEs, 1,362 autovacuums
--   phone_status  : 1 live row, 152,773 lifetime UPDATEs, 2,934 autovacuums
-- 227,761 UPDATEs against two single rows, needing 4,296 autovacuum runs to
-- stay clean. (It IS staying clean -- both tables measured at 44 and 2 dead
-- tuples, 64kB/56kB, autovacuum current. The database is healthy; this is
-- about removing pointless work, not repairing damage.)
--
-- Of that volume, ~120 UPDATEs/hour were provably pointless. Both
-- eg_check_gone_dark() branch (e) and eg_check_phone() branch (c) reset their
-- watcher_alerted flag in an `elsif` with NO guard on the flag actually being
-- set -- so in the healthy state, which is essentially always, each wrote
-- `false` over `false` once a minute, forever. Every other reset in both
-- functions (blind_alerted, detector_alerted, watcher_dark_alerted,
-- suspend_abuse_alerted, offline_alerted) already carries that guard; these
-- two were the outliers.
--
-- Beyond the waste, the timing matters: each pointless UPDATE takes an
-- exclusive row lock at exactly :00, which is when both cron jobs fire AND
-- when client heartbeats land. 8 of 12 client-facing 504s in the audited
-- window occurred within 2.5s of :00.
--
-- Behaviour is otherwise identical: the flag still clears the moment a real
-- anomaly resolves (the first pass where watcher_alerted is true and the
-- conditions have cleared), it just no longer rewrites an already-false
-- value. Full rebuild of both functions, extracted programmatically from the
-- newest committed versions (fix_brief_powerplug_wake_false_positive.sql and
-- drop_phone_unlock_escalation.sql, confirmed newest via git log) so every
-- other branch is byte-identical -- only the two guards differ.

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
  elsif d.watcher_alerted
        and not (d.watcher_new_account or d.watcher_wrong_user
                 or d.watcher_untrusted_library or d.watcher_debugger_attached
                 or d.watcher_agent_unhardened) then
    -- GUARDED 2026-09-14: was unconditional, so in the healthy state (i.e.
    -- essentially always) this wrote false over false EVERY MINUTE, taking an
    -- exclusive row lock on device_status id=1 at :00 -- precisely when client
    -- heartbeats arrive. Every other reset in this function was already
    -- guarded this way; this one was the outlier.
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

create or replace function public.eg_check_phone() returns void
language plpgsql security definer set search_path = public as $$
declare p public.phone_status;
begin
  select * into p from public.phone_status where id = 1;
  if p.monitor_beat is null then return; end if;

  -- (a) phone monitor script itself went dark [unchanged]
  if now() - p.monitor_beat > interval '5 minutes' and not p.offline_alerted then
    perform public.eg_send_email('⚫ EyeGuard — phone MONITOR offline',
      format('<p><b>The phone monitor (router) stopped reporting.</b></p>'
          || '<p>Last check-in %s ago — the router script or router itself may '
          || 'be down. The phone is unmonitored until it''s back.</p>',
          age(now(), p.monitor_beat)));
    update public.phone_status set offline_alerted = true where id = 1;
  elsif now() - p.monitor_beat <= interval '5 minutes' and p.offline_alerted then
    update public.phone_status set offline_alerted = false where id = 1;
  end if;

  -- (b) router watcher itself went dark [unchanged]
  if p.watcher_last_heartbeat is not null
     and now() - p.watcher_last_heartbeat > interval '10 minutes'
     and not p.watcher_alerted then
    perform public.eg_send_email('⚫ EyeGuard — router watcher offline',
      format('<p><b>The router integrity watcher stopped reporting.</b></p>'
          || '<p>Last seen %s ago. It may have been disabled -- script-'
          || 'tamper and process-liveness detection is NOT active while '
          || 'this is down.</p>', age(now(), p.watcher_last_heartbeat)));
    update public.phone_status set watcher_alerted = true where id = 1;
  end if;

  -- (c) router watcher found the script tampered or the phone monitor
  -- process not actually running [unchanged]
  if (p.watcher_script_tampered or p.watcher_process_down)
     and not p.watcher_alerted
     and p.watcher_last_heartbeat is not null
     and now() - p.watcher_last_heartbeat <= interval '10 minutes' then
    perform public.eg_send_email('🚨 EyeGuard — router monitor tampering detected',
      format('<p><b>%s</b></p><p>This may be an attempt to disable phone '
          || 'monitoring at the network level. Check in.</p>',
          case when p.watcher_script_tampered and p.watcher_process_down
                 then 'The phone monitor script on the router does not '
                      || 'match the published version, AND the process is '
                      || 'not currently running.'
               when p.watcher_script_tampered
                 then 'The phone monitor script on the router (eyeguard-'
                      || 'phone.py) does not match the published, known-'
                      || 'good version -- it may have been edited.'
               else 'The phone monitor process (eyeguard-phone.py) is not '
                      || 'currently running on the router.'
          end));
    update public.phone_status set watcher_alerted = true where id = 1;
  elsif p.watcher_alerted
        and not (p.watcher_script_tampered or p.watcher_process_down) then
    -- GUARDED 2026-09-14: same outlier as eg_check_gone_dark()'s branch (e) --
    -- wrote false over false every minute, locking phone_status id=1 at :00.
    update public.phone_status set watcher_alerted = false where id = 1;
  end if;

  -- (d) REMOVED 2026-09-12 -- see this file's header. Was: phone actively
  -- used (unlocked) around when it went dark -> urgent escalation email,
  -- fed entirely by the unreliable Shortcuts-based last_unlock_at signal.
end $$;
