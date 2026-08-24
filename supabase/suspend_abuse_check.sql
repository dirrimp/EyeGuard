-- Closes a real gap in eg_report_suspend()'s accepted-residual design
-- (anon_client_pivot.sql): that RPC sets status='clean_shutdown' with no
-- expiry and no independent check -- so a single call, with the app never
-- reopened, permanently silences eg_check_gone_dark()'s branch (a) for the
-- main app forever (it only fires when status='alive'). That's a much
-- bigger gap than "suppress one nap": it's "silence gone-dark for good with
-- one anon-key call," discovered while reviewing what "accept it" actually
-- meant in practice.
--
-- The fix does NOT require a password on every real sleep (still bad UX for
-- routine lid-close) and does NOT need any new client-side sleep-detection
-- code. It reuses a fact that's already true: the session watcher
-- (eyeguard/session_watcher.py) is a SEPARATE root process from the main
-- app, and like every other process on the Mac, it cannot run AT ALL while
-- the machine is genuinely asleep -- the whole OS suspends. So if
-- watcher_last_heartbeat keeps landing fresh well after the main app
-- claimed to have gone to sleep, that's direct proof the machine never
-- actually slept -- the suspend call was faked while the Mac stayed in
-- active use. Real sleep: both signals go stale together, no alert. Faked
-- suspend: the watcher's heartbeat keeps advancing while the main app's
-- doesn't, and that divergence is exactly what's being detected.

alter table public.device_status add column if not exists suspend_abuse_alerted boolean not null default false;

-- eg_heartbeat(): resuming after a real (or faked) shutdown always clears
-- this alert -- same reset-on-recovery pattern already used for
-- alerted/blind_alerted/detector_alerted.
create or replace function public.eg_heartbeat(
  p_screen_ok boolean default null,
  p_frames_analyzed bigint default null,
  p_detector_ok boolean default null
) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.device_status
     set last_heartbeat = now(),
         status = 'alive',
         alerted = false,
         suspend_abuse_alerted = false,
         screen_ok = coalesce(p_screen_ok, screen_ok),
         frames_analyzed = coalesce(p_frames_analyzed, frames_analyzed),
         detector_ok = coalesce(p_detector_ok, detector_ok),
         updated_at = now()
   where id = 1;
end $$;
revoke all on function public.eg_heartbeat(boolean, bigint, boolean) from public;
grant execute on function public.eg_heartbeat(boolean, bigint, boolean) to anon;

-- eg_check_gone_dark() gains a sixth branch, EXTENDING (not replacing) the
-- current live definition from anon_client_pivot.sql -- branches (a)-(e)
-- copied verbatim, unchanged. Only (f) below is new.
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

    -- (b) went blind: can't see the screen
    if d.screen_ok is false and not d.blind_alerted then
      perform public.eg_send_email(
        '🚨 EyeGuard — lost view of the screen',
        '<p><b>EyeGuard is running but can no longer see the screen.</b></p>'
        || '<p>Screen Recording may have been revoked, the display switched, or '
        || 'capture frozen. Detection is NOT working until this is resolved.</p>');
      update public.device_status set blind_alerted = true where id = 1;
    elsif d.screen_ok is not false and d.blind_alerted then
      update public.device_status set blind_alerted = false where id = 1;
    end if;

    -- (c) detector broken: running + seeing, but the self-test failed
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
  if d.watcher_last_heartbeat is not null
     and now() - d.watcher_last_heartbeat > interval '3 minutes'
     and not d.watcher_alerted then
    perform public.eg_send_email(
      '⚫ EyeGuard — session watcher went dark',
      format('<p><b>The account/session watcher stopped reporting.</b></p>'
          || '<p>Last seen %s ago. It may have been disabled, or the Mac may '
          || 'be off. The main app''s own detection may still be running, '
          || 'but new-account/user-switch detection is NOT while this is '
          || 'down.</p>', age(now(), d.watcher_last_heartbeat)));
    update public.device_status set watcher_alerted = true where id = 1;
  end if;

  -- (e) session watcher found a new account or the wrong active user [unchanged]
  if (d.watcher_new_account or d.watcher_wrong_user)
     and not d.watcher_alerted
     and d.watcher_last_heartbeat is not null
     and now() - d.watcher_last_heartbeat <= interval '3 minutes' then
    perform public.eg_send_email(
      '🚨 EyeGuard — account/session change detected',
      format('<p><b>%s</b></p><p>This may be an attempt to use the Mac '
          || 'outside the monitored account. Check in.</p>',
          case when d.watcher_new_account and d.watcher_wrong_user
                 then 'A new macOS user account was created AND the active '
                      || 'session is not the monitored account.'
               when d.watcher_new_account
                 then 'A new macOS user account was created.'
               else 'The active console session is not the monitored account.'
          end));
    update public.device_status set watcher_alerted = true where id = 1;
  elsif not (d.watcher_new_account or d.watcher_wrong_user) then
    update public.device_status set watcher_alerted = false where id = 1;
  end if;

  -- (f) NEW: main app claims "clean shutdown" (asleep) while the session
  -- watcher -- a separate process, itself unable to run at all during real
  -- OS sleep -- has kept reporting fresh heartbeats well after. A machine
  -- that's actually asleep can't run the watcher either, so this divergence
  -- is direct proof the shutdown signal was sent without a real sleep
  -- happening. The 10-minute gap (vs. the 3-minute grace used elsewhere)
  -- gives room for the brief, legitimate overlap right at the moment of a
  -- real sleep, where the watcher's last check might land a few seconds
  -- before suspend actually takes effect.
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
