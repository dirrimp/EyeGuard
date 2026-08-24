-- Closes the "in-memory patching is undetectable" gap accepted earlier in
-- this project's design. Confirmed on the real deployed Mac that root CAN
-- inspect another process's loaded libraries (vmmap works without any
-- special entitlement in this configuration) -- so rather than trying to
-- diff raw memory bytes (impractical for a Python process: the actual
-- interpreted logic lives in dynamic heap objects, not a fixed
-- on-disk-comparable region), eyeguard/session_watcher.py now checks WHERE
-- every library loaded into the monitor agent's process came from.
-- Anything outside a small set of trusted path roots (the app bundle,
-- /usr/lib, /System/Library) is the classic signature of
-- DYLD_INSERT_LIBRARIES-style injection -- used to hook or patch a running
-- process without ever touching disk, which the file-integrity manifest
-- check (integrity.py) cannot see. No baseline file is needed for this
-- check at all (nothing local for an admin to tamper with), matching the
-- same reasoning that already moved integrity.py off a local baseline.

alter table public.device_status add column if not exists watcher_untrusted_library boolean not null default false;

-- eg_watcher_heartbeat() signature changes (2 params -> 3) -- drop the old
-- one explicitly rather than leaving both defined, since PostgREST
-- dispatches RPC calls by name and having two overloads of the same
-- function name is genuinely ambiguous for it to resolve.
drop function if exists public.eg_watcher_heartbeat(boolean, boolean);

create or replace function public.eg_watcher_heartbeat(
  p_new_account boolean default false,
  p_wrong_user  boolean default false,
  p_untrusted_library boolean default false
) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.device_status
     set watcher_last_heartbeat = now(),
         watcher_new_account = p_new_account,
         watcher_wrong_user = p_wrong_user,
         watcher_untrusted_library = p_untrusted_library,
         watcher_alerted = case
           when not (p_new_account or p_wrong_user or p_untrusted_library)
             then false
           else watcher_alerted
         end
   where id = 1;
end $$;
revoke all on function public.eg_watcher_heartbeat(boolean, boolean, boolean) from public;
grant execute on function public.eg_watcher_heartbeat(boolean, boolean, boolean) to anon;

-- eg_check_gone_dark() gains a seventh branch, EXTENDING (not replacing)
-- the current live definition from suspend_abuse_check.sql -- branches
-- (a)-(f) copied verbatim, unchanged, plus branch (e) now also covers
-- watcher_untrusted_library alongside the existing new-account/wrong-user
-- conditions (same alert-and-clear shape, one more thing it watches for).
-- Only (g) is new.
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

  -- (e) session watcher found a new account, the wrong active user, OR
  -- (NEW) an untrusted library loaded in the monitor agent
  if (d.watcher_new_account or d.watcher_wrong_user or d.watcher_untrusted_library)
     and not d.watcher_alerted
     and d.watcher_last_heartbeat is not null
     and now() - d.watcher_last_heartbeat <= interval '3 minutes' then
    perform public.eg_send_email(
      '🚨 EyeGuard — account/session/process anomaly detected',
      format('<p><b>%s</b></p><p>This may be an attempt to bypass monitoring. '
          || 'Check in.</p>',
          case when d.watcher_untrusted_library
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
  elsif not (d.watcher_new_account or d.watcher_wrong_user or d.watcher_untrusted_library) then
    update public.device_status set watcher_alerted = false where id = 1;
  end if;

  -- (f) main app claims "clean shutdown" while the session watcher -- which
  -- cannot run at all during real OS sleep -- has kept reporting fresh
  -- heartbeats well after [unchanged]
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
