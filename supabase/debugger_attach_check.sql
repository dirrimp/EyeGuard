-- Second layer for gap #1 ("in-memory patching is undetectable"),
-- alongside injected_library_check.sql. Dylib injection is only ONE way to
-- patch a running process -- an attacker could instead attach a debugger
-- (lldb/gdb) directly and rewrite live Python heap objects in place, no
-- external library involved at all. eyeguard/session_watcher.py now also
-- checks the kernel's own P_TRACED process flag for the monitor agent via
-- sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID) -- the same mechanism
-- debuggers themselves rely on. Note: on the deployed Mac, debugger
-- attachment is already blocked by default at the OS level (macOS's
-- Developer Tools authorization gate) for anyone, even root -- this check
-- is a second layer behind that, not the only thing standing in the way.

alter table public.device_status add column if not exists watcher_debugger_attached boolean not null default false;

-- eg_watcher_heartbeat() signature changes (3 params -> 4).
drop function if exists public.eg_watcher_heartbeat(boolean, boolean, boolean);

create or replace function public.eg_watcher_heartbeat(
  p_new_account boolean default false,
  p_wrong_user  boolean default false,
  p_untrusted_library boolean default false,
  p_debugger_attached boolean default false
) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.device_status
     set watcher_last_heartbeat = now(),
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
revoke all on function public.eg_watcher_heartbeat(boolean, boolean, boolean, boolean) from public;
grant execute on function public.eg_watcher_heartbeat(boolean, boolean, boolean, boolean) to anon;

-- eg_check_gone_dark(): branch (e) extended once more to also cover
-- watcher_debugger_attached, EXTENDING the current live definition from
-- injected_library_check.sql -- branches (a)-(d) and (f) copied verbatim,
-- unchanged. Only the case logic inside (e) changes.
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

  -- (e) session watcher found a new account, the wrong active user, an
  -- untrusted library, OR (NEW) an attached debugger
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
