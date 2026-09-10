-- Session watcher now also reports whether the monitor agent is running
-- under the hardened runtime (2026-09-10).
--
-- Context: the agent's bundled Python interpreter IS hardened-runtime signed
-- (verified live via csops on the running process: CS_RUNTIME | CS_HARD |
-- CS_KILL set, CS_GET_TASK_ALLOW clear -- lldb attach denied,
-- DYLD_INSERT_LIBRARIES ignored). But the interpreter binary lives at
-- /Applications/EyeGuard.app/Contents/Resources/python/bin/python3.12, which
-- is OUTSIDE the root-owned code tree and the file-integrity manifest (that
-- only hashes eyeguard/*.py + run_agent.py). So it could be swapped for an
-- unhardened build, taking effect on the agent's next restart, with nothing
-- catching it.
--
-- Prevention: install_app.sh and deploy_watcher now lock the .app bundle to
-- root:wheel, non-user-writable, so a Standard user can't swap it.
-- Evidence (this migration): session_watcher checks the LIVE agent process
-- via csops() every cycle and reports p_agent_unhardened=true if CS_RUNTIME
-- is missing or CS_GET_TASK_ALLOW is set -- caught even if the swap was done
-- by someone with admin. Routes through the same branch (e)
-- "account/session/process anomaly" alert as the injected-library and
-- debugger checks.
--
-- eg_watcher_heartbeat(): 5 args -> 6 (+p_agent_unhardened).
-- eg_check_gone_dark(): full rebuild, only branch (e) changes -- branches
-- (a),(b),(c),(d),(f) copied verbatim from fix_darkwake_heartbeat_drift.sql
-- (confirmed newest via git log).

alter table public.device_status
  add column if not exists watcher_agent_unhardened boolean not null default false;

drop function if exists public.eg_watcher_heartbeat(boolean, boolean, boolean, boolean, boolean);

create or replace function public.eg_watcher_heartbeat(
  p_new_account boolean default false,
  p_wrong_user  boolean default false,
  p_untrusted_library boolean default false,
  p_debugger_attached boolean default false,
  p_confirmed_awake boolean default false,
  p_agent_unhardened boolean default false
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
         watcher_agent_unhardened = p_agent_unhardened,
         watcher_alerted = case
           when not (p_new_account or p_wrong_user or p_untrusted_library
                      or p_debugger_attached or p_agent_unhardened)
             then false
           else watcher_alerted
         end
   where id = 1;
end $$;
revoke all on function public.eg_watcher_heartbeat(boolean, boolean, boolean, boolean, boolean, boolean) from public;
grant execute on function public.eg_watcher_heartbeat(boolean, boolean, boolean, boolean, boolean, boolean) to anon;

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

  -- (d) session watcher went dark -- corroboration anchors to
  -- watcher_confirmed_awake_at (set ONLY on a real IOKit HasPoweredOn wake)
  -- [unchanged from fix_darkwake_heartbeat_drift.sql]
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
  -- attached debugger, OR the agent running un-hardened (NEW 2026-09-10 --
  -- interpreter may have been swapped for a build that permits lldb /
  -- DYLD_INSERT_LIBRARIES).
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

  -- (f) main app claims "clean shutdown" while the session watcher registered
  -- a real wake after -- [unchanged from fix_darkwake_heartbeat_drift.sql]
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
