-- Two things in one file, both touching eg_check_gone_dark()/
-- eg_watcher_heartbeat(), so they need to land together as one correct
-- create-or-replace rather than two separate ones that could race or
-- clobber each other.
--
-- ============================================================================
-- PART 1: RESTORES A REGRESSION. Read this even if you only care about part 2.
-- ============================================================================
-- supabase/fix_watcher_alert_debounce.sql (2026-08-26, applied directly by
-- Dad via the SQL editor, never committed to git) fixed a real bug -- branch
-- (d) "session watcher went dark" and branch (e) "account/session anomaly"
-- shared one `watcher_alerted` flag, and eg_watcher_heartbeat() reset that
-- SAME shared flag on every normal heartbeat, so the two stomped on each
-- other and produced a genuine one-email-per-minute spam loop. That
-- diagnosis was correct and the spam did stop.
--
-- BUT that file was written from a snapshot of supabase/anon_client_pivot.sql
-- (2 args to eg_watcher_heartbeat, branches a-e only) -- it didn't know about
-- two LATER commits that had already extended the real live schema:
-- injected_library_check.sql and debugger_attach_check.sql (both
-- 2026-08-25, both committed, both merged before the debounce fix was
-- written). The real live eg_watcher_heartbeat() took 4 args
-- (new_account/wrong_user/untrusted_library/debugger_attached) and branch
-- (e) covered all 4 conditions; a real branch (f), "possible fake asleep
-- signal" (supabase/suspend_abuse_check.sql), also already existed.
--
-- eg_watcher_heartbeat(...) is overloaded by argument count in Postgres, so
-- the debounce fix's 2-arg create-or-replace didn't touch the real 4-arg
-- function at all -- harmless, just a dead unused overload left behind
-- (cleaned up below). But eg_check_gone_dark() takes ZERO arguments, so
-- there is only ever one version of it, and the debounce fix's
-- create-or-replace of it DEFINITELY overwrote the real one. Since that
-- version only implemented branches (a)-(e) with the 2-condition (new
-- account/wrong user) form of (e), running it silently:
--   - dropped the untrusted-library and debugger-attached conditions from
--     branch (e) entirely -- their state was still being recorded by every
--     heartbeat (watcher_untrusted_library/watcher_debugger_attached
--     columns, untouched), just never checked or alerted on any more.
--   - dropped branch (f) (fake-asleep / suspend-abuse detection) completely.
-- Both are real security-relevant alert types, not cosmetic. If
-- fix_watcher_alert_debounce.sql was actually run (confirmed: yes), this has
-- been silently open since 2026-08-26.
--
-- This file is a full rebuild verified against the actual last-committed
-- state (debugger_attach_check.sql, confirmed via `git log` to be the
-- newest commit touching either function) -- not another snapshot. It
-- restores (e)'s full 4-condition coverage and all of (f), keeps the
-- legitimate part of the debounce fix (branches d/e no longer share a flag),
-- and adds the new sleep-awareness suppression for (d) below.
--
-- Standing lesson for next time: eg_check_gone_dark() takes no arguments,
-- so ANY create-or-replace of it fully replaces the live function --
-- writing one from anything other than the actual current definition (fetch
-- it live, or verify against the newest committed SQL touching it) silently
-- deletes whatever branches aren't reproduced. Should have been caught
-- before handing that file to Dad to run.
--
-- ============================================================================
-- PART 2: session-watcher sleep-awareness (2026-08-27) -- the actual new fix.
-- ============================================================================
-- Confirmed live: every "session watcher went dark" alert in a sample of 4
-- landed 3:05-3:21 after a `pmset -g log` "Entering Sleep state due to
-- 'Clamshell Sleep'" line -- right at branch (d)'s 3-minute threshold, every
-- single time. Root cause: session_watcher.py is a root LaunchDaemon with no
-- sleep/wake awareness at all (unlike the main app, which already has this
-- via NSWorkspace notifications in menubar.py -- see uploader.py's
-- suspend()/resume()). During real system sleep the daemon's process is
-- genuinely suspended -- it cannot heartbeat, cannot detect anything, cannot
-- even run -- and after ~3 minutes of that eg_check_gone_dark() has no way
-- to tell "legitimately asleep" from "disabled." This Mac sleeps often (318
-- sleep/wakes in 3 days per `pmset -g log`), so this fired regularly.
--
-- Fix: session_watcher.py gets its own IOKit-based sleep watcher (root
-- LaunchDaemon has no GUI session for NSWorkspace, so this needs the
-- kernel-level equivalent -- the exact same IORegisterForSystemPower
-- mechanism the original, now-deleted vault.py used for the same reason,
-- see git history at 71f700c:eyeguard/vault.py). On WillSleep/
-- WillPowerOff/WillRestart it calls the new eg_watcher_report_sleep() RPC
-- below BEFORE allowing the sleep transition to complete, so the signal is
-- guaranteed to land before the process actually suspends. Branch (d) then
-- treats a recent signal as an explanation for the heartbeat gap, capped at
-- 24h.
--
-- Why a time cap and not indefinite suppression: this is deliberately NOT
-- symmetric with how the main app's clean_shutdown status works (no expiry,
-- relies entirely on branch (f)'s cross-check against session_watcher's own
-- heartbeat for abuse detection instead). session_watcher has no equivalent
-- third, independent process to cross-check ITS OWN sleep claim against --
-- during a real sleep every process on the machine goes dark together, so
-- there's no divergence signal available the way there is for the main
-- app's claim. Someone holding the anon key (deliberately public) could in
-- theory call eg_watcher_report_sleep() repeatedly while the real daemon is
-- actually killed, suppressing this specific alert type indefinitely.
-- Accepted as a bounded residual, same tamper-EVIDENT-not-PROOF philosophy
-- as this project's other explicitly-documented tradeoffs (see
-- router/REMOTE_SSH_ACCESS.md's identical reasoning for a different case) --
-- 24h means a sustained fake-sleep-spam attempt still eventually gets
-- caught, and every real heartbeat clears the signal immediately (see
-- eg_watcher_heartbeat() below), so the exposure window in practice is only
-- ever as long as the daemon is genuinely not running. Also: someone with
-- the local access needed to run such a script already has much simpler,
-- equally-detectable ways to disable monitoring (kill the daemon outright,
-- which still alerts once the cap or a real check-in happens).

alter table public.device_status add column if not exists watcher_dark_alerted boolean not null default false;
alter table public.device_status add column if not exists watcher_sleep_signaled_at timestamptz;
-- watcher_account_alerted (added by the untracked debounce fix) and the
-- original watcher_alerted are both left in place, unused/reused
-- respectively per below -- same "don't remove what a rollback might still
-- reference" caution as every other historical column in this schema.

-- Dead overload cleanup: the untracked debounce fix's 2-arg version was
-- never called (session_watcher.py always sends 4 named args) but is real
-- schema clutter worth removing while this file is already touching the
-- same function.
drop function if exists public.eg_watcher_heartbeat(boolean, boolean);

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
         -- A genuine heartbeat proves the real daemon is actually running
         -- again -- clear any pending sleep-explains-the-gap signal so a
         -- stale signal from hours ago can't linger past the very next
         -- normal check-in.
         watcher_sleep_signaled_at = null,
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

-- New: called by session_watcher.py's IOKit sleep watcher right before the
-- Mac actually sleeps/powers off/restarts. Anon-key callable, no auth beyond
-- that (see the accepted-residual reasoning above) -- matches
-- eg_report_suspend()'s own "routine sleep shouldn't need a password prompt"
-- precedent for the main app.
create or replace function public.eg_watcher_report_sleep() returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.device_status set watcher_sleep_signaled_at = now() where id = 1;
end $$;
revoke all on function public.eg_watcher_report_sleep() from public;
grant execute on function public.eg_watcher_report_sleep() to anon;

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

  -- (d) session watcher went dark -- OWN flag (watcher_dark_alerted, split
  -- from (e)'s watcher_alerted by the 2026-08-26 debounce fix, correctly),
  -- with a freshness-gated recovery reset, UNLESS a recent WillSleep signal
  -- from the watcher's own IOKit sleep watcher explains the gap (see PART 2
  -- above for the full reasoning and the 24h cap).
  if d.watcher_last_heartbeat is not null then
    if now() - d.watcher_last_heartbeat > interval '3 minutes'
       and not d.watcher_dark_alerted
       and not (
         d.watcher_sleep_signaled_at is not null
         and d.watcher_sleep_signaled_at > d.watcher_last_heartbeat
         and now() - d.watcher_sleep_signaled_at <= interval '24 hours'
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

  -- (e) session watcher found a new account, the wrong active user, an
  -- untrusted library, OR an attached debugger -- restored to full 4-
  -- condition coverage (was silently reduced to 2 by the untracked debounce
  -- fix, see PART 1). OWN flag (watcher_alerted), never touches (d)'s.
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
  -- heartbeats well after. RESTORED -- was silently dropped entirely by the
  -- untracked debounce fix (see PART 1). Unchanged from
  -- debugger_attach_check.sql.
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
