-- Merge main-app-dark and session-watcher-dark into one email when they're
-- both really the same event (2026-09-16).
--
-- Confirmed live, this morning: a real ~51-minute total internet outage
-- (DNS resolution failures -- confirmed via agent_diagnostic.log and
-- session_watcher's own log, both showing identical
-- "nodename nor servname provided, or not known" errors) produced two
-- separate emails 47 minutes apart -- "monitoring went dark" at 05:52, then
-- "session watcher went dark" at 06:39. This was NOT independent double
-- alerting: branch (d)'s own alive_recent_corrob guard already suppresses
-- it from firing standalone WHILE main is concurrently 'alive'-but-stale --
-- that part was already working correctly. What actually happened: main
-- app recovered first (06:38, its own client pushed a heartbeat through the
-- instant connectivity returned), which cleared the suppression -- but the
-- session watcher hadn't caught up yet, so branch (d) fired its own
-- separate email one minute later once it was no longer suppressed. Two
-- emails, one real root cause, just staggered by the two processes'
-- slightly different recovery timing.
--
-- Fix: when branch (a) is about to fire, check the session watcher's OWN
-- dark condition right there too -- using the same three corroboration
-- guards branch (d) already trusts (a genuine sleep signal, clean-shutdown-
-- with-recent-heartbeat), MINUS the alive_recent_corrob guard specifically
-- (that one's whole purpose was avoiding a redundant STANDALONE watcher
-- email while main is also down -- moot here, since we're proactively
-- merging instead of suppressing). If watcher is also dark, send ONE
-- combined email and set BOTH alerted=true and watcher_dark_alerted=true --
-- the latter is what stops branch (d) from separately re-alerting once
-- main recovers slightly ahead of watcher, closing the exact gap that
-- produced this morning's second email. Branch (d) itself is otherwise
-- completely unchanged, including its own alive_recent_corrob guard, which
-- is exactly what correctly limits it to the standalone case now.
--
-- No information is lost -- the combined email names BOTH last-seen ages
-- and states both consequences (detection down, new-account/user-switch
-- checking down), same facts as the two original emails, just one message.
--
-- Verified before writing SQL: simulated all relevant state transitions in
-- pure Python (both-dark-simultaneously -> combined fires; main-only;
-- watcher-only; main-already-alerted-with-watcher-newly-dark -> correctly
-- suppressed by the SAME existing guard, not a regression; legitimate
-- overnight sleep -> none fire; the actual staggered sequence replayed
-- with real timestamps -> fires once at t1, confirmed silent at t2 when
-- main recovers 45 minutes later with watcher still catching up) before
-- ever touching SQL. Full rebuild verified against the newest live source
-- (guard_redundant_cron_updates.sql, PR #96 -- confirmed via git log,
-- NOT fix_brief_powerplug_wake_false_positive.sql, which I initially
-- extracted from by mistake and caught before writing anything -- that
-- file predates #96's watcher_alerted guard fix and would have silently
-- reverted it). Diffed line-by-line: only branch (a)'s body and one
-- comment line on branch (d) differ; the original standalone email text
-- is preserved verbatim in the else-branch, not dropped; (b), (c), (e),
-- (f) are byte-identical.
create or replace function public.eg_check_gone_dark() returns void
language plpgsql security definer set search_path = public as $$
declare d public.device_status;
declare watcher_also_dark boolean;  -- NEW 2026-09-16: see (a)'s own comment
begin
  select * into d from public.device_status where id = 1;
  if d.last_heartbeat is null then return; end if;

  -- (a) went dark: no heartbeat for 3+ minutes -- MERGED 2026-09-16 with (d)
  -- when the session watcher is ALSO concurrently dark. Confirmed live
  -- (2026-09-16, a real ~51min total internet outage -- DNS resolution
  -- failures on both processes): main app went dark at 05:51, session
  -- watcher's own guard below (the "not (status='alive' and stale>2min)"
  -- condition) correctly suppressed IT from also alerting standalone while
  -- main was concurrently down -- but the moment main recovered at 06:38
  -- (client heartbeat succeeded, clearing that suppression), the watcher
  -- was STILL stale (hadn't caught up yet), so branch (d) fired its OWN
  -- separate email one minute later at 06:39. Two emails, ~47 minutes
  -- apart, for one root cause. The existing suppression already prevented
  -- them firing in the SAME instant; what it didn't prevent was this
  -- staggered pair once main recovered slightly ahead of watcher.
  --
  -- Fix: when main is about to alert, check watcher's OWN dark condition
  -- right here too -- WITHOUT its alive_recent_corrob guard (that guard's
  -- whole purpose was avoiding a redundant STANDALONE watcher email while
  -- main is also down; here we're proactively merging instead of
  -- suppressing, so it no longer applies). The other two corroboration
  -- guards (a genuine sleep signal, clean-shutdown-with-recent-heartbeat)
  -- still apply unchanged -- they protect a different, still-relevant
  -- scenario (legitimate overnight sleep) that has nothing to do with this
  -- merge. If watcher is also dark, send ONE combined email and set BOTH
  -- alerted=true and watcher_dark_alerted=true -- the latter is what stops
  -- branch (d) below from separately re-alerting once main recovers,
  -- closing the exact gap that produced this morning's second email.
  if d.status = 'alive' and not d.alerted
     and now() - d.last_heartbeat > interval '3 minutes' then

    watcher_also_dark := d.watcher_last_heartbeat is not null
       and now() - d.watcher_last_heartbeat > interval '3 minutes'
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
       );

    if watcher_also_dark then
      perform public.eg_send_email(
        '⚫ EyeGuard — monitoring AND session watcher both went dark',
        format('<p><b>Both EyeGuard and the account/session watcher stopped '
            || 'reporting at the same time.</b></p><p>Monitoring last seen %s '
            || 'ago; the session watcher last seen %s ago.</p><p>This usually '
            || 'means the whole Mac lost network connectivity -- the two '
            || 'processes are independent, so both going dark together is '
            || 'expected in that case, not a sign of one being specifically '
            || 'targeted. Detection AND new-account/user-switch checking are '
            || 'both down until this resolves. If unexpected, check in.</p>',
            age(now(), d.last_heartbeat), age(now(), d.watcher_last_heartbeat)));
      update public.device_status set alerted = true, watcher_dark_alerted = true where id = 1;
    else
      perform public.eg_send_email(
        '⚫ EyeGuard — monitoring went dark',
        format('<p><b>EyeGuard stopped reporting.</b></p><p>Last seen %s ago. The Mac '
            || 'may be off, offline, or the monitor was stopped. If unexpected, '
            || 'check in.</p>', age(now(), d.last_heartbeat)));
      update public.device_status set alerted = true where id = 1;
    end if;
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

  -- (d) session watcher went dark, STANDALONE case only -- see the
  -- merged send inside (a) above for when main app is ALSO down at the
  -- same moment; this branch's own alive_recent_corrob guard below is
  -- exactly what makes that split correct: it suppresses THIS branch
  -- while main is concurrently 'alive'-but-stale, so it only fires here
  -- when watcher is dark on its own. [otherwise unchanged]
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