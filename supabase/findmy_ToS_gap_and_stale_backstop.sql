-- Close the Find My cross-check's silent-failure gap (2026-09-14).
--
-- Root cause of the 2026-09-13/14 phone-dark alert cluster: Apple pushed an
-- updated Terms of Service prompt on the Apple ID findmy_watcher.py uses,
-- which made every check raise PyiCloudAcceptTermsException. That type was
-- NOT a subclass of PyiCloudFailedLoginException and wasn't explicitly
-- handled by _find_my_last_seen(), so it fell through to check_once()'s
-- generic per-cycle local log line -- confirmed live: ~13 hours (2026-09-13
-- 20:50 through 2026-09-14 10:1x) with zero email, while
-- findmy_last_seen/findmy_reported_at sat frozen and fm_recent in
-- eg_on_red() went permanently false. Every ordinary phone-dark blip that
-- should have been silently absorbed (iOS suspending the VPN app) instead
-- fired a full email, worded as if Find My had positively confirmed
-- something was wrong with the PHONE -- when the actual problem was a
-- stuck credential prompt on the Mac.
--
-- Three changes, paired with a Python fix in eyeguard/findmy_watcher.py
-- (same commit) that now catches PyiCloudAcceptTermsException explicitly:
--
-- 1. eg_report_findmy_session_expired() gains p_reason (default
--    'session_expired', backward compatible with every existing caller --
--    same established pattern this project already uses repeatedly for
--    RPC evolution, e.g. eg_watcher_heartbeat's p_untrusted_library /
--    p_debugger_attached / p_confirmed_awake / p_agent_unhardened, each
--    added the same way across separate migrations). 'accept_terms' gets
--    its own email with the ACTUAL fix (accept the prompt at icloud.com --
--    no --setup, no 2FA) instead of the misleading --setup instructions.
--
-- 2. eg_check_phone() gains branch (e): a generic staleness backstop on
--    findmy_reported_at (stamped by every successful report regardless of
--    what last_seen value it carries, so its own staleness means "is the
--    watcher completing cycles at all"). 2 hours of margin over the normal
--    10-minute cadence. This is NOT redundant with (1) -- it's the net
--    that catches whatever the NEXT unhandled pyicloud exception type turns
--    out to be, the same way this ToS prompt caught this one only after
--    already running silently for hours.
--
-- 3. eg_on_red()'s phone-dark branch now checks findmy_reported_at's own
--    freshness BEFORE treating a stale findmy_last_seen as corroborating
--    evidence. An unhealthy cross-check means fm_last tells us nothing
--    either way -- the email now says that plainly instead of the
--    overstated "a stronger signal something's actually wrong" wording
--    that fired throughout the 2026-09-13/14 window.
--
-- Full rebuild of eg_check_phone() (newest: guard_redundant_cron_updates.sql,
-- PR #96, merged), eg_on_red() (newest: drop_phone_unlock_escalation.sql,
-- unchanged since 2026-09-12) and eg_report_findmy_session_expired()
-- (newest: findmy_session_expired_alert.sql, unchanged since 2026-09-02),
-- each confirmed newest via git log before extracting. Diffed against the
-- live definitions: only the changes described above differ; every other
-- branch is byte-identical.
--
-- DEPLOY ORDER: apply this BEFORE eyeguard/findmy_watcher.py's matching
-- change reaches the Mac. p_reason has a default, so old Python code
-- calling with {} keeps working against the new signature either way --
-- but new Python code calling with {"p_reason": "accept_terms"} would 404
-- against the OLD signature (this project has hit that exact failure mode
-- twice before: eg_report_network_gap, eg_watcher_heartbeat). The Mac
-- auto-deploys via deploy_watcher (~5 min after merge) -- there is no way
-- to hold that back, so run this SQL first.

alter table public.phone_status add column if not exists findmy_stale_alerted boolean not null default false;

create or replace function public.eg_report_findmy_session_expired(
  p_reason text default 'session_expired'
) returns void
language plpgsql security definer set search_path = public as $$
declare already boolean;
declare subj text; body text;
begin
  select findmy_session_expired_alerted into already
    from public.phone_status where id = 1;
  if not coalesce(already, false) then
    -- ADDED p_reason (2026-09-14): the original single cause this RPC
    -- covered ('session_expired' -- login failed or a fresh 2FA challenge
    -- is needed) requires a --setup re-run with Jonah's own phone in hand.
    -- 'accept_terms' (findmy_watcher.py's PyiCloudAcceptTermsException
    -- handling) is a completely different, much simpler fix -- Apple just
    -- wants an updated ToS prompt accepted at icloud.com, no --setup, no
    -- 2FA. Sending the --setup instructions for that cause would send
    -- Jonah looking for a prompt that was never the actual problem
    -- (confirmed exactly backwards during the 2026-09-13/14 ToS block,
    -- before this existed). One shared debounce flag still covers both --
    -- if a caller passes neither/an unrecognized reason, it falls back to
    -- the original 'session_expired' wording, the historically safe
    -- default.
    if p_reason = 'accept_terms' then
      subj := '📋 EyeGuard — Find My needs updated Terms of Service accepted';
      body := '<p><b>The Find My cross-check for phone-dark alerts has '
          || 'stopped working.</b></p><p>Apple is asking for updated Terms '
          || 'of Service to be accepted on this Apple ID before Find My '
          || 'data can be read again.</p><p><b>Fix:</b> sign in at '
          || 'icloud.com (or open Find My on any Apple device signed into '
          || 'this account) and accept the prompt. No password reset, no '
          || '2FA re-setup needed -- this is a one-click Apple-side '
          || 'prompt, not a credential problem.</p><p>Monitoring itself is '
          || 'NOT affected by this. Only the cross-check that tells real '
          || 'phone-sleep apart from actual unmonitored use is down -- '
          || 'until this is fixed, phone-dark alerts fall back to their '
          || 'noisier default (may fire on normal sleep, not just real '
          || 'bypass attempts).</p>';
    else
      subj := '🔑 EyeGuard — Find My session expired, needs immediate refresh';
      body := '<p><b>The Find My cross-check for phone-dark alerts has '
          || 'stopped working.</b></p><p>Jonah needs to run '
          || '<code>findmy_watcher.py --setup</code> again as soon as '
          || 'possible -- needs his own phone in hand for a 2FA code, '
          || 'can''t be done remotely.</p><p>Monitoring itself is NOT '
          || 'affected by this. Only the cross-check that tells real '
          || 'phone-sleep apart from actual unmonitored use is down -- '
          || 'until this is fixed, phone-dark alerts fall back to their '
          || 'noisier default (may fire on normal sleep, not just real '
          || 'bypass attempts).</p>';
    end if;
    perform public.eg_send_email(subj, body);
    update public.phone_status set findmy_session_expired_alerted = true where id = 1;
  end if;
end $$;
revoke all on function public.eg_report_findmy_session_expired(text) from public;
grant execute on function public.eg_report_findmy_session_expired(text) to anon;

-- The old zero-arg signature is superseded by the one above (same name,
-- now with a defaulted p_reason) -- drop it explicitly so two overloads
-- don't coexist silently.
drop function if exists public.eg_report_findmy_session_expired();

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

  -- (e) Find My cross-check itself has gone silent -- NEW (2026-09-14).
  -- Backstop for ANY findmy_watcher.py failure mode that ISN'T one of the
  -- specific cases eg_report_findmy_session_expired() already alerts on
  -- immediately (see that function's p_reason variants) -- e.g. exactly
  -- what happened on 2026-09-13/14: Apple pushed an updated ToS prompt,
  -- PyiCloudAcceptTermsException wasn't a type _find_my_last_seen() caught
  -- explicitly, so it fell through to the generic per-cycle local log line
  -- with NO email at all for ~13 hours (now fixed at the Python level too --
  -- this branch is defense in depth for whatever the NEXT unhandled
  -- exception type turns out to be).
  --
  -- findmy_reported_at is stamped by every SUCCESSFUL
  -- eg_report_findmy_status() call regardless of what last_seen value it
  -- carries, so its own staleness measures "is the watcher completing
  -- cycles at all", independent of whether the phone itself currently has
  -- live Find My data. 2 hours gives >10x margin over the normal 10-minute
  -- cron cadence (won't fire on one missed or slow tick) while still
  -- catching a real silent gap same-day rather than over days.
  if p.findmy_reported_at is not null
     and now() - p.findmy_reported_at > interval '2 hours'
     and not p.findmy_stale_alerted then
    perform public.eg_send_email(
      '⚫ EyeGuard — Find My cross-check went silent',
      format('<p><b>The Find My cross-check hasn''t completed a check-and-'
          || 'report cycle in %s.</b></p><p>This is a general backstop, not '
          || 'a specific diagnosis -- check findmy_watcher.out.log and '
          || 'findmy_watcher_crash.log on the Mac for the actual cause.</p>'
          || '<p>Monitoring itself is NOT affected. Only the cross-check '
          || 'that tells real phone-sleep apart from actual unmonitored use '
          || 'is down -- until this is fixed, phone-dark alerts fall back '
          || 'to their noisier default.</p>', age(now(), p.findmy_reported_at)));
    update public.phone_status set findmy_stale_alerted = true where id = 1;
  elsif p.findmy_reported_at is not null
        and now() - p.findmy_reported_at <= interval '2 hours'
        and p.findmy_stale_alerted then
    update public.phone_status set findmy_stale_alerted = false where id = 1;
  end if;
end $$;

create or replace function public.eg_on_red() returns trigger
language plpgsql security definer set search_path = public as $$
declare loc text; whenn text; kind text;
declare fm_last timestamptz; fm_recent boolean;
declare fm_reported_at timestamptz; fm_watcher_healthy boolean;
begin
  whenn := to_char(NEW.flagged_at at time zone 'America/New_York',
                   'Mon DD, HH12:MI AM');
  if NEW.reason like 'phone-dark%' then
    select findmy_last_seen, findmy_reported_at
      into fm_last, fm_reported_at
      from public.phone_status where id = 1;
    fm_recent := fm_last is not null and now() - fm_last <= interval '20 minutes';
    -- NEW (2026-09-14): is the CROSS-CHECK ITSELF currently able to report
    -- at all, independent of what fm_last says? findmy_reported_at is
    -- stamped on every successful eg_report_findmy_status() call regardless
    -- of the last_seen value it carries, so its own staleness answers that
    -- question directly. 20 minutes = 2x the normal 10-minute cron cadence,
    -- generous margin against one slow/missed tick without falsely
    -- disclaiming a genuinely fresh corroboration.
    fm_watcher_healthy := fm_reported_at is not null
                           and now() - fm_reported_at <= interval '20 minutes';

    if fm_recent then
      -- Present (Find My) -- idle/asleep, iOS most likely just suspended
      -- the VPN app in the background. Not an issue: the phone is either
      -- off (nothing risky possible) or present-and-idle (same).
      return NEW;
    end if;

    perform public.eg_send_email('📵 EyeGuard — phone went dark',
      format('<p><b>The iPhone stopped routing through the monitored network.</b></p>'
          || '<p>When: %s. The VPN may be off, the phone off, or out of signal. '
          || '%s If it wasn''t expected, it warrants a check-in.</p>', whenn,
          case
            -- FIXED 2026-09-14: previously this branch's stale fm_last was
            -- read as "a stronger signal something's wrong" even when the
            -- cross-check itself was the thing that was broken (confirmed
            -- live: a 13-hour Apple ToS block on 2026-09-13/14 made this
            -- fire that exact misleading wording on every phone-dark event
            -- in the window, pointing at the phone when the real problem
            -- was a stuck credential on the Mac). Check watcher health
            -- FIRST -- an unhealthy watcher means fm_last tells us nothing
            -- either way, so say that plainly instead of overstating it.
            when not fm_watcher_healthy then
              'The Find My cross-check itself hasn''t reported recently '
              || 'either, so this can''t be corroborated one way or the '
              || 'other right now -- treat it as an unconfirmed dark event, '
              || 'not a confirmed one.'
            when fm_last is not null then
              format('Find My also hasn''t seen it since %s -- a '
                     || 'stronger signal something''s actually wrong, '
                     || 'not just iOS suspending the VPN app.',
                     to_char(fm_last at time zone 'America/New_York',
                             'Mon DD, HH12:MI AM'))
            else 'Find My cross-check has no data yet (not set up, or the '
                 || 'session needs a fresh login).'
          end));
    return NEW;
  end if;
  if NEW.reason like 'phone-blocked%' or NEW.reason like 'phone-signal%' then
    perform public.eg_send_email('🔴 EyeGuard — phone hit an explicit site',
      format('<p><b>%s</b></p><p>When: %s</p>'
          || '<p>Seen on the iPhone via the network monitor.</p>',
          coalesce(NEW.reason, ''), whenn));
    return NEW;
  end if;
  if NEW.app = 'EyeGuard' or NEW.reason like 'tamper:%' then
    perform public.eg_send_email('🚨 EyeGuard — tampering detected',
      format('<p><b>EyeGuard detected local tampering.</b></p>'
          || '<p><b>When:</b> %s<br><b>Detail:</b> %s</p>'
          || '<p>The cloud record is append-only and cannot be erased.</p>',
          whenn, coalesce(NEW.reason, '')));
    return NEW;
  end if;
  loc := coalesce(NEW.app, 'an app')
       || coalesce(' — ' || nullif(coalesce(NEW.url, NEW.window_title), ''), '');
  kind := case when NEW.is_nudity then 'Explicit nudity'
               else 'Very revealing content' end;
  perform public.eg_send_email('🔴 EyeGuard alert — ' || kind,
    format('<p><b>%s was flagged.</b></p><p><b>When:</b> %s<br>'
        || '<b>Where:</b> %s</p><p>The review image is on the dashboard: '
        || '<a href="https://dirrimp.github.io/EyeGuard/">open dashboard</a></p>',
        kind, whenn, loc));
  return NEW;
end $$;
