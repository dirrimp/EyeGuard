-- Debounce two alert types that fire on a single reading/event with no
-- persistence check at all, unlike every other branch in this project's
-- alert functions -- both caused real spam on 2026-09-02.
--
-- Standing lesson (again): eg_heartbeat(), eg_check_gone_dark(),
-- eg_phone_heartbeat(), eg_check_phone(), and eg_on_red() all take fixed
-- argument lists or no arguments -- every create-or-replace below is a full
-- rebuild verified against the actual newest committed version of each
-- (confirmed via `git log` per function, not a snapshot), reproducing every
-- existing branch unchanged except the one being fixed. See
-- fix_watcher_dark_sleep_awareness.sql's own PART 1 for the last time this
-- was gotten wrong.
--
-- ============================================================================
-- FIX 1: "lost view of the screen" (device_status.screen_ok, branch (b) of
-- eg_check_gone_dark()) had ZERO debounce -- it alerted on the very first
-- heartbeat reporting screen_ok=false, no persistence requirement, unlike
-- branches (a)/(d)/(f) which are inherently elapsed-time-gated and (c) which
-- at least shares (b)'s gap. Root cause of the 2026-09-02 15:32 incident: a
-- single physically-impossible probe reading (brightness=2.61, >1.0 is not
-- a real value) that self-corrected in 18 seconds still triggered an
-- instant email. Fix: track screen_dark_since on device_status (set on the
-- first false reading, cleared on the first true one) and require 2 minutes
-- of continuous darkness before alerting -- long enough to survive one bad
-- reading, short enough to still catch a real problem quickly.
--
-- FIX 2: "phone actively used while unmonitored" (phone_unlock_active_use_
-- signal.sql's eg_on_red() phone-dark branch) escalated INSTANTLY on the
-- very first phone-dark flagged row correlated with a recent unlock -- no
-- persistence check either, because it fired from an AFTER INSERT trigger
-- reacting to a single row, not from a periodic elapsed-time check like
-- everywhere else in this project. Root cause of the 2026-09-02 11:46
-- incident (confirmed with Jonah: VPN/wifi monitor is never turned off,
-- phone is always on home wifi or the tunnel): leaving home causes a real
-- wifi -> cellular -> VPN-re-handshake gap that commonly exceeds the
-- router's fast 30s liveness threshold (router/eyeguard-phone.py's
-- dark_buffer_seconds) -- and that gap naturally coincides with unlocking,
-- since picking up the phone to leave is exactly when this happens. The two
-- conditions being correlated by ordinary behavior, not independent, is
-- exactly why requiring both didn't actually filter out this false-positive
-- shape. Fix: keep the router's own 30s threshold (correct for its own
-- purpose -- general liveness), but move the ESCALATION decision out of the
-- instant trigger and into eg_check_phone() (cron, once a minute, same
-- elapsed-time-based shape as eg_check_gone_dark()'s other branches),
-- requiring the phone to still be dark 2 minutes after going dark before
-- treating a recent unlock as a real bypass signal rather than a handoff.
-- ============================================================================

alter table public.device_status add column if not exists screen_dark_since timestamptz;
alter table public.phone_status add column if not exists dark_since timestamptz;
alter table public.phone_status add column if not exists active_use_alerted boolean not null default false;

-- ---- eg_heartbeat(): unchanged from suspend_abuse_check.sql except the new
-- screen_dark_since tracking (mirrors how screen_ok itself is coalesced).
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
         screen_dark_since = case
           when p_screen_ok is false then coalesce(screen_dark_since, now())
           when p_screen_ok is true then null
           else screen_dark_since
         end,
         frames_analyzed = coalesce(p_frames_analyzed, frames_analyzed),
         detector_ok = coalesce(p_detector_ok, detector_ok),
         updated_at = now()
   where id = 1;
end $$;
revoke all on function public.eg_heartbeat(boolean, bigint, boolean) from public;
grant execute on function public.eg_heartbeat(boolean, bigint, boolean) to anon;

-- ---- eg_check_gone_dark(): full rebuild from fix_watcher_dark_sleep_
-- awareness.sql (confirmed newest via git log). Branches (a),(c),(d),(e),(f)
-- copied verbatim, unchanged. Only (b) gets the new debounce.
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

    -- (b) went blind: can't see the screen -- DEBOUNCED (2026-09-02): must
    -- persist 2+ minutes, not just the first heartbeat reporting false. See
    -- FIX 1 above.
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

-- ---- eg_phone_heartbeat(): unchanged from router_admin_trust.sql except
-- the new dark_since tracking (mirrors phone_active's own coalesce).
create or replace function public.eg_phone_heartbeat(
  p_active boolean default null
) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.phone_status
     set monitor_beat = now(),
         last_seen = case when p_active then now() else last_seen end,
         phone_active = coalesce(p_active, phone_active),
         dark_since = case
           when p_active is false then coalesce(dark_since, now())
           when p_active is true then null
           else dark_since
         end,
         offline_alerted = false
   where id = 1;
end $$;
revoke all on function public.eg_phone_heartbeat(boolean) from public;
grant execute on function public.eg_phone_heartbeat(boolean) to anon;

-- ---- eg_check_phone(): full rebuild from router_admin_trust.sql (confirmed
-- newest). Branches (a),(b),(c) copied verbatim, unchanged. New (d) below
-- is the debounced phone-active-use escalation, moved here from eg_on_red().
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
  elsif not (p.watcher_script_tampered or p.watcher_process_down) then
    update public.phone_status set watcher_alerted = false where id = 1;
  end if;

  -- (d) NEW: phone actively used (unlocked) around when it went dark, AND
  -- the darkness has genuinely persisted 2+ minutes -- not just a brief
  -- network handoff (leaving home: wifi -> cellular -> VPN re-handshake).
  -- Moved here from eg_on_red()'s instant-on-INSERT firing; see FIX 2 above.
  if not p.phone_active and p.dark_since is not null
     and now() - p.dark_since >= interval '2 minutes'
     and p.last_unlock_at is not null
     and now() - p.last_unlock_at <= interval '20 minutes'
     and not p.active_use_alerted then
    perform public.eg_send_email('🚨 EyeGuard — phone actively used while unmonitored',
      format('<p><b>The iPhone was unlocked at %s, and has not been routing '
          || 'through the monitored network for %s.</b></p>'
          || '<p>Unlike a routine "phone went dark" (which can just mean the '
          || 'phone is asleep and iOS backgrounded the VPN app, or a brief '
          || 'network handoff while leaving home), this gap has persisted -- '
          || 'a real sign monitoring may have been bypassed, not just a '
          || 'momentary reconnect. Check in.</p>',
          to_char(p.last_unlock_at at time zone 'America/New_York', 'Mon DD, HH12:MI AM'),
          age(now(), p.dark_since)));
    update public.phone_status set active_use_alerted = true where id = 1;
  elsif p.phone_active and p.active_use_alerted then
    update public.phone_status set active_use_alerted = false where id = 1;
  end if;
end $$;

-- ---- eg_on_red(): full rebuild from phone_unlock_active_use_signal.sql
-- (confirmed newest). Every branch except the phone-dark "recently_unlocked"
-- case is copied verbatim, unchanged. That one case no longer emails
-- instantly -- it just returns, leaving the escalation decision to
-- eg_check_phone()'s new debounced branch (d) above. The row still lands in
-- flags either way (append-only, tamper-evident) regardless of this change.
create or replace function public.eg_on_red() returns trigger
language plpgsql security definer set search_path = public as $$
declare loc text; whenn text; kind text;
declare fm_last timestamptz; fm_recent boolean;
declare unlock_at timestamptz; recently_unlocked boolean;
begin
  whenn := to_char(NEW.flagged_at at time zone 'America/New_York',
                   'Mon DD, HH12:MI AM');
  if NEW.reason like 'phone-dark%' then
    select findmy_last_seen, last_unlock_at into fm_last, unlock_at
      from public.phone_status where id = 1;
    fm_recent := fm_last is not null and now() - fm_last <= interval '20 minutes';
    recently_unlocked := unlock_at is not null and now() - unlock_at <= interval '20 minutes';

    if recently_unlocked then
      -- DEFERRED (2026-09-02, see FIX 2 above): a single dark-flagged row
      -- alone doesn't prove a sustained gap -- network handoffs commonly
      -- exceed the router's fast 30s threshold and commonly coincide with
      -- unlocking. eg_check_phone() (cron, every 1 min) escalates this to
      -- the urgent email only if the phone is STILL dark 2+ minutes later.
      return NEW;
    elsif fm_recent then
      -- Present (Find My) but no evidence of active use -- idle/asleep,
      -- iOS most likely just suspended the VPN app in the background.
      return NEW;
    end if;

    perform public.eg_send_email('📵 EyeGuard — phone went dark',
      format('<p><b>The iPhone stopped routing through the monitored network.</b></p>'
          || '<p>When: %s. The VPN may be off, the phone off, or out of signal. '
          || '%s If it wasn''t expected, it warrants a check-in.</p>', whenn,
          case when fm_last is not null
                 then format('Find My also hasn''t seen it since %s -- a '
                              'stronger signal something''s actually wrong, '
                              'not just iOS suspending the VPN app.',
                              to_char(fm_last at time zone 'America/New_York',
                                      'Mon DD, HH12:MI AM'))
               else 'Find My cross-check has no data yet (not set up, or the '
                    'session needs a fresh login).'
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
