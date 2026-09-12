-- Retire the phone-unlock "actively in use" escalation (2026-09-12).
--
-- phone_unlock_active_use_signal.sql (2026-09-02) added a finer question on
-- top of the router's own phone-dark detection: not just "is the phone
-- on/monitored" but "was it ACTIVELY BEING USED right when it went dark" --
-- fed by an iPhone Shortcuts "When I Unlock My iPhone" automation hitting
-- eg_report_phone_unlock() directly.
--
-- That automation has proven structurally unreliable: Shortcuts' "Get
-- Contents of URL" has no documented error-suppression or retry mechanism
-- (confirmed via research -- Apple's own forums / community threads agree
-- "when an error occurs, the shortcut simply reports an error and stops",
-- and the ~25s request timeout isn't configurable), and its single HTTPS
-- call rides the same on-demand WireGuard tunnel already documented as
-- unstable everywhere else in this project. A dropped call there doesn't
-- just miss a data point -- it reads as "not recently unlocked," which is
-- the WRONG direction for a security signal (silently downgrades a real
-- escalation to a routine one, rather than failing safe).
--
-- Jonah's own re-scoping (2026-09-12): the escalation this signal fed was
-- solving a question this project no longer needs answered. "Phone off /
-- unmonitored" is already a non-issue by definition -- nothing risky can
-- happen on a phone that's off or not routing through the monitored path.
-- The only question that matters is "is the phone ON and monitored right
-- now", which the router's own signals already answer reliably with NO
-- phone-side automation at all: eyeguard-phone.py's WireGuard
-- Persistent-Keepalive rx-byte counter (works away from home) OR'd with ARP
-- reachability + DNS activity (works at home) -- see deploy/PHONE.md.
-- findmy_watcher.py's Find My cross-check is the corroboration this
-- migration keeps: Apple's own system-level presence signal, not something
-- that depends on any automation running on the monitored device.
--
-- Fix: eg_check_phone() drops branch (d) (the "phone actively used while
-- unmonitored" alert, the ONLY thing that read last_unlock_at). eg_on_red()
-- drops the recently_unlocked defer -- the phone-dark branch now only
-- checks Find My presence (fm_recent), same logic findmy_cross_check.sql
-- established, reverting past the 2026-09-02 unlock-signal addition.
--
-- NOT torn down (harmless, unused, no reason to risk a schema change for no
-- benefit): eg_report_phone_unlock() and phone_status.last_unlock_at stay in
-- place. The "When I Unlock My iPhone" Shortcut can simply be deleted from
-- the phone -- nothing server-side depends on it calling in anymore.
--
-- Full rebuild of both functions, verified against the newest committed
-- versions (fix_screen_and_phone_alert_debounce.sql, confirmed via git log).
-- eg_check_phone() branches (a),(b),(c) copied verbatim. eg_on_red()'s
-- non-phone-dark branches copied verbatim.

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

  -- (d) REMOVED 2026-09-12 -- see this file's header. Was: phone actively
  -- used (unlocked) around when it went dark -> urgent escalation email,
  -- fed entirely by the unreliable Shortcuts-based last_unlock_at signal.
end $$;

-- ---- eg_on_red(): the "recently_unlocked" defer is removed -- phone-dark
-- now suppresses ONLY on Find My corroboration (fm_recent), same as
-- findmy_cross_check.sql before the unlock signal was layered on top.
create or replace function public.eg_on_red() returns trigger
language plpgsql security definer set search_path = public as $$
declare loc text; whenn text; kind text;
declare fm_last timestamptz; fm_recent boolean;
begin
  whenn := to_char(NEW.flagged_at at time zone 'America/New_York',
                   'Mon DD, HH12:MI AM');
  if NEW.reason like 'phone-dark%' then
    select findmy_last_seen into fm_last from public.phone_status where id = 1;
    fm_recent := fm_last is not null and now() - fm_last <= interval '20 minutes';

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
