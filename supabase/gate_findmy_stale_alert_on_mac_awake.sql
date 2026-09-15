-- Gate the Find My staleness backstop on the Mac actually being awake
-- (2026-09-14b).
--
-- PR #98 added eg_check_phone() branch (e): alert if findmy_reported_at
-- goes stale for 2+ hours, as a defense-in-depth net for whatever
-- unhandled findmy_watcher.py exception comes next. It fired for real for
-- the first time at 02:41 -- a false positive. Jonah's Mac was closed and
-- charging, i.e. asleep, the entire window. findmy_watcher.py runs via
-- cron ON THE MAC; cron cannot fire while the Mac is asleep, so
-- findmy_reported_at going stale during ordinary overnight sleep was never
-- a real gap. This is the exact same principle this project settled on at
-- the very start of this investigation for screen-off/DRM: something not
-- running because it has nothing to monitor is not a monitoring failure.
-- Missed when branch (e) was written -- a real gap in that PR, not a
-- hypothetical being preempted here.
--
-- Fix: only fire if the Mac is demonstrably, DURABLY awake right now,
-- reusing the exact fields eg_check_gone_dark() already trusts for this
-- same "genuinely awake, not a blip" question (see that function's own
-- branch (f), which uses watcher_confirmed_awake_at the same way):
--   * device_status.status = 'alive' and last_heartbeat fresh (<=5 min) --
--     the Mac is reporting itself awake RIGHT NOW, not a stale leftover
--     row from before it slept.
--   * watcher_confirmed_awake_at older than 30 minutes -- awake long
--     enough for 3 findmy cron ticks' worth of chances at the normal
--     10-minute cadence. Without this, the alert would instead fire
--     reliably every single morning in the narrow window right after
--     wake, before cron has caught up on its own -- trading one
--     predictable false alarm for another, not actually fixing anything.
-- Any of these being null/absent (no device_status row, session watcher
-- itself down) fails the AND-chain and suppresses -- deliberate: this is
-- a defense-in-depth backstop, not the primary safety alert (that's
-- eg_check_gone_dark()'s own "session watcher went dark" branch), so the
-- wrong direction to fail is toward more noise, not less.
--
-- The currently-set findmy_stale_alerted flag from last night's false
-- positive clears itself on the very next eg_check_phone() run (every
-- 60s via cron) -- findmy_reported_at has been fresh since the terms
-- were accepted, so the existing clear-branch (untouched by this
-- migration) handles it with no manual reset needed.
--
-- Full rebuild of eg_check_phone() (newest: findmy_ToS_gap_and_stale_
-- backstop.sql, PR #98, merged), confirmed newest via git log. Diffed
-- against the live definition: branches (a)-(d) and the flag-clear half
-- of (e) are untouched; only the fire condition and its email text gained
-- the Mac-awake gating described above.

create or replace function public.eg_check_phone() returns void
language plpgsql security definer set search_path = public as $$
declare p public.phone_status;
declare d public.device_status;  -- NEW 2026-09-14b: see branch (e)'s comment
begin
  select * into p from public.phone_status where id = 1;
  if p.monitor_beat is null then return; end if;
  select * into d from public.device_status where id = 1;

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
  -- GATED 2026-09-14b: findmy_watcher.py runs via cron on the MAC, which
  -- goes to sleep every night -- a closed, charging lid, same as any other
  -- normal night. Cron cannot fire while the Mac is asleep, so
  -- findmy_reported_at going stale past 2 hours during ordinary overnight
  -- sleep was never a real gap, the same principle this project settled on
  -- for screen-off/DRM at the very start of this investigation: something
  -- not running because it has nothing to monitor is not a monitoring
  -- failure. This branch shipped without that check and fired its first
  -- night live (02:41, after the Mac had been closed and charging) -- a
  -- miss on my part, not a hypothetical.
  --
  -- Fix: only fire if the Mac is demonstrably, DURABLY awake right now --
  -- reusing the exact signals eg_check_gone_dark() already trusts for this
  -- same "genuinely awake, not a blip" question (see that function's
  -- branch (f)), not a new ad-hoc check:
  --   * d.status = 'alive' and d.last_heartbeat fresh (<=5 min) -- the Mac
  --     is reporting itself awake RIGHT NOW, not a stale leftover row.
  --   * d.watcher_confirmed_awake_at fresh-but-not-too-fresh: awake for
  --     more than 30 minutes (3 findmy cron ticks' worth of chances at the
  --     normal 10-minute cadence) -- without this, the alert would instead
  --     fire reliably every single morning in the narrow window right
  --     after wake, before cron has caught up on its own -- trading one
  --     predictable false alarm for another.
  -- Any of these being null/absent (e.g. device_status has no row, or the
  -- session watcher itself is down) fails the AND-chain and suppresses --
  -- deliberately: this is a defense-in-depth backstop, not the primary
  -- safety alert (that's eg_check_gone_dark()'s own "session watcher went
  -- dark" branch), so the wrong direction to fail is toward more noise.
  if p.findmy_reported_at is not null
     and now() - p.findmy_reported_at > interval '2 hours'
     and not p.findmy_stale_alerted
     and d.status = 'alive'
     and d.last_heartbeat is not null
     and now() - d.last_heartbeat <= interval '5 minutes'
     and d.watcher_confirmed_awake_at is not null
     and now() - d.watcher_confirmed_awake_at > interval '30 minutes' then
    perform public.eg_send_email(
      '⚫ EyeGuard — Find My cross-check went silent',
      format('<p><b>The Find My cross-check hasn''t completed a check-and-'
          || 'report cycle in %s, despite the Mac being awake.</b></p>'
          || '<p>This is a general backstop, not a specific diagnosis -- '
          || 'check findmy_watcher.out.log and findmy_watcher_crash.log on '
          || 'the Mac for the actual cause.</p><p>Monitoring itself is NOT '
          || 'affected. Only the cross-check that tells real phone-sleep '
          || 'apart from actual unmonitored use is down -- until this is '
          || 'fixed, phone-dark alerts fall back to their noisier '
          || 'default.</p>', age(now(), p.findmy_reported_at)));
    update public.phone_status set findmy_stale_alerted = true where id = 1;
  elsif p.findmy_reported_at is not null
        and now() - p.findmy_reported_at <= interval '2 hours'
        and p.findmy_stale_alerted then
    update public.phone_status set findmy_stale_alerted = false where id = 1;
  end if;
end $$;
