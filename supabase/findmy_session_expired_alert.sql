-- Immediate email when the Find My cross-check session dies (2026-09-02).
--
-- Confirmed live: eg_check_gone_dark()/eg_on_red() already fail SAFE when
-- findmy_last_seen goes stale (falls back to alerting on every phone-dark
-- event, same as before the cross-check existed) -- so an expired Find My
-- session was never a silent coverage gap. But nothing proactively told
-- anyone it had happened; the only way to notice was either the returning
-- symptom (alert-spam creeping back) or manually checking
-- findmy_watcher.err.log. Jonah asked for this to be immediate, not a
-- multi-day staleness check -- the session expiring is a known, expected,
-- one-time-per-cycle event (weeks to months apart per pyicloud's own
-- session lifetime), not an ongoing condition worth debouncing on a delay.

alter table public.phone_status add column if not exists findmy_session_expired_alerted boolean not null default false;

-- Called by findmy_watcher.py the moment it detects the saved session
-- needs a fresh 2FA challenge or the login itself fails (wrong password,
-- account issue) -- i.e. exactly the two cases that already print "run
-- --setup again" to the local log, now also surfaced immediately by email
-- instead of only sitting in a file nobody's watching. Debounced by
-- findmy_session_expired_alerted so it doesn't re-send every check_seconds
-- (600s) for as long as the session stays dead -- cleared automatically the
-- next time eg_report_findmy_status() lands a real report, proving --setup
-- was actually run again.
create or replace function public.eg_report_findmy_session_expired() returns void
language plpgsql security definer set search_path = public as $$
declare already boolean;
begin
  select findmy_session_expired_alerted into already
    from public.phone_status where id = 1;
  if not coalesce(already, false) then
    perform public.eg_send_email(
      '🔑 EyeGuard — Find My session expired, needs immediate refresh',
      '<p><b>The Find My cross-check for phone-dark alerts has stopped '
      || 'working.</b></p><p>Jonah needs to run '
      || '<code>findmy_watcher.py --setup</code> again as soon as possible '
      || '-- needs his own phone in hand for a 2FA code, can''t be done '
      || 'remotely.</p><p>Monitoring itself is NOT affected by this. Only '
      || 'the cross-check that tells real phone-sleep apart from actual '
      || 'unmonitored use is down -- until this is fixed, phone-dark alerts '
      || 'fall back to their noisier default (may fire on normal sleep, not '
      || 'just real bypass attempts).</p>');
    update public.phone_status set findmy_session_expired_alerted = true where id = 1;
  end if;
end $$;
revoke all on function public.eg_report_findmy_session_expired() from public;
grant execute on function public.eg_report_findmy_session_expired() to anon;

-- eg_report_findmy_status() (findmy_cross_check.sql) gains one line: a
-- successful report is proof the session is fine again, so clear any
-- standing expired-session alert -- otherwise the NEXT real expiry
-- wouldn't re-alert, since the flag would already be stuck true.
create or replace function public.eg_report_findmy_status(
  p_last_seen timestamptz
) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.phone_status
     set findmy_last_seen = p_last_seen,
         findmy_reported_at = now(),
         findmy_session_expired_alerted = false
   where id = 1;
end $$;
revoke all on function public.eg_report_findmy_status(timestamptz) from public;
grant execute on function public.eg_report_findmy_status(timestamptz) to anon;
