-- Retroactive network-gap context email (2026-09-03) -- see
-- eyeguard/net.py's general_internet_reachable() and uploader.py's
-- _heartbeat_failed()/_heartbeat_ok() for the client side.
--
-- Cannot change WHEN or WHETHER the real-time "monitoring went dark" alert
-- fires -- that stays fail-safe and unconditional, off the server's own
-- clock, same as always (a client that's actually offline can't call this
-- RPC to say so, so nothing here could ever be used to suppress it even in
-- principle). This only adds a calmer FOLLOW-UP once the client
-- reconnects, explaining whether the gap looked like "no network reachable
-- at all" (e.g. the Mac left the house with no wifi around -- nothing
-- risky possible either) vs. "Supabase specifically was unreachable while
-- the rest of the internet worked fine" (worth real suspicion -- a
-- selectively-blocked reporting path is exactly what this alert exists to
-- catch, so that case gets flagged, not soothed).
--
-- Trust level: p_confirmed_offline and p_gap_seconds are entirely
-- self-reported by the client -- same standing as every other local-only
-- signal in this project (screen_ok, detector_ok, tamper report text):
-- tamper-EVIDENT, not tamper-PROOF. A local admin could in principle lie
-- about either. Accepted residual, same as everywhere else, because the
-- one thing that can't be lied about -- whether the original alert fired
-- at all, and when -- was already decided before this ever runs.

create or replace function public.eg_report_network_gap(
  p_confirmed_offline boolean default false,
  p_gap_seconds double precision default 0
) returns void
language plpgsql security definer set search_path = public as $$
declare gap_txt text;
begin
  -- Server-side floor too (defense in depth) -- matches the 3-minute
  -- gone-dark threshold so a trivial blip that never even alerted can't
  -- generate a follow-up email regardless of what the client sends.
  if p_gap_seconds < 180 then return; end if;

  gap_txt := round(p_gap_seconds / 60.0, 1)::text || ' minutes';

  perform public.eg_send_email(
    case when p_confirmed_offline
           then '📡 EyeGuard — context on the earlier gap: no network found'
         else '📡 EyeGuard — context on the earlier gap: network was up'
    end,
    format('<p><b>Context on the monitoring gap that just ended (%s).</b></p>'
        || '<p>%s</p>'
        || '<p>This is a self-reported, lower-trust signal (same standing '
        || 'as every other local-only check in this project) -- '
        || 'informational only. It does not retract or explain away the '
        || 'earlier alert, which already reflects the server''s own clock.</p>',
        gap_txt,
        case when p_confirmed_offline
               then 'As best the Mac could tell locally, it had no path to '
                    || 'the general internet at all for the whole gap (not '
                    || 'just Supabase specifically) -- consistent with '
                    || 'being somewhere with no wifi or signal, not a '
                    || 'targeted block.'
               else 'The Mac found a path to the general internet reachable '
                    || 'at some point during the gap, even though it could '
                    || 'not reach Supabase specifically. This is NOT the '
                    || '"just no wifi around" case -- worth a closer look.'
          end));
end $$;
revoke all on function public.eg_report_network_gap(boolean, double precision) from public;
grant execute on function public.eg_report_network_gap(boolean, double precision) to anon;
