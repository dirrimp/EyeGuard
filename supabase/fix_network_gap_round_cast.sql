-- Fix eg_report_network_gap(): round(double precision, integer) does not
-- exist in Postgres (2026-09-09) -- round() with a decimal-places argument
-- only exists for numeric, not double precision (p_gap_seconds's type).
-- Confirmed live: manually invoking this RPC with real 2026-09-06 gap data
-- returned a 404 with "function round(double precision, integer) does not
-- exist. You might need to add explicit type casts." every single time --
-- meaning this function has NEVER successfully sent a single follow-up
-- email since it was created on 2026-09-03, for any outage. The client's
-- own error handling around this call was try/except-pass (by design, a
-- best-effort follow-up must never break real heartbeat recovery), so this
-- failed completely silently the whole time -- retry_network_gap_followup's
-- client-side retry fix (2026-09-08) made the call MORE persistent but
-- couldn't help, since the function itself was broken on every attempt.
--
-- Fix: cast to numeric before rounding, same value either way (1 decimal
-- place on a minutes figure). Everything else in the function unchanged.

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

  gap_txt := round((p_gap_seconds / 60.0)::numeric, 1)::text || ' minutes';

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
