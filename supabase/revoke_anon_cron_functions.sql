-- Lock down three cron-only functions that were never revoked from anon (2026-11-17, Agent 01).
-- Found by the review agent replay (.review/replay-2026-11.md): no file in supabase/ revokes these.
-- On Supabase, new public-schema functions are granted to anon and authenticated directly, so the
-- public anon key can call them over the REST API unless revoked (same gap as PR #112).
--   eg_send_weekly_summary()  SECURITY DEFINER, sends the weekly email: anyone could trigger it repeatedly.
--   eg_check_phone()          SECURITY DEFINER, runs the phone check that sends alert emails.
--   eg_prune_flags()          SECURITY DEFINER, deletes flags past retention.
-- All three are called only by pg_cron jobs, which run as the function owner and are NOT affected.
-- Coverage: SAME. No detection, threshold, alert or recipient changes. Safe to re-run.

revoke execute on function public.eg_send_weekly_summary()
  from public, anon, authenticated, service_role;
revoke execute on function public.eg_check_phone()
  from public, anon, authenticated, service_role;
revoke execute on function public.eg_prune_flags()
  from public, anon, authenticated, service_role;

-- ---- verify (read-only). Expect: false, false, false, true, true.
-- The last two confirm the router/Mac heartbeats the anon key needs are still callable.
select
  has_function_privilege('anon', 'public.eg_send_weekly_summary()', 'execute')        as anon_can_send_weekly,
  has_function_privilege('anon', 'public.eg_check_phone()', 'execute')                as anon_can_run_phone_check,
  has_function_privilege('anon', 'public.eg_prune_flags()', 'execute')                as anon_can_prune_flags,
  has_function_privilege('anon', 'public.eg_phone_heartbeat(boolean)', 'execute')     as phone_heartbeat_still_allowed,
  exists (select 1 from cron.job where command ilike '%eg_send_weekly_summary%')      as weekly_cron_still_scheduled;
