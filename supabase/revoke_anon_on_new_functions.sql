-- EyeGuard (2026-10-01): close a permission gap in the functions added today
-- (PRs #108 and #110). Run once in the SQL Editor. Safe to re-run.
--
-- Those files used `revoke all ... from public`, which is not enough on
-- Supabase: new functions in the public schema are also granted EXECUTE to the
-- `anon` and `authenticated` roles directly (see harden_functions.sql, which
-- revokes from all four roles for exactly this reason). Confirmed live on
-- 2026-10-01: the anon key could call eg_check_phone_sustained_dark() (http 204).
--
-- Why it matters: the anon key is public (it is in the repo and on every
-- client). With it, anyone could have called eg_send_email_jada(subject, html)
-- and sent arbitrary email to the Jada's-phone recipient list from the alerts
-- sender. The two check functions are harmless to call but have no reason to
-- be exposed either.
--
-- Not affected: the cron jobs and the trigger run as the function owner, so
-- alerts keep working. eg_phone_heartbeat_jada() MUST stay callable by anon
-- (the router uses it) and is deliberately not listed here.

revoke execute on function public.eg_send_email_jada(text, text)
  from public, anon, authenticated, service_role;
revoke execute on function public.eg_check_phone_jada()
  from public, anon, authenticated, service_role;
revoke execute on function public.eg_check_phone_sustained_dark()
  from public, anon, authenticated, service_role;

-- ---- verify (read-only). Expect: false, false, false, true.
select
  has_function_privilege('anon', 'public.eg_send_email_jada(text, text)', 'execute')      as anon_can_send_jada_email,
  has_function_privilege('anon', 'public.eg_check_phone_jada()', 'execute')               as anon_can_run_jada_check,
  has_function_privilege('anon', 'public.eg_check_phone_sustained_dark()', 'execute')     as anon_can_run_sustained_check,
  has_function_privilege('anon', 'public.eg_phone_heartbeat_jada(boolean)', 'execute')    as router_heartbeat_still_allowed;
