-- EyeGuard (2026-11-26): two Find My outage emails say how long / since when, in plain words. Run by Dad.
--
-- SEEN: the Find My session died 2026-11-25 05:41 and stayed dead ~39 h. Two emails were hard to read:
--   (1) "Find My cross-check went silent": "hasn't completed a check-and-report cycle in 16:58:48.122384" (a raw Postgres interval).
--   (2) "phone on but unmonitored": "The Find My cross-check is not reporting right now" (no hint how long it has been down).
-- WHAT THIS CHANGES: WORDING ONLY. (1) shows the age as "17 hours" (or "45 minutes" under an hour). (2) says
-- "has not reported since Nov 25, 05:10 AM". Same emails, same recipients, same moment, same conditions. Nothing is
-- suppressed, delayed or added; no threshold changes.
-- HOW: patches the LIVE eg_check_phone() and eg_check_phone_sustained_dark() text via pg_get_functiondef(); each exact fragment must be
-- present exactly once or it stops with an error and changes nothing. Re-running is a no-op.
-- ROLLBACK: re-run supabase/gate_findmy_stale_alert_on_mac_awake.sql and supabase/phone_sustained_dark.sql.

do $do$
declare
  def1 text; def2 text; n int;
  f1 text := 'age(now(), p.findmy_reported_at)';
  r1 text := E'(case when now() - p.findmy_reported_at >= interval ''1 hour'' then round(extract(epoch from now() - p.findmy_reported_at) / 3600.0)::int || '' hours'' else greatest(round(extract(epoch from now() - p.findmy_reported_at) / 60.0)::int, 1) || '' minutes'' end)';
  f2 text := E'''The Find My cross-check is not reporting right now, so this ''';
  r2 text := E'''The Find My cross-check has not reported since '' || coalesce(to_char(p.findmy_reported_at at time zone ''America/New_York'', ''Mon DD, HH12:MI AM''), ''ever'') || '', so this ''';
begin
  def1 := pg_get_functiondef('public.eg_check_phone()'::regprocedure);
  def2 := pg_get_functiondef('public.eg_check_phone_sustained_dark()'::regprocedure);
  if position('3600.0' in def1) > 0 and position('has not reported since' in def2) > 0 then
    raise notice 'findmy_down_wording: already applied, nothing to do';
    return;
  end if;
  n := (length(def1) - length(replace(def1, f1, ''))) / length(f1);
  if n <> 1 then
    raise exception 'findmy_down_wording: expected "%" exactly once in live eg_check_phone, found % times. Nothing changed. Tell Jonah: the live function differs from the repo.', f1, n;
  end if;
  n := (length(def2) - length(replace(def2, f2, ''))) / length(f2);
  if n <> 1 then
    raise exception 'findmy_down_wording: expected the not-reporting text exactly once in live eg_check_phone_sustained_dark, found % times. Nothing changed. Tell Jonah: the live function differs from the repo.', n;
  end if;
  execute replace(def1, f1, r1);
  execute replace(def2, f2, r2);
end $do$;

-- VERIFY (one row, 2 columns; both must be true)
select
  position('3600.0' in pg_get_functiondef('public.eg_check_phone()'::regprocedure)) > 0                               as stale_age_readable,
  position('has not reported since' in pg_get_functiondef('public.eg_check_phone_sustained_dark()'::regprocedure)) > 0 as dark_since_added;
