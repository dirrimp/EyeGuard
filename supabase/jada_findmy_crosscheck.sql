-- EyeGuard (2026-11-21): Find My cross-check for Jada's phone, same idea as Jonah's.
--
-- PROBLEM: Jada's "phone went dark" email has no Find My check (jada_phone.sql: "No Find My
-- cross-check exists for this phone, so debounce instead"). iOS suspends an idle WireGuard tunnel,
-- the router sees ~168 s of silence, and Jada's phone alerts about every 30 minutes all day
-- (32 alerts in one batch, 2026-11-19; 8 more between 18:02 and 19:10 on 2026-11-21 with the
-- router's new dark-context log showing wg quiet, ping false, not on the LAN). Jonah's own phone
-- gets this filter (a phone Find My saw in the last 20 minutes is idle, not off the grid).
-- Jada's iPhone 16 is listed under the same Apple ID Find My session, so the Mac watcher can read it.
--
-- WHAT THIS DOES
--   1. Two columns on phone_status_jada: findmy_last_seen, findmy_reported_at.
--   2. RPC eg_report_findmy_status_jada(p_last_seen), same trust level as Jonah's
--      eg_report_findmy_status (anon-callable; written by the Mac watcher). A time more than 5
--      minutes in the future is ignored.
--   3. The "Jada's phone went dark" EMAIL (only that branch of eg_on_jada_flag) is skipped when
--      Find My saw her phone within 20 minutes AND the Find My report itself is under 20 minutes
--      old. Otherwise it sends exactly as before (including the 30-minute debounce). The flag row
--      is recorded either way.
--   4. The email wording no longer says "There is no Find My cross-check for this phone".
--
-- WHAT IS NOT CHANGED: the "phone on but unmonitored" email (eg_check_phone_jada_sustained_dark,
-- after 10 minutes dark) and the "MONITOR offline" email are untouched, so a phone that is on but
-- off the monitored network still alerts. Explicit-site flags (verdict 'flagged') are untouched.
--
-- COVERAGE: this suppresses ONE email (the quick "went dark" one) while Find My says the phone was
-- recently seen. The data is self-reported by the Mac watcher: tamper-evident, not tamper-proof,
-- same standing as Jonah's existing cross-check.
--
-- HOW: patches the LIVE eg_on_jada_flag() text via pg_get_functiondef(); three exact lines must
-- each be present exactly once or it stops with an error and changes nothing. Re-running is a no-op.
--
-- ROLLBACK: paste the "create or replace function public.eg_on_jada_flag()" block (section 4) of
-- supabase/jada_phone.sql again. That restores the old function exactly. The two columns and the RPC
-- are harmless to leave in place (nothing reads them once the function is restored).

alter table public.phone_status_jada
  add column if not exists findmy_last_seen   timestamptz,
  add column if not exists findmy_reported_at timestamptz;

create or replace function public.eg_report_findmy_status_jada(p_last_seen timestamptz)
returns void language plpgsql security definer set search_path = public as $$
begin
  if p_last_seen is null or p_last_seen > now() + interval '5 minutes' then return; end if;
  update public.phone_status_jada
     set findmy_last_seen = p_last_seen, findmy_reported_at = now()
   where id = 1;
end $$;
revoke execute on function public.eg_report_findmy_status_jada(timestamptz) from public, anon, authenticated, service_role;
grant execute on function public.eg_report_findmy_status_jada(timestamptz) to anon;

do $$
declare
  def text;
  n int;
  frag text;
  f1 text := 'declare whenn text; last_mail timestamptz;';
  r1 text := 'declare whenn text; last_mail timestamptz; fm_last timestamptz; fm_rep timestamptz;';
  f2 text := 'select last_dark_email_at into last_mail';
  r2 text := E'select findmy_last_seen, findmy_reported_at into fm_last, fm_rep\n'
          || E'      from public.phone_status_jada where id = 1;\n'
          || E'    -- Find My (2026-11-21): seen in the last 20 minutes, and the report itself is fresh -> idle, not dark.\n'
          || E'    -- Same shape as Jonah''s phone. The flag row is already recorded; the debounce timer is not used up.\n'
          || E'    if fm_last is not null and fm_rep is not null\n'
          || E'       and now() - fm_last <= interval ''20 minutes''\n'
          || E'       and now() - fm_rep  <= interval ''20 minutes'' then\n'
          || E'      return NEW;\n'
          || E'    end if;\n'
          || E'    select last_dark_email_at into last_mail';
  f3 text := '''There is no Find My cross-check for this phone, so this is an ''';
  r3 text := '''Find My has not placed this phone anywhere in the last 20 minutes either (or the Find My check is not reporting), so this is an ''';
begin
  def := pg_get_functiondef('public.eg_on_jada_flag()'::regprocedure);
  if position('fm_rep' in def) > 0 then
    raise notice 'jada_findmy_crosscheck: already applied, nothing to do';
    return;
  end if;
  foreach frag in array array[f1, f2, f3] loop
    n := (length(def) - length(replace(def, frag, ''))) / length(frag);
    if n <> 1 then
      raise exception 'jada_findmy_crosscheck: expected the text "%" exactly once in the live eg_on_jada_flag, found % times. Nothing changed. Tell Jonah: the live function differs from the repo.', frag, n;
    end if;
  end loop;
  def := replace(def, f1, r1);
  def := replace(def, f2, r2);
  def := replace(def, f3, r3);
  execute def;
end $$;

-- VERIFY (one row, 6 columns; every column must be true)
select
  exists (select 1 from information_schema.columns where table_name = 'phone_status_jada' and column_name = 'findmy_last_seen')   as col_last_seen,
  exists (select 1 from information_schema.columns where table_name = 'phone_status_jada' and column_name = 'findmy_reported_at') as col_reported_at,
  has_function_privilege('anon', 'public.eg_report_findmy_status_jada(timestamptz)', 'execute')                                    as rpc_callable_by_anon,
  position('fm_rep' in pg_get_functiondef('public.eg_on_jada_flag()'::regprocedure)) > 0                                           as trigger_patched,
  position('phone went dark' in pg_get_functiondef('public.eg_on_jada_flag()'::regprocedure)) > 0                          as alert_text_kept,
  (select prosecdef from pg_proc where oid = 'public.eg_on_jada_flag()'::regprocedure)                                             as still_security_definer;
