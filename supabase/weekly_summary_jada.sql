-- EyeGuard: weekly summary counts JADA's phone events under the right headings.  2026-10-18.
-- COVERAGE: same (reporting only; no alert is added, removed or reworded).
--
-- PROBLEM (read from the live function text, 2026-10-18): Jada's rows carry a "jada-" reason prefix, so
--   * her explicit-site / DoH / Tor rows ("jada-phone-signal...") were counted under
--     "Explicit/revealing content flagged" instead of "Phone hit an explicit site";
--   * her phone-dark rows ("jada-phone-dark...", verdict alert) were not counted anywhere.
-- FIX: count her phone-signal/blocked rows with the phone-explicit bucket, keep them out of the content
-- bucket, and add one line "Jada's phone-dark: N". Jonah's buckets and the 150-199s heuristic are untouched.
--
-- HOW: edits ONLY those spots of the live function text (same pattern as central_mail_sender.sql). Every
-- edit must match exactly once or the script STOPS and changes nothing. Safe to re-run.

do $$
declare
  def text;
  olds text[] := array[
    $q$n_phone_dark_other int;$q$,
    $q$and reason not like 'phone-dark%';$q$,
    $q$(reason like 'phone-blocked%' or reason like 'phone-signal%');$q$,
    $q$n_phone_dark_other := n_phone_dark - coalesce(n_phone_dark_likely_false, 0);$q$,
    $q$not a proof), %s outside that band</li>'$q$,
    $q$n_phone_dark, coalesce(n_phone_dark_likely_false, 0), n_phone_dark_other,$q$];
  news text[] := array[
    $q$n_phone_dark_other int;
  n_jada_dark int;$q$,
    $q$and reason not like 'phone-dark%'
      and reason not like 'jada-phone-signal%'
      and reason not like 'jada-phone-blocked%'
      and reason not like 'jada-phone-dark%';$q$,
    $q$(reason like 'phone-blocked%' or reason like 'phone-signal%'
           or reason like 'jada-phone-blocked%' or reason like 'jada-phone-signal%');$q$,
    $q$n_phone_dark_other := n_phone_dark - coalesce(n_phone_dark_likely_false, 0);

  select count(*) into n_jada_dark from public.flags
    where flagged_at > since and reason like 'jada-phone-dark%';$q$,
    $q$not a proof), %s outside that band</li>'
    || '<li>Jada''s phone-dark: %s</li>'$q$,
    $q$n_phone_dark, coalesce(n_phone_dark_likely_false, 0), n_phone_dark_other, n_jada_dark,$q$];
  i int; hits int;
begin
  begin
    def := pg_get_functiondef('public.eg_send_weekly_summary()'::regprocedure);
  exception when undefined_function then
    raise exception 'eg_send_weekly_summary() not found; nothing was changed.';
  end;
  if def like '%n_jada_dark%' then
    raise notice 'eg_send_weekly_summary() already counts Jada''s phone events'; return;
  end if;
  for i in 1 .. array_length(olds, 1) loop
    hits := (length(def) - length(replace(def, olds[i], ''))) / length(olds[i]);
    if hits <> 1 then
      raise exception 'edit % matched % times (expected 1): the live function differs from what this script was written against; nothing was changed.', i, hits;
    end if;
    def := replace(def, olds[i], news[i]);
  end loop;
  execute def;
  raise notice 'eg_send_weekly_summary() now buckets Jada''s phone events correctly';
end $$;

-- ---- verify (read-only) -------------------------------------------------------------------------
select pg_get_functiondef('public.eg_send_weekly_summary()'::regprocedure) like '%n_jada_dark%' as weekly_counts_jada,
       pg_get_functiondef('public.eg_send_weekly_summary()'::regprocedure) like '%jada-phone-signal%' as jada_signal_bucketed;
