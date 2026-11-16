-- EyeGuard (2026-11-16): the daily digest counts FRAMES, not events. A few long video sessions produced
-- "1451 suggestive" (Nov 16), which reads like a flood and hides how many separate times it happened.
--
-- CHANGE: the digest now reports sessions (rows less than 10 minutes apart form one session) and still
-- shows the item count, with a short per-session list (when, app, items). NOTHING is dropped or hidden: every
-- row is still counted and still on the dashboard, the email still goes out whenever there is at least one item,
-- to the same recipients, at the same time (cron job unchanged). RED alerts are not touched.
--
-- SAME FILTER AS BEFORE: verdict = 'alert', last 24 hours, jada-phone-dark rows excluded.
--
-- DAD, BEFORE RUNNING: this rebuilds eg_daily_digest() from the 2026-10-01 version
-- (supabase/explicit_search_red_and_digest_fix.sql). The guard below refuses to run if the live function
-- does not look like that version (it must contain 'jada-phone-dark'), so a hand edit is never overwritten.
-- Run the PREVIEW at the bottom first if you want to see the numbers without sending an email.

do $$
begin
  if position('jada-phone-dark' in pg_get_functiondef('public.eg_daily_digest()'::regprocedure)) = 0 then
    raise exception 'live eg_daily_digest() is not the 2026-10-01 version; nothing was changed. Tell Jonah.';
  end if;
end $$;

create or replace function public.eg_daily_digest() returns void
language plpgsql security definer set search_path = public as $$
declare n int; s int; lines text;
begin
  with a as (
    select flagged_at, coalesce(app, 'an app') as app,
           lag(flagged_at) over (order by flagged_at) as prev
      from public.flags
     where verdict = 'alert' and flagged_at > now() - interval '24 hours'
       and reason not like 'jada-phone-dark%'
  ), g as (
    select *, sum(case when prev is null or flagged_at - prev > interval '10 minutes' then 1 else 0 end)
                over (order by flagged_at) as sess
      from a
  ), per as (
    select sess, min(flagged_at) as t0, max(flagged_at) as t1, count(*) as items,
           (array_agg(app order by flagged_at))[1] as app
      from g group by sess
  )
  select (select count(*) from g), (select count(*) from per),
         (select string_agg(
                   format('<li>%s – %s ET · %s · %s item(s)',
                     to_char(t0 at time zone 'America/New_York', 'Mon DD HH12:MI AM'),
                     to_char(t1 at time zone 'America/New_York', 'HH12:MI AM'),
                     replace(replace(replace(app, '&', '&amp;'), '<', '&lt;'), '>', '&gt;'),
                     items), '</li>' order by t0 desc)
            from (select * from per order by t0 desc limit 12) p)
    into n, s, lines;
  if n = 0 then return; end if;  -- nothing suggestive today, stay quiet
  perform public.eg_send_email(
    format('🟡 EyeGuard daily digest — %s session(s), %s item(s)', s, n),
    format('<p><b>%s suggestive item(s)</b> in <b>%s viewing session(s)</b> over the last 24 hours '
        || '(items less than 10 minutes apart count as one session).</p>'
        || '<ul>%s</li></ul>%s'
        || '<p>Review them on the dashboard: '
        || '<a href="https://dirrimp.github.io/EyeGuard/">open dashboard</a></p>',
        n, s, coalesce(lines, ''),
        case when s > 12 then '<p>Showing the 12 most recent sessions.</p>' else '' end));
end $$;

-- ---- verify (read-only). Expect one row: true, true, true.
select
  position('jada-phone-dark' in pg_get_functiondef('public.eg_daily_digest()'::regprocedure)) > 0 as still_excludes_jada_dark,
  position('viewing session' in pg_get_functiondef('public.eg_daily_digest()'::regprocedure)) > 0 as has_sessions,
  position('eg_send_email' in pg_get_functiondef('public.eg_daily_digest()'::regprocedure)) > 0   as still_emails;

-- ---- PREVIEW (read-only, sends nothing): the same numbers the email would show.
with a as (
  select flagged_at, lag(flagged_at) over (order by flagged_at) as prev
    from public.flags
   where verdict = 'alert' and flagged_at > now() - interval '24 hours' and reason not like 'jada-phone-dark%'
)
select count(*) as items,
       count(*) filter (where prev is null or flagged_at - prev > interval '10 minutes') as sessions
  from a;

-- Rollback: re-run supabase/explicit_search_red_and_digest_fix.sql section 2 (create or replace eg_daily_digest()).
