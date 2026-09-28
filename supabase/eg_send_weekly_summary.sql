-- Weekly summary email to Dad (2026-09-28), same SECURITY DEFINER + Resend
-- pattern as eg_daily_digest() (supabase/alerts.sql). Approved: Jonah
-- relays that Dad is OK with this being built on Dad's own existing Resend
-- setup -- unchanged from every other alert this project sends: the
-- reporting channel is never controlled by the monitored party (Jonah).
-- This file only ADDS a function + a cron schedule; it does not touch
-- eg_send_email() itself (see switch_sender_to_orthanc.sql, a SEPARATE
-- file, for the sender-address change -- kept apart deliberately, see that
-- file's own DEPLOY ORDER note).
--
-- SCOPE, deliberately narrower than a full GitHub-integrated report:
--
-- 1. "Merged this week" / "open PRs awaiting you" are delivered as DIRECT
--    LINKS into GitHub's own PR search, not re-implemented as a scraped
--    copy inside this function. Why: pg_net's http_get/http_post (already
--    used by eg_send_email for Resend) are ASYNCHRONOUS by design -- a
--    request queues and its response lands in net._http_response on a
--    separate poll, so reading a GitHub API response back INSIDE this same
--    function call needs a bounded polling loop. That's possible, but I
--    have no execute access against this live database (by design, per
--    this project's integrity rules -- Dad runs SQL, I don't), so I can't
--    actually test a polling loop here before asking Dad to schedule it
--    on a live cron job. A plain link needs no synchronization, can't
--    silently break the whole weekly cron job if GitHub's API ever
--    changes shape, and GitHub's own list is always more current than
--    anything this function could cache. If this proves too thin in
--    practice, a v2 with the pg_net polling version is a small, isolated
--    follow-up -- not blocking this one.
--
-- 2. "False vs real" alert counts: public.flags has no confirmed-false-
--    positive column (checked supabase/schema.sql directly -- verdict is
--    only flagged/alert/clear, never a human-reviewed label), so this
--    can't be computed exactly for every category. The one category with
--    a KNOWN, disclosed false-positive signature as of this week is
--    phone-dark's leaving-home transition (see the PR that added
--    router/eyeguard-phone.py's transition_grace_seconds, 2026-09-28):
--    every confirmed false case found so far reads "silent for 150-199s";
--    a materially longer gap is far more likely a real outage. This
--    digest reports THAT split for phone-dark specifically, labeled
--    explicitly as a heuristic (a duration threshold, not a proof), and
--    reports every other category as a plain count -- not labeled
--    false/real, because no such signature exists for those yet. Honest
--    now beats precise-looking-but-wrong.
--
-- Both scope decisions are deliberate engineering tradeoffs, not
-- shortcuts taken silently -- flagged here for Dad's/Jonah's own judgment
-- on whether they're worth revisiting later.

create or replace function public.eg_send_weekly_summary() returns void
language plpgsql security definer set search_path = public as $$
declare
  since timestamptz := now() - interval '7 days';
  since_label text := to_char(since at time zone 'America/New_York', 'Mon DD');
  until_label text := to_char(now() at time zone 'America/New_York', 'Mon DD');
  since_date_only text := to_char(since, 'YYYY-MM-DD');
  n_red int;
  n_tamper int;
  n_phone_signal int;
  n_phone_dark int;
  n_phone_dark_likely_false int;
  n_phone_dark_other int;
  body text;
begin
  -- Content-detection reds: everything that isn't one of the other known
  -- categories below. Mirrors eg_on_red()'s own bucket ORDER exactly
  -- (tamper/app='EyeGuard' first, then phone-blocked/phone-signal, then
  -- phone-dark, then "everything else is a content flag") so this stays
  -- consistent with what actually triggers each email today.
  select count(*) into n_red from public.flags
    where verdict = 'flagged' and flagged_at > since
      and app <> 'EyeGuard'
      and reason not like 'tamper:%'
      and reason not like 'phone-blocked%'
      and reason not like 'phone-signal%'
      and reason not like 'phone-dark%';

  select count(*) into n_tamper from public.flags
    where flagged_at > since
      and (app = 'EyeGuard' or reason like 'tamper:%');

  select count(*) into n_phone_signal from public.flags
    where flagged_at > since
      and (reason like 'phone-blocked%' or reason like 'phone-signal%');

  select count(*) into n_phone_dark from public.flags
    where flagged_at > since and reason like 'phone-dark%';

  -- Heuristic split, see this file's header -- 150-199s matches the
  -- disclosed leaving-home transition false-positive signature exactly
  -- (observed: always 168 or 169s); anything outside that band is
  -- reported separately as "other", not asserted to be a real outage
  -- either, just not matching the one known false pattern.
  select count(*) into n_phone_dark_likely_false from public.flags
    where flagged_at > since and reason like 'phone-dark%'
      and (substring(reason from 'silent for (\d+)s'))::int between 150 and 199;

  n_phone_dark_other := n_phone_dark - coalesce(n_phone_dark_likely_false, 0);

  body := format(
    '<p><b>EyeGuard weekly summary — %s to %s</b></p>'
    || '<h3>Alerts this week</h3>'
    || '<p style="color:#666">Best-effort categorization by reason prefix -- '
    ||    'see this function''s own source (supabase/eg_send_weekly_summary.sql) '
    ||    'for exactly how each bucket is matched.</p>'
    || '<ul>'
    || '<li>🔴 Explicit/revealing content flagged: %s</li>'
    || '<li>🚨 Tampering detected: %s</li>'
    || '<li>🔴 Phone hit an explicit site: %s</li>'
    || '<li>📵 Phone-dark: %s total — %s in the 150–199s band matching the '
    ||    'known leaving-home transition false-positive (heuristic only, '
    ||    'not a proof), %s outside that band</li>'
    || '</ul>'
    || '<h3>Merged this week</h3>'
    || '<p><a href="https://github.com/dirrimp/EyeGuard/pulls?q=is%%3Apr+is%%3Amerged+merged%%3A%%3E%%3D%s">'
    ||    'PRs merged since %s</a></p>'
    || '<h3>Awaiting you</h3>'
    || '<p><a href="https://github.com/dirrimp/EyeGuard/pulls?q=is%%3Aopen+is%%3Apr">'
    ||    'Open PRs</a> (every one needs your CODEOWNERS review before it can merge) '
    ||    '-- check each description for a "SQL to run" section and whether it '
    ||    'says ⚠️ REDUCES COVERAGE.</p>'
    || '<p><a href="https://github.com/dirrimp/EyeGuard/tree/main/supabase">'
    ||    'supabase/ folder on main</a> -- the full history of SQL already merged, '
    ||    'if you need to check what you''ve already run against a specific file.</p>',
    since_label, until_label, n_red, n_tamper, n_phone_signal,
    n_phone_dark, coalesce(n_phone_dark_likely_false, 0), n_phone_dark_other,
    since_date_only, since_label);

  perform public.eg_send_email('📊 EyeGuard weekly summary', body);
end $$;

select cron.unschedule('eyeguard-weekly-summary')
  where exists (select 1 from cron.job where jobname = 'eyeguard-weekly-summary');
-- 13:00 UTC Sundays (~9am EDT / 8am EST) -- same timezone assumption as
-- eyeguard-digest's own comment. Adjust the hour/day to taste.
select cron.schedule('eyeguard-weekly-summary', '0 13 * * 0',
  $$ select public.eg_send_weekly_summary(); $$);
