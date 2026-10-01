-- EyeGuard (2026-10-01): two small server changes. Run once in the SQL Editor.
--
-- 1. eg_on_red(): ONE new branch for explicit URL/search hits (reason
--    'signal: ...'), which the Mac agent now posts as RED. Everything else in
--    the function is copied VERBATIM from its newest committed version
--    (supabase/findmy_ToS_gap_and_stale_backstop.sql, 2026-09-14) -- this is a
--    full rebuild because Postgres has no "add a branch". COVERAGE: UP (an
--    explicit search now emails immediately instead of waiting for the daily
--    digest).
--
--    DAD, BEFORE RUNNING: if you have hand-edited eg_on_red() in the live
--    database since 2026-09-14, do not run part 1 as-is -- tell Jonah, and the
--    branch will be re-applied on top of your version. (eg_send_email(), which
--    holds the real recipient list, is NOT touched here.)
--
-- 2. eg_daily_digest(): stop counting Jada's phone-dark rows as "suggestive
--    items". Since PR #108 those rows are yellow (verdict = 'alert'), and the
--    digest counted every yellow row. Copied verbatim from supabase/alerts.sql
--    plus one condition. Her dark events are still emailed by eg_on_jada_flag()
--    and still shown on the dashboard.
--
-- Order: safe to run before or after the PR is merged. If the Mac agent posts
-- a red search row before this is run, it still emails, just with the generic
-- wording.

-- ---- 1. eg_on_red() --------------------------------------------------------
create or replace function public.eg_on_red() returns trigger
language plpgsql security definer set search_path = public as $$
declare loc text; whenn text; kind text;
declare fm_last timestamptz; fm_recent boolean;
declare fm_reported_at timestamptz; fm_watcher_healthy boolean;
begin
  whenn := to_char(NEW.flagged_at at time zone 'America/New_York',
                   'Mon DD, HH12:MI AM');
  if NEW.reason like 'phone-dark%' then
    select findmy_last_seen, findmy_reported_at
      into fm_last, fm_reported_at
      from public.phone_status where id = 1;
    fm_recent := fm_last is not null and now() - fm_last <= interval '20 minutes';
    -- NEW (2026-09-14): is the CROSS-CHECK ITSELF currently able to report
    -- at all, independent of what fm_last says? findmy_reported_at is
    -- stamped on every successful eg_report_findmy_status() call regardless
    -- of the last_seen value it carries, so its own staleness answers that
    -- question directly. 20 minutes = 2x the normal 10-minute cron cadence,
    -- generous margin against one slow/missed tick without falsely
    -- disclaiming a genuinely fresh corroboration.
    fm_watcher_healthy := fm_reported_at is not null
                           and now() - fm_reported_at <= interval '20 minutes';

    if fm_recent then
      -- Present (Find My) -- idle/asleep, iOS most likely just suspended
      -- the VPN app in the background. Not an issue: the phone is either
      -- off (nothing risky possible) or present-and-idle (same).
      return NEW;
    end if;

    perform public.eg_send_email('📵 EyeGuard — phone went dark',
      format('<p><b>The iPhone stopped routing through the monitored network.</b></p>'
          || '<p>When: %s. The VPN may be off, the phone off, or out of signal. '
          || '%s If it wasn''t expected, it warrants a check-in.</p>', whenn,
          case
            -- FIXED 2026-09-14: previously this branch's stale fm_last was
            -- read as "a stronger signal something's wrong" even when the
            -- cross-check itself was the thing that was broken (confirmed
            -- live: a 13-hour Apple ToS block on 2026-09-13/14 made this
            -- fire that exact misleading wording on every phone-dark event
            -- in the window, pointing at the phone when the real problem
            -- was a stuck credential on the Mac). Check watcher health
            -- FIRST -- an unhealthy watcher means fm_last tells us nothing
            -- either way, so say that plainly instead of overstating it.
            when not fm_watcher_healthy then
              'The Find My cross-check itself hasn''t reported recently '
              || 'either, so this can''t be corroborated one way or the '
              || 'other right now -- treat it as an unconfirmed dark event, '
              || 'not a confirmed one.'
            when fm_last is not null then
              format('Find My also hasn''t seen it since %s -- a '
                     || 'stronger signal something''s actually wrong, '
                     || 'not just iOS suspending the VPN app.',
                     to_char(fm_last at time zone 'America/New_York',
                             'Mon DD, HH12:MI AM'))
            else 'Find My cross-check has no data yet (not set up, or the '
                 || 'session needs a fresh login).'
          end));
    return NEW;
  end if;
  if NEW.reason like 'phone-blocked%' or NEW.reason like 'phone-signal%' then
    perform public.eg_send_email('🔴 EyeGuard — phone hit an explicit site',
      format('<p><b>%s</b></p><p>When: %s</p>'
          || '<p>Seen on the iPhone via the network monitor.</p>',
          coalesce(NEW.reason, ''), whenn));
    return NEW;
  end if;
  -- NEW (2026-10-01): explicit term in a URL / search on the Mac. The agent now
  -- posts the first such hit per 10 minutes as RED (reason 'signal: ...');
  -- without this branch it would fall through to the generic image wording
  -- below ("Very revealing content ... see image"), and these rows have no image.
  if NEW.reason like 'signal:%' then
    perform public.eg_send_email('🔴 EyeGuard — explicit search or URL',
      format('<p><b>An explicit term appeared in a URL, search or page title.</b></p>'
          || '<p><b>When:</b> %s<br><b>Where:</b> %s<br><b>Matched:</b> %s</p>'
          || '<p>No image is saved for these. Further hits in the next 10 '
          || 'minutes are on the dashboard as yellow items, not emailed.</p>',
          whenn,
          coalesce(NEW.app, 'an app')
            || coalesce(' — ' || nullif(coalesce(NEW.url, NEW.window_title), ''), ''),
          coalesce(nullif(split_part(NEW.reason, '— ', 2), ''), NEW.reason)));
    return NEW;
  end if;
  if NEW.app = 'EyeGuard' or NEW.reason like 'tamper:%' then
    perform public.eg_send_email('🚨 EyeGuard — tampering detected',
      format('<p><b>EyeGuard detected local tampering.</b></p>'
          || '<p><b>When:</b> %s<br><b>Detail:</b> %s</p>'
          || '<p>The cloud record is append-only and cannot be erased.</p>',
          whenn, coalesce(NEW.reason, '')));
    return NEW;
  end if;
  loc := coalesce(NEW.app, 'an app')
       || coalesce(' — ' || nullif(coalesce(NEW.url, NEW.window_title), ''), '');
  kind := case when NEW.is_nudity then 'Explicit nudity'
               else 'Very revealing content' end;
  perform public.eg_send_email('🔴 EyeGuard alert — ' || kind,
    format('<p><b>%s was flagged.</b></p><p><b>When:</b> %s<br>'
        || '<b>Where:</b> %s</p><p>The review image is on the dashboard: '
        || '<a href="https://dirrimp.github.io/EyeGuard/">open dashboard</a></p>',
        kind, whenn, loc));
  return NEW;
end $$;

-- ---- 2. eg_daily_digest() --------------------------------------------------
create or replace function public.eg_daily_digest() returns void
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  select count(*) into n from public.flags
    where verdict = 'alert' and flagged_at > now() - interval '24 hours'
      and reason not like 'jada-phone-dark%';   -- NEW 2026-10-01: a dark event is not a "suggestive item"
  if n = 0 then return; end if;  -- nothing suggestive today, stay quiet
  perform public.eg_send_email(
    format('🟡 EyeGuard daily digest — %s suggestive', n),
    format('<p><b>%s suggestive item(s)</b> were flagged in the last 24 hours.</p>'
        || '<p>Review them on the dashboard: '
        || '<a href="https://dirrimp.github.io/EyeGuard/">open dashboard</a></p>', n));
end $$;

-- ---- verify (read-only). Expect one row: true, true.
select
  position('signal:%' in pg_get_functiondef('public.eg_on_red()'::regprocedure)) > 0        as on_red_has_search_branch,
  position('jada-phone-dark' in pg_get_functiondef('public.eg_daily_digest()'::regprocedure)) > 0 as digest_excludes_jada_dark;
