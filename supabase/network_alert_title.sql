-- EyeGuard (2026-10-20): server wording for the router network monitor's alerts.
--
-- PROBLEM: eyeguard-dnsnet.py posts RED rows (app = 'Network', reason 'net-signal: ...' or
-- 'net-bypass: ...'). eg_on_red() has no branch for them, so the email said
-- "Very revealing content ... The review image is on the dashboard", which is false (no image
-- exists) and hides what happened. Seen live 2026-10-20 18:36 (Private Relay alert).
--
-- FIX: ONE new branch in eg_on_red(), above the tamper branch. Everything else is copied
-- VERBATIM from its newest committed version (supabase/explicit_search_red_and_digest_fix.sql,
-- 2026-10-01); Postgres has no "add a branch", so this is a full rebuild (tests/
-- test_network_alert_title.py asserts every old line survives).
--
-- COVERAGE: SAME. Same rows, same recipients (eg_send_email() is NOT touched), same moment;
-- only the subject and body text change.
--
-- DAD, BEFORE RUNNING: if you have hand-edited eg_on_red() in the live database since
-- 2026-10-01, do not run this as-is; tell Jonah and the branch will be re-applied on top of
-- your version.
--
-- ASCII-note: the emoji and em dashes below are the same ones the existing subjects use.

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
  -- NEW (2026-10-20): router network monitor (eyeguard-dnsnet.py) posts RED rows with
  -- app = 'Network' and reason 'net-signal: ...' (explicit name) or 'net-bypass: ...'
  -- (VPN / Tor / Private Relay / DoH / DoT / WireGuard). Without this branch they fall to the
  -- generic image wording below ("Very revealing content ... review image"), which is wrong:
  -- these rows have no image and the reason already names the device. Wording only: the
  -- same rows still email, to the same recipients, at the same moment.
  if NEW.app = 'Network' then
    perform public.eg_send_email(
      case when NEW.reason like 'net-signal:%'
           then '🔴 EyeGuard — explicit site on the home network'
           else '🔴 EyeGuard — network bypass signal' end,
      format('<p><b>%s</b></p><p><b>When:</b> %s</p>'
          || '<p>Seen by the router''s network monitor. It reads DNS names, destination '
          || 'addresses and TLS server names only. No screen content and no image exist '
          || 'for this alert.</p>',
          replace(replace(replace(coalesce(NEW.reason, ''), '&', '&amp;'), '<', '&lt;'), '>', '&gt;'),
          whenn));
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

-- ---- verify (read-only). Expect one row: true, true.
select
  position('app = ''Network''' in pg_get_functiondef('public.eg_on_red()'::regprocedure)) > 0 as has_network_branch,
  position('signal:%' in pg_get_functiondef('public.eg_on_red()'::regprocedure)) > 0         as keeps_search_branch;
