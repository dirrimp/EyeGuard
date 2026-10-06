-- EyeGuard: G11 MDM poller heartbeat + server-side "is it still watching?" check.
-- 2026-10-06.  ADDS alerting only. Nothing existing is redefined or weakened.
--
-- Why: PR #113 alerts when the phone does something. Nothing alerted when the
-- WATCHER stopped (poller crashed, cron stopped, G11 off, token rejected) or
-- when no phone was enrolled at all. A watcher that can fail silently is not a
-- watcher. The server now verifies the client instead of trusting it.
--
-- Three emails (each sent ONCE per condition, re-armed when it clears), all to
-- the same recipients as the app-install emails (it calls eg_send_email_mdm):
--   1. Heartbeats stopped for > 45 min (poller runs every 15 min = 3 misses).
--   2. Heartbeats arriving but NO phone is enrolled / an enrolled phone has
--      never returned an app list, continuously for > 2 hours.
--   3. Enrolled phone's newest app list is > 3 hours old, unless the poller's
--      own device_unreachable email is already active (no double mail).
--
-- Auth: same device token as eg_report_mdm_event (hash already in mdm_auth).
-- No new secret, nothing for Dad to generate. The credential can only call the
-- two RPCs; heartbeat returns {ok:true} and no data.
--
-- ======================= DAD: BEFORE RUNNING =================================
-- * NO placeholders to edit in this file.
-- * Run this ONLY after mdm_app_events.sql (already done). Do NOT re-run
--   mdm_app_events.sql afterwards: its eg_send_email_mdm() recipient list in
--   the repo still holds the placeholder and would overwrite your edited one.
-- * Run the whole file in the SQL editor, then the verify select at the bottom.
-- * First-run grace: last_heartbeat_at is seeded 2 hours in the FUTURE, so the
--   "stopped" email cannot fire until the G11 has had time to be updated.
--   If the G11 is never updated, you WILL get the "stopped" email ~2h45m
--   after running this. That is the system telling the truth.
-- =============================================================================

create extension if not exists pg_net;
create extension if not exists pgcrypto with schema extensions;

-- ---- 1. state columns (mdm_status is the existing single-row table) ----------
alter table public.mdm_status
  add column if not exists last_heartbeat_at  timestamptz,
  add column if not exists enrolled_count     int,
  add column if not exists unlisted_count     int,
  add column if not exists stalest_apps_age_s bigint,
  add column if not exists outbox_pending     int,
  add column if not exists quiet_alerted      boolean not null default false,
  add column if not exists blind_since        timestamptz,
  add column if not exists blind_alerted      boolean not null default false,
  add column if not exists stale_alerted      boolean not null default false;

update public.mdm_status
   set last_heartbeat_at = now() + interval '2 hours'
 where id = 1 and last_heartbeat_at is null;

-- ---- 2. the heartbeat entry point (callable with the device token) -----------
create or replace function public.eg_mdm_heartbeat(p_token text, p_info jsonb default '{}'::jsonb)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare en int; un int; ag bigint; ob int; blind boolean;
begin
  if p_token is null or length(p_token) < 32 or length(p_token) > 256
     or not exists (select 1 from public.mdm_auth
                    where token_sha256 = encode(digest(p_token, 'sha256'), 'hex')) then
    raise exception 'unauthorized' using errcode = 'PT401';
  end if;
  if p_info is null or jsonb_typeof(p_info) <> 'object' then
    raise exception 'info must be a JSON object' using errcode = 'PT400';
  end if;
  begin
    en := (p_info->>'enrolled')::int;
    un := coalesce((p_info->>'unlisted')::int, 0);
    ag := (p_info->>'stalest_apps_age_s')::bigint;
    ob := (p_info->>'outbox_pending')::int;
  exception when others then
    raise exception 'bad info' using errcode = 'PT400';
  end;
  -- "enrolled" is REQUIRED: omitting it must not be a way to dodge the blind check.
  if en is null or en < 0 or en > 1000 or un < 0 or un > 1000
     or (ag is not null and ag < 0) or (ob is not null and ob < 0) then
    raise exception 'bad info' using errcode = 'PT400';
  end if;
  blind := (en = 0 or un > 0);
  update public.mdm_status set
    last_heartbeat_at  = now(),                       -- server clock, never the client's
    enrolled_count     = en,
    unlisted_count     = un,
    stalest_apps_age_s = ag,
    outbox_pending     = ob,
    quiet_alerted      = false,
    blind_since        = case when blind then coalesce(blind_since, now()) else null end,
    blind_alerted      = case when blind then blind_alerted else false end,
    stale_alerted      = case when ag is not null and ag > 10800 then stale_alerted else false end
  where id = 1;
  return jsonb_build_object('ok', true);
end $$;
revoke execute on function public.eg_mdm_heartbeat(text, jsonb)
  from public, anon, authenticated, service_role;
grant execute on function public.eg_mdm_heartbeat(text, jsonb) to anon;

-- ---- 3. the check (cron only; no API role may run it) ------------------------
create or replace function public.eg_check_mdm_status() returns void
language plpgsql security definer set search_path = public as $$
declare s public.mdm_status;
begin
  select * into s from public.mdm_status where id = 1 for update;
  if s.last_heartbeat_at is null then return; end if;

  -- 1. watcher gone quiet. Takes priority: the figures below are only trusted
  --    while heartbeats are fresh.
  if now() - s.last_heartbeat_at > interval '45 minutes' then
    if not s.quiet_alerted then
      perform public.eg_send_email_mdm(
        E'\U0001F6D1 EyeGuard — iPhone app monitoring STOPPED reporting',
        format('<p><b>The G11 app-install monitor has not checked in for %s.</b></p>'
            || '<p>It reports every 15 minutes. Until it is back, installs on the '
            || 'iPhone are <b>not being watched</b>. Likely causes: the G11 is off or '
            || 'offline, the poller cron stopped or crashed, or the device token was '
            || 'rejected.</p>', age(now(), s.last_heartbeat_at)));
      update public.mdm_status set quiet_alerted = true where id = 1;
    end if;
    return;
  end if;

  -- 2. no phone is actually being watched
  if s.blind_since is not null and now() - s.blind_since > interval '2 hours'
     and not s.blind_alerted then
    perform public.eg_send_email_mdm(
      E'⚠️ EyeGuard — no iPhone is being watched by MDM',
      format('<p><b>The monitor is running, but no phone is under watch.</b></p>'
          || '<p>Enrolled phones: %s. Enrolled phones that have never returned an '
          || 'app list: %s. This has been true for %s. The MDM profile may not be '
          || 'installed yet, or it was removed.</p>',
          coalesce(s.enrolled_count::text, '?'), coalesce(s.unlisted_count::text, '?'),
          age(now(), s.blind_since)));
    update public.mdm_status set blind_alerted = true where id = 1;
  end if;

  -- 3. phone enrolled but its app list has gone stale (and the poller's own
  --    device_unreachable email is not already covering it)
  if coalesce(s.enrolled_count, 0) > 0 and coalesce(s.stalest_apps_age_s, 0) > 10800
     and not s.unreachable_alerted and not s.stale_alerted then
    perform public.eg_send_email_mdm(
      E'\U0001F4F5 EyeGuard — iPhone app list is stale',
      format('<p><b>No fresh app list from the iPhone for about %s hours.</b></p>'
          || '<p>The monitor is running, but the phone has not answered. It may be '
          || 'off, out of signal, or its management profile may have been removed. '
          || 'Installs in this period are not yet seen.</p>',
          round(s.stalest_apps_age_s / 3600.0, 1)));
    update public.mdm_status set stale_alerted = true where id = 1;
  end if;
end $$;
revoke execute on function public.eg_check_mdm_status()
  from public, anon, authenticated, service_role;

select cron.unschedule('eyeguard-mdm-status')
  where exists (select 1 from cron.job where jobname = 'eyeguard-mdm-status');
select cron.schedule('eyeguard-mdm-status', '*/5 * * * *',
  $$ select public.eg_check_mdm_status(); $$);

-- ---- 4. verify (read-only). Expect every column true. -----------------------
select
  has_function_privilege('anon', 'public.eg_mdm_heartbeat(text, jsonb)', 'execute')   as heartbeat_callable_by_anon,
  not has_function_privilege('anon', 'public.eg_check_mdm_status()', 'execute')        as check_locked,
  not has_function_privilege('authenticated', 'public.eg_check_mdm_status()', 'execute') as check_locked_authenticated,
  not has_table_privilege('anon', 'public.mdm_status', 'select')                       as status_not_anon_readable,
  exists (select 1 from cron.job where jobname = 'eyeguard-mdm-status')                as cron_scheduled,
  exists (select 1 from information_schema.columns
           where table_schema = 'public' and table_name = 'mdm_status'
             and column_name = 'last_heartbeat_at')                                    as columns_added;
