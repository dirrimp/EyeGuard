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
--   1. Heartbeats stopped for > 15 min (poller runs every 5 min = 3 misses).
--   2. Heartbeats arriving but NO phone is enrolled / an enrolled phone has
--      never returned an app list, continuously for > 2 hours.
--   3. Enrolled phone's newest app list is > 3 hours old, unless the poller's
--      own device_unreachable email is already active (no double mail).
--
-- Every alert above has an ALL-CLEAR email, sent only when that alert really went
-- out, so a network blip that raised a false alarm is closed out explicitly and
-- says how long the gap was and whether anything appeared during it:
--   monitor back online | a phone is being watched again | app list fresh again |
--   iPhone reachable again (this one also closes the #113 "unreachable" email).
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
-- * Cadence: the G11 poller must run every 5 minutes (deploy/g11_install.sh does this). This check
--   runs every minute and alerts when no heartbeat for > 15 min. If you run this SQL first, the
--   first-run grace below gives Jonah 2 hours to deploy the G11 side.
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

-- ---- 1b. permanent incident log (nothing here is ever cleared by recovery) ----
-- The alert flags in mdm_status reset when a condition clears; this table is the
-- lasting record of every gap in monitoring: what, when it started, when it ended.
-- Written only by the SECURITY DEFINER functions below; no API role can change it.
create table if not exists public.mdm_incidents (
  id         bigint generated always as identity primary key,
  kind       text not null check (kind in ('monitor_silent','no_phone_watched','app_list_stale','phone_unreachable','mdm_reenrolled')),
  started_at timestamptz not null default now(),
  ended_at   timestamptz,
  detail     text
);
alter table public.mdm_incidents enable row level security;
drop policy if exists "partner reads mdm_incidents" on public.mdm_incidents;
create policy "partner reads mdm_incidents" on public.mdm_incidents
  for select to authenticated using (
    auth.uid() in ('0e02aa87-1cd5-4bb6-a263-f51d4e2642b6',
                   '1818ac68-7ecf-4e39-a758-8526e496247d'));
revoke all on public.mdm_incidents from public, anon, authenticated, service_role;
grant select on public.mdm_incidents to authenticated;

-- ---- 2. the heartbeat entry point (callable with the device token) -----------
create or replace function public.eg_mdm_heartbeat(p_token text, p_info jsonb default '{}'::jsonb)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare en int; un int; ag bigint; ob int; blind boolean; old public.mdm_status;
        napps bigint := 0; gap interval; extra text := '';
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
  select * into old from public.mdm_status where id = 1 for update;
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

  -- ALL-CLEARS: only for an alert that was actually sent. Email failures never
  -- break the heartbeat.
  begin
    if old.quiet_alerted then
      update public.mdm_incidents set ended_at = now()
       where kind = 'monitor_silent' and ended_at is null;
      gap := age(now(), old.last_heartbeat_at);
      if to_regclass('public.mdm_apps') is not null then      -- present once the approvals SQL is installed
        execute 'select count(*) from public.mdm_apps where source = ''partner'' and first_seen_at > $1'
          into napps using old.last_heartbeat_at;
        extra := case when napps = 0 then '<p>No new app was detected in the app lists received since.</p>'
                      else format('<p><b>%s new app(s) appeared during or after the gap</b> and are '
                               || 'awaiting a decision in the Partner Dashboard (Apps).</p>', napps) end;
      end if;
      perform public.eg_send_email_mdm(
        E'\u2705 EyeGuard \u2014 iPhone app monitoring is back online',
        format('<p><b>The G11 app-install monitor is reporting again.</b> This clears the earlier '
            || '&ldquo;stopped reporting&rdquo; alert.</p><p>It was silent for about %s. Anything the '
            || 'phone reported meanwhile was queued and delivered. Events still waiting: %s.</p>%s'
            || '<p><b>This is not proof nothing happened.</b> MDM sees which apps are installed at each check, '
            || 'not what happened in between: an app installed and removed inside the gap is invisible, and the gap '
            || 'itself is recorded permanently in the incident log (Partner Dashboard).</p>',
            gap, coalesce(ob::text, '0'), extra));
    end if;
    if old.blind_alerted and not blind then
      update public.mdm_incidents set ended_at = now() where kind = 'no_phone_watched' and ended_at is null;
      perform public.eg_send_email_mdm(
        E'\u2705 EyeGuard \u2014 an iPhone is being watched again',
        format('<p><b>MDM now has %s enrolled phone(s) reporting app lists.</b> This clears the earlier '
            || '&ldquo;no iPhone is being watched&rdquo; alert.</p>', en));
    end if;
    if old.stale_alerted and not (ag is not null and ag > 10800) then
      update public.mdm_incidents set ended_at = now() where kind = 'app_list_stale' and ended_at is null;
      perform public.eg_send_email_mdm(
        E'\u2705 EyeGuard \u2014 iPhone app list is fresh again',
        '<p><b>The iPhone is answering again and its app list is current.</b> This clears the earlier '
        || '&ldquo;app list is stale&rdquo; alert.</p>');
    end if;
  exception when others then
    raise warning 'eg_mdm_heartbeat all-clear: % (heartbeat kept)', sqlerrm;
  end;
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
  if now() - s.last_heartbeat_at > interval '15 minutes' then
    if not s.quiet_alerted then
      perform public.eg_send_email_mdm(
        E'\U0001F6D1 EyeGuard \u2014 iPhone app monitoring STOPPED reporting',
        format('<p><b>The G11 app-install monitor has not checked in for %s.</b></p>'
            || '<p>It reports every 5 minutes. Until it is back, installs on the '
            || 'iPhone are <b>not being watched</b>. Likely causes: the G11 is off or '
            || 'offline, the poller cron stopped or crashed, or the device token was '
            || 'rejected.</p>', age(now(), s.last_heartbeat_at)));
      update public.mdm_status set quiet_alerted = true where id = 1;
      insert into public.mdm_incidents (kind, started_at, detail)
        values ('monitor_silent', s.last_heartbeat_at, 'no heartbeat from the G11 monitor');
    end if;
    return;
  end if;

  -- 2. no phone is actually being watched
  if s.blind_since is not null and now() - s.blind_since > interval '2 hours'
     and not s.blind_alerted then
    perform public.eg_send_email_mdm(
      E'\u26A0\uFE0F EyeGuard \u2014 no iPhone is being watched by MDM',
      format('<p><b>The monitor is running, but no phone is under watch.</b></p>'
          || '<p>Enrolled phones: %s. Enrolled phones that have never returned an '
          || 'app list: %s. This has been true for %s. The MDM profile may not be '
          || 'installed yet, or it was removed.</p>',
          coalesce(s.enrolled_count::text, '?'), coalesce(s.unlisted_count::text, '?'),
          age(now(), s.blind_since)));
    update public.mdm_status set blind_alerted = true where id = 1;
    insert into public.mdm_incidents (kind, started_at, detail)
      values ('no_phone_watched', s.blind_since, 'enrolled=' || coalesce(s.enrolled_count::text, '?')
                                              || ' unlisted=' || coalesce(s.unlisted_count::text, '?'));
  end if;

  -- 3. phone enrolled but its app list has gone stale (and the poller's own
  --    device_unreachable email is not already covering it)
  if coalesce(s.enrolled_count, 0) > 0 and coalesce(s.stalest_apps_age_s, 0) > 10800
     and not s.unreachable_alerted and not s.stale_alerted then
    perform public.eg_send_email_mdm(
      E'\U0001F4F5 EyeGuard \u2014 iPhone app list is stale',
      format('<p><b>No fresh app list from the iPhone for about %s hours.</b></p>'
          || '<p>The monitor is running, but the phone has not answered. It may be '
          || 'off, out of signal, or its management profile may have been removed. '
          || 'Installs in this period are not yet seen.</p>',
          round(s.stalest_apps_age_s / 3600.0, 1)));
    update public.mdm_status set stale_alerted = true where id = 1;
    insert into public.mdm_incidents (kind, started_at, detail)
      values ('app_list_stale', now() - make_interval(secs => s.stalest_apps_age_s),
              'newest app list about ' || round(s.stalest_apps_age_s / 3600.0, 1) || ' h old');
  end if;
end $$;
revoke execute on function public.eg_check_mdm_status()
  from public, anon, authenticated, service_role;

-- ---- 3b. all-clear when the phone answers again ------------------------------
-- BEFORE INSERT on purpose: PR #113's AFTER trigger clears unreachable_alerted on
-- this same event, so only a BEFORE trigger can still tell whether an
-- "unreachable" email was actually sent (and therefore needs closing out).
create or replace function public.eg_on_mdm_unreachable() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.mdm_incidents where kind = 'phone_unreachable' and ended_at is null) then
    insert into public.mdm_incidents (kind, started_at, detail)
      values ('phone_unreachable', NEW.detected_at, left(coalesce(NEW.device, 'iPhone'), 100));
  end if;
  return NEW;
exception when others then
  raise warning 'eg_on_mdm_unreachable: % (event kept)', sqlerrm;
  return NEW;
end $$;
revoke execute on function public.eg_on_mdm_unreachable() from public, anon, authenticated, service_role;
drop trigger if exists eg_mdm_incident_open on public.mdm_events;
create trigger eg_mdm_incident_open after insert on public.mdm_events
  for each row when (NEW.event_type = 'device_unreachable')
  execute function public.eg_on_mdm_unreachable();

create or replace function public.eg_on_mdm_recovered() returns trigger
language plpgsql security definer set search_path = public as $$
declare was boolean; since timestamptz;
begin
  select unreachable_alerted into was from public.mdm_status where id = 1;
  update public.mdm_incidents set ended_at = NEW.detected_at
   where kind = 'phone_unreachable' and ended_at is null;
  if was then
    select max(detected_at) into since from public.mdm_events
     where event_type = 'device_unreachable' and detected_at <= NEW.detected_at;
    perform public.eg_send_email_mdm(
      E'\u2705 EyeGuard \u2014 iPhone is reachable again',
      format('<p><b>The iPhone is answering MDM again.</b> This clears the earlier '
          || '&ldquo;cannot reach the phone&rdquo; alert.</p><p>It was first noticed unreachable about %s '
          || 'before this. Apps installed meanwhile show up in a separate new-app email.</p>',
          coalesce(age(NEW.detected_at, since)::text, 'an unknown time')));
  end if;
  return NEW;
exception when others then
  raise warning 'eg_on_mdm_recovered: % (event kept)', sqlerrm;
  return NEW;
end $$;
revoke execute on function public.eg_on_mdm_recovered()
  from public, anon, authenticated, service_role;

drop trigger if exists eg_mdm_recovered on public.mdm_events;
create trigger eg_mdm_recovered before insert on public.mdm_events
  for each row when (NEW.event_type = 'device_reachable_again')
  execute function public.eg_on_mdm_recovered();

-- ---- 3c. MDM removed and installed again ("re-enrolled") ---------------------------
-- A phone that goes offline (airplane mode, away from the home network) and has its MDM
-- profile removed sends no "check-out". Reinstalling inside any unreachable threshold would be
-- invisible. The G11 hook therefore reports every Authenticate (profile install) for a phone
-- it already knew, and the database emails at once, however short the gap. Needs the type to
-- be accepted: widen the stored list and the one function that validates it.
alter table public.mdm_events drop constraint if exists mdm_events_event_type_check;
alter table public.mdm_events add constraint mdm_events_event_type_check check (event_type in
  ('app_installed','app_removed','device_unreachable','device_reachable_again','device_reenrolled'));

-- Same function as in mdm_app_events.sql (PR #113) with ONE change: 'device_reenrolled' is an
-- accepted type. Do not re-run mdm_app_events.sql after this file.
create or replace function public.eg_report_mdm_event(p_token text, p_event jsonb)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  t text; det timestamptz; win timestamptz; k text; n bigint;
  nm text; bid text; ver text; dev text;
begin
  if p_token is null or length(p_token) < 32 or length(p_token) > 256
     or not exists (select 1 from public.mdm_auth
                    where token_sha256 = encode(digest(p_token, 'sha256'), 'hex')) then
    raise exception 'unauthorized' using errcode = 'PT401';
  end if;
  if p_event is null or jsonb_typeof(p_event) <> 'object' then
    raise exception 'event must be a JSON object' using errcode = 'PT400';
  end if;
  t := p_event->>'type';
  if t is null or t not in ('app_installed','app_removed','device_unreachable','device_reachable_again','device_reenrolled') then
    raise exception 'bad type' using errcode = 'PT400';
  end if;
  begin
    det := (p_event->>'detected_at')::timestamptz;
    win := nullif(p_event->>'window_start', '')::timestamptz;
  exception when others then
    raise exception 'bad timestamp' using errcode = 'PT400';
  end;
  if det is null then raise exception 'detected_at required' using errcode = 'PT400'; end if;
  nm  := left(p_event->>'name', 200);
  bid := left(p_event->>'bundle_id', 200);
  ver := left(p_event->>'version', 100);
  dev := left(coalesce(p_event->>'device', 'iPhone'), 100);
  if t like 'app\_%' and (bid is null or bid = '') then
    raise exception 'bundle_id required for app events' using errcode = 'PT400';
  end if;
  k := t || '|' || coalesce(bid, '') || '|' || to_char(det at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US');
  insert into public.mdm_events (event_type, detected_at, window_start, device,
                                 app_name, bundle_id, app_version, dedupe_key)
  values (t, det, win, dev, nm, bid, ver, k)
  on conflict (dedupe_key) do nothing;
  get diagnostics n = row_count;
  return jsonb_build_object('ok', true, 'duplicate', n = 0);
end $$;
revoke execute on function public.eg_report_mdm_event(text, jsonb)
  from public, anon, authenticated, service_role;
grant execute on function public.eg_report_mdm_event(text, jsonb) to anon;

create or replace function public.eg_on_mdm_reenrolled() returns trigger
language plpgsql security definer set search_path = public as $$
declare det text;
begin
  det := to_char(NEW.detected_at at time zone 'America/New_York', 'Mon DD, HH12:MI AM TZ');
  insert into public.mdm_incidents (kind, started_at, ended_at, detail)
    values ('mdm_reenrolled', NEW.detected_at, NEW.detected_at, left(coalesce(NEW.device, 'iPhone'), 100));
  perform public.eg_send_email_mdm(
    E'\U0001F6A8 EyeGuard \u2014 MDM was removed and installed again on ' || coalesce(NEW.device, 'iPhone'),
    format('<p><b>The MDM profile was installed again on %s at %s.</b></p>'
        || '<p>This server already knew this phone, so the profile was removed (or the phone was erased) '
        || 'and then enrolled again. While MDM was off, apps could have been installed or removed without '
        || 'being seen; the next app list shows what is on the phone now.</p>'
        || '<p>If nobody did this on purpose, treat it as tampering. If someone did, this email is the record of it.</p>',
        public.eg_mdm_esc(coalesce(NEW.device, 'iPhone')), det));
  return NEW;
exception when others then
  raise warning 'eg_on_mdm_reenrolled: % (event kept)', sqlerrm;
  return NEW;
end $$;
revoke execute on function public.eg_on_mdm_reenrolled() from public, anon, authenticated, service_role;

drop trigger if exists eg_mdm_reenrolled on public.mdm_events;
create trigger eg_mdm_reenrolled after insert on public.mdm_events
  for each row when (NEW.event_type = 'device_reenrolled')
  execute function public.eg_on_mdm_reenrolled();

select cron.unschedule('eyeguard-mdm-status')
  where exists (select 1 from cron.job where jobname = 'eyeguard-mdm-status');
select cron.schedule('eyeguard-mdm-status', '* * * * *',
  $$ select public.eg_check_mdm_status(); $$);

-- ---- 4. verify (read-only). Expect every column true. -----------------------
select
  has_function_privilege('anon', 'public.eg_mdm_heartbeat(text, jsonb)', 'execute')   as heartbeat_callable_by_anon,
  not has_function_privilege('anon', 'public.eg_check_mdm_status()', 'execute')        as check_locked,
  not has_function_privilege('authenticated', 'public.eg_check_mdm_status()', 'execute') as check_locked_authenticated,
  not has_table_privilege('anon', 'public.mdm_status', 'select')                       as status_not_anon_readable,
  exists (select 1 from cron.job where jobname = 'eyeguard-mdm-status')                as cron_scheduled,
  exists (select 1 from pg_trigger where tgname = 'eg_mdm_recovered')                  as recovery_trigger,
  exists (select 1 from pg_trigger where tgname = 'eg_mdm_reenrolled')                 as reenroll_trigger,
  not has_table_privilege('anon', 'public.mdm_incidents', 'select')                    as incidents_not_anon_readable,
  not has_table_privilege('authenticated', 'public.mdm_incidents', 'update')           as incidents_not_writable,
  exists (select 1 from information_schema.columns
           where table_schema = 'public' and table_name = 'mdm_status'
             and column_name = 'last_heartbeat_at')                                    as columns_added;
