-- EyeGuard: iPhone app-install alerts from the G11's MDM poller. 2026-10-03.
-- Adds monitoring only. Nothing here redefines or touches flags, eg_on_red(),
-- eg_send_email(), eg_daily_digest() or any existing trigger/cron job.
--
-- Flow: G11 poller (NanoMDM InstalledApplicationList diff) -> g11/eg-report.sh
-- -> POST /rest/v1/rpc/eg_report_mdm_event -> public.mdm_events (append-only)
-- -> AFTER INSERT trigger -> eg_send_email_mdm() -> Resend -> both partners.
--
-- Auth model: the G11 holds the public anon key (already public) PLUS a random
-- device token. Only the SHA-256 of the token is stored server-side
-- (public.mdm_auth, no API role can read or write it). The only thing the
-- credential can do is call eg_report_mdm_event(); it returns no data. Server
-- stamps received_at with its own clock; events are de-duplicated on
-- (type, bundle_id, detected_at) so the G11's retries can never double-email.
--
-- Emails: app_installed and device_unreachable are emailed immediately.
-- device_unreachable is emailed once per outage (re-armed by
-- device_reachable_again). app_removed and device_reachable_again are logged
-- only (not emailed).
--
-- ======================= DAD: BEFORE RUNNING =================================
-- 1. In eg_send_email_mdm() check the two lines marked  <-- CONFIRM:
--      'from' = the sender your live eg_send_email() uses today
--      'to'   = Jada + YOU. Replace dad@CHANGE-ME.invalid with your address.
--      (Until you do, the function skips sending and logs a warning, so a
--       forgotten edit cannot break anything else.)
-- 2. Make a device token LOCALLY (never paste the token anywhere but the G11):
--      T=$(openssl rand -hex 32); printf %s "$T" | shasum -a 256
--    Hand $T to Jonah privately for the G11 credential file; paste ONLY the
--    hash into the insert at the bottom of this file (section 7).
-- 3. Run this whole file in the SQL editor, then the verify select.
-- Rotation: insert a new hash, give the new token to the G11, delete the old row.
-- =============================================================================

create extension if not exists pg_net;
create extension if not exists pgcrypto with schema extensions;

-- ---- 1. token hash store (unreachable from every API role) ------------------
create table if not exists public.mdm_auth (
  token_sha256 text primary key check (token_sha256 ~ '^[0-9a-f]{64}$'),
  note         text,
  created_at   timestamptz not null default now()
);
alter table public.mdm_auth enable row level security;
revoke all on public.mdm_auth from public, anon, authenticated, service_role;

-- ---- 2. append-only event log -----------------------------------------------
create table if not exists public.mdm_events (
  id           bigint generated always as identity primary key,
  received_at  timestamptz not null default now(),   -- server clock
  event_type   text not null check (event_type in
                 ('app_installed','app_removed','device_unreachable','device_reachable_again')),
  detected_at  timestamptz not null,                  -- G11-reported
  window_start timestamptz,
  device       text,
  app_name     text,
  bundle_id    text,
  app_version  text,
  dedupe_key   text not null unique
);
alter table public.mdm_events enable row level security;
-- Partners (same two uids as phone_status_jada) may read; nobody can write
-- except through the RPC below.
drop policy if exists "partner reads mdm_events" on public.mdm_events;
create policy "partner reads mdm_events" on public.mdm_events
  for select to authenticated using (
    auth.uid() in ('0e02aa87-1cd5-4bb6-a263-f51d4e2642b6',
                   '1818ac68-7ecf-4e39-a758-8526e496247d'));
revoke all on public.mdm_events from public, anon, service_role;
revoke insert, update, delete, truncate on public.mdm_events from authenticated;
grant select on public.mdm_events to authenticated;

-- single-row state for the unreachable debounce
create table if not exists public.mdm_status (
  id int primary key default 1 check (id = 1),
  unreachable_alerted boolean not null default false,
  last_event_at timestamptz
);
insert into public.mdm_status (id) values (1) on conflict (id) do nothing;
alter table public.mdm_status enable row level security;
revoke all on public.mdm_status from public, anon, authenticated, service_role;

-- ---- 3. sender (own recipient list; never overwrites the live eg_send_email) -
create or replace function public.eg_send_email_mdm(subject text, html text)
returns void
language plpgsql security definer set search_path = public, vault as $$
declare api_key text;
        recipients jsonb := jsonb_build_array(
          'jadadirrim@pm.me',                                 -- <-- CONFIRM
          'dad@CHANGE-ME.invalid');                           -- <-- CONFIRM (Dad)
begin
  if recipients::text like '%.invalid%' then
    raise warning 'eg_send_email_mdm: recipient list still has a placeholder; NOT sending';
    return;
  end if;
  select decrypted_secret into api_key
    from vault.decrypted_secrets where name = 'resend_api_key' limit 1;
  if api_key is null then
    raise warning 'eg_send_email_mdm: no resend_api_key in Vault'; return;
  end if;
  perform net.http_post(
    url := 'https://api.resend.com/emails',
    headers := jsonb_build_object('Authorization', 'Bearer ' || api_key,
                                  'Content-Type', 'application/json'),
    body := jsonb_build_object(
      'from', 'EyeGuard <alerts@orthanc.me>',                 -- <-- CONFIRM
      'to', recipients, 'subject', subject, 'html', html));
end $$;
revoke execute on function public.eg_send_email_mdm(text, text)
  from public, anon, authenticated, service_role;

-- ---- 4. the one entry point the G11 may call ---------------------------------
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
  if t is null or t not in ('app_installed','app_removed','device_unreachable','device_reachable_again') then
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

-- ---- 5. email trigger --------------------------------------------------------
create or replace function public.eg_mdm_esc(s text) returns text
language sql immutable as $$
  select replace(replace(replace(coalesce(s, ''), '&', '&amp;'), '<', '&lt;'), '>', '&gt;')
$$;
revoke execute on function public.eg_mdm_esc(text) from public, anon, authenticated, service_role;

create or replace function public.eg_on_mdm_event() returns trigger
language plpgsql security definer set search_path = public as $$
declare det text; win text; st public.mdm_status;
begin
  det := to_char(NEW.detected_at at time zone 'America/New_York', 'Mon DD, HH12:MI AM TZ');
  win := to_char(NEW.window_start at time zone 'America/New_York', 'Mon DD, HH12:MI AM TZ');
  update public.mdm_status set last_event_at = now() where id = 1;

  if NEW.event_type = 'app_installed' then
    perform public.eg_send_email_mdm(
      '📲 EyeGuard — new app on ' || coalesce(NEW.device, 'iPhone') || ': '
        || coalesce(nullif(NEW.app_name, ''), NEW.bundle_id),
      format('<p><b>An app was installed on %s.</b></p>'
          || '<p><b>App:</b> %s<br><b>Bundle ID:</b> %s<br><b>Version:</b> %s<br>'
          || '<b>Detected:</b> %s</p>'
          || '<p>Installed some time between %s and %s. The phone does not '
          || 'report an exact install time, so this is the window in which it '
          || 'appeared. A redownload of a previously removed app shows up here too.</p>',
          public.eg_mdm_esc(NEW.device), public.eg_mdm_esc(NEW.app_name),
          public.eg_mdm_esc(NEW.bundle_id), public.eg_mdm_esc(NEW.app_version),
          det, coalesce(win, '(unknown: first check)'), det));
  elsif NEW.event_type = 'device_unreachable' then
    select * into st from public.mdm_status where id = 1;
    if not st.unreachable_alerted then
      update public.mdm_status set unreachable_alerted = true where id = 1;
      perform public.eg_send_email_mdm(
        '📵 EyeGuard — ' || coalesce(NEW.device, 'iPhone') || ' app monitoring cannot reach the phone',
        format('<p><b>App-install monitoring cannot reach %s.</b></p>'
            || '<p>Detected: %s. Last successful check: %s. Until it is reachable '
            || 'again, installs are not being watched. The phone may be off, out '
            || 'of signal, or its management profile may have been removed. '
            || 'Further unreachable reports during this outage are logged, not emailed.</p>',
            public.eg_mdm_esc(NEW.device), det, coalesce(win, '(unknown)')));
    end if;
  elsif NEW.event_type = 'device_reachable_again' then
    update public.mdm_status set unreachable_alerted = false where id = 1;
  end if;
  -- app_removed: logged only.
  return NEW;
exception when others then
  raise warning 'eg_on_mdm_event: % (event row kept)', sqlerrm;
  return NEW;
end $$;
revoke execute on function public.eg_on_mdm_event() from public, anon, authenticated, service_role;

drop trigger if exists eg_mdm_alert on public.mdm_events;
create trigger eg_mdm_alert after insert on public.mdm_events
  for each row execute function public.eg_on_mdm_event();

-- ---- 6. append-only (same convention as phase4_append_only.sql) -------------
revoke update, delete, truncate on public.mdm_events from public, anon, authenticated, service_role;

-- ---- 7. register the device token HASH (replace the placeholder) ------------
-- insert into public.mdm_auth (token_sha256, note)
--   values ('<64-hex sha256 from step 2>', 'G11 poller 2026-10');

-- ---- 8. verify (read-only) ----------------------------------------------------
-- Expect all true except token_registered until step 7 is done.
select
  has_function_privilege('anon', 'public.eg_report_mdm_event(text, jsonb)', 'execute') as rpc_callable_by_anon,
  not has_function_privilege('anon', 'public.eg_send_email_mdm(text, text)', 'execute') as sender_locked,
  not has_function_privilege('anon', 'public.eg_on_mdm_event()', 'execute')            as trigger_fn_locked,
  not has_table_privilege('anon', 'public.mdm_events', 'select')                       as events_not_anon_readable,
  not has_table_privilege('anon', 'public.mdm_auth', 'select')                         as auth_not_anon_readable,
  exists (select 1 from pg_trigger where tgname = 'eg_mdm_alert')                      as trigger_installed,
  exists (select 1 from public.mdm_auth)                                               as token_registered;
