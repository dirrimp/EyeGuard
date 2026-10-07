-- EyeGuard: Dad-owned integrity watch over the G11's EyeGuard code.  2026-10-07.
-- ADDS alerting only. Builds on mdm_app_events.sql (#113), mdm_heartbeat.sql (#114),
-- mdm_approvals.sql (#115). Run those first.
--
-- Trust path (same as the Mac release manifest):
--   merge to main -> CI (.github/workflows/publish-g11-manifest.yml, Dad's service-role
--   GitHub secret) inserts the hashes of the approved G11 files into g11_manifests
--   -> the G11 reports what it actually has every 5 min (--attest) -> THIS DATABASE compares.
--   The G11 never holds a key that can write a manifest, and the comparison is not done
--   on the G11.
--
--   * hash matches the LATEST manifest ............ ok
--   * hash matches an EARLIER manifest ............ outdated (reviewed code, deploy not done);
--                                                   emailed only after 24 h
--   * hash matches NO manifest, or item missing ... DRIFT: code nobody approved; emailed at once
--   * reports stop while the monitor still beats .. emailed (an attacker disabling only the report)
--   Each has an all-clear, and each opens/closes a row in the permanent mdm_incidents log.
--
-- WHAT THIS DOES AND DOES NOT PROVE (read this):
--   It catches hand edits, unreviewed deploys and anything that forgets to also fake the
--   report. It does NOT stop someone with root on the G11 from making the reporter send the
--   approved hashes while running other code: the reporter runs on the machine being
--   watched. A clean result is evidence, not proof. Proof needs a hardware root of trust
--   (TPM quote + IMA measurement log verified HERE, not on the G11); this table, RPC and
--   incident log are the plumbing that layer would plug into.
--
-- ======================= DAD: BEFORE RUNNING =================================
-- * NO placeholders. Run AFTER mdm_approvals.sql. Run the whole file, then the verify select.
-- * Then (one time) confirm the GitHub Actions secret SUPABASE_SERVICE_ROLE_KEY exists (it
--   already does if the Mac manifest workflow works). Merging this PR publishes the first
--   G11 manifest by itself.
-- * Until the first manifest exists nothing alerts (state 'no_manifest').
-- =============================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---- 1. approved manifests (written only by Dad's CI; history is immutable) --------
create table if not exists public.g11_manifests (
  version      text primary key check (length(version) between 1 and 80),   -- git commit sha
  items        jsonb not null check (jsonb_typeof(items) = 'object'),        -- {"file:poll.py": "sha256:..", "cron:poller": "sha256:.."}
  published_at timestamptz not null default now()
);
alter table public.g11_manifests enable row level security;      -- no policies: only a BYPASSRLS role (service_role) can touch it
revoke all on public.g11_manifests from public, anon, authenticated, service_role;
grant select, insert on public.g11_manifests to service_role;    -- CI inserts; nobody can update or delete

-- ---- 2. state --------------------------------------------------------------------
alter table public.mdm_status
  add column if not exists attest_at               timestamptz,
  add column if not exists attest_state            text,
  add column if not exists attest_detail           jsonb,
  add column if not exists attest_version          text,
  add column if not exists attest_outdated_since   timestamptz,
  add column if not exists attest_drift_alerted    boolean not null default false,
  add column if not exists attest_outdated_alerted boolean not null default false,
  add column if not exists attest_missing_alerted  boolean not null default false;

alter table public.mdm_incidents drop constraint if exists mdm_incidents_kind_check;
alter table public.mdm_incidents add constraint mdm_incidents_kind_check check (kind in (
  'monitor_silent','no_phone_watched','app_list_stale','phone_unreachable',
  'g11_drift','g11_outdated','g11_attest_missing'));

-- ---- 3. the G11 reports what it has; the server decides ------------------------------
create or replace function public.eg_mdm_attest(p_token text, p_report jsonb)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  items jsonb; k text; v jsonb; m public.g11_manifests; old public.mdm_status;
  exp text; obs text; drift jsonb := '[]'::jsonb; outd jsonb := '[]'::jsonb;
  st text; n int; lis text := '';
begin
  if p_token is null or length(p_token) < 32 or length(p_token) > 256
     or not exists (select 1 from public.mdm_auth
                    where token_sha256 = encode(digest(p_token, 'sha256'), 'hex')) then
    raise exception 'unauthorized' using errcode = 'PT401';
  end if;
  if p_report is null or jsonb_typeof(p_report) <> 'object' or jsonb_typeof(p_report->'items') <> 'object' then
    raise exception 'report must be an object with an items object' using errcode = 'PT400';
  end if;
  items := p_report->'items';
  select count(*) into n from jsonb_object_keys(items);
  if n > 50 then raise exception 'too many items' using errcode = 'PT400'; end if;
  for k, v in select * from jsonb_each(items) loop
    if k !~ '^(file|cron):[A-Za-z0-9_.-]{1,60}$' then
      raise exception 'bad item name' using errcode = 'PT400';
    end if;
    if jsonb_typeof(v) = 'null' then continue; end if;                       -- "I do not have it"
    if jsonb_typeof(v) <> 'string' or (v #>> '{}') !~ '^sha256:[0-9a-f]{64}$' then
      raise exception 'bad hash' using errcode = 'PT400';
    end if;
  end loop;

  select * into old from public.mdm_status where id = 1 for update;
  select * into m from public.g11_manifests order by published_at desc limit 1;
  if not found then
    update public.mdm_status set attest_at = now(), attest_state = 'no_manifest',
           attest_detail = '[]'::jsonb, attest_version = null where id = 1;
    return jsonb_build_object('ok', true, 'state', 'no_manifest');
  end if;

  for k, v in select * from jsonb_each(m.items) loop
    exp := v #>> '{}';
    obs := items ->> k;                                                      -- NULL when absent or JSON null
    if obs is not distinct from exp then continue; end if;
    if obs is null then
      drift := drift || jsonb_build_array(jsonb_build_object('item', k, 'status', 'missing'));
    elsif exists (select 1 from public.g11_manifests o where o.items ->> k = obs) then
      outd := outd || jsonb_build_array(jsonb_build_object('item', k, 'status', 'outdated'));
    else
      drift := drift || jsonb_build_array(jsonb_build_object('item', k, 'status', 'unknown'));
    end if;
  end loop;
  st := case when jsonb_array_length(drift) > 0 then 'drift'
             when jsonb_array_length(outd)  > 0 then 'outdated' else 'ok' end;

  update public.mdm_status set
    attest_at = now(), attest_state = st, attest_detail = drift || outd, attest_version = m.version,
    attest_outdated_since = case when st = 'outdated' then coalesce(old.attest_outdated_since, now()) else null end,
    attest_drift_alerted  = (st = 'drift' and old.attest_drift_alerted),
    attest_outdated_alerted = (st = 'outdated' and old.attest_outdated_alerted),
    attest_missing_alerted  = false
  where id = 1;

  begin
    if st = 'drift' and not old.attest_drift_alerted then
      select string_agg('<li>' || public.eg_mdm_esc(d->>'item') || ' &mdash; '
               || case d->>'status' when 'missing' then 'missing on the G11'
                                    else 'hash matches no approved version' end || '</li>', '')
        into lis from jsonb_array_elements(drift) d;
      perform public.eg_send_email_mdm(
        E'\U0001F6A8 EyeGuard \u2014 G11 code differs from what Dad approved',
        format('<p><b>The G11 reports EyeGuard code that matches no version ever approved and published.</b></p>'
            || '<ul>%s</ul><p>Latest approved version: %s. Most likely a hand edit or a deploy that skipped review. '
            || 'If nobody made this change on purpose, treat it as tampering.</p>'
            || '<p><b>A clean result is evidence, not proof:</b> the report is produced on the G11, so '
            || 'someone with root there can send approved hashes while running other code.</p>',
            lis, public.eg_mdm_esc(left(m.version, 12))));
      update public.mdm_status set attest_drift_alerted = true where id = 1;
      insert into public.mdm_incidents (kind, detail)
        values ('g11_drift', left((select string_agg(d->>'item', ', ') from jsonb_array_elements(drift) d), 300));
    elsif st <> 'drift' and old.attest_drift_alerted then
      update public.mdm_incidents set ended_at = now() where kind = 'g11_drift' and ended_at is null;
      perform public.eg_send_email_mdm(
        E'\u2705 EyeGuard \u2014 G11 code matches an approved version again',
        '<p><b>The G11 now reports only approved EyeGuard code.</b> This clears the earlier '
        || '&ldquo;code differs from what Dad approved&rdquo; alert. The gap stays in the incident log; '
        || 'the unapproved version that ran meanwhile is not reconstructed here.</p>');
    end if;
    if st = 'ok' and old.attest_outdated_alerted then
      update public.mdm_incidents set ended_at = now() where kind = 'g11_outdated' and ended_at is null;
      perform public.eg_send_email_mdm(
        E'\u2705 EyeGuard \u2014 G11 is on the latest approved code',
        '<p><b>The G11 now runs the latest approved version.</b> This clears the earlier '
        || '&ldquo;G11 is behind&rdquo; reminder.</p>');
    end if;
    if old.attest_missing_alerted then
      update public.mdm_incidents set ended_at = now() where kind = 'g11_attest_missing' and ended_at is null;
      perform public.eg_send_email_mdm(
        E'\u2705 EyeGuard \u2014 G11 integrity reports are arriving again',
        '<p><b>The G11 is sending its integrity report again.</b> This clears the earlier alert.</p>');
    end if;
  exception when others then
    raise warning 'eg_mdm_attest alerts: % (report kept)', sqlerrm;
  end;
  return jsonb_build_object('ok', true, 'state', st, 'manifest', left(m.version, 12));
end $$;
revoke execute on function public.eg_mdm_attest(text, jsonb) from public, anon, authenticated, service_role;
grant execute on function public.eg_mdm_attest(text, jsonb) to anon;

-- ---- 4. reminders / missing reports (cron only) ---------------------------------------
create or replace function public.eg_check_g11_integrity() returns void
language plpgsql security definer set search_path = public as $$
declare s public.mdm_status; m public.g11_manifests; fresh boolean;
begin
  select * into s from public.mdm_status where id = 1 for update;
  select * into m from public.g11_manifests order by published_at desc limit 1;
  if not found then return; end if;                      -- nothing approved yet: nothing to compare
  fresh := s.last_heartbeat_at is not null
           and now() - s.last_heartbeat_at between interval '0 seconds' and interval '15 minutes';

  -- reviewed code, but the deploy was never done
  if s.attest_state = 'outdated' and s.attest_outdated_since < now() - interval '24 hours'
     and not s.attest_outdated_alerted then
    perform public.eg_send_email_mdm(
      E'\u26A0\uFE0F EyeGuard \u2014 G11 is running older approved code',
      '<p><b>The G11 has been on an older approved version for over 24 hours.</b></p>'
      || '<p>Newer code was merged and approved but not deployed (run deploy/g11_install.sh on the G11).</p>');
    update public.mdm_status set attest_outdated_alerted = true where id = 1;
    insert into public.mdm_incidents (kind, started_at, detail)
      values ('g11_outdated', s.attest_outdated_since, 'behind ' || left(m.version, 12));
  end if;

  -- the monitor beats but the integrity report is not coming (or never started)
  if fresh and not s.attest_missing_alerted
     and ((s.attest_at is null and m.published_at < now() - interval '24 hours')
          or (s.attest_at is not null and now() - s.attest_at > interval '15 minutes')) then
    perform public.eg_send_email_mdm(
      E'\U0001F6A8 EyeGuard \u2014 G11 integrity reports have stopped',
      format('<p><b>The G11 monitor is still reporting, but its integrity report %s.</b></p>'
          || '<p>Either the deploy never installed the report, or something disabled just that part. '
          || 'Without it nobody is comparing the G11 code with what Dad approved.</p>',
          case when s.attest_at is null then 'has never arrived'
               else 'has not arrived for ' || age(now(), s.attest_at) end));
    update public.mdm_status set attest_missing_alerted = true where id = 1;
    insert into public.mdm_incidents (kind, started_at, detail)
      values ('g11_attest_missing', coalesce(s.attest_at, now()), 'monitor alive, integrity report absent');
  end if;
end $$;
revoke execute on function public.eg_check_g11_integrity() from public, anon, authenticated, service_role;

select cron.unschedule('eyeguard-g11-integrity')
  where exists (select 1 from cron.job where jobname = 'eyeguard-g11-integrity');
select cron.schedule('eyeguard-g11-integrity', '* * * * *', $$ select public.eg_check_g11_integrity(); $$);

-- ---- 5. what the partner dashboard shows ------------------------------------------------
create or replace function public.eg_mdm_attest_status() returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare s public.mdm_status; m public.g11_manifests;
begin
  if not public.eg_is_mdm_partner() then
    raise exception 'not allowed' using errcode = 'PT403';
  end if;
  select * into s from public.mdm_status where id = 1;
  select * into m from public.g11_manifests order by published_at desc limit 1;
  return jsonb_build_object('state', coalesce(s.attest_state, 'none'), 'at', s.attest_at,
    'detail', coalesce(s.attest_detail, '[]'::jsonb), 'manifest', left(m.version, 12),
    'manifest_published_at', m.published_at);
end $$;
revoke execute on function public.eg_mdm_attest_status() from public, anon, authenticated, service_role;
grant execute on function public.eg_mdm_attest_status() to authenticated;

-- ---- 6. verify (read-only). Expect every column true. -----------------------------------
select
  has_function_privilege('anon', 'public.eg_mdm_attest(text, jsonb)', 'execute')        as attest_callable_by_anon,
  not has_function_privilege('anon', 'public.eg_check_g11_integrity()', 'execute')       as check_locked,
  not has_function_privilege('anon', 'public.eg_mdm_attest_status()', 'execute')         as status_not_anon,
  not has_table_privilege('anon', 'public.g11_manifests', 'select')                      as manifests_not_anon_readable,
  not has_table_privilege('authenticated', 'public.g11_manifests', 'select')             as manifests_not_user_readable,
  not has_table_privilege('service_role', 'public.g11_manifests', 'update')              as manifests_immutable,
  not has_table_privilege('service_role', 'public.g11_manifests', 'delete')              as manifests_undeletable,
  exists (select 1 from cron.job where jobname = 'eyeguard-g11-integrity')               as cron_scheduled;
