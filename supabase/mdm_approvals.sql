-- EyeGuard: official app list + partner approve/deny for the G11 MDM monitor.
-- 2026-10-07.  Builds on mdm_app_events.sql (PR #113) and mdm_heartbeat.sql (#114).
-- ADDS alerting/controls only. Nothing existing is redefined or weakened.
--
-- The SERVER owns the official list. The G11 only relays raw snapshots of the
-- phone's installed apps; the server compares them to the list. (Before this,
-- the G11 held the baseline in files: lose them and it re-baselined silently.)
--
--  * First snapshot with >= 1 app is auto-trusted ONCE (source='baseline') and
--    the baseline closes. After that nothing the G11 sends can approve an app.
--  * Any app not on the list becomes 'pending' and one email goes to Dad and
--    Jada. Only their two accounts can approve / deny / revoke, through
--    eg_mdm_decide() from the partner dashboard. Not the G11, not anon, not Jonah.
--  * deny = flagged (reminded daily while installed) + a queued MDM 'remove'
--    + the bundle id joins the block list the G11 pushes as a restriction.
--    Remove only works for apps MDM installed; block needs a SUPERVISED phone.
--    The G11 reports every outcome back and failures are emailed; the emails say
--    plainly when the phone is not supervised and enforcement is impossible.
--  * Every decision lands in an append-only log (who, when, what).
--
-- ======================= DAD: BEFORE RUNNING =================================
-- * NO placeholders to edit. Run AFTER mdm_app_events.sql and mdm_heartbeat.sql.
-- * Do NOT re-run mdm_app_events.sql afterwards (its recipient placeholder would
--   overwrite your edited sender).
-- * Run the whole file, then the verify select at the bottom (all true).
-- * To re-open the baseline on purpose (new phone): only you, in SQL:
--     update public.mdm_status set baseline_closed = false where id = 1;
-- =============================================================================

-- ---- 1. who counts as a partner (same two uids as phone_status_jada) ----------
create or replace function public.eg_is_mdm_partner() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(auth.uid() in ('0e02aa87-1cd5-4bb6-a263-f51d4e2642b6'::uuid,
                                 '1818ac68-7ecf-4e39-a758-8526e496247d'::uuid), false)
$$;
revoke execute on function public.eg_is_mdm_partner() from public, anon, authenticated, service_role;
grant execute on function public.eg_is_mdm_partner() to authenticated;

-- ---- 2. state ------------------------------------------------------------------
alter table public.mdm_status
  add column if not exists baseline_closed          boolean not null default false,
  add column if not exists last_snapshot_at         timestamptz,
  add column if not exists last_snapshot_detected_at timestamptz,
  add column if not exists supervised               boolean,
  add column if not exists block_ok                 boolean,
  add column if not exists block_detail             text,
  add column if not exists block_count              int,
  add column if not exists block_applied_at         timestamptz;

create table if not exists public.mdm_apps (
  bundle_id     text primary key check (length(bundle_id) between 1 and 200),
  app_name      text,
  app_version   text,
  status        text not null check (status in ('approved','pending','denied')),
  source        text not null check (source in ('baseline','partner')),
  present       boolean not null default true,
  first_seen_at timestamptz not null,
  last_seen_at  timestamptz not null,
  decided_at    timestamptz,
  decided_by    uuid,
  last_nag_at   timestamptz
);
create table if not exists public.mdm_app_log (
  id        bigint generated always as identity primary key,
  at        timestamptz not null default now(),
  bundle_id text not null,
  kind      text not null check (kind in ('baseline','new','gone','reappeared')),
  detail    text
);
create table if not exists public.mdm_decisions (
  id        bigint generated always as identity primary key,
  at        timestamptz not null default now(),
  uid       uuid not null,
  email     text,
  bundle_id text not null,
  decision  text not null check (decision in ('approve','deny','revoke')),
  note      text
);
create table if not exists public.mdm_actions (
  id         bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  bundle_id  text not null,
  action     text not null check (action in ('remove')),
  status     text not null default 'queued' check (status in ('queued','sent','done','failed')),
  attempts   int not null default 0,
  result     text
);

do $$ declare t text; begin
  foreach t in array array['mdm_apps','mdm_app_log','mdm_decisions','mdm_actions'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('drop policy if exists "partner reads %s" on public.%I', t, t);
    execute format('create policy "partner reads %s" on public.%I for select to authenticated using (public.eg_is_mdm_partner())', t, t);
    execute format('revoke all on public.%I from public, anon, authenticated, service_role', t);
    execute format('grant select on public.%I to authenticated', t);
  end loop;
end $$;

-- ---- 3. snapshot: the G11 relays what is installed; the server decides --------
create or replace function public.eg_mdm_snapshot(p_token text, p_snapshot jsonb)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  st public.mdm_status; det timestamptz; apps jsonb; a jsonb;
  bid text; nm text; ver text; dev text; sup boolean;
  seen text[] := '{}'; fresh jsonb := '[]'::jsonb; ex public.mdm_apps;
  cnt int := 0; skipped int := 0; closing boolean := false; n int;
  rows text := ''; subj text;
begin
  if p_token is null or length(p_token) < 32 or length(p_token) > 256
     or not exists (select 1 from public.mdm_auth
                    where token_sha256 = encode(digest(p_token, 'sha256'), 'hex')) then
    raise exception 'unauthorized' using errcode = 'PT401';
  end if;
  if p_snapshot is null or jsonb_typeof(p_snapshot) <> 'object'
     or jsonb_typeof(p_snapshot->'apps') <> 'array' then
    raise exception 'snapshot must be an object with an apps array' using errcode = 'PT400';
  end if;
  apps := p_snapshot->'apps';
  if jsonb_array_length(apps) = 0 or jsonb_array_length(apps) > 2000 then
    raise exception 'bad app count' using errcode = 'PT400';   -- empty is never a real phone
  end if;
  begin
    det := (p_snapshot->>'detected_at')::timestamptz;
    sup := (p_snapshot->>'supervised')::boolean;
  exception when others then
    raise exception 'bad snapshot field' using errcode = 'PT400';
  end;
  if det is null then raise exception 'detected_at required' using errcode = 'PT400'; end if;
  dev := left(coalesce(p_snapshot->>'device', 'iPhone'), 100);

  select * into st from public.mdm_status where id = 1 for update;
  if st.last_snapshot_detected_at is not null and det <= st.last_snapshot_detected_at then
    return jsonb_build_object('ok', true, 'stale', true);       -- replay / out-of-order
  end if;
  closing := not st.baseline_closed;

  for a in select * from jsonb_array_elements(apps) loop
    if jsonb_typeof(a) <> 'object' then skipped := skipped + 1; continue; end if;
    bid := left(a->>'bundle_id', 200);
    if bid is null or bid = '' then skipped := skipped + 1; continue; end if;
    nm  := left(a->>'name', 200);
    ver := left(a->>'version', 100);
    seen := seen || bid;
    cnt := cnt + 1;
    select * into ex from public.mdm_apps where bundle_id = bid;
    if not found then
      if closing then
        insert into public.mdm_apps (bundle_id, app_name, app_version, status, source, first_seen_at, last_seen_at)
          values (bid, nm, ver, 'approved', 'baseline', det, det);
        insert into public.mdm_app_log (bundle_id, kind, detail) values (bid, 'baseline', ver);
      else
        insert into public.mdm_apps (bundle_id, app_name, app_version, status, source, first_seen_at, last_seen_at)
          values (bid, nm, ver, 'pending', 'partner', det, det);
        insert into public.mdm_app_log (bundle_id, kind, detail) values (bid, 'new', ver);
        fresh := fresh || jsonb_build_array(jsonb_build_object('bundle_id', bid, 'name', nm, 'version', ver));
      end if;
    else
      if not ex.present then
        insert into public.mdm_app_log (bundle_id, kind, detail) values (bid, 'reappeared', ex.status);
      end if;
      update public.mdm_apps set present = true, last_seen_at = det,
             app_name = coalesce(nm, app_name), app_version = coalesce(ver, app_version)
       where bundle_id = bid;
    end if;
  end loop;

  if cnt = 0 then raise exception 'no valid apps' using errcode = 'PT400'; end if;

  with g as (update public.mdm_apps set present = false
              where present and not (bundle_id = any(seen)) returning bundle_id)
  insert into public.mdm_app_log (bundle_id, kind) select bundle_id, 'gone' from g;
  -- an app that is gone no longer needs its removal
  update public.mdm_actions set status = 'done', result = 'app no longer installed', updated_at = now()
   where status in ('queued','sent') and bundle_id in
         (select bundle_id from public.mdm_apps where not present);

  update public.mdm_status set baseline_closed = true, last_snapshot_at = now(),
         last_snapshot_detected_at = det, supervised = coalesce(sup, supervised)
   where id = 1;

  n := jsonb_array_length(fresh);
  if n > 0 then
    for a in select * from jsonb_array_elements(fresh) loop
      rows := rows || format('<li><b>%s</b> &mdash; %s (version %s)</li>',
        public.eg_mdm_esc(coalesce(nullif(a->>'name', ''), a->>'bundle_id')),
        public.eg_mdm_esc(a->>'bundle_id'), public.eg_mdm_esc(a->>'version'));
    end loop;
    subj := case when n = 1
      then E'\U0001F4F2 EyeGuard — new app awaiting approval: '
           || coalesce(nullif(fresh->0->>'name', ''), fresh->0->>'bundle_id')
      else E'\U0001F4F2 EyeGuard — ' || n || ' new apps awaiting approval' end;
    perform public.eg_send_email_mdm(subj,
      format('<p><b>%s new app(s) appeared on %s that are not on the approved list.</b></p><ul>%s</ul>'
          || '<p>Open the <a href="https://dirrimp.github.io/EyeGuard/">Partner Dashboard</a>, '
          || 'go to <b>Apps</b>, and <b>Approve</b> or <b>Deny</b> each one. Until approved they '
          || 'stay on the pending list and you will be reminded daily. The phone reports '
          || 'detection time, not install time.</p>', n, public.eg_mdm_esc(dev), rows));
  end if;
  return jsonb_build_object('ok', true, 'apps', cnt, 'new', n, 'skipped', skipped, 'baseline', closing);
end $$;
revoke execute on function public.eg_mdm_snapshot(text, jsonb) from public, anon, authenticated, service_role;
grant execute on function public.eg_mdm_snapshot(text, jsonb) to anon;

-- ---- 4. partner decisions (partners only; never the G11) -----------------------
create or replace function public.eg_mdm_decide(p_bundle_id text, p_decision text, p_note text default null)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); em text; ex public.mdm_apps; st public.mdm_status;
        newstatus text; verb text; hint text := '';
begin
  if not public.eg_is_mdm_partner() then
    raise exception 'not allowed' using errcode = 'PT403';
  end if;
  if p_decision not in ('approve','deny','revoke') then
    raise exception 'bad decision' using errcode = 'PT400';
  end if;
  select * into ex from public.mdm_apps where bundle_id = p_bundle_id for update;
  if not found then raise exception 'unknown app' using errcode = 'PT404'; end if;
  select email into em from auth.users where id = uid;

  newstatus := case p_decision when 'approve' then 'approved' when 'deny' then 'denied' else 'pending' end;
  if ex.status = newstatus then
    return jsonb_build_object('ok', true, 'status', ex.status, 'unchanged', true);
  end if;
  update public.mdm_apps set status = newstatus, decided_at = now(), decided_by = uid, last_nag_at = null
   where bundle_id = p_bundle_id;
  insert into public.mdm_decisions (uid, email, bundle_id, decision, note)
    values (uid, em, p_bundle_id, p_decision, left(p_note, 500));

  select * into st from public.mdm_status where id = 1;
  if p_decision = 'deny' then
    if ex.present and not exists (select 1 from public.mdm_actions
         where bundle_id = p_bundle_id and status in ('queued','sent')) then
      insert into public.mdm_actions (bundle_id, action) values (p_bundle_id, 'remove');
    end if;
    hint := case when st.supervised is true
      then '<p>The app is on the block list and a removal has been queued.</p>'
      else '<p><b>This phone is not supervised</b>, so MDM cannot block this app and can only '
           || 'remove apps it installed itself. The app stays flagged and you will be reminded '
           || 'daily while it remains installed.</p>' end;
  end if;
  verb := case p_decision when 'approve' then 'APPROVED' when 'deny' then 'DENIED' else 'moved back to pending' end;
  perform public.eg_send_email_mdm(
    E'\U0001F5F3️ EyeGuard — ' || coalesce(nullif(ex.app_name, ''), ex.bundle_id) || ' ' || verb,
    format('<p><b>%s</b> %s <b>%s</b> (%s).</p>%s',
      public.eg_mdm_esc(coalesce(em, 'a partner')), lower(verb),
      public.eg_mdm_esc(coalesce(nullif(ex.app_name, ''), ex.bundle_id)),
      public.eg_mdm_esc(ex.bundle_id), hint));
  return jsonb_build_object('ok', true, 'status', newstatus);
end $$;
revoke execute on function public.eg_mdm_decide(text, text, text) from public, anon, authenticated, service_role;
grant execute on function public.eg_mdm_decide(text, text, text) to authenticated;

-- ---- 5. what the G11 must enforce, and how it went -----------------------------
create or replace function public.eg_mdm_sync(p_token text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare acts jsonb; blocked jsonb;
begin
  if p_token is null or length(p_token) < 32 or length(p_token) > 256
     or not exists (select 1 from public.mdm_auth
                    where token_sha256 = encode(digest(p_token, 'sha256'), 'hex')) then
    raise exception 'unauthorized' using errcode = 'PT401';
  end if;
  with u as (
    update public.mdm_actions set status = 'sent', attempts = attempts + 1, updated_at = now()
     where id in (select id from public.mdm_actions
                   where attempts < 3
                     and (status = 'queued' or (status = 'sent' and updated_at < now() - interval '30 minutes'))
                   order by id limit 50)
    returning id, bundle_id, action)
  select coalesce(jsonb_agg(jsonb_build_object('id', id, 'bundle_id', bundle_id, 'action', action)), '[]'::jsonb)
    into acts from u;
  select coalesce(jsonb_agg(bundle_id order by bundle_id), '[]'::jsonb)
    into blocked from public.mdm_apps where status = 'denied';
  return jsonb_build_object('blocked', blocked, 'actions', acts);
end $$;
revoke execute on function public.eg_mdm_sync(text) from public, anon, authenticated, service_role;
grant execute on function public.eg_mdm_sync(text) to anon;

create or replace function public.eg_mdm_action_result(p_token text, p_id bigint, p_ok boolean, p_detail text default null)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare r public.mdm_actions; nm text;
begin
  if p_token is null or length(p_token) < 32 or length(p_token) > 256
     or not exists (select 1 from public.mdm_auth
                    where token_sha256 = encode(digest(p_token, 'sha256'), 'hex')) then
    raise exception 'unauthorized' using errcode = 'PT401';
  end if;
  select * into r from public.mdm_actions where id = p_id and status = 'sent' for update;
  if not found then return jsonb_build_object('ok', true, 'ignored', true); end if;
  if p_ok then
    update public.mdm_actions set status = 'done', result = left(p_detail, 300), updated_at = now() where id = p_id;
  elsif r.attempts >= 3 then
    update public.mdm_actions set status = 'failed', result = left(p_detail, 300), updated_at = now() where id = p_id;
    select coalesce(nullif(app_name, ''), bundle_id) into nm from public.mdm_apps where bundle_id = r.bundle_id;
    perform public.eg_send_email_mdm(
      E'⚠️ EyeGuard — could not remove denied app: ' || coalesce(nm, r.bundle_id),
      format('<p><b>MDM could not remove %s from the phone</b> after %s attempts.</p>'
          || '<p>Reason reported: %s</p><p>MDM can only remove apps it installed itself. The app stays '
          || 'flagged as denied and you will be reminded daily while it is installed.</p>',
          public.eg_mdm_esc(coalesce(nm, r.bundle_id)), r.attempts, public.eg_mdm_esc(left(p_detail, 300))));
  else
    update public.mdm_actions set status = 'queued', result = left(p_detail, 300), updated_at = now() where id = p_id;
  end if;
  return jsonb_build_object('ok', true);
end $$;
revoke execute on function public.eg_mdm_action_result(text, bigint, boolean, text) from public, anon, authenticated, service_role;
grant execute on function public.eg_mdm_action_result(text, bigint, boolean, text) to anon;

create or replace function public.eg_mdm_block_result(p_token text, p_ok boolean, p_count int, p_detail text default null)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare prev boolean;
begin
  if p_token is null or length(p_token) < 32 or length(p_token) > 256
     or not exists (select 1 from public.mdm_auth
                    where token_sha256 = encode(digest(p_token, 'sha256'), 'hex')) then
    raise exception 'unauthorized' using errcode = 'PT401';
  end if;
  select block_ok into prev from public.mdm_status where id = 1;
  update public.mdm_status set block_ok = p_ok, block_count = p_count,
         block_detail = left(p_detail, 300), block_applied_at = now() where id = 1;
  if not p_ok and prev is distinct from false then
    perform public.eg_send_email_mdm(
      E'⚠️ EyeGuard — could not apply the app block list',
      format('<p><b>The G11 could not push the app block list (%s app(s)) to the phone.</b></p>'
          || '<p>Reason reported: %s</p><p>Blocking requires a <b>supervised</b> phone. '
          || 'Denied apps stay flagged and are reminded daily.</p>',
          coalesce(p_count::text, '?'), public.eg_mdm_esc(left(p_detail, 300))));
  end if;
  return jsonb_build_object('ok', true);
end $$;
revoke execute on function public.eg_mdm_block_result(text, boolean, int, text) from public, anon, authenticated, service_role;
grant execute on function public.eg_mdm_block_result(text, boolean, int, text) to anon;

-- ---- 6. reminders (cron only) ---------------------------------------------------
create or replace function public.eg_check_mdm_apps() returns void
language plpgsql security definer set search_path = public as $$
declare s public.mdm_status; pend text; dnd text; np int; nd int;
begin
  select * into s from public.mdm_status where id = 1;
  select count(*), coalesce(string_agg('<li>' || public.eg_mdm_esc(coalesce(nullif(app_name, ''), bundle_id))
           || ' &mdash; ' || public.eg_mdm_esc(bundle_id) || '</li>', ''), '')
    into np, pend from public.mdm_apps
   where status = 'pending' and present and first_seen_at < now() - interval '24 hours'
     and (last_nag_at is null or last_nag_at < now() - interval '24 hours');
  if np > 0 then
    perform public.eg_send_email_mdm(
      E'\U0001F4F2 EyeGuard — ' || np || ' app(s) still awaiting approval',
      format('<p><b>These apps have been on the phone for over a day without a decision:</b></p><ul>%s</ul>'
          || '<p>Open the <a href="https://dirrimp.github.io/EyeGuard/">Partner Dashboard</a> '
          || '&rarr; Apps to approve or deny.</p>', pend));
    update public.mdm_apps set last_nag_at = now()
     where status = 'pending' and present and first_seen_at < now() - interval '24 hours'
       and (last_nag_at is null or last_nag_at < now() - interval '24 hours');
  end if;
  select count(*), coalesce(string_agg('<li>' || public.eg_mdm_esc(coalesce(nullif(app_name, ''), bundle_id))
           || ' &mdash; ' || public.eg_mdm_esc(bundle_id) || '</li>', ''), '')
    into nd, dnd from public.mdm_apps
   where status = 'denied' and present
     and (last_nag_at is null or last_nag_at < now() - interval '24 hours');
  if nd > 0 then
    perform public.eg_send_email_mdm(
      E'\U0001F6AB EyeGuard — ' || nd || ' DENIED app(s) still on the phone',
      format('<p><b>These apps were denied but are still installed:</b></p><ul>%s</ul><p>%s</p>', dnd,
        case when s.supervised is true
          then 'The phone is supervised: check that the block list applied.'
          else '<b>The phone is not supervised</b>, so MDM cannot block them. Remove them on the phone.' end));
    update public.mdm_apps set last_nag_at = now()
     where status = 'denied' and present and (last_nag_at is null or last_nag_at < now() - interval '24 hours');
  end if;
end $$;
revoke execute on function public.eg_check_mdm_apps() from public, anon, authenticated, service_role;

select cron.unschedule('eyeguard-mdm-apps')
  where exists (select 1 from cron.job where jobname = 'eyeguard-mdm-apps');
select cron.schedule('eyeguard-mdm-apps', '*/15 * * * *', $$ select public.eg_check_mdm_apps(); $$);

-- ---- 7. append-only logs ----------------------------------------------------------
revoke update, delete, truncate on public.mdm_app_log, public.mdm_decisions
  from public, anon, authenticated, service_role;

-- ---- 8. verify (read-only). Expect every column true. ---------------------------
select
  has_function_privilege('anon', 'public.eg_mdm_snapshot(text, jsonb)', 'execute')          as snapshot_callable_by_anon,
  not has_function_privilege('anon', 'public.eg_mdm_decide(text, text, text)', 'execute')   as decide_not_anon,
  has_function_privilege('authenticated', 'public.eg_mdm_decide(text, text, text)', 'execute') as decide_for_logged_in,
  not has_function_privilege('anon', 'public.eg_check_mdm_apps()', 'execute')               as reminders_locked,
  not has_table_privilege('anon', 'public.mdm_apps', 'select')                              as apps_not_anon_readable,
  not has_table_privilege('authenticated', 'public.mdm_apps', 'insert')                     as apps_not_writable,
  exists (select 1 from cron.job where jobname = 'eyeguard-mdm-apps')                       as cron_scheduled;
