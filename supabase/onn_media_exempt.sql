-- EyeGuard Onn (2026-11-24): YouTube TV black-frame exemption, server side. Run by Dad.
-- Design: docs/ONN-MEDIA-SESSION-ADDENDUM.md (PR #193). Agreed by Jonah on 2026-11-24 in chat: YouTube TV ONLY (the only
-- copy-protected player on the TV), Jada approves, SmartTube stays installed but gets NO exemption. Dad's review is the approval.
--
-- !! REDUCES COVERAGE (once the new app build reports the exemption): the "Onn monitor is only seeing black" alert stops counting
-- black frames while YouTube TV is verifiably playing AND the box has uploaded an encrypted title record for that window.
-- Everything else (SmartTube, Jellyfin, the browser, the home screen, any other app, YouTube TV with no title record) counts black
-- exactly as today. THIS FILE ALONE CHANGES NOTHING for the running 0.2.2 app: it never sends the new fields, so the server
-- treats every black frame as black. The exemption only takes effect after the 0.3.0 build is approved and installed.
--
-- WHAT THIS ADDS
--   1. onn_beats: black_exempt, titles_sent, listener_ok.   onn_status: listener_ok, listener_off_since, listener_alerted.
--      The incident log accepts one new kind, onn_listener_off.
--   2. onn_titles: one row per ENCRYPTED title record (EGF2 envelope, base64). The server cannot read a title. Not readable by
--      anon. Readable by the signed-in owner (same as onn_beats). Pruned after 30 days (Jonah's answer, 2026-11-17).
--   3. eg_onn_title(token, info): the box uploads one encrypted record. Accepts only the YouTube TV package, an EGF2 blob,
--      a server-checked object name and time, and at most 120 records an hour.
--   4. eg_onn_heartbeat patched IN PLACE (exactly-once guards, no rebuild from an old copy): optional black_exempt, titles_sent
--      and listener_ok. The server honours black_exempt ONLY when listener_ok is true AND an encrypted title record arrived in the
--      beat window; otherwise those frames count as black. It can never exceed the beat's own black count.
--      An all-black beat that is exempt is also NOT reported as "identical frames" (it is not exempt from that by accident).
--   5. eg_check_onn_listener(), every minute: if the new build says its media listener is OFF for 3 minutes, email once
--      ("exemption off, titles not recorded"), and an all-clear when it is back. Switching the listener off cannot hide anything
--      (black frames count as black again), but it IS the way to stop titles being recorded, so it is reported.
--   6. A daily prune of onn_titles older than 30 days.
--
-- HONEST LIMITS: the title is what YouTube TV says is playing, not what is on screen. The server checks that an encrypted
-- record EXISTS, not what is in it (it cannot read it). A box that uploads junk records can keep the exemption: that is
-- tamper-evident (Dad opens the records), not tamper-proof. Reading titles needs the viewer (a separate change); until then
-- they are stored encrypted and nobody can read them, by design.
--
-- ROLLBACK (by hand): make the exemption inert at once with
--   update public.onn_status set listener_ok = null where id = 1;   -- (no effect on the rule itself)
-- or restore the phase 5a heartbeat by re-running supabase/onn_monitor_phase5a_titlefacts.sql. The columns, table and
-- eg_onn_title may stay. To stop the listener email: select cron.unschedule('eyeguard-onn-listener');

-- ---- 1. columns ------------------------------------------------------------------------------------------------
alter table public.onn_beats
  add column if not exists black_exempt int,
  add column if not exists titles_sent  int,
  add column if not exists listener_ok  boolean;
alter table public.onn_status
  add column if not exists listener_ok         boolean,
  add column if not exists listener_off_since  timestamptz,
  add column if not exists listener_alerted    boolean not null default false;

-- the incident log must accept the new kind. This is phase 3's list plus 'onn_listener_off'; if a row of some other kind exists,
-- Postgres refuses the change and nothing is altered.
alter table public.onn_incidents drop constraint if exists onn_incidents_kind_check;
alter table public.onn_incidents add constraint onn_incidents_kind_check check (kind in (
  'onn_silent','onn_service_off','onn_blind','onn_black','onn_frozen','onn_gap','onn_drift','onn_outdated','onn_detector','onn_listener_off'));

-- ---- 2. encrypted title records ----------------------------------------------------------------------------------
create table if not exists public.onn_titles (
  id          bigserial primary key,
  received_at timestamptz not null default now(),
  object_name text        not null check (object_name ~ '^onn-title/[0-9T:.+-]+_title\.enc$' and length(object_name) <= 80),
  pkg         text        not null check (pkg = 'com.google.android.youtube.tvunplugged'),
  ciphertext  text        not null check (length(ciphertext) between 64 and 12000 and ciphertext ~ '^RUdGM[A-Za-z0-9+/]+={0,2}$')
);
create index if not exists onn_titles_received_idx on public.onn_titles (received_at);
alter table public.onn_titles enable row level security;
revoke all on public.onn_titles from public, anon, authenticated, service_role;
revoke all on sequence public.onn_titles_id_seq from public, anon, authenticated, service_role;
grant select on public.onn_titles to authenticated;
drop policy if exists "partner reads onn titles" on public.onn_titles;
create policy "partner reads onn titles" on public.onn_titles for select to authenticated
  using (auth.uid() in ('0e02aa87-1cd5-4bb6-a263-f51d4e2642b6', '1818ac68-7ecf-4e39-a758-8526e496247d'));

-- ---- 3. eg_onn_title: one encrypted record (device token) ----------------------------------------------------------
-- p_info: {pkg, object, ct}. ct = base64 of an EGF2 envelope (starts "EGF2", which is "RUdGM" in base64). The AES-GCM
-- additional data inside it is the object name, so a record moved or renamed on the server cannot be decrypted.
create or replace function public.eg_onn_title(p_token text, p_info jsonb)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  pk text; obj text; ct text; m text[]; ts timestamptz; n int;
begin
  if p_token is null or length(p_token) < 32 or length(p_token) > 256
     or not exists (select 1 from public.onn_auth where token_sha256 = encode(digest(p_token, 'sha256'), 'hex')) then
    raise exception 'unauthorized' using errcode = 'PT401';
  end if;
  if p_info is null or jsonb_typeof(p_info) <> 'object' then
    raise exception 'info must be a JSON object' using errcode = 'PT400';
  end if;
  begin
    pk  := p_info->>'pkg';
    obj := p_info->>'object';
    ct  := p_info->>'ct';
  exception when others then
    raise exception 'bad info' using errcode = 'PT400';
  end;
  if pk is distinct from 'com.google.android.youtube.tvunplugged' or obj is null or ct is null
     or length(ct) not between 64 and 12000 or ct !~ '^RUdGM[A-Za-z0-9+/]+={0,2}$' then
    raise exception 'bad info' using errcode = 'PT400';
  end if;
  m := regexp_match(obj, '^onn-title/(\d{4}-\d\d-\d\d)T(\d\d):(\d\d):(\d\d)(\.\d{1,6})?\+00:00_title\.enc$');
  if m is null then raise exception 'bad object name' using errcode = 'PT400'; end if;
  begin
    ts := (m[1] || 'T' || m[2] || ':' || m[3] || ':' || m[4] || coalesce(m[5], '') || '+00')::timestamptz;
  exception when others then
    raise exception 'bad object name' using errcode = 'PT400';
  end;
  if ts < now() - interval '15 minutes' or ts > now() + interval '2 minutes' then
    raise exception 'object time outside the accepted window' using errcode = 'PT400';
  end if;
  if exists (select 1 from public.onn_titles where object_name = obj) then
    return jsonb_build_object('ok', true, 'duplicate', true);
  end if;
  select count(*) into n from public.onn_titles where received_at > now() - interval '1 hour';
  if n >= 120 then raise exception 'too many title records this hour' using errcode = 'PT429'; end if;
  insert into public.onn_titles (object_name, pkg, ciphertext) values (obj, pk, ct);
  return jsonb_build_object('ok', true);
end $$;
revoke execute on function public.eg_onn_title(text, jsonb) from public, anon, authenticated, service_role;
grant execute on function public.eg_onn_title(text, jsonb) to anon;

-- ---- 4. patch the LIVE heartbeat in place ---------------------------------------------------------------------------
-- Nine exact fragments; each must be present exactly once or this stops with an error and changes nothing.
do $do$
declare
  def text; frag text; n int; i int;
  f text[] := array[
    'te int; tt int; ts int; td int;',
    E'td    := coalesce((p_info->>''title_distinct'')::int, 0);',
    'or te not between 0 and 1000000 or tt not between 0 and te or ts not between 0 and tt or td not between 0 and tt',
    'blackrun  := svc and screen_on and suc >= 5 and blk >= suc * 0.9;',
    'frozen    := svc and screen_on and suc >= 5 and dh <= 1 and not blackrun;',
    'black_ok  := svc and suc >= 5 and blk < suc * 0.9;',
    'title_events, title_with_text, title_specific, title_distinct)',
    'te, tt, ts, td);',
    'last_beat_at   = now(),'
  ];
  r text[] := array[
    E'te int; tt int; ts int; td int;\n  bx int; tsent int; lok boolean; exempt_ok boolean := false;',
    E'td    := coalesce((p_info->>''title_distinct'')::int, 0);\n    bx    := coalesce((p_info->>''black_exempt'')::int, 0);\n    tsent := coalesce((p_info->>''titles_sent'')::int, 0);\n    lok   := (p_info->>''listener_ok'')::boolean;',
    'or te not between 0 and 1000000 or tt not between 0 and te or ts not between 0 and tt or td not between 0 and tt or bx not between 0 and blk or tsent not between 0 and 1000',
    E'exempt_ok := bx > 0 and lok is true and exists (select 1 from public.onn_titles where received_at > now() - make_interval(secs => win + 120));\n  blackrun  := svc and screen_on and suc >= 5 and (blk - case when exempt_ok then bx else 0 end) >= suc * 0.9;',
    'frozen    := svc and screen_on and suc >= 5 and dh <= 1 and not (blk >= suc * 0.9);',
    'black_ok  := svc and suc >= 5 and (blk - case when exempt_ok then bx else 0 end) < suc * 0.9;',
    'title_events, title_with_text, title_specific, title_distinct, black_exempt, titles_sent, listener_ok)',
    'te, tt, ts, td, bx, tsent, lok);',
    E'last_beat_at   = now(),\n    listener_ok    = lok,\n    listener_off_since = case when lok is false then coalesce(listener_off_since, now()) else null end,'
  ];
begin
  def := pg_get_functiondef('public.eg_onn_heartbeat(text, jsonb)'::regprocedure);
  if position('black_exempt' in def) > 0 then
    raise notice 'onn_media_exempt: heartbeat already patched, nothing to do';
    return;
  end if;
  for i in 1 .. array_length(f, 1) loop
    frag := f[i];
    n := (length(def) - length(replace(def, frag, ''))) / length(frag);
    if n <> 1 then
      raise exception 'onn_media_exempt: expected the text "%" exactly once in the live eg_onn_heartbeat, found % times. Nothing changed. Tell Jonah: the live function differs from the repo.', frag, n;
    end if;
  end loop;
  for i in 1 .. array_length(f, 1) loop
    def := replace(def, f[i], r[i]);
  end loop;
  execute def;
end $do$;

-- ---- 5. the listener check (cron only) ---------------------------------------------------------------------------------
create or replace function public.eg_check_onn_listener() returns void
language plpgsql security definer set search_path = public as $$
declare s public.onn_status;
begin
  select * into s from public.onn_status where id = 1 for update;
  if s.last_beat_at is null then return; end if;
  if s.listener_off_since is not null and now() - s.listener_off_since > interval '3 minutes'
     and now() - s.last_beat_at <= interval '15 minutes' and not s.listener_alerted then
    perform public.eg_onn_mail(E'\u26A0\uFE0F EyeGuard \u2014 the Onn media listener is OFF',
      format('<p><b>The Onn monitor reports that its media listener is off.</b> It has been off for %s.</p>'
          || '<p>While it is off, black (copy-protected) frames from YouTube TV count as black again and <b>no title is recorded</b>. '
          || 'Someone may have switched it off in Settings. It can only be re-enabled by the ADB step used at install.</p>',
          age(now(), s.listener_off_since)));
    update public.onn_status set listener_alerted = true where id = 1;
    perform public.eg_onn_open('onn_listener_off', s.listener_off_since, 'media listener not enabled');
  elsif s.listener_alerted and s.listener_ok is not false then
    update public.onn_status set listener_alerted = false where id = 1;
    perform public.eg_onn_close('onn_listener_off');
    perform public.eg_onn_mail(E'\u2705 EyeGuard \u2014 the Onn media listener is back on',
      '<p><b>The media listener on the Onn is enabled again.</b> This clears the earlier &ldquo;listener OFF&rdquo; alert. '
      || 'The time it was off stays in the incident log.</p>');
  end if;
end $$;
revoke execute on function public.eg_check_onn_listener() from public, anon, authenticated, service_role;

-- ---- 6. schedules (idempotent) --------------------------------------------------------------------------------------------
select cron.unschedule('eyeguard-onn-listener') where exists (select 1 from cron.job where jobname = 'eyeguard-onn-listener');
select cron.schedule('eyeguard-onn-listener', '* * * * *', $$ select public.eg_check_onn_listener(); $$);
select cron.unschedule('eyeguard-onn-titles-prune') where exists (select 1 from cron.job where jobname = 'eyeguard-onn-titles-prune');
select cron.schedule('eyeguard-onn-titles-prune', '17 4 * * *', $$ delete from public.onn_titles where received_at < now() - interval '30 days'; $$);

-- ---- 7. verify (read-only). Expect every column true. --------------------------------------------------------------------
select
  has_function_privilege('anon', 'public.eg_onn_title(text, jsonb)', 'execute')                              as title_callable_by_anon,
  has_function_privilege('anon', 'public.eg_onn_heartbeat(text, jsonb)', 'execute')                          as heartbeat_callable_by_anon,
  not has_function_privilege('anon', 'public.eg_check_onn_listener()', 'execute')                            as listener_check_locked_anon,
  not has_function_privilege('authenticated', 'public.eg_check_onn_listener()', 'execute')                   as listener_check_locked_auth,
  not has_table_privilege('anon', 'public.onn_titles', 'select')                                             as titles_not_anon_readable,
  not has_table_privilege('anon', 'public.onn_titles', 'insert')                                             as titles_not_anon_writable,
  position('black_exempt' in pg_get_functiondef('public.eg_onn_heartbeat(text, jsonb)'::regprocedure)) > 0   as heartbeat_patched,
  position('selftest_argmax' in pg_get_functiondef('public.eg_onn_heartbeat(text, jsonb)'::regprocedure)) > 0 as heartbeat_keeps_phase3,
  (select count(*) = 2 from cron.job where jobname in ('eyeguard-onn-listener', 'eyeguard-onn-titles-prune')) as two_jobs_scheduled,
  exists (select 1 from information_schema.columns where table_schema = 'public' and table_name = 'onn_status' and column_name = 'listener_alerted') as status_columns,
  (select pg_get_constraintdef(oid) like '%onn_listener_off%' from pg_constraint where conname = 'onn_incidents_kind_check') as incident_kind_added;
