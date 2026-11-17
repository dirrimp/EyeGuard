-- EyeGuard: Onn TV screen monitor, PHASE 1 (database side only).  2026-11-17.
-- Design and conditions: docs/ONN-SCREEN-MONITOR-REVIEW.md (PR #162, merged).
--
-- ADDS tables, one device-token RPC and alerts. Nothing existing is redefined, weakened or removed.
-- NOTHING reports to this yet: the Android app is phase 2. Until the first valid heartbeat arrives
-- the checks below do nothing, so running this SQL cannot send an alert by itself.
--
-- The server verifies the box; the box does not vouch for itself (design conditions 3, 9, 10, 16):
--   * heartbeat carries COUNTS (attempted / succeeded / analysed / black / distinct frames), not flags,
--     so "service on but blind" is visible (the 2026-11-12 Mac lesson: capture was dead for 38.5 h
--     while a flag-style health check passed);
--   * every heartbeat is kept in onn_beats for 30 days, so Dad and Jonah can read real screen-state
--     data before the screenshot-GAP alert is armed (it ships OFF; see step 6);
--   * app version, signing-certificate hash and model hash are compared with onn_approved, which only
--     Dad writes by hand; a swapped APK or model is emailed at once;
--   * every alert has an ALL-CLEAR email (sent only if the alert really went out) and a permanent row
--     in onn_incidents.
--
-- What this does NOT prove: it is detection, not prevention. Someone with the remote can turn the
-- accessibility service off in Settings; that is reported by the app (service off) or by silence.
--
-- Emails reuse eg_send_email_mdm (the live function with Dad's real recipient list).
-- ======================= DAD: BEFORE RUNNING =================================
-- * NO placeholders to edit in this file. Run it AFTER mdm_app_events.sql, mdm_heartbeat.sql and
--   g11_attest.sql (already done). DO NOT re-run mdm_app_events.sql afterwards: its eg_send_email_mdm()
--   in the repo still holds placeholder recipients and would overwrite your edited one.
-- * Run the whole file in the SQL editor, then the verify select at the bottom (expect all true).
-- * Safe to run twice. To undo everything: the ROLLBACK block at the very bottom.
-- * Steps 5 to 7 are commented. They are done later, by hand, when phase 2 is installed:
--     5. register the device token HASH (Jonah generates the token; you only ever see the hash)
--     6. approve the app (version + certificate hash), later also the model hash
--     7. arm the screenshot-gap alert after the screen-state data has been reviewed
-- =============================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---- 1. token hash store (unreachable from every API role) ------------------
create table if not exists public.onn_auth (
  token_sha256 text primary key check (token_sha256 ~ '^[0-9a-f]{64}$'),
  note         text,
  created_at   timestamptz not null default now()
);
alter table public.onn_auth enable row level security;
revoke all on public.onn_auth from public, anon, authenticated, service_role;

-- ---- 2. approved builds (written by hand by Dad; the app can never add to it) -
create table if not exists public.onn_approved (
  id           bigint generated always as identity primary key,
  app_version  text not null check (length(app_version) between 1 and 40),
  cert_sha256  text not null check (cert_sha256 ~ '^[0-9a-f]{64}$'),
  model_sha256 text check (model_sha256 is null or model_sha256 ~ '^[0-9a-f]{64}$'),  -- null until phase 3
  approved_at  timestamptz not null default now(),
  note         text
);
alter table public.onn_approved enable row level security;
revoke all on public.onn_approved from public, anon, authenticated, service_role;

-- ---- 3. state, history, incident log ----------------------------------------
create table if not exists public.onn_status (
  id               int primary key check (id = 1),
  last_beat_at     timestamptz,                -- SERVER clock. Null until the first valid heartbeat: no alerts before that.
  svc_enabled      boolean,
  svc_off_since    timestamptz,
  screen_state     text,
  app_version      text,
  cert_sha256      text,
  model_sha256     text,
  blind_beats      int not null default 0,     -- consecutive beats: service on, screen on, 0 frames analysed
  black_beats      int not null default 0,     -- ... screen on, >= 90% of frames black
  frozen_beats     int not null default 0,     -- ... screen on, frames all identical
  gap_beats        int not null default 0,     -- ... screen on, fewer than half the expected screenshots
  gap_armed        boolean not null default false,   -- ships OFF; Dad arms it after reviewing onn_beats (step 7)
  silent_alerted   boolean not null default false,
  off_alerted      boolean not null default false,
  blind_alerted    boolean not null default false,
  black_alerted    boolean not null default false,
  frozen_alerted   boolean not null default false,
  gap_alerted      boolean not null default false,
  drift_alerted    boolean not null default false,
  outdated_alerted boolean not null default false,
  outdated_since   timestamptz
);
insert into public.onn_status (id) values (1) on conflict (id) do nothing;
alter table public.onn_status enable row level security;
revoke all on public.onn_status from public, anon, authenticated, service_role;

create table if not exists public.onn_beats (
  id            bigint generated always as identity primary key,
  received_at   timestamptz not null default now(),
  app_version   text, cert_sha256 text, model_sha256 text,
  svc_enabled   boolean not null,
  screen_state  text not null check (screen_state in ('on','off','saver','unknown')),
  screen_on_s   int not null, window_s int not null, interval_s int not null,
  attempted     int not null, succeeded int not null, analysed int not null,
  black         int not null, distinct_hashes int not null,
  reenabled     int not null default 0     -- times the app had to re-enable its own service
);
create index if not exists onn_beats_received_idx on public.onn_beats (received_at);
alter table public.onn_beats enable row level security;

create table if not exists public.onn_incidents (
  id         bigint generated always as identity primary key,
  kind       text not null check (kind in ('onn_silent','onn_service_off','onn_blind','onn_black','onn_frozen',
                                           'onn_gap','onn_drift','onn_outdated')),
  started_at timestamptz not null default now(),
  ended_at   timestamptz,
  detail     text
);
alter table public.onn_incidents enable row level security;

-- Partners (Dad, Jada) may READ the history and the incident log; nobody can change either through the API.
drop policy if exists "partner reads onn_beats" on public.onn_beats;
create policy "partner reads onn_beats" on public.onn_beats
  for select to authenticated using (
    auth.uid() in ('0e02aa87-1cd5-4bb6-a263-f51d4e2642b6', '1818ac68-7ecf-4e39-a758-8526e496247d'));
drop policy if exists "partner reads onn_incidents" on public.onn_incidents;
create policy "partner reads onn_incidents" on public.onn_incidents
  for select to authenticated using (
    auth.uid() in ('0e02aa87-1cd5-4bb6-a263-f51d4e2642b6', '1818ac68-7ecf-4e39-a758-8526e496247d'));
revoke all on public.onn_beats, public.onn_incidents from public, anon, authenticated, service_role;
grant select on public.onn_beats, public.onn_incidents to authenticated;

-- ---- 4a. helpers (not callable by any API role) -----------------------------
create or replace function public.eg_onn_mail(subject text, html text) returns void
language plpgsql security definer set search_path = public as $$
begin
  perform public.eg_send_email_mdm(subject, html);
exception when others then
  raise warning 'eg_onn_mail: % (state change kept)', sqlerrm;
end $$;
revoke execute on function public.eg_onn_mail(text, text) from public, anon, authenticated, service_role;

create or replace function public.eg_onn_open(k text, started timestamptz, d text) returns void
language sql security definer set search_path = public as $$
  insert into public.onn_incidents (kind, started_at, detail)
  select k, started, left(d, 500)
  where not exists (select 1 from public.onn_incidents where kind = k and ended_at is null);
$$;
revoke execute on function public.eg_onn_open(text, timestamptz, text) from public, anon, authenticated, service_role;

create or replace function public.eg_onn_close(k text) returns void
language sql security definer set search_path = public as $$
  update public.onn_incidents set ended_at = now() where kind = k and ended_at is null;
$$;
revoke execute on function public.eg_onn_close(text) from public, anon, authenticated, service_role;

-- ---- 4b. the heartbeat (callable with the device token) ---------------------
-- p_info: {app_version, cert_sha256, model_sha256?, svc_enabled, screen_state, screen_on_s, window_s,
--          interval_s, attempted, succeeded, analysed, black, distinct_hashes, reenabled?}
-- All counts cover the window since the previous beat. The server clock is the only clock used.
create or replace function public.eg_onn_heartbeat(p_token text, p_info jsonb default '{}'::jsonb)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  ver text; cert text; model text; svc boolean; scr text;
  son int; win int; itv int; att int; suc int; ana int; blk int; dh int; ren int;
  old public.onn_status; screen_on boolean; blind boolean; blackrun boolean; frozen boolean; gap boolean;
  expected numeric; last_beat timestamptz; gapint interval;
  blind_ok boolean; black_ok boolean; frozen_ok boolean; gap_ok boolean;
begin
  if p_token is null or length(p_token) < 32 or length(p_token) > 256
     or not exists (select 1 from public.onn_auth
                    where token_sha256 = encode(digest(p_token, 'sha256'), 'hex')) then
    raise exception 'unauthorized' using errcode = 'PT401';
  end if;
  if p_info is null or jsonb_typeof(p_info) <> 'object' then
    raise exception 'info must be a JSON object' using errcode = 'PT400';
  end if;
  begin
    ver   := p_info->>'app_version';
    cert  := lower(p_info->>'cert_sha256');
    model := nullif(lower(p_info->>'model_sha256'), '');
    svc   := (p_info->>'svc_enabled')::boolean;
    scr   := p_info->>'screen_state';
    son   := (p_info->>'screen_on_s')::int;
    win   := (p_info->>'window_s')::int;
    itv   := (p_info->>'interval_s')::int;
    att   := (p_info->>'attempted')::int;
    suc   := (p_info->>'succeeded')::int;
    ana   := (p_info->>'analysed')::int;
    blk   := (p_info->>'black')::int;
    dh    := (p_info->>'distinct_hashes')::int;
    ren   := coalesce((p_info->>'reenabled')::int, 0);
  exception when others then
    raise exception 'bad info' using errcode = 'PT400';
  end;
  -- Every field is REQUIRED (omitting one must not be a way to dodge a check) and bounded.
  if ver is null or length(ver) not between 1 and 40 or cert is null or cert !~ '^[0-9a-f]{64}$'
     or (model is not null and model !~ '^[0-9a-f]{64}$') or svc is null
     or scr is null or scr not in ('on','off','saver','unknown')
     or son is null or win is null or itv is null or att is null or suc is null or ana is null
     or blk is null or dh is null
     or win not between 1 and 3600 or itv not between 1 and 3600 or son not between 0 and 3600
     or att not between 0 and 100000 or suc not between 0 and att or ana not between 0 and suc
     or blk not between 0 and suc or dh not between 0 and suc or ren not between 0 and 1000 then
    raise exception 'bad info' using errcode = 'PT400';
  end if;

  select * into old from public.onn_status where id = 1 for update;
  last_beat := old.last_beat_at;

  screen_on := son >= 120;                                   -- at least 2 minutes of screen-on in this window
  blind     := svc and screen_on and ana = 0;                -- service on, screen on, nothing examined
  blackrun  := svc and screen_on and suc >= 5 and blk >= suc * 0.9;
  frozen    := svc and screen_on and suc >= 5 and dh <= 1 and not blackrun;
  expected  := son::numeric / itv;
  gap       := old.gap_armed and svc and screen_on and expected >= 4 and suc < expected * 0.5;
  -- an alert clears only when the beat PROVES the condition is gone (a screen-off beat clears nothing)
  blind_ok  := svc and ana > 0;
  black_ok  := svc and suc >= 5 and blk < suc * 0.9;
  frozen_ok := svc and suc >= 5 and dh > 1;
  gap_ok    := svc and screen_on and not gap;

  -- keep history (a flood guard: at most one stored beat per 30 s)
  if last_beat is null or now() - last_beat >= interval '30 seconds' then
    insert into public.onn_beats (app_version, cert_sha256, model_sha256, svc_enabled, screen_state, screen_on_s,
                                  window_s, interval_s, attempted, succeeded, analysed, black, distinct_hashes, reenabled)
    values (ver, cert, model, svc, scr, son, win, itv, att, suc, ana, blk, dh, ren);
  end if;

  update public.onn_status set
    last_beat_at   = now(),
    svc_enabled    = svc,
    svc_off_since  = case when svc then null else coalesce(svc_off_since, now()) end,
    screen_state   = scr, app_version = ver, cert_sha256 = cert, model_sha256 = model,
    blind_beats    = case when blind    then blind_beats  + 1 else 0 end,
    black_beats    = case when blackrun then black_beats  + 1 else 0 end,
    frozen_beats   = case when frozen   then frozen_beats + 1 else 0 end,
    gap_beats      = case when gap      then gap_beats    + 1 else 0 end,
    silent_alerted = false,
    off_alerted    = case when svc then false else off_alerted end,
    blind_alerted  = case when blind_ok  then false else blind_alerted  end,
    black_alerted  = case when black_ok  then false else black_alerted  end,
    frozen_alerted = case when frozen_ok then false else frozen_alerted end,
    gap_alerted    = case when gap_ok    then false else gap_alerted    end
  where id = 1;

  -- ALL-CLEARS: only for an alert that was actually sent. A failed email never breaks the heartbeat.
  begin
    if old.silent_alerted then
      gapint := age(now(), old.last_beat_at);
      perform public.eg_onn_close('onn_silent');
      perform public.eg_onn_mail(E'✅ EyeGuard — the Onn TV monitor is reporting again',
        format('<p><b>The Onn screen monitor is checking in again.</b> This clears the earlier '
            || '&ldquo;stopped reporting&rdquo; alert.</p><p>It was silent for about %s. '
            || '<b>Nothing was watched during that time</b>, and the gap stays in the permanent incident log.</p>', gapint));
    end if;
    if old.off_alerted and svc then
      perform public.eg_onn_close('onn_service_off');
      perform public.eg_onn_mail(E'✅ EyeGuard — the Onn monitor service is back on',
        '<p><b>The accessibility service on the Onn is enabled again.</b> This clears the earlier '
        || '&ldquo;service switched off&rdquo; alert. The time it was off stays in the incident log.</p>');
    end if;
    if old.blind_alerted and blind_ok then
      perform public.eg_onn_close('onn_blind');
      perform public.eg_onn_mail(E'✅ EyeGuard — the Onn monitor is examining the screen again',
        '<p><b>Screenshots are being analysed again.</b> This clears the earlier &ldquo;service on but not '
        || 'seeing the screen&rdquo; alert.</p>');
    end if;
    if old.black_alerted and black_ok then
      perform public.eg_onn_close('onn_black');
      perform public.eg_onn_mail(E'✅ EyeGuard — the Onn screen is no longer all black',
        '<p><b>The Onn monitor is capturing real picture content again.</b> This clears the earlier '
        || '&ldquo;black frames&rdquo; alert.</p>');
    end if;
    if old.frozen_alerted and frozen_ok then
      perform public.eg_onn_close('onn_frozen');
      perform public.eg_onn_mail(E'✅ EyeGuard — the Onn monitor sees a changing screen again',
        '<p><b>Frames are changing again.</b> This clears the earlier &ldquo;identical frames&rdquo; alert.</p>');
    end if;
    if old.gap_alerted and gap_ok then
      perform public.eg_onn_close('onn_gap');
      perform public.eg_onn_mail(E'✅ EyeGuard — the Onn monitor is taking screenshots again',
        '<p><b>Screenshots are arriving at the expected rate.</b> This clears the earlier gap alert.</p>');
    end if;
  exception when others then
    raise warning 'eg_onn_heartbeat all-clear: % (heartbeat kept)', sqlerrm;
  end;
  return jsonb_build_object('ok', true);
end $$;
revoke execute on function public.eg_onn_heartbeat(text, jsonb)
  from public, anon, authenticated, service_role;
grant execute on function public.eg_onn_heartbeat(text, jsonb) to anon;

-- ---- 5. the check (cron only; no API role may run it) -----------------------
-- Thresholds are constants HERE, reviewed in a PR. The app cannot change them.
--   silent 15 min (beats are every 5)   | service off 3 min   | blind 3 beats (~15 min)
--   black  6 beats (~30 min)            | frozen 12 beats (~1 h) | gap 3 beats (only if armed)
--   drift: immediate when the reported build matches NO approved build; outdated after 24 h
create or replace function public.eg_check_onn_status() returns void
language plpgsql security definer set search_path = public as $$
declare s public.onn_status; latest public.onn_approved; matches_latest boolean;
        matches_any boolean; n int;
begin
  delete from public.onn_beats where received_at < now() - interval '30 days';
  select * into s from public.onn_status where id = 1 for update;
  if s.last_beat_at is null then return; end if;           -- never reported yet: nothing to watch

  -- 1. silence. Takes priority: the figures below are only trusted while heartbeats are fresh.
  if now() - s.last_beat_at > interval '15 minutes' then
    if not s.silent_alerted then
      perform public.eg_onn_mail(E'\U0001F6D1 EyeGuard — the Onn TV monitor STOPPED reporting',
        format('<p><b>The Onn screen monitor has not checked in for %s.</b></p>'
            || '<p>It reports every 5 minutes. Until it is back, <b>the TV is not being watched</b>. Likely causes: '
            || 'the app was force-stopped, disabled or uninstalled, the box was unplugged or rebooted and the service '
            || 'did not come back, or the box lost its network.</p>', age(now(), s.last_beat_at)));
      update public.onn_status set silent_alerted = true where id = 1;
      perform public.eg_onn_open('onn_silent', s.last_beat_at, 'no heartbeat from the Onn monitor');
    end if;
    return;
  end if;

  -- 2. service switched off (the app is alive and says its accessibility service is not enabled)
  if s.svc_enabled is false and s.svc_off_since is not null and now() - s.svc_off_since > interval '3 minutes'
     and not s.off_alerted then
    perform public.eg_onn_mail(E'\U0001F6A8 EyeGuard — the Onn monitor service was switched OFF',
      format('<p><b>The accessibility service that watches the Onn screen is not enabled.</b> It has been off for %s.</p>'
          || '<p>The TV is <b>not being watched</b> until it is switched back on. Someone may have turned it off in '
          || 'Settings. It can only be re-enabled by the ADB step used at install.</p>', age(now(), s.svc_off_since)));
    update public.onn_status set off_alerted = true where id = 1;
    perform public.eg_onn_open('onn_service_off', s.svc_off_since, 'accessibility service not enabled');
  end if;

  -- 3. service on, screen on, but nothing is being examined
  if s.blind_beats >= 3 and not s.blind_alerted then
    perform public.eg_onn_mail(E'⚠️ EyeGuard — the Onn monitor is on but not seeing the screen',
      format('<p><b>The service is enabled and the TV is on, but %s check-ins in a row analysed no frames.</b></p>'
          || '<p>Screenshots may be failing, throttled or blocked. This is the case a plain &ldquo;is it running&rdquo; '
          || 'check misses.</p>', s.blind_beats));
    update public.onn_status set blind_alerted = true where id = 1;
    perform public.eg_onn_open('onn_blind', now() - make_interval(mins => s.blind_beats * 5), 'screen on, 0 frames analysed');
  end if;

  -- 4. all-black frames (also what protected / DRM video looks like: a blind spot to know about, not to ignore)
  if s.black_beats >= 6 and not s.black_alerted then
    perform public.eg_onn_mail(E'⚠️ EyeGuard — the Onn monitor is only seeing black',
      format('<p><b>Almost every screenshot for about %s minutes has been black while the TV is on.</b></p>'
          || '<p>Protected (DRM) video is blanked by Android and cannot be seen. If this is a streaming app, that is '
          || 'the explanation, and it is also a blind spot. If nothing like that is playing, the capture is not working.</p>',
          s.black_beats * 5));
    update public.onn_status set black_alerted = true where id = 1;
    perform public.eg_onn_open('onn_black', now() - make_interval(mins => s.black_beats * 5), 'screen on, mostly black frames');
  end if;

  -- 5. identical frames for about an hour while the screen is on
  if s.frozen_beats >= 12 and not s.frozen_alerted then
    perform public.eg_onn_mail(E'⚠️ EyeGuard — the Onn monitor sees the same picture every time',
      format('<p><b>Every screenshot for about %s minutes has been identical while the TV is on.</b></p>'
          || '<p>A paused video or an idle menu looks like this too. If the screen is really changing, the capture is stuck.</p>',
          s.frozen_beats * 5));
    update public.onn_status set frozen_alerted = true where id = 1;
    perform public.eg_onn_open('onn_frozen', now() - make_interval(mins => s.frozen_beats * 5), 'screen on, identical frames');
  end if;

  -- 6. screenshots arriving much slower than set (ARMED BY DAD only, after the screen-state data is reviewed)
  if s.gap_armed and s.gap_beats >= 3 and not s.gap_alerted then
    perform public.eg_onn_mail(E'⚠️ EyeGuard — the Onn monitor is taking too few screenshots',
      format('<p><b>For %s check-ins in a row, fewer than half the expected screenshots arrived while the TV was on.</b></p>'
          || '<p>The box may be overloaded (for example during 4K playback) or the service is being throttled.</p>', s.gap_beats));
    update public.onn_status set gap_alerted = true where id = 1;
    perform public.eg_onn_open('onn_gap', now() - make_interval(mins => s.gap_beats * 5), 'screenshots below half the expected rate');
  end if;

  -- 7. build integrity: what the box says it runs vs what Dad approved
  select count(*) into n from public.onn_approved;
  if n > 0 and s.app_version is not null then
    select * into latest from public.onn_approved order by id desc limit 1;
    matches_latest := latest.app_version = s.app_version and latest.cert_sha256 = s.cert_sha256
                      and latest.model_sha256 is not distinct from s.model_sha256;
    matches_any := exists (select 1 from public.onn_approved a
                            where a.app_version = s.app_version and a.cert_sha256 = s.cert_sha256
                              and a.model_sha256 is not distinct from s.model_sha256);
    if matches_latest then
      if s.drift_alerted or s.outdated_alerted then
        perform public.eg_onn_close('onn_drift'); perform public.eg_onn_close('onn_outdated');
        perform public.eg_onn_mail(E'✅ EyeGuard — the Onn monitor build is the approved one again',
          '<p><b>The app, its signing key and its model match what Dad approved.</b> This clears the earlier build alert.</p>');
      end if;
      update public.onn_status set drift_alerted = false, outdated_alerted = false, outdated_since = null where id = 1;
    elsif not matches_any then
      if not s.drift_alerted then
        perform public.eg_onn_mail(E'\U0001F6A8 EyeGuard — the Onn monitor is running a build nobody approved',
          format('<p><b>The version, signing key or model reported by the Onn matches none of the approved builds.</b></p>'
              || '<p>Reported version: %s. Treat this as tampering until someone confirms an update was installed on purpose. '
              || 'If it was, Dad approves the new build in the database and this clears.</p>',
              public.eg_mdm_esc(coalesce(s.app_version, '?'))));
        update public.onn_status set drift_alerted = true where id = 1;
        perform public.eg_onn_open('onn_drift', now(), 'reported build matches no approved build');
      end if;
    else   -- an older approved build
      if s.outdated_since is null then
        update public.onn_status set outdated_since = now() where id = 1;
      elsif now() - s.outdated_since > interval '24 hours' and not s.outdated_alerted then
        perform public.eg_onn_mail(E'⚠️ EyeGuard — the Onn monitor has not been updated',
          '<p><b>The Onn is still running an older approved build for more than 24 hours.</b> Updates are installed by hand '
          || 'over ADB; this is a reminder that the newest reviewed build is not installed yet.</p>');
        update public.onn_status set outdated_alerted = true where id = 1;
        perform public.eg_onn_open('onn_outdated', s.outdated_since, 'older approved build still running');
      end if;
    end if;
  end if;
end $$;
revoke execute on function public.eg_check_onn_status()
  from public, anon, authenticated, service_role;

select cron.unschedule('eyeguard-onn-status')
  where exists (select 1 from cron.job where jobname = 'eyeguard-onn-status');
select cron.schedule('eyeguard-onn-status', '* * * * *', $$ select public.eg_check_onn_status(); $$);

-- ---- 5. LATER, by hand, when phase 2 is installed (do NOT run now) ------------
-- Token: Jonah makes it (openssl rand -hex 32) and puts it on the box; Dad only ever sees the HASH:
--   insert into public.onn_auth (token_sha256, note) values ('<64-hex sha256 of the token>', 'Onn monitor 2026-11');
-- ---- 6. LATER: approve a build (version + the signing certificate's sha256; model hash after phase 3):
--   insert into public.onn_approved (app_version, cert_sha256, note) values ('0.1.0', '<64-hex>', 'phase 2 health-only');
-- ---- 7. LATER: arm the gap alert after reviewing onn_beats (screen_state / screen_on_s over several days):
--   update public.onn_status set gap_armed = true where id = 1;

-- ---- 8. verify (read-only). Expect every column true. ------------------------
select
  has_function_privilege('anon', 'public.eg_onn_heartbeat(text, jsonb)', 'execute')        as heartbeat_callable_by_anon,
  not has_function_privilege('anon', 'public.eg_check_onn_status()', 'execute')              as check_locked_anon,
  not has_function_privilege('authenticated', 'public.eg_check_onn_status()', 'execute')     as check_locked_authenticated,
  not has_function_privilege('anon', 'public.eg_onn_mail(text, text)', 'execute')            as mail_locked,
  not has_table_privilege('anon', 'public.onn_auth', 'select')                               as auth_not_anon_readable,
  not has_table_privilege('anon', 'public.onn_status', 'select')                             as status_not_anon_readable,
  not has_table_privilege('anon', 'public.onn_beats', 'select')                              as beats_not_anon_readable,
  not has_table_privilege('authenticated', 'public.onn_beats', 'update')                     as beats_not_writable,
  not has_table_privilege('authenticated', 'public.onn_incidents', 'update')                 as incidents_not_writable,
  not has_table_privilege('anon', 'public.onn_approved', 'select')                           as approved_not_anon_readable,
  exists (select 1 from cron.job where jobname = 'eyeguard-onn-status')                      as cron_scheduled,
  (select last_beat_at is null and not gap_armed from public.onn_status where id = 1)        as idle_and_gap_off,
  exists (select 1 from public.onn_status where id = 1)                                      as status_row;

-- ---- ROLLBACK (only if Dad wants this removed; run by hand) ---------------------
-- select cron.unschedule('eyeguard-onn-status');
-- drop function if exists public.eg_check_onn_status(), public.eg_onn_heartbeat(text, jsonb),
--   public.eg_onn_mail(text, text), public.eg_onn_open(text, timestamptz, text), public.eg_onn_close(text);
-- drop table if exists public.onn_beats, public.onn_incidents, public.onn_status, public.onn_approved, public.onn_auth;
