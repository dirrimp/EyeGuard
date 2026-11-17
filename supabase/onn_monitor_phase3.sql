-- EyeGuard: Onn TV monitor, PHASE 3 (database side for real detection).  2026-11-17.
-- Design: docs/ONN-PHASE3-DETECTION-DESIGN.md (#166). Builds on onn_monitor_phase1.sql (live). Run it AFTER phase 1.
--
-- ADDS: (1) eg_onn_flag(): the token-checked call the Onn's detector uses to record an exposure flag; (2) a SERVER-side check of the
-- detector's self-test (the box reports the numbers it computes on a fixed synthetic input; THIS DATABASE compares them with golden
-- values from the Mac's model and decides pass/fail; the app's own opinion is not an input); (3) alerts for a failing detector.
-- REPLACES (create or replace) two phase 1 functions, eg_onn_heartbeat and eg_check_onn_status, with the SAME logic plus the new
-- fields. Every phase 1 alert, threshold and all-clear is unchanged. Re-running onn_monitor_phase1.sql restores the phase 1 versions.
--
-- NOTHING changes behaviour until a phase 3 build reports a model hash: a phase 2 app sends no model, so the new checks stay idle.
-- Nothing is registered or approved by running this file.
--
-- WHAT eg_onn_flag DOES (and does not):
--   * validates the token, the label (one of the four explicit labels), the score (never below 0.80, the Mac's flag_threshold),
--     the foreground package text, and that the encrypted frame ALREADY EXISTS in the 'frames' bucket under onn/ (the box must
--     upload first, so the server verifies the upload instead of trusting a claim);
--   * takes flagged_at from the frame's own file name (the dashboard viewer requires them to match) and accepts it only within
--     15 minutes before / 2 minutes after the server clock;
--   * inserts the flags row (app 'Onn TV', is_nudity true, grade Likely). The existing eg_red_alert trigger emails it as usual.
--   * VOLUME RULE, same idea as the Mac's explicit-term signal: the FIRST exposure flag in any 10-minute window is a RED row (emailed
--     at once); further detections in that window are still stored, with their encrypted frame, as YELLOW rows on the dashboard and
--     in the daily digest, not emailed one by one. NOTHING is dropped. A window with no detection re-arms RED.
--   * HONEST LIMIT: anyone holding the public anon key can already insert flags rows directly (supabase/anon_client_pivot.sql; the
--     Mac needs that path). So this RPC does not stop a forged row. It validates, checks the frame exists, de-duplicates,
--     applies the volume rule, and is what the Onn uses; flags remain append-only for every role, so a real flag can never be erased.
--
-- ======================= DAD: BEFORE RUNNING =================================
-- * NO placeholders to edit. Run AFTER onn_monitor_phase1.sql. Do NOT re-run mdm_app_events.sql afterwards (it would overwrite the
--   edited eg_send_email_mdm). Run the whole file in the SQL editor, then check the verify select at the bottom: every column true.
-- * Safe to run twice. ROLLBACK at the very bottom.
-- * Later, by hand (commented below): approve the phase 3 build INCLUDING its model hash, in onn_approved.
-- =============================================================================

-- ---- 1. schema additions (all "if not exists"; nothing is removed) ------------------------------------------------
alter table public.onn_status
  add column if not exists detector_bad_beats int not null default 0,
  add column if not exists detector_alerted   boolean not null default false;

alter table public.onn_beats
  add column if not exists selftest_argmax int,
  add column if not exists selftest_max    double precision,
  add column if not exists selftest_ok     boolean,         -- decided by the SERVER from the two numbers above
  add column if not exists model_ms        int,
  add column if not exists frames_flagged  int,
  add column if not exists flags_dropped   int;

alter table public.onn_incidents drop constraint if exists onn_incidents_kind_check;
alter table public.onn_incidents add constraint onn_incidents_kind_check check (kind in (
  'onn_silent','onn_service_off','onn_blind','onn_black','onn_frozen','onn_gap','onn_drift','onn_outdated','onn_detector'));

-- golden values: what NudeNet 320n (sha256 c15d8273...1f0f) outputs on the fixed synthetic input in tools/onn_fit_reference.py.
-- Computed on the Mac (onnxruntime 1.27.0) and reproduced on the real Onn (ORT 1.31.1, fit test 2026-11-17: argmax identical,
-- max identical, relative differences about 1e-8). rel_tol 1e-4 is far above that and far below any real fault.
create table if not exists public.onn_golden (
  id         int primary key check (id = 1),
  argmax     int not null,
  max_value  double precision not null,
  rel_tol    double precision not null check (rel_tol > 0 and rel_tol <= 0.01),
  note       text
);
insert into public.onn_golden (id, argmax, max_value, rel_tol, note)
  values (1, 8355, 319.69696044921875, 0.0001, 'NudeNet 320n c15d8273..., tools/onn_fit_reference.py, Mac ORT 1.27.0; Onn ORT 1.31.1 matched')
  on conflict (id) do nothing;
alter table public.onn_golden enable row level security;
revoke all on public.onn_golden from public, anon, authenticated, service_role;

-- every flag the Onn recorded (de-duplication, the volume rule, and a record of RED vs YELLOW)
create table if not exists public.onn_flag_log (
  object      text primary key,                  -- the frame's path in the 'frames' bucket
  received_at timestamptz not null default now(),
  flagged_at  timestamptz not null,
  label       text not null,
  score       real not null,
  verdict     text not null check (verdict in ('flagged','alert')),
  flag_id     uuid
);
create index if not exists onn_flag_log_received_idx on public.onn_flag_log (received_at);
alter table public.onn_flag_log enable row level security;
drop policy if exists "partner reads onn_flag_log" on public.onn_flag_log;
create policy "partner reads onn_flag_log" on public.onn_flag_log
  for select to authenticated using (
    auth.uid() in ('0e02aa87-1cd5-4bb6-a263-f51d4e2642b6', '1818ac68-7ecf-4e39-a758-8526e496247d'));
revoke all on public.onn_flag_log from public, anon, authenticated, service_role;
grant select on public.onn_flag_log to authenticated;

-- ---- 2. the heartbeat: phase 1 logic + detector fields (callable with the device token) ---------------------------
-- New p_info fields (required whenever model_sha256 is reported): selftest_argmax, selftest_max, model_ms.
-- Optional: frames_flagged, flags_dropped (counts since the last beat; flags_dropped = detections the app could not deliver).
create or replace function public.eg_onn_heartbeat(p_token text, p_info jsonb default '{}'::jsonb)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  ver text; cert text; model text; svc boolean; scr text;
  son int; win int; itv int; att int; suc int; ana int; blk int; dh int; ren int;
  old public.onn_status; screen_on boolean; blind boolean; blackrun boolean; frozen boolean; gap boolean;
  expected numeric; last_beat timestamptz; gapint interval;
  sa int; sm double precision; mms int; ff int; fd int; g public.onn_golden;
  selftest_ok boolean := null; det_bad boolean := false;
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
    sa    := (p_info->>'selftest_argmax')::int;
    sm    := (p_info->>'selftest_max')::double precision;
    mms   := (p_info->>'model_ms')::int;
    ff    := coalesce((p_info->>'frames_flagged')::int, 0);
    fd    := coalesce((p_info->>'flags_dropped')::int, 0);
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
     or blk not between 0 and suc or dh not between 0 and suc or ren not between 0 and 1000
     or ff not between 0 and 100000 or fd not between 0 and 100000
     -- a build that reports a model MUST report its self-test result and timing (omitting them cannot dodge the check)
     or (model is not null and (sa is null or sm is null or mms is null or sa < 0 or mms not between 1 and 600000))
     or (sm is not null and (sm <> sm or sm = 'Infinity'::double precision or sm = '-Infinity'::double precision)) then
    raise exception 'bad info' using errcode = 'PT400';
  end if;

  -- THE SERVER decides whether the detector self-test passed: it compares the numbers the box computed on a fixed synthetic
  -- input with the golden values from the Mac's model (onn_golden). The app's own opinion is not an input.
  if model is not null and svc then
    select * into g from public.onn_golden where id = 1;
    if found then
      selftest_ok := (sa = g.argmax) and abs(sm - g.max_value) <= g.rel_tol * abs(g.max_value);
      det_bad := not selftest_ok;
    end if;
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
                                  window_s, interval_s, attempted, succeeded, analysed, black, distinct_hashes, reenabled,
                                  selftest_argmax, selftest_max, selftest_ok, model_ms, frames_flagged, flags_dropped)
    values (ver, cert, model, svc, scr, son, win, itv, att, suc, ana, blk, dh, ren, sa, sm, selftest_ok, mms, ff, fd);
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
    detector_bad_beats = case when det_bad then detector_bad_beats + 1 else 0 end,
    detector_alerted   = case when selftest_ok is true then false else detector_alerted end,
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
    if old.detector_alerted and selftest_ok is true then
      perform public.eg_onn_close('onn_detector');
      perform public.eg_onn_mail(E'\u2705 EyeGuard \u2014 the Onn detector self-test passes again',
        '<p><b>The Onn detector produces the expected result on its test input again.</b> This clears the earlier '
        || '&ldquo;detector may be broken&rdquo; alert.</p>');
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
revoke execute on function public.eg_onn_heartbeat(text, jsonb) from public, anon, authenticated, service_role;
grant execute on function public.eg_onn_heartbeat(text, jsonb) to anon;

-- ---- 3. the check: phase 1 logic + the detector self-test alert (cron only; no API role may run it) ----------------
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

  -- 5b. the detector self-test (computed by the SERVER from the box's numbers) has failed on 2 beats in a row
  if s.detector_bad_beats >= 2 and not s.detector_alerted then
    perform public.eg_onn_mail(E'\U0001F6A8 EyeGuard \u2014 the Onn detector may be broken',
      format('<p><b>The Onn is running, but its exposure detector failed its self-test on %s check-ins in a row.</b></p>'
          || '<p>The model or its runtime may have broken, or the app was changed. <b>A quiet Onn feed must NOT be read as '
          || '&ldquo;all clear&rdquo;</b> until this is fixed.</p>', s.detector_bad_beats));
    update public.onn_status set detector_alerted = true where id = 1;
    perform public.eg_onn_open('onn_detector', now() - make_interval(mins => s.detector_bad_beats * 5), 'detector self-test failing');
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
revoke execute on function public.eg_check_onn_status() from public, anon, authenticated, service_role;

-- ---- 4. eg_onn_flag: record one exposure detection (callable with the device token) --------------------------------
-- p_info: {label, score, object, foreground?}.  object = 'onn/<UTC timestamp>_flagged_d1.jpg.enc' (already uploaded).
create or replace function public.eg_onn_flag(p_token text, p_info jsonb)
returns jsonb
language plpgsql security definer set search_path = public, extensions, storage as $$
declare
  lbl text; sc real; obj text; fg text; m text[]; ts timestamptz; v text; fid uuid; recent boolean; n int;
begin
  if p_token is null or length(p_token) < 32 or length(p_token) > 256
     or not exists (select 1 from public.onn_auth where token_sha256 = encode(digest(p_token, 'sha256'), 'hex')) then
    raise exception 'unauthorized' using errcode = 'PT401';
  end if;
  if p_info is null or jsonb_typeof(p_info) <> 'object' then
    raise exception 'info must be a JSON object' using errcode = 'PT400';
  end if;
  begin
    lbl := p_info->>'label';
    sc  := (p_info->>'score')::real;
    obj := p_info->>'object';
    fg  := coalesce(p_info->>'foreground', '');
  exception when others then
    raise exception 'bad info' using errcode = 'PT400';
  end;
  -- the labels are the Mac's explicit_labels (config.yaml); the floor is the Mac's flag_threshold. The app cannot lower either.
  if lbl is null or lbl not in ('FEMALE_BREAST_EXPOSED','FEMALE_GENITALIA_EXPOSED','BUTTOCKS_EXPOSED','ANUS_EXPOSED')
     or sc is null or sc <> sc or sc < 0.80 or sc > 1.0 or obj is null or length(obj) > 120
     or length(fg) > 120 or fg !~ '^[A-Za-z0-9._-]*$' then          -- fg is shown in the alert email: letters, digits . _ - only
    raise exception 'bad info' using errcode = 'PT400';
  end if;
  m := regexp_match(obj, '^onn/(\d{4}-\d\d-\d\d)T(\d\d)-(\d\d)-(\d\d)(\.\d{1,6})?\+00-00_flagged_d1\.jpg\.enc$');
  if m is null then raise exception 'bad object name' using errcode = 'PT400'; end if;
  begin
    ts := (m[1] || 'T' || m[2] || ':' || m[3] || ':' || m[4] || coalesce(m[5], '') || '+00')::timestamptz;
  exception when others then
    raise exception 'bad object name' using errcode = 'PT400';
  end;
  if ts < now() - interval '15 minutes' or ts > now() + interval '2 minutes' then
    raise exception 'object time outside the accepted window' using errcode = 'PT400';
  end if;
  -- the server checks the box really uploaded the encrypted frame
  if not exists (select 1 from storage.objects where bucket_id = 'frames' and name = obj) then
    raise exception 'frame not uploaded' using errcode = 'PT404';
  end if;
  if exists (select 1 from public.onn_flag_log where object = obj) then
    return jsonb_build_object('ok', true, 'duplicate', true);
  end if;
  -- sanity ceiling: a healthy app flags at most one frame per 15 s (240/h). 400/h means something is wrong, so refuse loudly.
  select count(*) into n from public.onn_flag_log where received_at > now() - interval '1 hour';
  if n >= 400 then raise exception 'too many flags this hour' using errcode = 'PT429'; end if;

  recent := exists (select 1 from public.onn_flag_log where verdict = 'flagged' and received_at > now() - interval '10 minutes');
  v := case when recent then 'alert' else 'flagged' end;

  insert into public.flags (flagged_at, verdict, is_nudity, grade, risk, app, window_title, reason, score, image_path)
  values (ts, v, true, 'Likely', 'high', 'Onn TV', nullif(fg, ''),
          'nudenet:' || lbl || '=' || to_char(sc, 'FM0.00'), sc, obj)
  returning id into fid;
  insert into public.onn_flag_log (object, flagged_at, label, score, verdict, flag_id)
  values (obj, ts, lbl, sc, v, fid);
  return jsonb_build_object('ok', true, 'verdict', v);
end $$;
revoke execute on function public.eg_onn_flag(text, jsonb) from public, anon, authenticated, service_role;
grant execute on function public.eg_onn_flag(text, jsonb) to anon;

-- ---- 5. LATER, by hand, when the phase 3 build exists (do NOT run now) ---------------------------------------------
-- Approve the build INCLUDING its model hash (the app reports its own; a different model or APK then raises the drift alert):
--   insert into public.onn_approved (app_version, cert_sha256, model_sha256, note)
--   values ('0.2.0', '9ec032dbc94305237c06e76f624d763fee368e53fddc0b107b1e62360eca0162',
--           'c15d8273adad2d0a92f014cc69ab2d6c311a06777a55545f2c4eb46f51911f0f', 'phase 3 detector');
-- Approve it BEFORE installing the build, or the first heartbeat raises the "nobody approved" email.

-- ---- 6. verify (read-only). Expect every column true. -------------------------------------------------------------
select
  has_function_privilege('anon', 'public.eg_onn_flag(text, jsonb)', 'execute')               as flag_callable_by_anon,
  has_function_privilege('anon', 'public.eg_onn_heartbeat(text, jsonb)', 'execute')          as heartbeat_callable_by_anon,
  not has_function_privilege('anon', 'public.eg_check_onn_status()', 'execute')              as check_locked_anon,
  not has_function_privilege('authenticated', 'public.eg_check_onn_status()', 'execute')     as check_locked_authenticated,
  not has_table_privilege('anon', 'public.onn_golden', 'select')                             as golden_not_anon_readable,
  not has_table_privilege('anon', 'public.onn_flag_log', 'select')                           as flag_log_not_anon_readable,
  not has_table_privilege('authenticated', 'public.onn_flag_log', 'update')                  as flag_log_not_writable,
  exists (select 1 from public.onn_golden where id = 1 and argmax = 8355)                    as golden_seeded,
  exists (select 1 from information_schema.columns where table_schema = 'public' and table_name = 'onn_beats'
           and column_name = 'selftest_ok')                                                   as beats_columns,
  exists (select 1 from information_schema.columns where table_schema = 'public' and table_name = 'onn_status'
           and column_name = 'detector_alerted')                                              as status_columns,
  (select pg_get_constraintdef(oid) like '%onn_detector%' from pg_constraint
    where conname = 'onn_incidents_kind_check')                                               as incident_kind_added,
  exists (select 1 from cron.job where jobname = 'eyeguard-onn-status')                      as cron_still_scheduled,
  (select pg_get_functiondef('public.eg_onn_heartbeat(text, jsonb)'::regprocedure) like '%selftest_argmax%') as heartbeat_is_phase3;

-- ---- ROLLBACK (only if Dad wants phase 3 removed; run by hand) -----------------------------------------------------
-- 1. re-run supabase/onn_monitor_phase1.sql   (restores the phase 1 eg_onn_heartbeat and eg_check_onn_status)
-- 2. drop function if exists public.eg_onn_flag(text, jsonb);
-- 3. drop table if exists public.onn_flag_log, public.onn_golden;   -- the flags rows already written stay (append-only)
-- (the extra columns are harmless and may stay; the incident-kind constraint may stay)
