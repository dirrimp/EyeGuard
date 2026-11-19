-- EyeGuard Onn, phase 5a: "title facts" (facts only; NO title text ever leaves the TV). Run by Dad.
-- Context: docs/ONN-DRM-TITLE-DESIGN.md. Protected (DRM) video is black to the detector. Before any title is collected, we need to know
-- whether the TV even exposes one. The app counts, per 5-minute beat, over an allowlist of media apps only:
--   title_events     window events seen in those apps
--   title_with_text  of those, events that carried any text
--   title_specific   of those, events whose text was not just the app's or screen's generic name
--   title_distinct   distinct specific texts (a salted hash is compared on the box, then thrown away; only this count is sent)
-- Nothing else changes: this replaces eg_onn_heartbeat with the phase 3 body plus these four OPTIONAL counts (omitted = 0, bounded).
-- COVERAGE: unchanged or increased. No alert is added, removed or loosened.

alter table public.onn_beats
  add column if not exists title_events    int,
  add column if not exists title_with_text int,
  add column if not exists title_specific  int,
  add column if not exists title_distinct  int;

create or replace function public.eg_onn_heartbeat(p_token text, p_info jsonb default '{}'::jsonb)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  ver text; cert text; model text; svc boolean; scr text;
  son int; win int; itv int; att int; suc int; ana int; blk int; dh int; ren int;
  old public.onn_status; screen_on boolean; blind boolean; blackrun boolean; frozen boolean; gap boolean;
  expected numeric; last_beat timestamptz; gapint interval;
  te int; tt int; ts int; td int;
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
    te    := coalesce((p_info->>'title_events')::int, 0);
    tt    := coalesce((p_info->>'title_with_text')::int, 0);
    ts    := coalesce((p_info->>'title_specific')::int, 0);
    td    := coalesce((p_info->>'title_distinct')::int, 0);
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
     or te not between 0 and 1000000 or tt not between 0 and te or ts not between 0 and tt or td not between 0 and tt
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
                                  selftest_argmax, selftest_max, selftest_ok, model_ms, frames_flagged, flags_dropped,
                                  title_events, title_with_text, title_specific, title_distinct)
    values (ver, cert, model, svc, scr, son, win, itv, att, suc, ana, blk, dh, ren, sa, sm, selftest_ok, mms, ff, fd, te, tt, ts, td);
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

-- verify (read-only). Expect every column true.
select
  has_function_privilege('anon', 'public.eg_onn_heartbeat(text, jsonb)', 'execute')   as heartbeat_callable_by_anon,
  (select pg_get_functiondef('public.eg_onn_heartbeat(text, jsonb)'::regprocedure) like '%title_distinct%') as heartbeat_is_phase5a,
  (select pg_get_functiondef('public.eg_onn_heartbeat(text, jsonb)'::regprocedure) like '%selftest_argmax%') as still_has_phase3,
  exists (select 1 from information_schema.columns where table_schema='public' and table_name='onn_beats' and column_name='title_distinct') as beats_columns,
  not has_table_privilege('anon', 'public.onn_beats', 'select')                        as beats_not_anon_readable;

-- ROLLBACK (by hand): re-run supabase/onn_monitor_phase3.sql (restores the phase 3 heartbeat). The four columns may stay.
