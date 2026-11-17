-- EyeGuard: Onn TV monitor, PHASE 3b (database). 2026-11-17. Run AFTER onn_monitor_phase3.sql (already run). Replaces ONE function.
--
-- ADDS to eg_onn_flag a fifth label, 'ONN_TEST': the end-to-end self-test of the Onn's encrypt + upload path using a SYNTHETIC image
-- (design gate 3). A test row is ALWAYS a YELLOW row on the dashboard (reason 'onn-test: ...', grade Test, is_nudity false): it sends NO email,
-- is never counted toward the 10-minute RED window (so it can neither cause a false alarm nor hide a real one), and the four real labels,
-- the 0.80 floor, the frame-exists check, the time window, de-duplication and the 400/hour ceiling are all unchanged.
-- Everything else in phase 3 (tables, heartbeat, check function, grants) is untouched; the function's grants persist across "create or replace".
--
-- ======================= DAD: BEFORE RUNNING =================================
-- * NO placeholders. Run the whole file in the SQL editor, then the verify select: every column true. Safe to run twice.
-- * Rollback: re-run supabase/onn_monitor_phase3.sql (restores the phase 3 version of the function).
-- =============================================================================

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
  if lbl is null or lbl not in ('FEMALE_BREAST_EXPOSED','FEMALE_GENITALIA_EXPOSED','BUTTOCKS_EXPOSED','ANUS_EXPOSED','ONN_TEST')
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

  -- ONN_TEST is the end-to-end self-test of the Onn's encrypt + upload path with a SYNTHETIC image (never a detection). It is always a
  -- YELLOW row (no email), is not nudity, is clearly labelled, and never counts toward the RED window, so it can neither raise a false
  -- alarm nor hide a real one.
  recent := exists (select 1 from public.onn_flag_log where verdict = 'flagged' and received_at > now() - interval '10 minutes');
  v := case when lbl = 'ONN_TEST' or recent then 'alert' else 'flagged' end;

  if lbl = 'ONN_TEST' then
    insert into public.flags (flagged_at, verdict, is_nudity, grade, risk, app, window_title, reason, score, image_path)
    values (ts, 'alert', false, 'Test', 'low', 'Onn TV', nullif(fg, ''),
            'onn-test: end-to-end self-test of the encrypted upload path (synthetic image, not a detection)', sc, obj)
    returning id into fid;
  else
    insert into public.flags (flagged_at, verdict, is_nudity, grade, risk, app, window_title, reason, score, image_path)
    values (ts, v, true, 'Likely', 'high', 'Onn TV', nullif(fg, ''),
            'nudenet:' || lbl || '=' || to_char(sc, 'FM0.00'), sc, obj)
    returning id into fid;
  end if;
  insert into public.onn_flag_log (object, flagged_at, label, score, verdict, flag_id)
  values (obj, ts, lbl, sc, v, fid);
  return jsonb_build_object('ok', true, 'verdict', v);
end $$;

revoke execute on function public.eg_onn_flag(text, jsonb) from public, anon, authenticated, service_role;
grant execute on function public.eg_onn_flag(text, jsonb) to anon;

-- ---- verify (read-only). Expect every column true. ----------------------------------------------------------------
select
  has_function_privilege('anon', 'public.eg_onn_flag(text, jsonb)', 'execute')                       as flag_callable_by_anon,
  (select pg_get_functiondef('public.eg_onn_flag(text, jsonb)'::regprocedure) like '%ONN_TEST%')     as test_label_accepted,
  (select pg_get_functiondef('public.eg_onn_flag(text, jsonb)'::regprocedure) like '%FEMALE_BREAST_EXPOSED%') as real_labels_kept,
  not has_function_privilege('authenticated', 'public.eg_onn_flag(text, jsonb)', 'execute')           as not_callable_by_logged_in_users,
  exists (select 1 from public.onn_golden where id = 1)                                               as phase3_still_there;
