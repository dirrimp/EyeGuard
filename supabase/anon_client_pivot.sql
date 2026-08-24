-- Admin-trust-model pivot (2026-08-24): Jonah now has full admin rights on
-- his own Mac, which means the secret/service_role key can no longer be
-- assumed hidden from him -- once he can read that key, he can also read
-- any client-supplied field directly (last_heartbeat, status) and write it
-- himself over raw HTTP, bypassing whatever the client SOFTWARE intends.
--
-- This file is the single source of truth for the new client-facing surface:
-- the client (Mac app) holds ONLY the public anon key from now on. Every
-- write goes through either an explicit anon-scoped RLS policy (flags,
-- mirroring the frames-bucket pattern already proven in
-- phase4c_storage_anon_insert.sql) or a SECURITY DEFINER RPC that validates
-- and stamps server-side (device_status) -- never a raw table write with a
-- powerful key.
--
-- Supersedes the effective grants in phase4_pause.sql / harden_pause.sql
-- (which currently conflict with each other on who may call eg_check_pause).
-- Those files are left in place as historical record of the reasoning trail,
-- same convention as every other phased SQL file in this repo -- this file
-- is what's actually live going forward. Idempotent, safe to re-run.

-- ===== 1. flags: open direct anon insert =====
-- Already append-only against every role (phase4_append_only.sql's
-- `revoke update, delete ... from anon, authenticated, service_role`,
-- confirmed live to actually hold for /rest/v1/ table access) -- so letting
-- anon insert directly is safe. verdict/reason/score are self-reported
-- detection output, not a security-critical field; nothing regresses here
-- versus today (service_role already inserted this exact shape).
drop policy if exists "agent inserts flags" on public.flags;
create policy "agent inserts flags" on public.flags
  for insert to anon with check (true);
grant insert on public.flags to anon;
grant usage on schema public to anon;

-- ===== 2. device_status: remove all direct client writes =====
-- No table policy is added for device_status. Every write must go through
-- one of the RPCs below, all of which stamp last_heartbeat = now() -- the
-- SERVER's clock, never a client-supplied timestamp -- since the entire
-- gone-dark alert hinges on this value being honest, and there is no other
-- way to make a client-forgeable timestamp trustworthy.
revoke insert, update, delete on public.device_status from anon, authenticated, service_role;

-- eg_heartbeat(): the ONLY way status='alive' + last_heartbeat gets set.
-- No timestamp parameter exists in this signature -- the client cannot
-- submit one even if it tries.
create or replace function public.eg_heartbeat(
  p_screen_ok boolean default null,
  p_frames_analyzed bigint default null,
  p_detector_ok boolean default null
) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.device_status
     set last_heartbeat = now(),
         status = 'alive',
         alerted = false,
         screen_ok = coalesce(p_screen_ok, screen_ok),
         frames_analyzed = coalesce(p_frames_analyzed, frames_analyzed),
         detector_ok = coalesce(p_detector_ok, detector_ok),
         updated_at = now()
   where id = 1;
end $$;
revoke all on function public.eg_heartbeat(boolean, bigint, boolean) from public;
grant execute on function public.eg_heartbeat(boolean, bigint, boolean) to anon;

-- eg_report_suspend(): the sleep/wake "don't gone-dark me" beacon. NOT
-- password-gated on purpose -- routine sleep shouldn't need a password
-- prompt every time the lid closes -- but still server-timestamped.
-- ACCEPTED RESIDUAL (confirmed with the user 2026-08-24): anyone holding the
-- public anon key could call this to suppress gone-dark for this
-- installation. Low real-world value to an outside attacker (they gain
-- nothing from silencing someone else's accountability alert), and real
-- protection here would need either a password prompt on every sleep (bad
-- UX) or per-device auth infrastructure (real complexity) not justified for
-- this one low-value endpoint. Revisit only if actually abused.
create or replace function public.eg_report_suspend() returns void
language sql security definer set search_path = public as $$
  update public.device_status
     set status = 'clean_shutdown', last_heartbeat = now(), updated_at = now()
   where id = 1;
$$;
revoke all on function public.eg_report_suspend() from public;
grant execute on function public.eg_report_suspend() to anon;

-- ===== 3. eg_check_pause: open to anon (service_role no longer exists
--          client-side) -- the server-side lockout (not "you need a secret
--          key to even try") becomes the actual defense against brute
--          force. It's already stateful in `settings`, which no API role
--          (not even service_role) can write directly -- a local admin
--          cannot reset the lockout counter no matter what key they hold. =====
revoke execute on function public.eg_check_pause(text) from public, service_role;
grant  execute on function public.eg_check_pause(text) to anon;

-- eg_authorized_stop(pw): the atomic, password-gated clean-shutdown call.
-- Replaces eg_authorize.sh's old two-call sequence (eg_check_pause, THEN a
-- separate raw device_status POST) which had a real gap -- nothing tied the
-- two calls together, so a direct POST to device_status with the old secret
-- key could set status='clean_shutdown' without ever passing the password
-- check. This RPC makes "check, then set" one atomic server-side operation.
create or replace function public.eg_authorized_stop(pw text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare ok boolean;
begin
  ok := public.eg_check_pause(pw);
  if ok then
    update public.device_status
       set status = 'clean_shutdown', last_heartbeat = now(), updated_at = now()
     where id = 1;
  end if;
  return ok;
end $$;
revoke all on function public.eg_authorized_stop(text) from public;
grant execute on function public.eg_authorized_stop(text) to anon;

-- ===== 4. Session-watcher support: device_status gains its own component
--          liveness fields, so the SessionWatcher LaunchDaemon (new-account
--          + active-console-user checks, see eyeguard/session_watcher.py)
--          can be gone-dark-checked independently of the main app -- killing
--          the watcher must be just as visible as killing the main app,
--          via the same alert mechanism, not a silent gap. =====
alter table public.device_status add column if not exists watcher_last_heartbeat timestamptz;
alter table public.device_status add column if not exists watcher_new_account     boolean not null default false;
alter table public.device_status add column if not exists watcher_wrong_user     boolean not null default false;
alter table public.device_status add column if not exists watcher_alerted        boolean not null default false;

-- eg_watcher_heartbeat(): server-stamped, same principle as eg_heartbeat()
-- above -- no timestamp parameter, no way for the client to forge staleness.
create or replace function public.eg_watcher_heartbeat(
  p_new_account boolean default false,
  p_wrong_user  boolean default false
) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.device_status
     set watcher_last_heartbeat = now(),
         watcher_new_account = p_new_account,
         watcher_wrong_user = p_wrong_user,
         watcher_alerted = case when not (p_new_account or p_wrong_user) then false
                                else watcher_alerted end
   where id = 1;
end $$;
revoke all on function public.eg_watcher_heartbeat(boolean, boolean) from public;
grant execute on function public.eg_watcher_heartbeat(boolean, boolean) to anon;

-- eg_check_gone_dark() gains a fourth and fifth branch, EXTENDING (not
-- replacing) the current live definition from self_test.sql -- (a) main-app
-- gone-dark, (b) blind, (c) detector-broken are copied verbatim from there,
-- unchanged, so this replace doesn't regress anything shipped since the
-- earlier exploration this pivot was planned against. Only (d)/(e) below
-- are new. Reuses the exact same eg_send_email() internal call already used
-- by every other alert in this system -- no new email infrastructure needed.
create or replace function public.eg_check_gone_dark() returns void
language plpgsql security definer set search_path = public as $$
declare d public.device_status;
begin
  select * into d from public.device_status where id = 1;
  if d.last_heartbeat is null then return; end if;

  -- (a) went dark: no heartbeat for 3+ minutes [unchanged from self_test.sql]
  if d.status = 'alive' and not d.alerted
     and now() - d.last_heartbeat > interval '3 minutes' then
    perform public.eg_send_email(
      '⚫ EyeGuard — monitoring went dark',
      format('<p><b>EyeGuard stopped reporting.</b></p><p>Last seen %s ago. The Mac '
          || 'may be off, offline, or the monitor was stopped. If unexpected, '
          || 'check in.</p>', age(now(), d.last_heartbeat)));
    update public.device_status set alerted = true where id = 1;
  end if;

  -- only evaluate the "alive but unhealthy" checks on a fresh heartbeat
  -- [unchanged from self_test.sql]
  if d.status = 'alive' and now() - d.last_heartbeat <= interval '3 minutes' then

    -- (b) went blind: can't see the screen
    if d.screen_ok is false and not d.blind_alerted then
      perform public.eg_send_email(
        '🚨 EyeGuard — lost view of the screen',
        '<p><b>EyeGuard is running but can no longer see the screen.</b></p>'
        || '<p>Screen Recording may have been revoked, the display switched, or '
        || 'capture frozen. Detection is NOT working until this is resolved.</p>');
      update public.device_status set blind_alerted = true where id = 1;
    elsif d.screen_ok is not false and d.blind_alerted then
      update public.device_status set blind_alerted = false where id = 1;
    end if;

    -- (c) detector broken: running + seeing, but the self-test failed
    if d.detector_ok is false and not d.detector_alerted then
      perform public.eg_send_email(
        '🚨 EyeGuard — detection may be broken',
        '<p><b>EyeGuard is running and can see the screen, but its detector '
        || 'self-test is failing.</b></p><p>The analysis pipeline may have broken '
        || '(e.g. after a macOS update). A quiet feed right now should NOT be '
        || 'read as "all clear" until this is fixed.</p>');
      update public.device_status set detector_alerted = true where id = 1;
    elsif d.detector_ok is not false and d.detector_alerted then
      update public.device_status set detector_alerted = false where id = 1;
    end if;

  end if;

  -- (d) NEW: session watcher went dark -- its own heartbeat, checked
  -- separately from the main app's, so disabling the watcher alone (leaving
  -- the main app running) is still visible.
  if d.watcher_last_heartbeat is not null
     and now() - d.watcher_last_heartbeat > interval '3 minutes'
     and not d.watcher_alerted then
    perform public.eg_send_email(
      '⚫ EyeGuard — session watcher went dark',
      format('<p><b>The account/session watcher stopped reporting.</b></p>'
          || '<p>Last seen %s ago. It may have been disabled, or the Mac may '
          || 'be off. The main app''s own detection may still be running, '
          || 'but new-account/user-switch detection is NOT while this is '
          || 'down.</p>', age(now(), d.watcher_last_heartbeat)));
    update public.device_status set watcher_alerted = true where id = 1;
  end if;

  -- (e) NEW: session watcher found a new account or the wrong active user
  if (d.watcher_new_account or d.watcher_wrong_user)
     and not d.watcher_alerted
     and d.watcher_last_heartbeat is not null
     and now() - d.watcher_last_heartbeat <= interval '3 minutes' then
    perform public.eg_send_email(
      '🚨 EyeGuard — account/session change detected',
      format('<p><b>%s</b></p><p>This may be an attempt to use the Mac '
          || 'outside the monitored account. Check in.</p>',
          case when d.watcher_new_account and d.watcher_wrong_user
                 then 'A new macOS user account was created AND the active '
                      || 'session is not the monitored account.'
               when d.watcher_new_account
                 then 'A new macOS user account was created.'
               else 'The active console session is not the monitored account.'
          end));
    update public.device_status set watcher_alerted = true where id = 1;
  elsif not (d.watcher_new_account or d.watcher_wrong_user) then
    update public.device_status set watcher_alerted = false where id = 1;
  end if;
end $$;

-- ===== 5. release_manifests: published "known-good" file hashes for the
--          packaged-app integrity check (eyeguard/integrity.py). Anon can
--          only ever READ this -- it's populated by a release script using
--          the maintainer's OWN service_role key, at build time, on a
--          machine the shipped app never touches. =====
create table if not exists public.release_manifests (
  version      text primary key,
  manifest     jsonb not null,
  published_at timestamptz not null default now()
);
alter table public.release_manifests enable row level security;
drop policy if exists "anyone reads manifests" on public.release_manifests;
create policy "anyone reads manifests" on public.release_manifests
  for select to anon using (true);
-- Deliberately no insert/update/delete policy for anon or authenticated --
-- default RLS deny handles it. Only settable via the SQL Editor or a
-- release script using service_role directly (never anon).
