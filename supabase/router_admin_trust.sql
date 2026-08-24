-- Router admin-trust pivot (2026-08-24): Jonah is getting the SSH key to the
-- router for network administration -- root shell, not just the GUI login
-- router_check_loop() was already built for (2026-08-05). SSH is a much
-- bigger jump: it can read/edit router/eyeguard-phone.py directly, and it
-- can read whatever secret file the script depends on. This is the same
-- admin-trust pivot the Mac already went through, applied to the router --
-- the router script's secret_file dependency (currently broken: the
-- leftover .supabase_secret it pointed at was already deleted as a stale
-- artifact from before this pivot) is replaced with the same anon-key +
-- server-verified-RPC model as everywhere else in this project.

-- ---- 1. phone_status: server-stamped heartbeat, no direct write path ------
-- RLS was already enabled with no insert/update policy for anon at all
-- (confirmed live: only service_role could write, via the old secret key) --
-- so this doesn't need a revoke, only the RPC that replaces the old raw
-- POST. Same principle as the Mac's eg_heartbeat(): no timestamp parameter
-- exists, so the router genuinely cannot submit one -- now() is the only
-- value that ever lands in monitor_beat/last_seen.
create or replace function public.eg_phone_heartbeat(
  p_active boolean default null
) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.phone_status
     set monitor_beat = now(),
         last_seen = case when p_active then now() else last_seen end,
         phone_active = coalesce(p_active, phone_active),
         offline_alerted = false
   where id = 1;
end $$;
revoke all on function public.eg_phone_heartbeat(boolean) from public;
grant execute on function public.eg_phone_heartbeat(boolean) to anon;

-- ---- 2. router_manifests: published "known-good" hash of the deployed
--          router script, for the SEPARATE watcher process (#3) to check
--          against -- same reasoning as the Mac's release_manifests: a
--          trust anchor stored where the entity being checked could also
--          edit it (a local file, or the script checking itself) isn't a
--          trust anchor. Kept as its own table, not reused from the Mac's
--          release_manifests, since the two devices have entirely
--          different deploy pipelines and versioning -- conflating them
--          would just be confusing, not simpler. =====
create table if not exists public.router_manifests (
  version      text primary key,
  manifest     jsonb not null,
  published_at timestamptz not null default now()
);
alter table public.router_manifests enable row level security;
drop policy if exists "anyone reads router manifests" on public.router_manifests;
create policy "anyone reads router manifests" on public.router_manifests
  for select to anon using (true);
-- No insert/update/delete policy for anon -- default RLS deny. Only
-- settable via the SQL Editor or deploy/publish_router_manifest.sh using
-- the maintainer's own service_role key, run from a machine that is never
-- the router itself.

-- ---- 3. router watcher: an INDEPENDENT process's heartbeat, separate from
--          eyeguard-phone.py -- because a check running INSIDE the process
--          being checked can be disabled by the exact same edit that
--          disables everything else (the same reasoning that made the Mac's
--          session_watcher a separate LaunchDaemon, not a thread inside the
--          main app). Reports two things: is eyeguard-phone.py's on-disk
--          script hash still what was published (script-integrity), and is
--          the eyeguard-phone.py process actually running (liveness,
--          independent of whether IT thinks it's still heartbeating). =====
alter table public.phone_status add column if not exists watcher_last_heartbeat timestamptz;
alter table public.phone_status add column if not exists watcher_script_tampered boolean not null default false;
alter table public.phone_status add column if not exists watcher_process_down boolean not null default false;
alter table public.phone_status add column if not exists watcher_alerted boolean not null default false;

create or replace function public.eg_router_watcher_heartbeat(
  p_script_tampered boolean default false,
  p_process_down boolean default false
) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.phone_status
     set watcher_last_heartbeat = now(),
         watcher_script_tampered = p_script_tampered,
         watcher_process_down = p_process_down,
         watcher_alerted = case when not (p_script_tampered or p_process_down)
                                then false else watcher_alerted end
   where id = 1;
end $$;
revoke all on function public.eg_router_watcher_heartbeat(boolean, boolean) from public;
grant execute on function public.eg_router_watcher_heartbeat(boolean, boolean) to anon;

-- eg_check_phone() gains two new branches, extending the current live
-- definition from phone.sql verbatim -- the original phone-monitor-offline
-- check is unchanged. Only the watcher branches are new.
create or replace function public.eg_check_phone() returns void
language plpgsql security definer set search_path = public as $$
declare p public.phone_status;
begin
  select * into p from public.phone_status where id = 1;
  if p.monitor_beat is null then return; end if;

  -- (a) phone monitor script itself went dark [unchanged from phone.sql]
  if now() - p.monitor_beat > interval '5 minutes' and not p.offline_alerted then
    perform public.eg_send_email('⚫ EyeGuard — phone MONITOR offline',
      format('<p><b>The phone monitor (router) stopped reporting.</b></p>'
          || '<p>Last check-in %s ago — the router script or router itself may '
          || 'be down. The phone is unmonitored until it''s back.</p>',
          age(now(), p.monitor_beat)));
    update public.phone_status set offline_alerted = true where id = 1;
  elsif now() - p.monitor_beat <= interval '5 minutes' and p.offline_alerted then
    update public.phone_status set offline_alerted = false where id = 1;
  end if;

  -- (b) NEW: router watcher itself went dark -- checked independently of
  -- the phone monitor, so disabling the watcher alone is still visible.
  if p.watcher_last_heartbeat is not null
     and now() - p.watcher_last_heartbeat > interval '10 minutes'
     and not p.watcher_alerted then
    perform public.eg_send_email('⚫ EyeGuard — router watcher offline',
      format('<p><b>The router integrity watcher stopped reporting.</b></p>'
          || '<p>Last seen %s ago. It may have been disabled -- script-'
          || 'tamper and process-liveness detection is NOT active while '
          || 'this is down.</p>', age(now(), p.watcher_last_heartbeat)));
    update public.phone_status set watcher_alerted = true where id = 1;
  end if;

  -- (c) NEW: router watcher found the script tampered or the phone monitor
  -- process not actually running
  if (p.watcher_script_tampered or p.watcher_process_down)
     and not p.watcher_alerted
     and p.watcher_last_heartbeat is not null
     and now() - p.watcher_last_heartbeat <= interval '10 minutes' then
    perform public.eg_send_email('🚨 EyeGuard — router monitor tampering detected',
      format('<p><b>%s</b></p><p>This may be an attempt to disable phone '
          || 'monitoring at the network level. Check in.</p>',
          case when p.watcher_script_tampered and p.watcher_process_down
                 then 'The phone monitor script on the router does not '
                      || 'match the published version, AND the process is '
                      || 'not currently running.'
               when p.watcher_script_tampered
                 then 'The phone monitor script on the router (eyeguard-'
                      || 'phone.py) does not match the published, known-'
                      || 'good version -- it may have been edited.'
               else 'The phone monitor process (eyeguard-phone.py) is not '
                      || 'currently running on the router.'
          end));
    update public.phone_status set watcher_alerted = true where id = 1;
  elsif not (p.watcher_script_tampered or p.watcher_process_down) then
    update public.phone_status set watcher_alerted = false where id = 1;
  end if;
end $$;
