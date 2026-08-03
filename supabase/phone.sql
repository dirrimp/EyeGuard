-- EyeGuard phone monitoring — the DB side (run once in the SQL Editor).
-- Pairs with router/eyeguard-phone.py, which mirrors the phone's AdGuard query
-- log into the flags table and heartbeats phone_status.

-- ---- phone monitor heartbeat (separate from the Mac's device_status) -------
create table if not exists public.phone_status (
  id              int primary key default 1,
  monitor_beat    timestamptz,   -- last time the router script checked in
  last_seen       timestamptz,   -- last time the phone was active via AdGuard
  phone_active    boolean,
  offline_alerted boolean not null default false,
  constraint phone_single_row check (id = 1)
);
insert into public.phone_status (id) values (1) on conflict (id) do nothing;

alter table public.phone_status enable row level security;
drop policy if exists "partner reads phone_status" on public.phone_status;
create policy "partner reads phone_status" on public.phone_status
  for select to authenticated using (
    auth.uid() in ('0e02aa87-1cd5-4bb6-a263-f51d4e2642b6',
                   '1818ac68-7ecf-4e39-a758-8526e496247d'));
-- The router writes phone_status with the secret key (service_role bypasses RLS).

-- ---- phone-specific alert emails ------------------------------------------
-- The router pushes phone events into flags as verdict=flagged with a phone
-- reason. Give them their own email text instead of the generic one. (The 30s
-- phone-dark is enforced ROUTER-side — this just words the email.)
create or replace function public.eg_on_red() returns trigger
language plpgsql security definer set search_path = public as $$
declare loc text; whenn text; kind text;
begin
  whenn := to_char(NEW.flagged_at at time zone 'America/New_York',
                   'Mon DD, HH12:MI AM');
  if NEW.reason like 'phone-dark%' then
    perform public.eg_send_email('📵 EyeGuard — phone went dark',
      format('<p><b>The iPhone stopped routing through the monitored network.</b></p>'
          || '<p>When: %s. The VPN may be off, the phone off, or out of signal. '
          || 'If it wasn''t expected, it warrants a check-in.</p>', whenn));
    return NEW;
  end if;
  if NEW.reason like 'phone-blocked%' or NEW.reason like 'phone-signal%' then
    perform public.eg_send_email('🔴 EyeGuard — phone hit an explicit site',
      format('<p><b>%s</b></p><p>When: %s</p>'
          || '<p>Seen on the iPhone via the network monitor.</p>',
          coalesce(NEW.reason, ''), whenn));
    return NEW;
  end if;
  if NEW.app = 'EyeGuard' or NEW.reason like 'tamper:%' then
    perform public.eg_send_email('🚨 EyeGuard — tampering detected',
      format('<p><b>EyeGuard detected local tampering.</b></p>'
          || '<p><b>When:</b> %s<br><b>Detail:</b> %s</p>'
          || '<p>The cloud record is append-only and cannot be erased.</p>',
          whenn, coalesce(NEW.reason, '')));
    return NEW;
  end if;
  loc := coalesce(NEW.app, 'an app')
       || coalesce(' — ' || nullif(coalesce(NEW.url, NEW.window_title), ''), '');
  kind := case when NEW.is_nudity then 'Explicit nudity'
               else 'Very revealing content' end;
  perform public.eg_send_email('🔴 EyeGuard alert — ' || kind,
    format('<p><b>%s was flagged.</b></p><p><b>When:</b> %s<br>'
        || '<b>Where:</b> %s</p><p>The review image is on the dashboard: '
        || '<a href="https://shrimp-iord.github.io/EyeGuard/">open dashboard</a></p>',
        kind, whenn, loc));
  return NEW;
end $$;

-- ---- router-script-down alert (the 30s phone-dark is router-enforced; this
--      catches the case where the ROUTER SCRIPT itself stops reporting) -------
create or replace function public.eg_check_phone() returns void
language plpgsql security definer set search_path = public as $$
declare p public.phone_status;
begin
  select * into p from public.phone_status where id = 1;
  if p.monitor_beat is null then return; end if;
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
end $$;

select cron.unschedule('eyeguard-phone-monitor')
  where exists (select 1 from cron.job where jobname = 'eyeguard-phone-monitor');
select cron.schedule('eyeguard-phone-monitor', '* * * * *',
  $$ select public.eg_check_phone(); $$);
