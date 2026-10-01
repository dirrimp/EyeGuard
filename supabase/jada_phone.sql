-- EyeGuard: second monitored phone (Jada's iPhone) -- the DB side. 2026-10-01.
-- Pairs with the second instance of router/eyeguard-phone.py
-- (/etc/eyeguard/phone-jada.json, service eyeguard-phone-jada).
--
-- PURELY ADDITIVE. This file creates new objects only. It does NOT touch
-- phone_status, eg_phone_heartbeat(), eg_check_phone(), eg_on_red(),
-- eg_send_email() or the eg_red_alert trigger, so nothing about Jonah's phone
-- or Mac alerting can change by running it. Safe to re-run.
--
-- Why new objects instead of extending the existing ones: phone_status is a
-- single row (check id = 1) and eg_on_red()'s phone branches read that row
-- (Find My cross-check) -- all of it is Jonah's phone. Jada's phone therefore
-- reports with its own app label ("Jada's iPhone") and its own reason prefix
-- ("jada-phone-..."), which eg_on_red()'s `like 'phone-dark%'` etc. can never
-- match, and gets its own status row, heartbeat RPC, monitor-offline check
-- and email trigger here.
--
-- What the EXISTING trigger still does with her rows (unchanged, by decision):
--   * her RED rows (explicit site / DoH / Tor, verdict = 'flagged') fall
--     through to eg_on_red()'s generic last branch, so the existing recipient
--     list also gets an email. Its subject says "Very revealing content"
--     (generic wording), but the "Where:" line reads "Jada's iPhone -- <site>".
--   * her phone-dark rows are posted with verdict = 'alert' (yellow), which the
--     existing trigger ignores (it fires on 'flagged' only). Reason: there is
--     no Find My cross-check for her phone, so a dark event is unconfirmed, and
--     the generic branch would have mailed it as "Very revealing content".
--     Her dark events are emailed by THIS file's trigger instead, debounced.
--
-- ============================ DAD: BEFORE RUNNING ===========================
-- 1. In eg_send_email_jada() below, check the two lines marked  <-- CONFIRM:
--      'from'  must be the same sender your live eg_send_email() uses today.
--      'to'    is who receives alerts about Jada's phone. jadadirrim@pm.me is
--              Jada (confirmed by Jonah 2026-10-01). Add your own address to
--              the array if you want the correctly-worded copies and her
--              phone-dark alerts (recommended).
-- 2. Get a one-line consent statement directly from Jada (see the PR).
-- ============================================================================

-- ---- 1. status row for Jada's phone (separate from phone_status) ----------
create table if not exists public.phone_status_jada (
  id                 int primary key default 1,
  monitor_beat       timestamptz,   -- last time the router instance checked in
  last_seen          timestamptz,   -- last time the phone was confirmed alive
  phone_active       boolean,
  dark_since         timestamptz,
  offline_alerted    boolean not null default false,
  last_dark_email_at timestamptz,   -- debounce for the phone-dark email
  constraint phone_jada_single_row check (id = 1)
);
insert into public.phone_status_jada (id) values (1) on conflict (id) do nothing;

alter table public.phone_status_jada enable row level security;
drop policy if exists "partner reads phone_status_jada" on public.phone_status_jada;
create policy "partner reads phone_status_jada" on public.phone_status_jada
  for select to authenticated using (
    auth.uid() in ('0e02aa87-1cd5-4bb6-a263-f51d4e2642b6',
                   '1818ac68-7ecf-4e39-a758-8526e496247d'));
-- No insert/update/delete policy: the only write path is the RPC below.

-- ---- 2. server-stamped heartbeat (mirror of eg_phone_heartbeat) -----------
create or replace function public.eg_phone_heartbeat_jada(
  p_active boolean default null
) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.phone_status_jada
     set monitor_beat = now(),
         last_seen = case when p_active then now() else last_seen end,
         phone_active = coalesce(p_active, phone_active),
         dark_since = case
           when p_active is false then coalesce(dark_since, now())
           when p_active is true then null
           else dark_since
         end,
         offline_alerted = false
   where id = 1;
end $$;
revoke all on function public.eg_phone_heartbeat_jada(boolean) from public;
grant execute on function public.eg_phone_heartbeat_jada(boolean) to anon;

-- ---- 3. sender for Jada's-phone alerts ------------------------------------
-- Own recipient list, so nothing here depends on (or can overwrite) the live,
-- hand-edited eg_send_email().
create or replace function public.eg_send_email_jada(subject text, html text)
returns void
language plpgsql security definer set search_path = public, vault as $$
declare api_key text;
begin
  select decrypted_secret into api_key
    from vault.decrypted_secrets where name = 'resend_api_key' limit 1;
  if api_key is null then
    raise notice 'eg_send_email_jada: no resend_api_key in Vault'; return;
  end if;
  perform net.http_post(
    url := 'https://api.resend.com/emails',
    headers := jsonb_build_object('Authorization', 'Bearer ' || api_key,
                                  'Content-Type', 'application/json'),
    body := jsonb_build_object(
      'from', 'EyeGuard <alerts@orthanc.me>',                 -- <-- CONFIRM
      'to',   jsonb_build_array('jadadirrim@pm.me'),          -- <-- CONFIRM
      'subject', subject, 'html', html));
end $$;
-- Supabase also grants EXECUTE to anon/authenticated directly, so `from public`
-- alone leaves this callable with the public anon key (fixed 2026-10-01).
revoke execute on function public.eg_send_email_jada(text, text)
  from public, anon, authenticated, service_role;

-- ---- 4. email on Jada's-phone events --------------------------------------
-- A second AFTER INSERT trigger on flags, restricted by WHEN to her device's
-- rows only, so it never runs for any other row. Any error inside it is
-- swallowed: an email problem must never roll back the flag row itself (the
-- append-only record matters more than the notification).
create or replace function public.eg_on_jada_flag() returns trigger
language plpgsql security definer set search_path = public as $$
declare whenn text; last_mail timestamptz;
begin
  whenn := to_char(NEW.flagged_at at time zone 'America/New_York',
                   'Mon DD, HH12:MI AM');
  if NEW.reason like 'jada-phone-dark%' then
    -- No Find My cross-check exists for this phone, so debounce instead: at
    -- most one dark email per 30 minutes. Every dark event is still recorded
    -- as its own row on the dashboard.
    select last_dark_email_at into last_mail
      from public.phone_status_jada where id = 1;
    if last_mail is not null and now() - last_mail < interval '30 minutes' then
      return NEW;
    end if;
    update public.phone_status_jada set last_dark_email_at = now() where id = 1;
    perform public.eg_send_email_jada('📵 EyeGuard — Jada''s phone went dark',
      format('<p><b>Jada''s iPhone stopped routing through the monitored network.</b></p>'
          || '<p>When: %s. The VPN may be off, the phone off, or out of signal. '
          || 'There is no Find My cross-check for this phone, so this is an '
          || 'unconfirmed dark event. Further dark events in the next 30 '
          || 'minutes are recorded on the dashboard but not emailed.</p>', whenn));
    return NEW;
  end if;
  if NEW.verdict = 'flagged' then
    perform public.eg_send_email_jada('🔴 EyeGuard — Jada''s phone hit an explicit site',
      format('<p><b>%s</b></p><p>When: %s</p>'
          || '<p>Seen on Jada''s iPhone via the network monitor.</p>',
          coalesce(NEW.reason, ''), whenn));
  end if;
  return NEW;
exception when others then
  raise warning 'eg_on_jada_flag: % (flag row kept)', sqlerrm;
  return NEW;
end $$;

drop trigger if exists eg_jada_alert on public.flags;
create trigger eg_jada_alert after insert on public.flags
  for each row when (NEW.app = 'Jada''s iPhone' and NEW.verdict in ('flagged', 'alert'))
  execute function public.eg_on_jada_flag();

-- ---- 5. monitor-offline check for her instance ----------------------------
-- Catches the router instance for Jada's phone going silent (the router
-- watcher also flags a stopped instance; this is the server-side backstop).
create or replace function public.eg_check_phone_jada() returns void
language plpgsql security definer set search_path = public as $$
declare p public.phone_status_jada;
begin
  select * into p from public.phone_status_jada where id = 1;
  if p.monitor_beat is null then return; end if;   -- never checked in yet
  if now() - p.monitor_beat > interval '5 minutes' and not p.offline_alerted then
    perform public.eg_send_email_jada('⚫ EyeGuard — Jada''s phone MONITOR offline',
      format('<p><b>The monitor for Jada''s phone (router) stopped reporting.</b></p>'
          || '<p>Last check-in %s ago. Her phone is unmonitored until it''s back.</p>',
          age(now(), p.monitor_beat)));
    update public.phone_status_jada set offline_alerted = true where id = 1;
  end if;
  -- offline_alerted is cleared by the next heartbeat (eg_phone_heartbeat_jada).
end $$;

revoke execute on function public.eg_check_phone_jada()
  from public, anon, authenticated, service_role;

select cron.unschedule('eyeguard-phone-monitor-jada')
  where exists (select 1 from cron.job where jobname = 'eyeguard-phone-monitor-jada');
select cron.schedule('eyeguard-phone-monitor-jada', '* * * * *',
  $$ select public.eg_check_phone_jada(); $$);

-- ---- 6. verify (read-only; run after the above) ---------------------------
-- Expect: one row, all three true.
select
  exists (select 1 from public.phone_status_jada where id = 1)              as status_row,
  exists (select 1 from pg_trigger where tgname = 'eg_jada_alert')          as trigger_installed,
  exists (select 1 from cron.job where jobname = 'eyeguard-phone-monitor-jada') as cron_scheduled;
