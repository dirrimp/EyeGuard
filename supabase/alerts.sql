-- EyeGuard alert emails via Resend (server-side, pg_net -> Resend HTTP API).
-- PREREQUISITES (do first, once):
--   1. Resend domain alerts.jjpetwasteservices.com shows "Verified".
--   2. Create a Resend API key, then store it in Supabase Vault (SQL Editor):
--        select vault.create_secret('re_YOUR_KEY_HERE', 'resend_api_key');
--      (Pasting the key into YOUR SQL editor is fine — Vault encrypts it. It
--       never goes through chat.)
--   3. Then run THIS file.
--
-- Recipients: father + spouse. From: alerts@alerts.jjpetwasteservices.com.
-- Timestamps use America/New_York (EST/EDT, DST-aware).

create extension if not exists pg_net;

-- ---- shared sender ---------------------------------------------------------
create or replace function public.eg_send_email(subject text, html text)
returns void
language plpgsql security definer set search_path = public, vault as $$
declare api_key text;
begin
  select decrypted_secret into api_key
    from vault.decrypted_secrets where name = 'resend_api_key' limit 1;
  if api_key is null then
    raise notice 'eg_send_email: no resend_api_key in Vault'; return;
  end if;
  perform net.http_post(
    url := 'https://api.resend.com/emails',
    headers := jsonb_build_object('Authorization', 'Bearer ' || api_key,
                                  'Content-Type', 'application/json'),
    body := jsonb_build_object(
      'from', 'EyeGuard <alerts@alerts.jjpetwasteservices.com>',
      'to',   jsonb_build_array('partner1@example.com', 'partner2@example.com'),  -- set your real recipients
      'subject', subject, 'html', html));
end $$;

-- ---- 🔴 RED: email the instant a revealing/nudity frame is flagged ---------
create or replace function public.eg_on_red() returns trigger
language plpgsql security definer set search_path = public as $$
declare loc text; whenn text; kind text;
begin
  loc := coalesce(NEW.app, 'an app')
       || coalesce(' — ' || nullif(coalesce(NEW.url, NEW.window_title), ''), '');
  whenn := to_char(NEW.flagged_at at time zone 'America/New_York',
                   'Mon DD, HH12:MI AM');
  kind := case when NEW.is_nudity then 'Explicit nudity' else 'Very revealing content' end;
  perform public.eg_send_email(
    '🔴 EyeGuard alert — ' || kind,
    format('<p><b>%s was flagged.</b></p><p><b>When:</b> %s<br>'
        || '<b>Where:</b> %s</p><p>The review image is on the dashboard: '
        || '<a href="https://dirrimp.github.io/EyeGuard/">open dashboard</a></p>',
        kind, whenn, loc));
  return NEW;
end $$;

drop trigger if exists eg_red_alert on public.flags;
create trigger eg_red_alert after insert on public.flags
  for each row when (NEW.verdict = 'flagged')
  execute function public.eg_on_red();

-- ---- ⚫ GONE DARK: email if no heartbeat for 3+ min (unexpected) -----------
create or replace function public.eg_check_gone_dark() returns void
language plpgsql security definer set search_path = public as $$
declare d public.device_status;
begin
  select * into d from public.device_status where id = 1;
  if d.last_heartbeat is not null and d.status = 'alive' and not d.alerted
     and now() - d.last_heartbeat > interval '3 minutes' then
    perform public.eg_send_email(
      '⚫ EyeGuard — monitoring went dark',
      format('<p><b>EyeGuard stopped reporting.</b></p>'
          || '<p>Last seen %s ago. The Mac may be off, offline, or the monitor '
          || 'was stopped. If this wasn''t expected, it warrants a check-in.</p>',
          age(now(), d.last_heartbeat)));
    update public.device_status set alerted = true where id = 1;
  end if;
end $$;

select cron.unschedule('eyeguard-gone-dark')
  where exists (select 1 from cron.job where jobname = 'eyeguard-gone-dark');
select cron.schedule('eyeguard-gone-dark', '* * * * *',
  $$ select public.eg_check_gone_dark(); $$);

-- ---- 🟡 YELLOW: once-daily digest of suggestive flags ----------------------
create or replace function public.eg_daily_digest() returns void
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  select count(*) into n from public.flags
    where verdict = 'alert' and flagged_at > now() - interval '24 hours';
  if n = 0 then return; end if;  -- nothing suggestive today, stay quiet
  perform public.eg_send_email(
    format('🟡 EyeGuard daily digest — %s suggestive', n),
    format('<p><b>%s suggestive item(s)</b> were flagged in the last 24 hours.</p>'
        || '<p>Review them on the dashboard: '
        || '<a href="https://dirrimp.github.io/EyeGuard/">open dashboard</a></p>', n));
end $$;

select cron.unschedule('eyeguard-digest')
  where exists (select 1 from cron.job where jobname = 'eyeguard-digest');
-- 12:00 UTC daily (~8am EDT / 7am EST). Adjust the hour to taste.
select cron.schedule('eyeguard-digest', '0 12 * * *',
  $$ select public.eg_daily_digest(); $$);
