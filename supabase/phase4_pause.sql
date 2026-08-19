-- Phase 4, Part 2: a partner-held password to authorize stopping EyeGuard.
--
-- The password is stored ONLY as a SHA-256 hash, in a table no API role can read
-- or write. A security-definer function checks a submitted password and returns
-- only true/false — the hash is never exposed, and the agent's key can't change
-- it. This gates the pause/uninstall scripts; any other stop trips gone-dark.
--
-- Run once in the SQL Editor, then set the hash (see the setup note in chat).

create table if not exists public.settings (
  id                  int primary key default 1,
  pause_password_hash text,
  constraint settings_single_row check (id = 1)
);
insert into public.settings (id) values (1) on conflict (id) do nothing;

alter table public.settings enable row level security;
-- No API role touches settings directly (no policies + revoke all). Only the
-- definer function below (running as postgres) can read the hash.
revoke all on public.settings from anon, authenticated, service_role;

-- Returns true iff the submitted password matches the stored hash. Never
-- reveals the hash. pgcrypto's digest() lives in the extensions schema.
create or replace function public.eg_check_pause(pw text) returns boolean
language sql security definer set search_path = public, extensions as $$
  select exists (
    select 1 from public.settings
    where id = 1
      and pause_password_hash is not null
      and pause_password_hash = encode(digest(pw, 'sha256'), 'hex'));
$$;
revoke all on function public.eg_check_pause(text) from public;
grant execute on function public.eg_check_pause(text)
  to anon, authenticated, service_role;

-- Give tamper/system events their own alert email (instead of the generic
-- "revealing content" one). A tamper row is app='EyeGuard' / reason 'tamper:%'.
create or replace function public.eg_on_red() returns trigger
language plpgsql security definer set search_path = public as $$
declare loc text; whenn text; kind text;
begin
  whenn := to_char(NEW.flagged_at at time zone 'America/New_York',
                   'Mon DD, HH12:MI AM');
  if NEW.app = 'EyeGuard' or NEW.reason like 'tamper:%' then
    perform public.eg_send_email(
      '🚨 EyeGuard — tampering detected',
      format('<p><b>EyeGuard detected local tampering.</b></p>'
          || '<p><b>When:</b> %s<br><b>Detail:</b> %s</p>'
          || '<p>The cloud record is append-only and cannot be erased. '
          || 'If this wasn''t expected, it warrants a check-in.</p>',
          whenn, coalesce(NEW.reason, '')));
    return NEW;
  end if;
  loc := coalesce(NEW.app, 'an app')
       || coalesce(' — ' || nullif(coalesce(NEW.url, NEW.window_title), ''), '');
  kind := case when NEW.is_nudity then 'Explicit nudity'
               else 'Very revealing content' end;
  perform public.eg_send_email(
    '🔴 EyeGuard alert — ' || kind,
    format('<p><b>%s was flagged.</b></p><p><b>When:</b> %s<br>'
        || '<b>Where:</b> %s</p><p>The review image is on the dashboard: '
        || '<a href="https://dirrimp.github.io/EyeGuard/">open dashboard</a></p>',
        kind, whenn, loc));
  return NEW;
end $$;
