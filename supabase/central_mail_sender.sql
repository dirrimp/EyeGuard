-- EyeGuard: ONE place defines the alert sender, and it must be orthanc.me.  2026-10-09.
--
-- WHY: every EyeGuard email goes through exactly three SQL functions (eg_send_email for the
-- Mac/phone/digest/weekly/deploy alerts, eg_send_email_jada, eg_send_email_mdm), and each had its
-- own hand-typed 'from' address. They drifted apart (one on the old domain, two on orthanc.me),
-- and when orthanc.me was not yet verified in Resend every email was refused (HTTP 403) with no
-- one told. Typing the sender in three places made that possible.
--
-- WHAT THIS DOES:
--   1. Creates public.eg_mail_config (one row): the sender address. A CHECK constraint requires it
--      to be  Name <something@orthanc.me>  so nothing can ever be pointed at another domain by
--      accident. Seeded from the sender the LIVE eg_send_email() uses today.
--   2. Creates eg_mail_from() which returns it (not callable by any API role).
--   3. Rewrites ONLY the 'from' value inside eg_send_email, eg_send_email_jada and
--      eg_send_email_mdm to call eg_mail_from(). Everything else in those functions is kept
--      exactly as Dad has it (recipient lists, security definer, search_path, privileges).
--   To change the sender later (one place, one statement, Dad only):
--      update public.eg_mail_config set from_address = 'EyeGuard <alerts@orthanc.me>', changed_at = now() where id = 1;
--   Safe to re-run. It STOPS without changing anything if the live sender cannot be read or is
--   not an orthanc.me address.
--
-- ======================= DAD: BEFORE RUNNING =================================
-- * Run this AFTER orthanc.me shows "Verified" in Resend and a test email returns 200.
--   (It does not change the address, it only centralises it, so it is safe either way.)
-- * No placeholders. Run the whole file; the result table at the end must show the
--   eg_mail_from() call in all three functions and the one sender address.
-- =============================================================================

create table if not exists public.eg_mail_config (
  id           int primary key default 1 check (id = 1),
  from_address text not null check (from_address ~ '^[^<>@]+ <[^<>@ ]+@orthanc\.me>$'),
  changed_at   timestamptz not null default now()
);
alter table public.eg_mail_config enable row level security;
revoke all on public.eg_mail_config from public, anon, authenticated, service_role;

do $$
declare
  live_def text; live_from text; def text; newdef text; f text; fn regprocedure; fixed int := 0;
  fns text[] := array['public.eg_send_email(text,text)', 'public.eg_send_email_jada(text,text)',
                      'public.eg_send_email_mdm(text,text)'];
begin
  begin
    live_def := pg_get_functiondef('public.eg_send_email(text,text)'::regprocedure);
  exception when undefined_function or undefined_object then
    raise exception 'The live eg_send_email(text,text) was not found; nothing was changed.';
  end;

  if not exists (select 1 from public.eg_mail_config where id = 1) then
    live_from := substring(live_def from $re$'from',\s*'([^']+)'$re$);
    if live_from is null and live_def like '%eg_mail_from()%' then
      raise exception 'eg_send_email already uses eg_mail_from() but eg_mail_config is empty; set it by hand (see the header).';
    end if;
    if live_from is null then
      raise exception 'Could not read the sender from the live eg_send_email(); nothing was changed.';
    end if;
    if live_from !~ '^[^<>@]+ <[^<>@ ]+@orthanc\.me>$' then
      raise exception 'The live sender is "%", not an orthanc.me address. Verify orthanc.me in Resend and switch eg_send_email() to it first; nothing was changed.', live_from;
    end if;
    insert into public.eg_mail_config (id, from_address) values (1, live_from);
    raise notice 'sender recorded in eg_mail_config: %', live_from;
  end if;

  create or replace function public.eg_mail_from() returns text
    language sql stable security definer set search_path = public as
    $f$ select from_address from public.eg_mail_config where id = 1 $f$;
  revoke execute on function public.eg_mail_from() from public, anon, authenticated, service_role;

  foreach f in array fns loop
    begin
      fn := f::regprocedure;
    exception when undefined_function or undefined_object then
      raise notice '% is not installed; skipped', f;
      continue;
    end;
    def := pg_get_functiondef(fn);
    if def like '%eg_mail_from()%' then
      raise notice '% already uses eg_mail_from()', f;
    elsif substring(def from $re$'from',\s*'[^']+'$re$) is null then
      raise notice '% has no readable sender; left alone', f;
    else
      newdef := regexp_replace(def, $re$'from',\s*'[^']+'$re$, $r$'from', public.eg_mail_from()$r$);
      execute newdef;
      fixed := fixed + 1;
      raise notice '% now takes its sender from eg_mail_from()', f;
    end if;
  end loop;
  raise notice 'functions changed: %', fixed;
end $$;

-- ---- verify (read-only) -------------------------------------------------------------------------
select p.proname as function,
       case when pg_get_functiondef(p.oid) like '%eg_mail_from()%' then 'eg_mail_from()  (central)'
            else coalesce(substring(pg_get_functiondef(p.oid) from $re$'from',\s*'([^']+)'$re$), '?') || '  (STILL HAND-TYPED)'
       end as sender_source,
       (select from_address from public.eg_mail_config where id = 1) as central_sender
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public'
   and p.proname in ('eg_send_email', 'eg_send_email_mdm', 'eg_send_email_jada')
 order by 1;
