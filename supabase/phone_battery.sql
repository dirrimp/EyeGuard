-- EyeGuard: Jonah's phone battery, so a dead phone is reported as "Phone dead", not as a mystery.  2026-11-19.  Run by Dad.
-- Needs supabase/email_source_labels.sql run FIRST (it creates the wording hook this file replaces).
--
-- WHAT THIS DOES
--   1. phone_battery (one row): the last battery percentage the G11's device manager (MDM) read from Jonah's iPhone, and when.
--   2. eg_mdm_battery(p_token, p_pct, p_age_s): how the G11 reports it. Same device token as eg_mdm_heartbeat (mdm_auth),
--      bounds-checked, and an older reading never overwrites a newer one. Not readable or writable by the public key.
--   3. Replaces the wording hook eg_email_adjust(): when the "phone went dark" email for JONAH'S phone is about to be sent and the
--      last reading is 5% or lower and not older than 30 minutes, the email says it was most likely a dead phone:
--      subject "... [Jonah's Phone] - Phone dead (battery was N%)". The email is STILL SENT to both partners at the same moment.
--      Anything else is unchanged. A phone at 6% or more, an old or missing reading, and every other email keep their wording.
--
-- COVERAGE: unchanged. Nothing is suppressed, delayed or sent to fewer people. Honest limits: a reading is at most about 5 minutes
-- old (the poller runs every 5 minutes), so a phone that drains from 15% to 0% in between is still reported the normal way, and a
-- phone switched off at 4% on purpose is also worded as "likely died": the email says it is an inference from the last reading
-- and gives the reading and its time, so Dad can judge.
--
-- ======================= DAD: BEFORE RUNNING =================================
-- * Run supabase/email_source_labels.sql first (its verify row must be all true).
-- * No placeholders. Run the whole file; the final table must be all true.
-- =============================================================================

create table if not exists public.phone_battery (
  id          int primary key default 1 check (id = 1),
  pct         int not null check (pct between 0 and 100),
  read_at     timestamptz not null,           -- when the phone answered (server clock minus the reported age)
  reported_at timestamptz not null default now()
);
alter table public.phone_battery enable row level security;
revoke all on public.phone_battery from public, anon, authenticated, service_role;

create or replace function public.eg_mdm_battery(p_token text, p_pct int, p_age_s int default 0)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare r timestamptz;
begin
  if p_token is null or length(p_token) < 32 or length(p_token) > 256
     or not exists (select 1 from public.mdm_auth
                    where token_sha256 = encode(digest(p_token, 'sha256'), 'hex')) then
    raise exception 'unauthorized' using errcode = 'PT401';
  end if;
  if p_pct is null or p_pct not between 0 and 100 or p_age_s is null or p_age_s not between 0 and 21600 then
    raise exception 'bad info' using errcode = 'PT400';
  end if;
  r := now() - make_interval(secs => p_age_s);     -- the server clock is the only clock
  insert into public.phone_battery (id, pct, read_at) values (1, p_pct, r)
  on conflict (id) do update set pct = excluded.pct, read_at = excluded.read_at, reported_at = now()
    where excluded.read_at > public.phone_battery.read_at;   -- never let an older reading replace a newer one
  return jsonb_build_object('ok', true);
end $$;
revoke execute on function public.eg_mdm_battery(text, int, int) from public, anon, authenticated, service_role;
grant execute on function public.eg_mdm_battery(text, int, int) to anon;

-- The wording hook (identity in email_source_labels.sql). Only the exact "phone went dark" email for Jonah's phone is touched.
create or replace function public.eg_email_adjust(via text, subject text, html text, out new_subject text, out new_html text)
language plpgsql stable set search_path = public as $f$
declare b public.phone_battery; mins int; at_txt text;
begin
  new_subject := subject; new_html := html;
  if via <> 'main' or subject not like '%EyeGuard [Jonah''s Phone] % phone went dark' then return; end if;
  select * into b from public.phone_battery where id = 1;
  if not found or b.pct > 5 or b.read_at < now() - interval '30 minutes' then return; end if;
  mins := greatest(0, round(extract(epoch from (now() - b.read_at)) / 60.0)::int);
  at_txt := to_char(b.read_at at time zone 'America/New_York', 'Mon DD, HH12:MI AM');
  new_subject := regexp_replace(subject, 'phone went dark$', format('Phone dead (battery was %s%%)', b.pct));
  new_html := regexp_replace(html, '^(<p><b>Source: [^<]*</b></p>)',
    format('\1<p><b>Phone dead: Jonah''s phone went dark and its battery was at %s%% when it was last read (%s, about %s minute(s) earlier).</b></p>'
        || '<p>This dark event was most likely caused by the phone running out of battery. That is an inference from the last battery reading, '
        || 'not a confirmation: a phone switched off on purpose would look the same. The normal details follow.</p>',
        b.pct, at_txt, mins));
end $f$;
revoke execute on function public.eg_email_adjust(text, text, text) from public, anon, authenticated, service_role;

-- verify (read-only). Expect every column true.
select
  has_function_privilege('anon', 'public.eg_mdm_battery(text, int, int)', 'execute')                         as battery_rpc_callable_by_anon,
  not has_table_privilege('anon', 'public.phone_battery', 'select')                                           as table_not_anon_readable,
  not has_table_privilege('authenticated', 'public.phone_battery', 'select')                                  as table_not_partner_readable,
  not has_function_privilege('anon', 'public.eg_email_adjust(text, text, text)', 'execute')                   as hook_locked,
  (select pg_get_functiondef('public.eg_email_adjust(text, text, text)'::regprocedure) like '%phone_battery%') as hook_is_battery,
  (select pg_get_functiondef('public.eg_send_email(text,text)'::regprocedure) like '%eg_email_label(%')       as wrappers_present;

-- ROLLBACK (by hand, Dad): re-run supabase/email_source_labels.sql's hook definition (the identity eg_email_adjust), e.g.
--   create or replace function public.eg_email_adjust(via text, subject text, html text, out new_subject text, out new_html text)
--   language plpgsql stable as $f$ begin new_subject := subject; new_html := html; end $f$;
-- The table and the RPC may stay.
