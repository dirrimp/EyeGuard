-- EyeGuard: every alert goes to BOTH partners, from ONE recipient list.  2026-10-18.
-- COVERAGE: UP (more people are told; nothing is removed).
--
-- WHY: the three sender functions each had their own hand-typed recipient list, so they drifted:
--   * eg_send_email      (Mac, Jonah's phone, router, digest, weekly)   -> Dad (+ whoever Dad typed)
--   * eg_send_email_jada (Jada's phone)                                  -> Jada only
--   * eg_send_email_mdm  (app installs / heartbeat / MDM)                -> Jada + Dad
-- so Jada never saw the "phone went dark" burst, and Dad never saw Jada's phone alerts in their own
-- wording. Jonah and Jada decided on 2026-10-18: both partners receive all alerts.
--
-- WHAT THIS DOES
--  1. eg_mail_config gets a `recipients` column (checked: a JSON array of real-looking addresses,
--     no ".invalid" placeholders). Seeded with the UNION of the addresses in the three live
--     functions, so nobody who gets mail today stops getting it. Read the result table at the end.
--  2. eg_mail_to() returns it (closed to every API role). The three functions are rewritten so ONLY
--     the recipient line changes (same pattern as central_mail_sender.sql).
--  3. eg_on_red(): rows from Jada's phone (app = Jada's iPhone) are already emailed, with correct
--     wording, by eg_on_jada_flag(). Without this, now that both lists match, each of her events
--     would arrive twice and one copy would be mislabeled "Very revealing content". eg_on_red now
--     skips ONLY those rows. Her Router/tamper rows (app = Router) and everything from Jonah's
--     devices are untouched.
--
-- To change who gets alerts later (one place, Dad only):
--    update public.eg_mail_config set recipients = jsonb_build_array('a@x.com','b@y.com'), changed_at = now() where id = 1;
-- Safe to re-run. It STOPS without changing anything if it cannot read the live recipient lists,
-- or if eg_mail_config (central_mail_sender.sql) is not installed yet.

alter table public.eg_mail_config add column if not exists recipients jsonb;

create or replace function public.eg_recipients_ok(r jsonb) returns boolean
language sql immutable as $$
  select r is not null and jsonb_typeof(r) = 'array' and jsonb_array_length(r) between 1 and 10
     and not exists (select 1 from jsonb_array_elements_text(r) e
                      where e !~* '^[^@[:space:]<>]+@[^@[:space:]<>]+\.[a-z]{2,}$' or e ilike '%.invalid')
$$;
do $$ begin
  alter table public.eg_mail_config
    add constraint eg_mail_config_recipients_ok check (recipients is null or public.eg_recipients_ok(recipients));
exception when duplicate_object then null; end $$;

do $$
declare
  fns text[] := array['public.eg_send_email(text,text)', 'public.eg_send_email_jada(text,text)',
                      'public.eg_send_email_mdm(text,text)'];
  f text; fn regprocedure; def text; newdef text; blk text; tok text;
  found text[] := '{}'; merged jsonb; changed int := 0;
begin
  if not exists (select 1 from information_schema.tables where table_schema = 'public' and table_name = 'eg_mail_config') then
    raise exception 'eg_mail_config is missing: run central_mail_sender.sql first; nothing was changed.';
  end if;
  if not exists (select 1 from public.eg_mail_config where id = 1) then
    raise exception 'eg_mail_config has no row; run central_mail_sender.sql first; nothing was changed.';
  end if;

  if (select recipients from public.eg_mail_config where id = 1) is null then
    foreach f in array fns loop
      begin fn := f::regprocedure; exception when undefined_function or undefined_object then continue; end;
      def := pg_get_functiondef(fn);
      blk := coalesce(substring(def from $re$'to',\s*jsonb_build_array\(([^)]*)\)$re$),
                      substring(def from $re$recipients\s+jsonb\s*:=\s*jsonb_build_array\(([^;]*?)\);$re$));
      if blk is null then continue; end if;
      for tok in select m[1] from regexp_matches(regexp_replace(blk, '--[^\n]*', '', 'g'), '''([^'']+)''', 'g') as m loop
        if tok ~* '^[^@[:space:]<>]+@[^@[:space:]<>]+\.[a-z]{2,}$' and tok not ilike '%.invalid'
           and not (lower(tok) = any (select lower(x) from unnest(found) x)) then
          found := found || tok;
        end if;
      end loop;
    end loop;
    if coalesce(array_length(found, 1), 0) = 0 then
      raise exception 'Could not read any recipient from the live sender functions; nothing was changed.';
    end if;
    merged := to_jsonb(found);
    update public.eg_mail_config set recipients = merged, changed_at = now() where id = 1;
    raise notice 'recipients recorded in eg_mail_config: %', merged;
  end if;
  if (select recipients from public.eg_mail_config where id = 1) is null then
    raise exception 'recipients still empty; nothing was changed.';
  end if;

  create or replace function public.eg_mail_to() returns jsonb
    language sql stable security definer set search_path = public as
    $f$ select recipients from public.eg_mail_config where id = 1 $f$;
  revoke execute on function public.eg_mail_to() from public, anon, authenticated, service_role;

  foreach f in array fns loop
    begin fn := f::regprocedure; exception when undefined_function or undefined_object then
      raise notice '% is not installed; skipped', f; continue; end;
    def := pg_get_functiondef(fn);
    if def like '%eg_mail_to()%' then
      raise notice '% already uses eg_mail_to()', f; continue;
    end if;
    newdef := regexp_replace(def, $re$'to',\s*jsonb_build_array\([^)]*\)$re$, $r$'to', public.eg_mail_to()$r$);
    if newdef = def then
      newdef := regexp_replace(def, $re$recipients\s+jsonb\s*:=\s*jsonb_build_array\([^;]*?\);$re$,
                               $r$recipients jsonb := public.eg_mail_to();$r$);
    end if;
    if newdef = def then raise exception '% has no recipient line I can safely rewrite; nothing was changed.', f; end if;
    execute newdef;
    changed := changed + 1;
    raise notice '% now takes its recipients from eg_mail_to()', f;
  end loop;
  raise notice 'functions changed: %', changed;
end $$;

-- ---- eg_on_red(): do not double-send (or mislabel) Jada's own-phone events -------------------
do $$
declare def text; newdef text; fn regprocedure;
begin
  begin fn := 'public.eg_on_red()'::regprocedure;
  exception when undefined_function then raise exception 'eg_on_red() not found; nothing was changed.'; end;
  def := pg_get_functiondef(fn);
  if def like '%Jada''''s iPhone%' then
    raise notice 'eg_on_red() already skips Jada''s phone rows'; return;
  end if;
  newdef := regexp_replace(def, E'\nbegin\n',
    E'\nbegin\n  -- Jada''s phone rows are emailed, correctly worded, to both partners by eg_on_jada_flag().\n'
    || E'  if NEW.app = ''Jada''''s iPhone'' then return NEW; end if;\n', '');
  if newdef = def then raise exception 'eg_on_red() has no begin line I can safely patch; nothing was changed.'; end if;
  execute newdef;
  raise notice 'eg_on_red() now leaves Jada''s phone rows to eg_on_jada_flag()';
end $$;

-- ---- verify (read-only) -----------------------------------------------------------------------
select p.proname as function,
       case when pg_get_functiondef(p.oid) like '%eg_mail_to()%' then 'eg_mail_to()  (central)'
            else 'STILL HAND-TYPED' end as recipient_source
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public' and p.proname in ('eg_send_email', 'eg_send_email_mdm', 'eg_send_email_jada')
union all
select 'RECIPIENTS (read these)', (select recipients::text from public.eg_mail_config where id = 1)
union all
select 'eg_on_red skips Jada phone rows', (pg_get_functiondef('public.eg_on_red()'::regprocedure) like '%Jada''''s iPhone%')::text
 order by 1;
