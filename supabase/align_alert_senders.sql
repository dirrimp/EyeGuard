-- EyeGuard: make the MDM and Jada-phone alert emails use the SAME sender as the live
-- eg_send_email().  2026-10-09.
--
-- WHY: Resend refuses to send from a domain that is not verified in the account
-- ("The orthanc.me domain is not verified", HTTP 403). eg_send_email_mdm() (PR #113) and
-- eg_send_email_jada() were written with 'EyeGuard <alerts@orthanc.me>' (the sender planned in
-- switch_sender_to_orthanc.sql) instead of the sender the live system actually sends from, so
-- every MDM alert (new app, unreachable, re-enrolled, all-clears) and every Jada-phone alert
-- has been rejected. That file's own header warns about exactly this hazard.
--
-- WHAT THIS DOES (nothing is guessed):
--   1. Reads the sender from the LIVE eg_send_email() (the one that already works for the
--      Mac alerts, whatever Dad has it set to).
--   2. Rewrites ONLY the 'from' value inside eg_send_email_mdm() and eg_send_email_jada()
--      to match. Everything else in those functions is kept exactly as Dad has them:
--      recipient lists, security definer, search_path, and privileges (it uses
--      pg_get_functiondef + create or replace, which preserves them).
--   3. Does nothing to a function that already matches, skips a function that is not
--      installed, and stops with a clear message (changing nothing) if the live sender
--      cannot be read.
--   Safe to re-run.
--
-- ======================= DAD: BEFORE RUNNING =================================
-- * NO placeholders. Run the whole file, then read the result table at the bottom:
--   all three functions must show the SAME sender.
-- * If the live sender ITSELF is the unverified orthanc.me one (meaning
--   switch_sender_to_orthanc.sql was run early), this file cannot help: every alert is
--   failing. Verify orthanc.me in Resend (DNS lives at deSEC; Jonah adds the records) or
--   revert eg_send_email() to its previous sender, then re-run this file.
-- * Afterwards confirm with:  select id, status_code, left(content::text,120)
--                             from net._http_response order by id desc limit 5;
--   (200 = accepted by Resend).
-- =============================================================================

do $$
declare
  live_from text; def text; cur_from text; newdef text; f text; fn regprocedure; fixed int := 0;
  fns text[] := array['public.eg_send_email_mdm(text,text)', 'public.eg_send_email_jada(text,text)'];
begin
  begin
    def := pg_get_functiondef('public.eg_send_email(text,text)'::regprocedure);
  exception when undefined_function or undefined_object then
    raise exception 'The live eg_send_email(text,text) was not found; nothing was changed.';
  end;
  live_from := substring(def from $re$'from',\s*'([^']+)'$re$);
  if live_from is null then
    raise exception 'Could not read the sender from the live eg_send_email(); nothing was changed.';
  end if;
  if live_from ~ '[\\&]' then
    raise exception 'Unexpected characters in the live sender (%); nothing was changed.', live_from;
  end if;

  foreach f in array fns loop
    begin
      fn := f::regprocedure;
    exception when undefined_function or undefined_object then
      raise notice '% is not installed; skipped', f;
      continue;
    end;
    def := pg_get_functiondef(fn);
    cur_from := substring(def from $re$'from',\s*'([^']+)'$re$);
    if cur_from is null then
      raise notice '% has no readable sender; left alone', f;
    elsif cur_from = live_from then
      raise notice '% already uses the live sender', f;
    else
      newdef := regexp_replace(def, $re$'from',\s*'[^']+'$re$, format($f$'from', '%s'$f$, live_from));
      execute newdef;
      fixed := fixed + 1;
      raise notice '%: sender % -> %', f, cur_from, live_from;
    end if;
  end loop;
  raise notice 'functions changed: %', fixed;
end $$;

-- ---- verify (read-only). All installed rows must show the SAME sender. -----------------------
select p.proname                                                   as function,
       substring(pg_get_functiondef(p.oid) from $re$'from',\s*'([^']+)'$re$) as sender_in_use
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public'
   and p.proname in ('eg_send_email', 'eg_send_email_mdm', 'eg_send_email_jada')
 order by 1;
