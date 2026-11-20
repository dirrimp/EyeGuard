-- EyeGuard: every alert email says WHICH device it is about.  2026-11-19.  Run by Dad.
--
-- WHY: the emails say "the iPhone", "EyeGuard stopped reporting", "the monitor"... and you cannot tell
-- Jonah's Mac from Jonah's phone, Jada's phone or the TV without reading the whole body.
--
-- WHAT THIS DOES (wording only; it never decides whether an email is sent, to whom, or when):
--   * The subject gets a tag right after "EyeGuard", e.g.  "... EyeGuard [Jonah's Mac] - monitoring went dark".
--   * The body gets a first line "Source: Jonah's Mac".
--   * Sources: Jonah's Mac, Jonah's Phone, Jada's Phone, TV, plus Router / Home network / Home server (G11) / All devices
--     for emails that are not about one of those four. If nothing matches, the email says "Source: not identified"
--     (and still sends); tests fail the repo if any known subject falls there.
--   * How: the three live sender functions are RENAMED to eg_send_email_raw / eg_send_email_jada_raw /
--     eg_send_email_mdm_raw (their bodies, recipients, sender and privileges are untouched), and three thin
--     wrappers take the old names, so every caller (all the alert functions and triggers) is labelled without any of
--     them being edited. If labelling ever errors, the wrapper sends the ORIGINAL unlabelled email.
--   * Each wrapper also calls eg_email_adjust(), a wording hook that does nothing today (see below).
--   * The wrappers do NOT call Resend; the one sender and the recipient lists are exactly as they were.
--
-- COVERAGE: unchanged. No alert is added, removed, delayed or suppressed.
-- Safe to re-run (it stops with a message if a sender was re-created by an older SQL file after this ran).
--
-- ======================= DAD: BEFORE RUNNING =================================
-- * No placeholders. Run the whole file; the final table must be all true.
-- * Later edits: re-running an OLD file that does "create or replace function eg_send_email" would replace the wrapper
--   and silently drop the labels; run this file again and it will tell you.
-- =============================================================================

create or replace function public.eg_email_source(via text, subject text, html text) returns text
language plpgsql immutable set search_path = public as $f$
declare s text := lower(coalesce(subject, '')); h text := lower(coalesce(html, ''));
begin
  if via = 'jada' then return 'Jada''s Phone'; end if;
  if s ~ '\monn\M' or h ~ 'where:</b> onn tv' then return 'TV'; end if;
  if s ~ 'g11' then return 'Home server (G11)'; end if;
  if s ~ 'weekly summary' or s ~ 'digest' then return 'All devices'; end if;
  if s ~ 'new app on' then return 'Jonah''s Phone'; end if;
  if s ~ 'jada' then return 'Jada''s Phone'; end if;
  if s ~ 'router' then return 'Router'; end if;
  if s ~ 'home network' or s ~ 'network bypass' then return 'Home network'; end if;
  if s ~ 'phone' or s ~ 'iphone' or s ~ 'find my' or s ~ 'app list' or s ~ 'app monitoring'
     or s ~ 'app block' or s ~ 'denied app' or s ~ 'mdm' then return 'Jonah''s Phone'; end if;
  if via = 'mdm' then return 'Jonah''s Phone'; end if;
  if s ~ 'monitoring' or s ~ 'session watcher' or s ~ 'screen' or s ~ 'detection' or s ~ 'account/session'
     or s ~ 'asleep' or s ~ 'tamper' or s ~ 'auto-deployed' or s ~ 'restarted' or s ~ 'reboot'
     or s ~ 'explicit search' or s ~ 'eyeguard alert' or s ~ 'earlier gap' then return 'Jonah''s Mac'; end if;
  return null;
end $f$;
revoke execute on function public.eg_email_source(text, text, text) from public, anon, authenticated, service_role;

-- subject: tag after the first "EyeGuard" (keeps any leading emoji); body: a first "Source:" line.
create or replace function public.eg_email_label(via text, subject text, html text, out new_subject text, out new_html text)
language plpgsql immutable set search_path = public as $f$
declare lbl text := public.eg_email_source(via, subject, html); tag text;
begin
  if lbl is null then lbl := 'not identified'; end if;
  tag := '[' || lbl || ']';
  if subject like '%EyeGuard%' then new_subject := regexp_replace(subject, 'EyeGuard', 'EyeGuard ' || tag);
  else new_subject := tag || ' ' || subject; end if;
  new_html := '<p><b>Source: ' || lbl || '</b></p>' || html;
end $f$;
revoke execute on function public.eg_email_label(text, text, text) from public, anon, authenticated, service_role;

-- wording hook: returns its input unchanged. A later, separately reviewed SQL file may replace it (for example to say
-- "Phone dead" when the phone's battery was nearly empty); it can only change the subject and body text.
create or replace function public.eg_email_adjust(via text, subject text, html text, out new_subject text, out new_html text)
language plpgsql stable set search_path = public as $f$
begin
  new_subject := subject; new_html := html;
end $f$;
revoke execute on function public.eg_email_adjust(text, text, text) from public, anon, authenticated, service_role;

do $do$
declare
  names text[] := array['eg_send_email', 'eg_send_email_jada', 'eg_send_email_mdm'];
  vias  text[] := array['main', 'jada', 'mdm'];
  i int; n text; v text; live_def text; done boolean;
begin
  for i in 1 .. 3 loop
    n := names[i]; v := vias[i];
    begin
      live_def := pg_get_functiondef(('public.' || n || '(text,text)')::regprocedure);
    exception when undefined_function or undefined_object then
      raise notice '% is not installed; skipped', n; continue;
    end;
    done := live_def like '%eg_email_label(%';
    if done then
      raise notice '% is already the labelling wrapper', n;
    else
      if to_regprocedure('public.' || n || '_raw(text,text)') is not null then
        raise exception '% exists but the live % is not the wrapper (an older SQL file re-created the sender). Stop: tell Jonah; nothing was changed for this sender.', n || '_raw', n;
      end if;
      execute format('alter function public.%I(text,text) rename to %I', n, n || '_raw');
      execute format($w$
        create function public.%1$I(subject text, html text) returns void
        language plpgsql security definer set search_path = public as $b$
        declare ns text; nh text; as2 text; ah2 text;
        begin
          begin
            select l.new_subject, l.new_html into ns, nh from public.eg_email_label(%2$L, subject, html) l;
            begin   -- optional wording hook (identity today); a failure here keeps the labelled email
              select a.new_subject, a.new_html into as2, ah2 from public.eg_email_adjust(%2$L, ns, nh) a;
              ns := coalesce(as2, ns); nh := coalesce(ah2, nh);
            exception when others then
              raise warning '%1$s: eg_email_adjust failed (%%), sending the labelled email: %%', %1$L, sqlerrm;
            end;
          exception when others then
            raise warning '%1$s: labelling failed (%%), sending the original: %%', %1$L, sqlerrm;
            ns := subject; nh := html;
          end;
          perform public.%3$I(coalesce(ns, subject), coalesce(nh, html));
        end $b$;
      $w$, n, v, n || '_raw');
      execute format('revoke execute on function public.%I(text,text) from public, anon, authenticated, service_role', n);
      raise notice '% is now the labelling wrapper', n;
    end if;
  end loop;
end $do$;

-- verify (read-only). Expect every column true.
select
  (select pg_get_functiondef('public.eg_send_email(text,text)'::regprocedure) like '%eg_email_label(%')       as main_is_wrapper,
  (select pg_get_functiondef('public.eg_send_email_jada(text,text)'::regprocedure) like '%eg_email_label(%')  as jada_is_wrapper,
  (select pg_get_functiondef('public.eg_send_email_mdm(text,text)'::regprocedure) like '%eg_email_label(%')   as mdm_is_wrapper,
  (select pg_get_functiondef('public.eg_send_email_raw(text,text)'::regprocedure) like '%net.http_post%')     as raw_still_sends,
  not has_function_privilege('anon', 'public.eg_send_email(text,text)', 'execute')                            as main_locked,
  not has_function_privilege('anon', 'public.eg_send_email_raw(text,text)', 'execute')                        as raw_locked,
  not has_function_privilege('anon', 'public.eg_email_source(text,text,text)', 'execute')                     as source_locked,
  public.eg_email_source('main', 'EyeGuard - monitoring went dark', '') = 'Jonah''s Mac'                      as sample_ok;

-- ROLLBACK (by hand, Dad): for each of the three:
--   drop function public.eg_send_email(text,text);  alter function public.eg_send_email_raw(text,text) rename to eg_send_email;
--   (same for eg_send_email_jada / eg_send_email_mdm), then optionally drop public.eg_email_label and public.eg_email_source.
