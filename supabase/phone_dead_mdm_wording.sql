-- EyeGuard (2026-11-24): the "Phone dead" battery wording also reaches the MDM "cannot reach the phone" email. Run by Dad.
--
-- SEEN: Jonah's phone ran out of battery. The only email was the MDM one, 35 minutes later, saying "The phone may be off, out of signal, or
-- its management profile may have been removed." The battery inference added in PR #187 only rewrites the quick "phone went dark" email, and
-- only when the reading is under 30 minutes old. The MDM email is sent 30+ minutes AFTER the last contact by design, so its last battery reading
-- is always at least that old and it never got the wording.
--
-- WHAT THIS CHANGES: WORDING ONLY. When the MDM "cannot reach the phone" email is about to go out, and the last battery reading was 5% or
-- lower and at most 90 minutes old, the subject gets " (battery was N%: phone likely dead)" appended and the body starts with a short
-- line giving the reading, its time, and saying it is an inference, not a confirmation. The email is still sent once, to the same
-- recipients, at the same moment, with the original text after it. Nothing is suppressed, delayed or added.
-- NOT CHANGED: the dark-email rule (still 5% and 30 minutes), every other email, every threshold, the senders.
--
-- HOW: patches the LIVE eg_email_adjust() text via pg_get_functiondef(); four exact fragments must each be present exactly once or it stops
-- with an error and changes nothing. Re-running is a no-op.
-- ROLLBACK: re-run supabase/phone_battery.sql's hook definition (the "create or replace function public.eg_email_adjust" block).

do $do$
declare
  def text; frag text; n int; i int;
  f text[] := array[
    'declare b public.phone_battery; mins int; at_txt text;',
    E'if via <> ''main'' or subject not like ''%EyeGuard [Jonah''''s Phone] % phone went dark'' then return; end if;',
    'b.read_at < now() - interval ''30 minutes'' then return; end if;',
    E'at_txt := to_char(b.read_at at time zone ''America/New_York'', ''Mon DD, HH12:MI AM'');'
  ];
  r text[] := array[
    'declare b public.phone_battery; mins int; at_txt text; is_mdm boolean;',
    E'is_mdm := via = ''mdm'' and subject like ''%EyeGuard [Jonah''''s Phone] %app monitoring cannot reach the phone'';\n  if not is_mdm and (via <> ''main'' or subject not like ''%EyeGuard [Jonah''''s Phone] % phone went dark'') then return; end if;',
    'b.read_at < now() - (case when is_mdm then interval ''90 minutes'' else interval ''30 minutes'' end) then return; end if;',
    E'at_txt := to_char(b.read_at at time zone ''America/New_York'', ''Mon DD, HH12:MI AM'');\n'
    || E'  if is_mdm then\n'
    || E'    new_subject := subject || format('' (battery was %s%%: phone likely dead)'', b.pct);\n'
    || E'    new_html := regexp_replace(html, ''^(<p><b>Source: [^<]*</b></p>)'',\n'
    || E'      format(''\\1<p><b>Phone likely dead: its battery was at %s%% when it was last read (%s, about %s minute(s) before this alert).</b></p>''\n'
    || E'          || ''<p>This is an inference from the last battery reading, not a confirmation: a phone switched off on purpose would look the same. The normal details follow.</p>'',\n'
    || E'        b.pct, at_txt, mins));\n'
    || E'    return;\n'
    || E'  end if;'
  ];
begin
  def := pg_get_functiondef('public.eg_email_adjust(text, text, text)'::regprocedure);
  if position('is_mdm' in def) > 0 then
    raise notice 'phone_dead_mdm_wording: already applied, nothing to do';
    return;
  end if;
  for i in 1 .. array_length(f, 1) loop
    frag := f[i];
    n := (length(def) - length(replace(def, frag, ''))) / length(frag);
    if n <> 1 then
      raise exception 'phone_dead_mdm_wording: expected the text "%" exactly once in the live eg_email_adjust, found % times. Nothing changed. Tell Jonah: the live function differs from the repo.', frag, n;
    end if;
  end loop;
  for i in 1 .. array_length(f, 1) loop
    def := replace(def, f[i], r[i]);
  end loop;
  execute def;
end $do$;

-- VERIFY (one row, 4 columns; every column must be true)
select
  position('is_mdm' in pg_get_functiondef('public.eg_email_adjust(text, text, text)'::regprocedure)) > 0                    as patched,
  position('phone went dark' in pg_get_functiondef('public.eg_email_adjust(text, text, text)'::regprocedure)) > 0           as dark_rule_kept,
  not has_function_privilege('anon', 'public.eg_email_adjust(text, text, text)', 'execute')                                  as hook_still_locked,
  position('phone_battery' in pg_get_functiondef('public.eg_email_adjust(text, text, text)'::regprocedure)) > 0             as still_reads_battery;
