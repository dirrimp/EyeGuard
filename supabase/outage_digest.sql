-- EyeGuard (2026-11-21): when the home network drops, send ONE email for the pile-up, not twelve.
--
-- PROBLEM: on 2026-11-20 the modem lost power. The router restarted, and over 6 minutes Dad and Jada got
-- about 12 emails: phone MONITOR offline, Jada's phone MONITOR offline, the TV STOPPED reporting (twice),
-- iPhone app monitoring STOPPED, router watcher offline, then "reporting again" / "back online" for each.
-- Those monitors all sit behind the same router, so they go quiet and come back together.
--
-- WHAT THIS DOES (REDUCES COVERAGE: it DELAYS secondary alerts by up to 10 minutes; it drops nothing)
--   Only these "a monitor went quiet" emails are involved (matched on the subject):
--     phone MONITOR offline (Jonah's and Jada's), router watcher offline, Onn TV monitor STOPPED reporting,
--     iPhone app monitoring STOPPED reporting.  Their two recovery emails ("Onn TV monitor is reporting
--     again", "iPhone app monitoring is back online") join the same pile-up.
--   1. The FIRST such alert is sent immediately, unchanged, with one added line saying that any others in
--      the next 10 minutes will arrive together at a stated time.
--   2. Any other involved email in those 10 minutes is HELD (stored in full, nothing summarised away).
--   3. When the 10 minutes are up (a job runs every minute): one held item is sent as it was; two or more are
--      sent as ONE email titled "home network" that contains every original subject, time and text.
--   Everything else is untouched and never held: Mac alerts, "phone went dark", "phone on but unmonitored",
--   explicit-content alerts, tamper alerts, all of them send at once even during a window.
--
-- SAFETY NETS (each one is tested)
--   * Fail-open: if the new gate raises for any reason, the email is sent normally, immediately.
--   * Nothing is dropped: anything still held after the window is released by the minute job, and ALSO by the
--     next email that passes through any sender (so a stopped job cannot strand an alert), and anything held
--     longer than 15 minutes goes out regardless. A failed send leaves the items held for the next try.
--   * Not callable with the public key; the tables are closed to every API role.
--
-- HOW: three wrappers from email_source_labels.sql get one extra step, patched into the LIVE text with
-- pg_get_functiondef(); the exact lines must each be present exactly once or it stops and changes nothing.
-- Requires email_source_labels.sql to be run first. Re-running is a no-op.
--
-- ROLLBACK (three statements, any order; nothing held is lost):
--   select cron.unschedule('eyeguard-outage-flush');
--   create or replace function public.eg_outage_kind(subject text) returns text language sql immutable as $$ select null::text $$;
--   select public.eg_outage_flush();
-- With the kind function returning null nothing is ever held again, so every email sends at once as before, and
-- the last statement releases anything still held. The wrappers, tables and gate may stay in place harmlessly.

create table if not exists public.outage_burst (
  id int primary key check (id = 1),
  opened_at timestamptz, window_end timestamptz, first_subject text, first_via text);
insert into public.outage_burst(id) values (1) on conflict do nothing;
create table if not exists public.outage_held (
  id bigserial primary key,
  held_at timestamptz not null default now(),
  via text not null, subject text not null, html text not null, kind text not null,
  released_at timestamptz);
alter table public.outage_burst enable row level security;
alter table public.outage_held enable row level security;
revoke all on public.outage_burst, public.outage_held from public, anon, authenticated, service_role;
revoke all on sequence public.outage_held_id_seq from public, anon, authenticated, service_role;

create or replace function public.eg_outage_kind(subject text) returns text
language sql immutable as $$
  select case
    when subject like '%phone MONITOR offline%'                          then 'down'
    when subject like '%router watcher offline%'                         then 'down'
    when subject like '%Onn TV monitor STOPPED reporting%'               then 'down'
    when subject like '%iPhone app monitoring STOPPED reporting%'        then 'down'
    when subject like '%Onn TV monitor is reporting again%'              then 'up'
    when subject like '%iPhone app monitoring is back online%'           then 'up'
    else null end
$$;

create or replace function public.eg_outage_html_esc(t text) returns text
language sql immutable as $$ select replace(replace(replace(t, '&', '&amp;'), '<', '&lt;'), '>', '&gt;') $$;

-- Releases held items once their window is over (or they are 15 minutes old). Cron calls this every minute;
-- the gate calls it too. A failed send raises, so the items stay held and the next call retries.
create or replace function public.eg_outage_flush() returns void
language plpgsql security definer set search_path = public as $$
declare b public.outage_burst; n int; rec record; body text := ''; subj text; ns text; nh text; first_t text;
begin
  select * into b from public.outage_burst where id = 1 for update;
  select count(*) into n from public.outage_held where released_at is null;
  if n = 0 then
    if b.window_end is not null and b.window_end <= now() then
      update public.outage_burst set window_end = null where id = 1;
    end if;
    return;
  end if;
  if b.window_end is not null and b.window_end > now()
     and not exists (select 1 from public.outage_held where released_at is null and held_at < now() - interval '15 minutes') then
    return;                                   -- window still open
  end if;
  first_t := to_char(b.opened_at at time zone 'America/New_York', 'HH12:MI AM');
  if n = 1 then
    select * into rec from public.outage_held where released_at is null;
    nh := rec.html || format('<p><i>This email was held until %s because it came within 10 minutes of another alert (%s), in case several monitors were affected together. Nothing else was changed.</i></p>',
                             to_char(now() at time zone 'America/New_York', 'HH12:MI AM'), public.eg_outage_html_esc(coalesce(b.first_subject, '')));
    if rec.via = 'jada' then perform public.eg_send_email_jada_raw(rec.subject, nh);
    elsif rec.via = 'mdm' then perform public.eg_send_email_mdm_raw(rec.subject, nh);
    else perform public.eg_send_email_raw(rec.subject, nh); end if;
  else
    for rec in select * from public.outage_held where released_at is null order by id loop
      body := body || format('<hr><p><b>%s</b><br>%s</p>%s',
                public.eg_outage_html_esc(rec.subject),
                to_char(rec.held_at at time zone 'America/New_York', 'HH12:MI AM'), rec.html);
    end loop;
    subj := format(E'\u26AB EyeGuard \u2014 home network: %s more monitor alerts, sent together', n);
    select l.new_subject, l.new_html into ns, nh
      from public.eg_email_label('main', subj,
        format('<p><b>%s more monitor emails came in within 10 minutes of the first one (%s: %s).</b></p>'
            || '<p>They are sent together instead of one by one, and nothing is left out: every original subject, time and text is below. '
            || 'The monitors behind the home router usually go quiet and come back together when the modem or router loses power or its internet link.</p>%s',
            n, first_t, public.eg_outage_html_esc(coalesce(b.first_subject, '')), body)) l;
    perform public.eg_send_email_raw(coalesce(ns, subj), coalesce(nh, body));
  end if;
  update public.outage_held set released_at = now() where released_at is null;
  update public.outage_burst set window_end = null where id = 1;
end $$;

create or replace function public.eg_outage_gate(via text, subject text, html text,
                                                 out action text, out new_subject text, out new_html text)
language plpgsql security definer set search_path = public as $$
declare k text; b public.outage_burst; win interval := interval '10 minutes';
begin
  action := 'send'; new_subject := subject; new_html := html;
  begin
    perform public.eg_outage_flush();         -- anything overdue goes out even if the minute job has stopped
  exception when others then
    raise warning 'eg_outage_gate: flush failed (%), continuing', sqlerrm;
  end;
  k := public.eg_outage_kind(subject);
  if k is null then return; end if;           -- not an outage-family email: never held
  select * into b from public.outage_burst where id = 1 for update;
  if b.window_end is not null and b.window_end > now() then
    insert into public.outage_held(via, subject, html, kind) values (via, subject, html, k);
    action := 'hold'; return;
  end if;
  if k = 'down' then
    update public.outage_burst set opened_at = now(), window_end = now() + win, first_subject = subject, first_via = via where id = 1;
    new_html := html || format('<p><i>If other monitors also go quiet in the next 10 minutes, they will be sent together in one email at about %s (New York time) instead of one by one. Nothing is dropped.</i></p>',
                               to_char((now() + win) at time zone 'America/New_York', 'HH12:MI AM'));
  end if;
end $$;

revoke execute on function public.eg_outage_kind(text), public.eg_outage_html_esc(text), public.eg_outage_flush(),
  public.eg_outage_gate(text,text,text) from public, anon, authenticated, service_role;

-- patch the three live wrappers
do $do$
declare
  names text[] := array['eg_send_email', 'eg_send_email_jada', 'eg_send_email_mdm'];
  vias  text[] := array['main', 'jada', 'mdm'];
  i int; n text; v text; def text; cnt int; frag text;
  f_decl text := 'declare ns text; nh text; as2 text; ah2 text;';
  r_decl text := 'declare ns text; nh text; as2 text; ah2 text; act text; gs text; gh text;';
  f_send text; r_send text;
begin
  for i in 1 .. 3 loop
    n := names[i]; v := vias[i];
    def := pg_get_functiondef(('public.' || n || '(text,text)')::regprocedure);
    if position('eg_outage_gate' in def) > 0 then
      raise notice '% already has the outage gate', n; continue;
    end if;
    if position('eg_email_label(' in def) = 0 then
      raise exception '% is not the labelling wrapper: run supabase/email_source_labels.sql first. Nothing changed.', n;
    end if;
    f_send := 'perform public.' || n || '_raw(coalesce(ns, subject), coalesce(nh, html));';
    r_send := E'begin\n    select g.action, g.new_subject, g.new_html into act, gs, gh from public.eg_outage_gate(' || quote_literal(v)
           || E', coalesce(ns, subject), coalesce(nh, html)) g;\n    if act = ''hold'' then return; end if;\n    ns := coalesce(gs, ns); nh := coalesce(gh, nh);\n'
           || E'  exception when others then\n    raise warning ''' || n || E': outage gate failed (%), sending now: %'', sqlerrm, sqlstate;\n  end;\n  ' || f_send;
    foreach frag in array array[f_decl, f_send] loop
      cnt := (length(def) - length(replace(def, frag, ''))) / length(frag);
      if cnt <> 1 then
        raise exception 'outage_digest: expected "%" exactly once in the live %, found % times. Nothing changed. Tell Jonah: the live function differs from the repo.', frag, n, cnt;
      end if;
    end loop;
    def := replace(def, f_decl, r_decl);
    def := replace(def, f_send, r_send);
    execute def;
  end loop;
end $do$;

select cron.unschedule('eyeguard-outage-flush') where exists (select 1 from cron.job where jobname = 'eyeguard-outage-flush');
select cron.schedule('eyeguard-outage-flush', '* * * * *', $$ select public.eg_outage_flush(); $$);

-- VERIFY (one row, 8 columns; every column must be true)
select
  (select pg_get_functiondef('public.eg_send_email(text,text)'::regprocedure)      like '%eg_outage_gate%')                          as main_gated,
  (select pg_get_functiondef('public.eg_send_email_jada(text,text)'::regprocedure) like '%eg_outage_gate%')                          as jada_gated,
  (select pg_get_functiondef('public.eg_send_email_mdm(text,text)'::regprocedure)  like '%eg_outage_gate%')                          as mdm_gated,
  exists (select 1 from cron.job where jobname = 'eyeguard-outage-flush')                                                           as flush_scheduled,
  not has_function_privilege('anon', 'public.eg_outage_gate(text,text,text)', 'execute')
    and not has_function_privilege('anon', 'public.eg_outage_flush()', 'execute')                                                    as functions_locked,
  not has_table_privilege('anon', 'public.outage_held', 'select') and not has_table_privilege('anon', 'public.outage_burst', 'select') as tables_closed,
  not has_function_privilege('anon', 'public.eg_send_email(text,text)', 'execute')                                                   as sender_still_locked,
  (select count(*) from public.outage_held where released_at is null) = 0                                                            as nothing_held_now;
