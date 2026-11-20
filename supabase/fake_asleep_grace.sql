-- EyeGuard (2026-11-20): 3-minute grace on the "possible fake asleep signal" email.
--
-- PROBLEM (seen live 2026-11-20 08:48): Jonah opened the lid at 08:47:29. The session watcher
-- reported the real wake at 08:47:35. The main app's "alive" heartbeat had not yet landed
-- (it sends one at wake and then every 60 seconds), so for a few seconds the server saw
-- "main app says asleep, watcher says awake" and emailed Dad and Jada. The server then saw
-- status = alive, so it was a race, not a fake sleep. The check had no grace at all.
--
-- FIX: ONE extra condition in branch (f) of eg_check_gone_dark(): the watcher's confirmed wake
-- must be MORE THAN 3 MINUTES old. Heartbeats are 60 seconds apart, so a healthy Mac is back
-- to 'alive' long before that. The real case (a fake "asleep" signal while the Mac stays
-- awake) lasts much longer than 3 minutes and still alerts, up to 3 minutes later than before.
--
-- COVERAGE: this DELAYS one alert by up to 3 minutes. It is not removed, not muted, and goes to
-- the same recipients through the same sender. It needs Jonah's and Dad's approval (see the PR).
--
-- HOW (no rebuild from an old copy): eg_check_gone_dark() has been re-created 16 times, some of
-- them by patches that rewrite the live text. So this file reads the LIVE definition with
-- pg_get_functiondef(), adds the one condition, and stops with an error, changing nothing,
-- unless the exact line it expects is present exactly once. Grants are kept (create or replace).
-- Running it twice is a no-op.
--
-- ROLLBACK (paste this block instead):
--   do $$ declare def text; begin
--     def := pg_get_functiondef('public.eg_check_gone_dark()'::regprocedure);
--     def := replace(def, E'\n     and d.watcher_confirmed_awake_at < now() - interval ''3 minutes''', '');
--     execute def; end $$;

do $$
declare
  def  text;
  old_frag text := 'and d.watcher_confirmed_awake_at > d.last_heartbeat';
  new_frag text := E'and d.watcher_confirmed_awake_at > d.last_heartbeat\n     and d.watcher_confirmed_awake_at < now() - interval ''3 minutes''';
  n int;
begin
  def := pg_get_functiondef('public.eg_check_gone_dark()'::regprocedure);
  if position('d.watcher_confirmed_awake_at < now() - interval ''3 minutes''' in def) > 0 then
    raise notice 'fake_asleep_grace: already applied, nothing to do';
    return;
  end if;
  n := (length(def) - length(replace(def, old_frag, ''))) / length(old_frag);
  if n <> 1 then
    raise exception 'fake_asleep_grace: expected the line "%" exactly once in the live function, found % times. Nothing changed. Tell Jonah: the live function differs from the repo.', old_frag, n;
  end if;
  execute replace(def, old_frag, new_frag);
end $$;

-- VERIFY (one row, 3 columns; every column must be true)
select
  position('d.watcher_confirmed_awake_at < now() - interval ''3 minutes''' in pg_get_functiondef('public.eg_check_gone_dark()'::regprocedure)) > 0 as grace_present,
  position('possible fake "asleep" signal' in pg_get_functiondef('public.eg_check_gone_dark()'::regprocedure)) > 0 as alert_text_kept,
  (select prosecdef from pg_proc where oid = 'public.eg_check_gone_dark()'::regprocedure) as still_security_definer;
