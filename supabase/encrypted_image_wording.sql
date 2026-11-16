-- EyeGuard (2026-11-16): the RED alert email said "The review image is on the dashboard", but review frames
-- are encrypted before upload (since 2026-08-24, eyeguard/frame_crypto.py) and the dashboard page cannot
-- decrypt them, so every image showed a broken-image icon. The email now says what is true.
--
-- WORDING ONLY. Same rows, same recipients, same moment, same subject; eg_send_email() is NOT touched.
--
-- HOW: this does NOT rebuild eg_on_red() from a committed copy. It reads the LIVE function text, swaps ONE
-- sentence, and re-creates it, so any hand edit already in the database is kept. If the old sentence is not
-- found exactly once, it raises and changes nothing.
--
-- Run once in the SQL Editor. Safe to run again (second run: the old sentence is gone, it raises, nothing changes).

do $$
declare
  old_s constant text := 'The review image is on the dashboard: ';
  new_s constant text := 'Details are on the dashboard. The review image is encrypted and opens only on a device that holds the viewing key: ';
  d text;
  n int;
begin
  d := pg_get_functiondef('public.eg_on_red()'::regprocedure);
  n := (length(d) - length(replace(d, old_s, ''))) / length(old_s);
  if n <> 1 then
    raise exception 'expected the old sentence exactly once in eg_on_red(), found %; nothing was changed', n;
  end if;
  execute replace(d, old_s, new_s);
end $$;

-- Verify (read-only). Expect one row: true, true, true.
select
  position('Details are on the dashboard' in pg_get_functiondef('public.eg_on_red()'::regprocedure)) > 0 as has_new_wording,
  position('The review image is on the dashboard' in pg_get_functiondef('public.eg_on_red()'::regprocedure)) = 0 as old_wording_gone,
  position('explicit site on the home network' in pg_get_functiondef('public.eg_on_red()'::regprocedure)) > 0 as other_branches_intact;

-- Rollback (run only if you want the old sentence back):
-- do $$ declare d text := pg_get_functiondef('public.eg_on_red()'::regprocedure);
--   o constant text := 'Details are on the dashboard. The review image is encrypted and opens only on a device that holds the viewing key: ';
-- begin execute replace(d, o, 'The review image is on the dashboard: '); end $$;
