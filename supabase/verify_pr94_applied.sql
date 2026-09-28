-- Read-only check: was PR #94 ("Retire the flaky phone-unlock escalation;
-- rely on router + Find My only", supabase/drop_phone_unlock_escalation.sql)
-- actually run against this database? Dad asked (2026-09-28) -- he wasn't
-- sure.
--
-- No writes. Safe to run any time, as many times as you like.
--
-- NOTE for whoever reads this next: PR #94 did not DROP any function or
-- trigger -- it REDEFINED two existing ones (eg_check_phone, eg_on_red) to
-- remove a branch and a code path. So "does the function still exist" is
-- the wrong question here; "does it still contain the OLD, pre-#94 code"
-- is the right one. That's what this checks.
--
-- HOW TO READ THE RESULT:
--   Two rows expected, one per function. `pr_94_applied` must be `true` for
--   BOTH. If either is `false`, or a row is missing entirely (the function
--   doesn't exist under that name -- shouldn't happen, but would also mean
--   something's wrong), PR #94's SQL has not been fully applied and
--   supabase/drop_phone_unlock_escalation.sql needs to be run.

select
  proname,
  case proname
    when 'eg_check_phone' then
      -- PR #94 removed branch (d), the ONLY code that ever read
      -- last_unlock_at. Its absence from the function body means branch
      -- (d) is gone.
      position('last_unlock_at' in prosrc) = 0
    when 'eg_on_red' then
      -- PR #94 removed the "recently_unlocked" defer from the phone-dark
      -- branch. Its absence means that defer is gone.
      position('recently_unlocked' in prosrc) = 0
  end as pr_94_applied
from pg_proc
where pronamespace = 'public'::regnamespace
  and proname in ('eg_check_phone', 'eg_on_red');
