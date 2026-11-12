-- Remove the broken pg_cron job eyeguard-image-retention.
--
-- supabase/phase4b_hardening.sql scheduled it as a plain
--   delete from storage.objects where bucket_id = 'frames' and created_at < now() - interval '7 days';
-- Supabase blocks that statement (storage.protect_delete: "Direct deletion from
-- storage tables is not allowed. Use the Storage API instead."), so every hourly run
-- failed and review frames older than 7 days were never purged. The purge now runs
-- through the Storage API from .github/workflows/purge-frames.yml
-- (tools/purge_frames.py).
--
-- RUN THIS ONLY AFTER the workflow has worked once (see the PR description):
-- otherwise nothing purges frames at all. Leaving the broken job in place is
-- harmless (it fails and changes nothing); it only adds noise to cron.job_run_details.
--
-- Run once in the SQL Editor. Safe to run again.
select cron.unschedule('eyeguard-image-retention')
  where exists (select 1 from cron.job where jobname = 'eyeguard-image-retention');

-- Verify: expect zero rows.
select jobid, jobname from cron.job where jobname = 'eyeguard-image-retention';

-- Rollback: none needed. (Re-creating the old job would only bring the failures back.)
