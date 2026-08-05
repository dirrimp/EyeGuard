-- Phase 4c — the real fix for the storage evidence-deletion gap.
--
-- Discovered 2026-08-05: phase4b_hardening.sql's
--   `revoke delete, update on storage.objects from service_role`
-- does NOT actually restrict the Storage REST API — confirmed empirically
-- live (upload, then DELETE, then overwrite via PUT, all still succeeded
-- with the secret/service_role key, even AFTER that revoke was run and
-- confirmed applied). This appears to be a Supabase platform property:
-- service_role unconditionally bypasses Storage-level authorization, not
-- just RLS, regardless of the underlying table's own grants — unlike
-- /rest/v1/ table access, where a REVOKE against service_role DOES hold
-- (confirmed working for public.flags' own append-only lockdown, Phase 4).
--
-- Real fix: image uploads move OFF the secret/service_role key entirely,
-- onto the PUBLIC anon/publishable key (already embedded in the public
-- GitHub Pages dashboard + this public repo's config.yaml — its exposure
-- is by design, safe as long as RLS is correctly scoped). Storage DOES
-- enforce RLS for anon/authenticated callers. Grant INSERT-only to anon,
-- scoped to the 'frames' bucket; no UPDATE/DELETE policy exists for anon,
-- so RLS's default-deny blocks both. A per-file size cap bounds the one
-- new residual this opens (the already-public anon key could otherwise be
-- used by anyone to spam the bucket with junk uploads — a storage-quota
-- nuisance, not an evidence-tampering risk, and now capped).
--
-- Run once in the SQL Editor. Requires eyeguard/uploader.py's
-- publishable_key wiring (this PR) to actually be used by the agent.

update storage.buckets set file_size_limit = 5242880  -- 5MB/file cap
  where id = 'frames';

drop policy if exists "agent inserts frames" on storage.objects;
create policy "agent inserts frames" on storage.objects
  for insert to anon
  with check (bucket_id = 'frames');
