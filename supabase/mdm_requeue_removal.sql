-- EyeGuard: keep removing a DENIED app until it is actually gone (supersedes eg_mdm_sync from mdm_approvals.sql).
--
-- Why (2026-10-18): Duolingo was denied and then could neither be opened (block profile) nor deleted. The
-- removal was queued only at the moment of denial and closed as "done" on the phone's first Acknowledged, so a
-- no-op acknowledgement ended enforcement while the app stayed installed. The G11 now escalates (plain
-- RemoveApplication, then take management of the app, then remove it; poll.py), and this file makes the server
-- keep asking while the last snapshot still shows the app.
--
-- ONLY eg_mdm_sync changes: GENERATED from the committed definition in mdm_approvals.sql with one block
-- inserted ahead of its action selection; every original line is kept (tests/test_mdm_requeue.py asserts it).
-- eg_mdm_snapshot / eg_mdm_decide / eg_mdm_action_result and every table are untouched. No alert is weakened:
-- this only adds removal attempts for apps a partner already denied.
-- If you hand-edited the live eg_mdm_sync since mdm_approvals.sql, stop and tell me first.
--
-- Run once in the Supabase SQL editor, as the project owner. Safe to re-run.

create or replace function public.eg_mdm_sync(p_token text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare acts jsonb; blocked jsonb;
begin
  if p_token is null or length(p_token) < 32 or length(p_token) > 256
     or not exists (select 1 from public.mdm_auth
                    where token_sha256 = encode(digest(p_token, 'sha256'), 'hex')) then
    raise exception 'unauthorized' using errcode = 'PT401';
  end if;
  -- NEW (2026-10-18): enforcement did not stop at the first answer. A removal was queued ONLY at the moment a
  -- partner denied the app, and one phone "Acknowledged" closed it as done even when the app stayed installed
  -- (the user could neither open nor delete it, and the daily reminder nagged forever). So: a denied app that the
  -- last snapshot still shows as installed gets a fresh removal, unless one is already in flight, one ran in the
  -- last hour (give the next snapshot time to show it gone), one FAILED in the last 24 h (that already emailed
  -- the partners), or 8 have been made in 24 h. The G11 escalates the method on its own; the server only asks.
  insert into public.mdm_actions (bundle_id, action)
  select a.bundle_id, 'remove'
    from public.mdm_apps a
   where a.status = 'denied' and a.present
     and not exists (select 1 from public.mdm_actions x
                      where x.bundle_id = a.bundle_id and x.status in ('queued','sent'))
     and not exists (select 1 from public.mdm_actions x
                      where x.bundle_id = a.bundle_id and x.updated_at > now() - interval '1 hour')
     and not exists (select 1 from public.mdm_actions x
                      where x.bundle_id = a.bundle_id and x.status = 'failed'
                        and x.updated_at > now() - interval '24 hours')
     and (select count(*) from public.mdm_actions x
           where x.bundle_id = a.bundle_id and x.created_at > now() - interval '24 hours') < 8;
  with u as (
    update public.mdm_actions set status = 'sent', attempts = attempts + 1, updated_at = now()
     where id in (select id from public.mdm_actions
                   where attempts < 3
                     and (status = 'queued' or (status = 'sent' and updated_at < now() - interval '30 minutes'))
                   order by id limit 50)
    returning id, bundle_id, action)
  select coalesce(jsonb_agg(jsonb_build_object('id', id, 'bundle_id', bundle_id, 'action', action)), '[]'::jsonb)
    into acts from u;
  select coalesce(jsonb_agg(bundle_id order by bundle_id), '[]'::jsonb)
    into blocked from public.mdm_apps where status = 'denied';
  return jsonb_build_object('blocked', blocked, 'actions', acts);
end $$;
revoke execute on function public.eg_mdm_sync(text) from public, anon, authenticated, service_role;
grant execute on function public.eg_mdm_sync(text) to anon;

-- verify (expect: t, f, f)
select
  has_function_privilege('anon', 'public.eg_mdm_sync(text)', 'execute')          as anon_can_sync_with_token,
  has_function_privilege('authenticated', 'public.eg_mdm_sync(text)', 'execute') as authenticated_can_call,
  has_function_privilege('service_role', 'public.eg_mdm_sync(text)', 'execute')  as service_role_can_call;
