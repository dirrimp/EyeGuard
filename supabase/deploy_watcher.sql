-- Auto-deploy pipeline (2026-08-24): a root daemon on the monitored Mac
-- polls GitHub for main's latest commit and, when it changes, deploys it
-- immediately -- the merge into main (GitHub branch protection + Dad's PR
-- review) IS the approval; there is no second gate. This RPC exists only so
-- Dad gets an email of what just auto-deployed (same commit-list summary
-- deploy/update.sh's own confirmation prompt already showed, just surfaced
-- after the fact instead of requiring him to be at Jonah's Mac to see it).

create or replace function public.eg_report_deploy(
  p_sha text, p_summary text
) returns void
language plpgsql security definer set search_path = public as $$
begin
  perform public.eg_send_email(
    '✅ EyeGuard — auto-deployed a new version',
    format('<p><b>New commit(s) landed on main and were deployed '
        || 'automatically:</b></p><pre>%s</pre><p>Now running %s.</p>',
        p_summary, left(p_sha, 9)));
end $$;
revoke all on function public.eg_report_deploy(text, text) from public;
grant execute on function public.eg_report_deploy(text, text) to anon;
