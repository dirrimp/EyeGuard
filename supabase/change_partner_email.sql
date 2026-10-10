-- EyeGuard: change the login email of partner 2 (Jada's existing dashboard account).  2026-10-10.
--
-- WHY: Jada tried to sign in to the Partner Dashboard with jadadirrim@pm.me and got
-- "This email isn't registered for access". The dashboard never creates accounts; her account
-- already exists (partner 2, id 1818ac68-...) under a DIFFERENT email, and every access rule in
-- the system is tied to that account id. Do NOT create a new user: a new account gets a new id
-- and would see nothing and could not approve or deny apps.
--
-- WHAT THIS DOES: changes only the email on that ONE account (and its email identity) to
-- jadadirrim@pm.me, so she can sign in with the address she uses. Same account, same id, so
-- all her access is unchanged. It refuses to change anything if: the account is not found, the
-- new address already belongs to a different account, or the email is already correct.
-- Tested against a real Supabase auth server (GoTrue): the old address stops working, the new
-- one receives a magic link, and completing it logs in as the SAME account id.
--
-- ======================= DAD: BEFORE RUNNING =================================
-- 1. First run the read-only check and look at the email on the 1818ac68 row. If that is
--    already an address Jada can open, you do NOT need this file: she just types that one.
--      select id, email, last_sign_in_at from auth.users
--      where id in ('0e02aa87-1cd5-4bb6-a263-f51d4e2642b6','1818ac68-7ecf-4e39-a758-8526e496247d');
--    (0e02aa87... is YOUR account; this file never touches it.)
-- 2. If she cannot open that old inbox, run this whole file. The last table shows the result.
-- 3. Then Jada signs in at the dashboard with jadadirrim@pm.me. (If "check your email" appears
--    but no link arrives, check Supabase > Authentication > SMTP / Emails: the login email is
--    sent by Supabase Auth.)
-- =============================================================================

do $$
declare
  uid       constant uuid := '1818ac68-7ecf-4e39-a758-8526e496247d';
  new_email constant text := 'jadadirrim@pm.me';
  cur text;
begin
  select email into cur from auth.users where id = uid;
  if not found then
    raise exception 'No account with id %. Nothing was changed.', uid;
  end if;
  if lower(coalesce(cur, '')) = lower(new_email) then
    raise notice 'The account already uses %. Nothing was changed.', new_email;
    return;
  end if;
  if exists (select 1 from auth.users where lower(email) = lower(new_email) and id <> uid) then
    raise exception '% already belongs to a DIFFERENT account. Nothing was changed.', new_email;
  end if;

  update auth.users
     set email = lower(new_email),
         email_confirmed_at = coalesce(email_confirmed_at, now()),
         updated_at = now()
   where id = uid;
  update auth.identities
     set identity_data = jsonb_set(identity_data, '{email}', to_jsonb(lower(new_email))),
         updated_at = now()
   where user_id = uid and provider = 'email';
  raise notice 'Changed the login email from % to %.', cur, new_email;
end $$;

-- ---- verify (read-only). Partner 2 must show jadadirrim@pm.me; partner 1 must be unchanged. ----------
select id, email, email_confirmed_at is not null as confirmed
  from auth.users
 where id in ('0e02aa87-1cd5-4bb6-a263-f51d4e2642b6', '1818ac68-7ecf-4e39-a758-8526e496247d')
 order by id;
