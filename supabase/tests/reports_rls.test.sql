begin;
create extension if not exists pgtap with schema extensions;
select plan(11);

-- Test-only identities and seed rows; the transaction rolls back after pgTAP.
insert into auth.users (id, email) values
  ('11111111-1111-4111-8111-111111111111', 'microscope-rls-a@example.invalid'),
  ('22222222-2222-4222-8222-222222222222', 'microscope-rls-b@example.invalid');

insert into public.reports (user_id, run_id, summary) values
  ('11111111-1111-4111-8111-111111111111', 'seed-a', '{"findings":[]}'::jsonb),
  ('22222222-2222-4222-8222-222222222222', 'seed-b', '{"findings":[]}'::jsonb);

select ok(
  (select relrowsecurity from pg_class where oid = 'public.reports'::regclass),
  'RLS is enabled on reports'
);

set local request.jwt.claim.sub = '11111111-1111-4111-8111-111111111111';
set local role authenticated;
select is((select count(*)::int from public.reports), 1, 'user A sees only their own report');
select lives_ok(
  $$insert into public.reports (user_id, run_id, summary)
    values ('11111111-1111-4111-8111-111111111111', 'own-a', '{"findings":[]}'::jsonb)$$,
  'user A can insert their own report'
);
select throws_ok(
  $$insert into public.reports (user_id, run_id, summary)
    values ('22222222-2222-4222-8222-222222222222', 'spoof-a', '{"findings":[]}'::jsonb)$$,
  '42501', null, 'user A cannot insert a report for user B'
);
select lives_ok(
  $$update public.reports set run_id = 'changed-a' where run_id = 'seed-a'$$,
  'user A can update their own report'
);
select lives_ok(
  $$update public.reports set run_id = 'spoofed-b' where run_id = 'seed-b'$$,
  'user A update attempt against user B does not error'
);
select lives_ok(
  $$delete from public.reports where run_id = 'changed-a'$$,
  'user A can delete their own report'
);
select lives_ok(
  $$delete from public.reports where run_id = 'seed-b'$$,
  'user A delete attempt against user B does not error'
);

reset role;
set local request.jwt.claim.sub = '22222222-2222-4222-8222-222222222222';
set local role authenticated;
select is((select count(*)::int from public.reports), 1, 'user B sees only their own report');
select is((select count(*)::int from public.reports where run_id = 'seed-b'), 1, 'user A could not update or delete user B report');

reset role;
set local role anon;
select throws_ok(
  $$select id from public.reports$$,
  '42501', null, 'anonymous users cannot read reports'
);

reset role;
select * from finish();
rollback;
