-- Microscope P4b: minimal user-owned report metadata/evidence.
-- Apply with the Supabase CLI after linking the intended project.
create table if not exists public.reports (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users (id) on delete cascade,
    created_at timestamptz not null default now(),
    run_id text not null,
    source_sha256 text,
    summary jsonb not null check (jsonb_typeof(summary) = 'object'),
    tool_versions jsonb not null default '{}'::jsonb check (jsonb_typeof(tool_versions) = 'object')
);

create index if not exists reports_user_created_at_idx
    on public.reports (user_id, created_at desc);

alter table public.reports enable row level security;
revoke all on table public.reports from anon, authenticated;
grant select, insert, update, delete on table public.reports to authenticated;

drop policy if exists "Users can read their own reports" on public.reports;
create policy "Users can read their own reports"
    on public.reports for select to authenticated
    using ((select auth.uid()) = user_id);

drop policy if exists "Users can insert their own reports" on public.reports;
create policy "Users can insert their own reports"
    on public.reports for insert to authenticated
    with check ((select auth.uid()) = user_id);

drop policy if exists "Users can update their own reports" on public.reports;
create policy "Users can update their own reports"
    on public.reports for update to authenticated
    using ((select auth.uid()) = user_id)
    with check ((select auth.uid()) = user_id);

drop policy if exists "Users can delete their own reports" on public.reports;
create policy "Users can delete their own reports"
    on public.reports for delete to authenticated
    using ((select auth.uid()) = user_id);
