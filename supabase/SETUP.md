# Optional Supabase report saving (P4b)

The scanner and local JSON download work without Supabase. The application accepts `SUPABASE_URL` and
`SUPABASE_ANON_KEY` from its process environment or the ignored `.streamlit/secrets.toml` file. Use only the
publishable/anon key. Never put a secret/service-role key in the app, a local secrets file, or this repository.

## Database setup and verification

1. Install the Supabase CLI and Docker, then run `supabase start` from the repository.
2. Run `supabase test db`. The `reports_rls.test.sql` suite must pass all 11 checks, including two-user isolation
   across select, insert, update, and delete. Keep report saving disabled if any check fails.
3. Apply `migrations/20261014000000_reports.sql` to the intended Supabase project using the normal reviewed
   migration workflow. Do not put a database password or secret key in the app.
4. Configure the local app with the project URL and publishable key. Set
   `MICROSCOPE_SUPABASE_RLS_VERIFIED=1` only after the migration is applied and the RLS checks have passed for the
   database the app will use. Otherwise the UI stays in local-only mode.

The app stores only the authenticated user id, run id, source hash, tool versions, contract notices, and a reduced
finding summary after the user reviews the payload and confirms. It does not send Solidity source, generated tests,
patch contents, compiler input, or raw traces. Local artifacts remain available if sign-in or saving fails.

Authentication uses Supabase Auth password sign-in. The app keeps the short-lived access/refresh session only in the
current Streamlit session; it never uses Auth Admin or a service-role key.
