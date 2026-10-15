# Supabase + Gemini Integration Contract

This document defines the approved boundaries for the two external services. Read it with `AGENTS.md` and `CODEX_BUILD_SPEC.md`. It does not authorize implementing integrations before the corresponding phase is approved.

## 1. Responsibility split

| Component | Responsibility | Must not do |
|---|---|---|
| Local Python worker | Run Slither, build facts/hypotheses, generate supported Foundry tests, execute local EVM tests, patch and regression-test | Upload source or call Gemini to decide findings |
| Streamlit app | Local scan UX, evidence, replay, diffs, download, sign-in, explicit report save, optional explanation | Fabricate evidence or expose secrets |
| Supabase Auth | User sign-in/session | Run contract analysis |
| Supabase Postgres | Store user-owned saved report data and minimal metadata | Store original source by default or allow cross-user reads |
| Gemini | Explain already-established findings in plain language | Detect/confirm vulnerabilities, assign status, prove exploitability, or verify a patch |

## 2. Supabase requirements

- Use Supabase Auth for optional sign-in. A user must still be able to run a local scan without signing in.
- Use Postgres for a minimal `reports` table. Suggested fields: `id` (UUID), `user_id` (UUID linked to auth user), `created_at`, `run_id`, `source_sha256`, `summary` (JSONB), `report_markdown` (optional), and `tool_versions` (JSONB). Keep the schema minimal; don't add tables without a demonstrated need.
- Enable Row Level Security. Policies must ensure authenticated users can select, insert, update, and delete only rows where `user_id = auth.uid()`. Test isolation using two test users or equivalent policy tests before calling the feature complete.
- Use the Supabase publishable/anon key in the client together with the authenticated session and RLS. Never place the service-role key in Streamlit code, browser code, repository files, or `.env.example`.
- `.env` stays untracked. `.env.example` contains names/placeholders only, e.g. `SUPABASE_URL=`, `SUPABASE_ANON_KEY=`, `GEMINI_API_KEY=`.
- Do not upload source code, compiler input, generated attack tests, full traces, or patches automatically. Default saved report is structured findings/evidence and optional report Markdown only. Clearly disclose the fields before saving.
- If Supabase is not configured or unavailable, local scan, testing, report display, and local download continue. Saving/sign-in shows a useful error; local artifacts remain available.

## 3. Gemini explanation requirements

- Invoke Gemini only on explicit user action after facts/findings exist.
- Send the smallest useful payload: category, rule id, evidence strings, relevant line numbers, assumptions, unknown reasons, and actual test status. Remove secrets and unnecessary source text. Never send the whole contract by default.
- Ask for a concise explanation in plain language that distinguishes observed evidence from assumptions and explicitly says what was not proven.
- Display a persistent label: **AI-generated explanation — not proof**.
- Gemini output is display-only. It cannot change `candidate`, `inconclusive`, `reproduced`, `not_reproduced`, `mitigated_in_test`, or `regression_failure`; it cannot create detector hits, test outcomes, patch diffs, traces, or benchmark results.
- Treat the response as untrusted text. Do not execute it, treat it as instructions, or render raw HTML from it.
- If the API fails, is rate-limited, or returns unusable output, show an error and keep the evidence report usable. Gemini must never be required for core functionality.

## 4. Secrets, cost and privacy

- Keep API keys in local environment variables for the local Streamlit server; never place keys in source code or prompts. Do not print keys in logs or error messages.
- Use free tiers where practical, but do not assume quota, price, or availability without checking current provider settings.
- Make cloud calls visible and user-triggered. No background source upload, automatic explanation request, or telemetry.
- The app must not claim source was deleted remotely if it was never uploaded; accurately state which artifacts are local and which report fields were saved.

## 5. Implementation order and time boxes

1. **P1–P3:** implement and validate the evidence pipeline, attack tests and patch verification locally. No Supabase/Gemini calls.
2. **Checkpoint (about 6:00):** the evidence chain works end to end for at least one contract. Do not start Supabase or Gemini before this passes.
3. **P4a (about 1:15):** local Streamlit UI and report download, no cloud calls.
4. **P4b Supabase (about 1:00):** Auth, explicit save/open, `reports` table with RLS, two-user isolation test, local-only fallback.
5. **P4c Gemini (about 0:30):** one **Explain finding** button per finding, fixed error state.
6. **Final checks:** verify two-user report isolation, run without cloud credentials, run with Gemini unavailable, and confirm Gemini output cannot alter evidence statuses.

### Hard cutoffs and cut order

- If the evidence chain is not working by about 6:30, skip P4b and P4c entirely.
- Cut Gemini first. It is one button over already-computed evidence and nothing depends on it.
- Supabase is all or nothing: do not ship saved reports without a passing two-user RLS test. If cut, local report download stays and the UI says "local-only mode".
- Gemini failure handling: any error, quota problem or missing key shows the fixed message "Explanation unavailable — the evidence above is unaffected." The demo must never depend on Gemini or on network access.

If time runs short, preserve the evidence pipeline and local demo. A basic, tested Supabase save flow is more important than elaborate AI wording; Gemini explanation is optional and may be cut without breaking the product.
