# Microscope — Canonical Documentation

This folder is the **single active documentation set** for the current hackathon MVP. Read files in this order.

## Read order

1. `README.md` — this index and conflict rules.
2. `MICROSCOPE_PLAN.md` — what the product is and what is in/out of scope.
3. `AGENTS.md` — how the AI coding editor must work.
4. `CURRENT_STATUS.md` — verified environment, baseline results, and current phase.
5. `CODEX_BUILD_SPEC.md` — detailed technical rules, schemas, detection logic, tests, phases, and acceptance gates. This is the implementation authority for analysis and testing.
6. `SUPABASE_GEMINI_INTEGRATION.md` — exact boundaries for the database/backend and explanation-only AI integration.
7. `KNOWN_LIMITATIONS.md` — limitations already known and items that must stay visible in the UI/report.

## Rules for resolving conflicts

- Security, privacy, and evidence-correctness rules take priority.
- `CODEX_BUILD_SPEC.md` is authoritative for implementation details and acceptance criteria.
- `MICROSCOPE_PLAN.md` is authoritative for product intent and the MVP boundary, unless a more specific requirement is explicitly approved by the human.
- `CURRENT_STATUS.md` records observed reality; it is not a wish list.
- If two documents conflict, do not silently choose. Tell the human exactly which lines/requirements conflict and wait for a decision.

## Active architecture and scope

- **Local worker:** Slither, rule-based hypotheses, generated Foundry tests, local EVM execution, patching, and regression tests run locally.
- **Streamlit app:** local interface for scans, evidence, replay artifacts, patch diffs, and report download.
- **Supabase:** managed authentication and Postgres database for user-owned saved reports/metadata. It does not run contract analysis. RLS is mandatory; never expose a service-role key.
- **Gemini:** optional explanation only, after evidence exists. It cannot decide vulnerability status, produce proof, or verify a patch. Send a minimal sanitized finding summary, not full source by default.
- **Privacy:** source is not saved to Supabase by default. Saving a report must be an explicit user action and must state which report fields will be stored.

Phase P1 remains offline and local. Supabase/Gemini work must wait until the relevant approved phase; do not add cloud calls to analysis/tests just because these integrations are in the product plan.

## Time plan

About 10 hours in total, with a checkpoint at about 6:00 and a defined cut order. See `CODEX_BUILD_SPEC.md` §11. Phases: P0 audit, P1 facts/hypotheses, P2 attack runner, P3 patcher, then P4a UI, P4b Supabase, P4c Gemini, P5 mini-benchmark, P6 polish and backup.

## Working rules

- Work one phase at a time. Stop at every phase gate and wait for human approval.
- Keep all code, source contracts, secrets, and generated results local. No commits, pushes, remote changes, deployments, or uploads unless explicitly approved.
- Never invent results, traces, benchmark numbers, or successful test outcomes.
- Report elapsed time against the time box at every stop-gate.

## Revision log

- **Revision 2 (2026-10-14):** 10-hour budget and schedule; P4 split into P4a (UI), P4b (Supabase), P4c (Gemini) with a 6:00 checkpoint and hard cutoffs; explicit cut order; `no_privileged_var_inferred` contract notice and optional AC-1b; mini-benchmark (6 contracts, 4 minimum) with a freeze-first rule; one unseen demo contract; real recorded backup run; time-discipline rules. No verified results changed.
