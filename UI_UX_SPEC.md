# Microscope Local Workbench — UI/UX Spec (P4a)

**Status:** Human-directed design, approved by the user on 2026-10-14 (“create ur own ui ux and continue if possible”).

## Design intent

Make the evidence chain easy to inspect without turning static warnings into claims of exploitability or safety. Keep the interface local-first and quiet: a dark graphite canvas, warm white text, restrained teal accents, and amber/red status colors paired with explicit status words. No score, leaderboard, animated progress, or synthetic replay.

## Information architecture

One Streamlit workbench with four sidebar destinations:

1. **Scan** — choose one built-in demo fixture or upload a `.sol` file; preserve the upload's basename safely; validate extension, UTF-8 and the 200 KB limit; run Slither and supported Foundry attack/patch checks with live stage updates from the backend; select the newly created run immediately. “Live” means actual Foundry execution in an isolated offline local EVM, never a deployed contract or blockchain transaction.
2. **Findings** — identify the selected run by timestamp, input name and source hash; show counts by actual finding status, then expandable cards with category/rule, function and source lines, a plain-language status description, evidence, assumptions, and unknown reasons. Render `contract_notes` notices verbatim and visibly. Keep detector hits in a separate technical disclosure. After a completed scan, open this view automatically and offer a direct link to attack evidence.
3. **Attack evidence** — explain that supported candidates are tested automatically during a scan; show which stages actually ran, recorded original/patched/regression outcomes, and actual `steps`/oracle fields; show explicit missing-artifact states; display a stored patch diff when available. Never invent a timeline, balances, or traces.
4. **Reports** — browse stored local runs and download a JSON evidence bundle assembled only from artifacts that exist. Exclude Solidity source. No account, cloud save, or Gemini action in P4a.

## Interaction and safety

- Built-in fixtures are labelled as demos and run with `fixture=true`; uploaded files run with `fixture=false`.
- Uploads must be `.sol` and at most 200,000 bytes. The source is held in a temporary local file only for the scan and is not copied into the report bundle.
- A single busy indicator covers the real scan operation and receives stage updates only when backend work actually starts or finishes; no percentage or fabricated substep progress. Before a run, show whether Slither, solc, and Foundry are available in the website process.
- Each new scan becomes the selected run. The run selector shows time, source basename, source digest and a unique run suffix so results from different inputs are not confused.
- Missing, malformed, or empty artifacts are distinguished. An empty findings array says “No findings were recorded for this run”; it never says “safe” or “clean.”
- Status labels preserve the stored machine status. `not_reproduced` is explicitly not a safety result; `mitigated_in_test` is qualified as limited to the executed attack and regression tests.
- Solidity source remains local. Gemini and Supabase are optional external integrations: Gemini receives only allowlisted finding fields after an explicit request; cloud report saving requires sign-in and explicit confirmation.
- When Gemini is not configured, the finding action produces a clearly labeled local evidence summary and the UI says how to enable AI. A local summary is never called AI.

## Visual and accessibility rules

- Use high-contrast dark surfaces, teal for navigation/action, amber for candidate/inconclusive, green for reproduced/mitigated outcomes, and red for failures. Every state includes a text label so color is never the only signal.
- Keep source locations and one-line summaries in the card header; put raw JSON, detector details, and tool output behind expanders.
- Use native Streamlit form controls and keyboard-operable navigation. Keep empty/error text close to the affected panel.

## P4a acceptance

- Scan demo fixture and upload flows with truthful validation, busy, completion, and error states.
- Findings view renders stored findings and notices; no status is inferred from detector names or UI logic.
- Replay view uses only stored run artifacts, including patch diff and original/patched/regression outcomes.
- Reports page downloads a local JSON bundle without Solidity source.
- Works with no cloud credentials; Supabase and Gemini remain out of scope.
