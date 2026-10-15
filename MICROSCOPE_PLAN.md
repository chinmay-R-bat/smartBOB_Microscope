# Microscope — Product Plan

**Project:** Microscope — evidence-driven Solidity security workbench  
**Hackathon track/problem:** Track C, PS-5 “Contract Under the Microscope”  
**Current builder setup:** one human supervising an AI coding editor  
**Time budget:** about 10 hours in total; phase plan, checkpoint and cut order are in `CODEX_BUILD_SPEC.md` §11  
**MVP mode:** local-first analysis, Supabase-managed auth/database, Gemini explanations only; no GitHub push

## 1. The problem

Static analyzers can identify suspicious code, but a warning alone does not demonstrate that a specific attack succeeds, nor does it prove that a proposed fix blocks the attack without breaking expected behavior. Beginners and reviewers need evidence they can inspect, not just a severity label or an AI-written explanation.

## 2. The product promise

**Microscope turns a static-analysis suspect into a testable hypothesis, attempts a bounded local attack, and tests the same attack against a proposed patch.** It reports exactly what the executed tests establish and what remains unknown.

**Tagline:** *Don’t warn. Prove. Then verify the fix.*

## 3. The core workflow

1. **Inspect:** accept a Solidity source file and run Slither to collect static-analysis facts and detector results.
2. **Form a hypothesis:** use explicit, explainable rules to produce `candidate` or `inconclusive` findings. Static analysis alone never says an exploit was proven. If a contract has no recognisable authorization guard anywhere, show a visible "no privileged variable inferred" notice instead of an empty result; this is not a clean bill of health.
3. **Attempt reproduction:** when a supported attack template fits the contract shape, generate a Foundry test and execute it against a local EVM.
4. **Try a patch:** generate a deterministic, limited-scope patch for supported cases.
5. **Verify:** rerun the same attack and a regression test against the patched source.
6. **Present evidence:** show stored facts, test outcomes, trace/replay artifacts when available, patch diff, assumptions, and limitations.

## 4. Evidence vocabulary

- `candidate`: static facts suggest a plausible issue; no exploit has been proven.
- `inconclusive`: evidence is insufficient, analysis failed, or the contract shape is unsupported.
- `reproduced`: an executed test demonstrated the specified attack outcome.
- `not_reproduced`: the attempted test did not demonstrate the outcome. This does **not** mean safe.
- `mitigated_in_test`: the same attack was blocked by the patch and the required regression test passed.
- `regression_failure`: the attack still worked or the required regression test failed.

Only real tool/test output may set an execution-based state. A missing trace must be shown as missing; never synthesize one.

## 5. MVP scope

### Included

- Solidity 0.8.x, primarily single-file or small contracts that can be compiled locally.
- Two issue families only: access-control mistakes and ETH reentrancy.
- Slither facts/detectors, rule-based hypotheses, supported Foundry attack templates, deterministic template patches, repeat attack/regression tests, local JSON/Markdown evidence artifacts, and a small Streamlit UI.
- Supabase Auth for sign-in and Supabase Postgres for user-owned report metadata/evidence. Apply Row Level Security (RLS) so users can access only their own saved reports.
- Source code is analysed locally and is not saved to Supabase by default. Saving a report must not silently upload the original source.
- Gemini is optional and explanation-only, exposed as a single "Explain finding" button with a fixed error state if the call fails. It receives a minimal, sanitized finding/evidence summary—not the full source by default—and cannot create findings, change statuses, generate proof, or decide whether a patch worked.
- Demonstration fixtures must be visibly labelled as fixtures.
- A small illustrative benchmark (6 contracts planned, 4 minimum) only if the earlier phases are working and the time budget allows it, plus one human-supplied unseen demo contract that is not one of the fixtures.

### Not included in this MVP

- Hosted/cloud contract analysis, GitHub import, network RPC, or any mainnet interaction. Supabase is used for authentication and report persistence, not for running Slither/Foundry remotely.
- LLM-based vulnerability decisions or automatic execution of generated commands.
- Additional vulnerability classes, broad fuzzing, multi-chain/Vyper/proxy support, CI/SARIF, or a complex contract graph.
- Any promise to find all vulnerabilities or guarantee that a contract is safe.

## 6. Product principles

1. Evidence before explanation.
2. Unknown remains unknown.
3. Slither warnings are clues, not verdicts.
4. The same attack test is used before and after a patch.
5. Every unsupported shape has a visible reason instead of a guessed answer.
6. The interface renders stored artifacts; it must not fabricate progress, findings, or traces.
7. Supabase stores user-owned reports and minimal metadata, not source by default; enforce RLS.
8. Gemini explanations are optional, clearly labelled, evidence-grounded, and never authoritative.
9. Minimize scope to deliver one reliable end-to-end path.

## 7. Demo success criteria

A successful demo should show at least one supported vulnerability moving through the evidence chain: static candidate → actual reproduction → patch diff → same attack blocked → regression passes. If a phase cannot reliably deliver that chain, follow the cut order in `CODEX_BUILD_SPEC.md` §11 and state the limitation honestly.

Additional criteria:

- **Checkpoint at about 6 hours:** the chain above works end to end for at least one contract before any Supabase or Gemini work starts.
- **Unseen contract:** one contract that is not a fixture is run live; its result is shown as it comes out (a visible `inconclusive` is acceptable, a faked success is not).
- **Backup:** a real recorded run of the tool exists in case the live environment fails.

## 8. Cut order if time runs short

1. Gemini explanation button. 2. Benchmark shrinks to the 4-contract minimum. 3. Supabase, all or nothing: no saved reports without a passing two-user RLS test. The evidence pipeline and local demo are never cut.
