# Microscope — Known Limitations

This is a living record. The items below include limitations already specified by the design and things the implementation must preserve. Update the status after tests expose more information; do not silently mark an item solved.

## 1. Scope limitations

- The MVP targets Solidity 0.8.x, primarily single-file or small projects.
- Only access-control mistakes and ETH reentrancy are in scope.
- Attack and patch templates support only particular contract shapes. Unsupported inputs must return `inconclusive` with a reason.
- No findings does not mean safe. `not_reproduced` means only that the selected test did not demonstrate the specified attack.
- Four reference tests and a small self-authored benchmark are illustrative, not statistically significant evidence of general accuracy.

## 2. Access-control limitations

- The current privileged-variable approach infers candidate privileged state from authorization guards actually recognized in the contract. If no recognized guard exists anywhere, an unguarded owner/admin variable may not be inferred; therefore AC-1 may produce no suspect. The tool now emits a visible `no_privileged_var_inferred` contract notice in that case (spec §6.4, test case 17); this is a notice, not proof of safety, and must not be shown as "no issues". Status: planned in P1, not yet verified by a passing test.
- Optional AC-1b (infer an owner-like variable from a constructor assignment of `msg.sender`) is a structural heuristic. If implemented it can misidentify privilege, so its suspects stay `candidate` and carry an explicit assumption.
- A recognized guard anywhere in the function’s call/modifier closure does not prove that the guard dominates every path to the sensitive state write. The current design does not perform full path-sensitive authorization proof.
- Authorization implemented through helper functions, external registries, local aliases, `tx.origin`, inline assembly, or unfamiliar patterns may be unknown/inconclusive.
- Role-mapping analysis may identify a candidate, but the first access-control attack template does not support role-mapping attacks; unsupported role templates must remain inconclusive.
- An unprotected function that sends ETH is not automatically a vulnerability. The MVP intentionally avoids treating all unprotected ETH sends as suspects.
- Slither does not directly identify the reference treasury’s unprotected owner-change function; rule-based facts are needed. `Function.is_protected()` is comparison-only and must not determine the result.

## 3. Reentrancy limitations

- The current RE-1 design focuses on ETH low-level calls using `call{value: ...}` and a state variable read before the call and written after it.
- `transfer` and `send` are excluded from the initial reentrancy detector rule; this is a documented scope limitation, not a universal security guarantee.
- Internal-call effects need careful call-graph/CFG handling. If effects cannot be resolved reliably, report unknown or inconclusive. Do not silently skip unsupported cases.
- Lock recognition is structural and may miss unusual guards or conservatively classify an unfamiliar guard as unknown.
- Assembly in the relevant closure downgrades the analysis to unknown/inconclusive.
- A static candidate does not establish an exploit. Only the generated Foundry test can establish `reproduced` under that template’s assumptions.

## 4. Tooling and execution limitations

- Compiler failures, Slither loading failures, timeouts, malformed tool output, harness errors, or missing artifacts must be visible and may force `inconclusive`.
- CLI-only Slither fallback can produce reentrancy candidates from `reentrancy-eth` detector hits, but cannot produce access-control candidates in that mode.
- Detector file paths can be unreliable when tools run from a neutral working directory; normalize/match by contract/function signature where specified in `CODEX_BUILD_SPEC.md`.
- `low-level-calls` also appears on a safe fixture. It is warning context, not an exploit result.
- The UI must show “No replay artifact” when there is no stored trace. Never synthesize replay steps or balances.

## 5. Patcher limitations

- Patching is deterministic and template-based, not a general-purpose Solidity repair system.
- Only the patch shapes and privileged variable kinds specified in the build spec are supported.
- If the target function cannot be patched safely, or compilation/testing cannot complete, report the precise reason and do not claim mitigation.
- `mitigated_in_test` requires both the same attack to be blocked and the required regression test to pass.

## 6. Security and product claims

- No mainnet, RPC, deployment, network scan, or automatic execution of analyzed contract code is part of this MVP.
- Do not claim “finds all bugs,” “guarantees safety,” or “more accurate than Slither.”
- Optional LLM explanations, if ever approved later, are commentary only and cannot decide status or proof.
- Treat uploaded source as untrusted. Enforce size/type/path checks, timeouts, temporary workspaces, minimal environment, and no `shell=True` for untrusted input.

## 7. Process, demo and integration limitations

- The live demo depends on WSL2, Slither, solc and Foundry working on the demo machine. A backup is a real recorded run of the tool, never staged output.
- The unseen demo contract may fall outside the supported attack/patch shapes; the result is then `inconclusive` with a visible reason, and that is shown as is.
- The planned mini-benchmark is small (6 contracts, 4 minimum), self-authored and held-out. It is illustrative, not statistically significant, and may show Microscope no better than Slither alone on some cases; report that honestly.
- Gemini depends on network, key and quota. When unavailable, the UI shows a fixed message and the evidence is unaffected. Explanations are commentary only.
- Supabase RLS is checked with two test users, not by a formal security audit. If the isolation test does not pass, saved reports are not shipped and the app runs in local-only mode.

## 8. How to maintain this file

When a limitation is fixed or narrowed, record the evidence and relevant test. Do not delete a limitation solely because code was added; first show the test that demonstrates the change.
