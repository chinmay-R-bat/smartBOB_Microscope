# MICROSCOPE — Codex Build Spec (architecture, rules, phases, tests)

**Project:** Microscope — evidence-driven Solidity scanner (Track C, PS-5 "Contract Under the Microscope")
**Builder:** Codex, supervised by one human (Chinmay) · **Total budget:** ~10 hours (time plan, checkpoint and cut order in §11) · **Everything stays local (no GitHub push)**
**Companion docs:** `MICROSCOPE_PLAN.md` (product plan), `AGENTS.md` (short rules for Codex)

> Read this whole file before writing code. Work **one phase at a time**. At the end of each phase: run the tests, then stop and report using the format in §14. Do not start the next phase without the human's go-ahead.

---

## 1. What we are building (one paragraph)

Slither finds *suspects*. Our rules turn Slither facts into **hypotheses** (never verdicts). A generated **attack test** run in Foundry on a local EVM decides whether a hypothesis is **reproduced**. A **template patch** is then verified by re-running the *same* attack plus a regression test. A Streamlit page renders only stored evidence. Supabase provides authentication and report persistence; it does not run analysis. Gemini is optional, last, and explanation-only. The source contract is analysed locally and is not uploaded by default.

**Hard evidence rule:** only an executed test may produce `reproduced` / `mitigated_in_test`. Static analysis may only produce `candidate` or `inconclusive`.

---

## 2. Non-negotiable rules for Codex

1. **No decisions based on file names, contract names, function names, or variable names** from the fixtures. (`owner`, `setOwner`, `withdraw`, `onlyOwner`… must never appear as detection logic. Slither itself hardcodes `onlyOwner` — we deliberately do not trust that.) The tests in §10 enforce this by renaming everything.
2. **Preserve unknown.** If evidence is insufficient, output `unknown` / `inconclusive` with a machine-readable reason. Never round unknown to "protected" or "unprotected".
3. **No fake results.** Demo fixtures must be labelled `fixture: true` in output. UI shows only stored JSON; no stored trace ⇒ "No replay artifact".
4. **No accuracy claims** from the 4 fixtures or the 12-contract benchmark. Say "illustrative".
5. **Smallest reliable implementation.** No new frameworks, no new vulnerability classes, no extra features beyond this spec.
6. **Untrusted input:** run Slither/forge with timeouts, in a temp dir, no network, no keys, no RPC URLs. No mainnet. Keep the analysis worker offline after dependency installation.
10. **Supabase boundary:** use Supabase Auth + Postgres only for sign-in and user-owned saved reports. RLS is mandatory. Never use a service-role key in Streamlit/client code. Do not upload source by default.
11. **Gemini boundary:** explanations only, after a finding has evidence. Send minimal sanitized evidence; never send full source by default. Gemini cannot create or change findings/statuses, claim proof, or decide patch success. If Gemini is unavailable, core scanning and reporting still work.
7. **Do not modify** `src/**`, `test/Exploits.t.sol` (reference fixtures) except by explicit human request.
8. Keep `KNOWN_LIMITATIONS.md` updated whenever something is partial.
9. Pin dependencies (`pip freeze > requirements.lock.txt`). Use stdlib `dataclasses` + `enum` (avoid pydantic; Python 3.14 compat unknown).
12. **Time discipline:** report elapsed time against the §11 time box at every stop-gate. If a phase passes 1.5x its time box, stop and report instead of continuing. Never trade evidence correctness for speed; cut scope using the §11 cut order instead.

---

## 3. Verified environment facts

**Human's machine (confirmed):** Windows 11 + WSL2 Ubuntu · project at `~/microscope` · Python 3.14.4 in `.venv` · Slither 0.11.6 · Foundry (forge/anvil/cast) 1.8.5 · solc 0.8.24 (project) · `forge test` → 4/4 reference tests pass.

**Slither baseline (confirmed by human):**

| Contract | Detectors fired |
|---|---|
| VulnerableVault | `reentrancy-eth`, `low-level-calls` |
| SafeVault | `low-level-calls` only |
| VulnerableTreasury | `missing-zero-check`, `low-level-calls` — **does not flag unprotected `setOwner`** |
| SafeTreasury | `events-access`, `missing-zero-check`, `low-level-calls` |

Consequences: (a) `low-level-calls` is noise — never a reentrancy signal; (b) Slither does not detect our access-control bug class, which justifies our own privilege rule; (c) detector hits are *corroboration only*.

### 3.1 Slither 0.11.6 API — VERIFIED by probing (same version as the human's)

- `Slither(path, cwd=<neutral temp dir>, compile_force_framework="solc")` works. **Why both kwargs:** crytic-compile otherwise detects `foundry.toml`, calls `forge config`, and borrows the project's solc settings (and fails if `forge` is missing). Uploaded contracts must be analysed independent of our own project config. (Multi-file projects with remappings are out of MVP scope.)
- `sl.contracts_derived`, `c.functions_declared`, `c.state_variables_declared`, `sl.get_contract_from_name(name)[0]`, `c.get_function_from_signature("setOwner(address)")`.
- Per function: `name`, `visibility`, `payable`, `is_constructor`, `is_implemented`, `modifiers` (list of `Modifier` objects), `canonical_name` (e.g. `SafeTreasury.setOwner(address)`), `source_mapping.lines` (list of ints), `source_mapping.filename.relative`, `nodes`, `all_state_variables_written()`, `state_variables_written`, `all_internal_calls()`, `all_low_level_calls()`.
- `Modifier` has `.nodes` including a node of type `NodeType.PLACEHOLDER` (the `_;`). Modifier nodes carry the real guard: e.g. a `require` node with IR `Binary(EQUAL, msg.sender, StateVariable owner)`.
- Per node: `type`, `is_conditional(include_loop=False)`, `state_variables_read`, `state_variables_written`, `solidity_variables_read` (contains `msg.sender` as `SolidityVariableComposed`), `irs`, `sons`, `fathers`.
- IR classes (`slither.slithir.operations`): `Binary` (`.type` is `BinaryType.EQUAL` etc., `.variable_left`, `.variable_right`), `SolidityCall` (`.function.name` e.g. `require(bool,string)`), `LowLevelCall` (`.function_name == "call"`, **`.call_value` is not None for `call{value: x}`**), `InternalCall` (`.function`), `HighLevelCall`.
- State write through a mapping (`balances[msg.sender] = 0`) appears in `node.state_variables_written` as the mapping variable (`balances`). State read in `x = balances[msg.sender]` appears in `node.state_variables_read`.
- State variable canonical name: `Contract.var` (use as stable identity, e.g. `SafeTreasury.owner`).
- CLI JSON: `slither <file> --compile-force-framework solc --json out.json` → `{success, error, results:{detectors:[{check, impact, confidence, elements:[{type, name, source_mapping:{lines, filename_relative,...}, type_specific_fields:{parent, signature}}]}]}}`. **`filename_relative` is unreliable under a neutral cwd** (`../../home/...`). Match hits by `type_specific_fields.parent` (contract) + `signature`/`name`, not by path.

### 3.2 Pitfalls discovered (design around them)

1. **`Function.is_protected()` is NOT trustworthy.** It returns True if (a) any modifier is *named* `onlyOwner` regardless of its body, or (b) `msg.sender` appears in any condition **or is passed as any call argument**. So `require(balances[msg.sender] >= x)` or `token.transfer(msg.sender, x)` make a function "protected". → Store its value in facts as `slither_is_protected` for comparison only. Never use it as the verdict.
2. **`node_id` order ≠ execution order.** In `setOwner` of SafeTreasury: node 0 → son 2 → son 1. Always traverse from `function.entry_point` via `node.sons`. Never use list order or `node_id` for "before/after".
3. Modifier bodies are **separate CFGs**; function nodes don't include them. Analyse `function.modifiers[i].nodes` explicitly.
4. `low-level-calls` fires on SafeVault too. Never use it.
5. Detector JSON paths are odd under neutral cwd (see above).

### 3.3 Verify at runtime (don't assume) — write a small `scanner/api_check.py`

Run once at startup of `facts.py`; failures produce `facts.api_warnings[]` and downgrade the affected function to `unknown`, not a crash. Verify existence of: `Function.entry_point`, `Node.sons`, `Node.is_conditional`, `Node.internal_calls`, `Function.all_internal_calls`, `LowLevelCall.call_value`, `LowLevelCall.function_name`, `SolidityCall.function.name`, `Modifier.nodes`, `NodeType.PLACEHOLDER`, `Binary.type`, `Index` IR (`variable_left/right`), `StateVariable.type` (string form like `mapping(address => bool)`), `Function.contains_assembly`. Record `slither.__version__`, `solc --version`, python version in every facts file.

---

## 4. Architecture

```
upload .sol
   │
[1] scanner/facts.py        Slither API → facts.json  (fallback: CLI JSON only)
   │
[2] scanner/hypotheses.py   facts → suspects.json     (candidate | inconclusive)
   │
[3] scanner/templates/      Jinja → Foundry test (+ attacker contract)
   │
[4] scanner/runner.py       forge test (timeout) → parse logs → status
   │
[5] scanner/patcher.py      deterministic patch → compile → SAME attack → regression
   │
[6] scanner/report.py       evidence JSON + Markdown
   │
[7] app.py (Streamlit)      renders local evidence; optional Supabase auth/save; optional Gemini explanation only
```

**Repo layout (add to existing `~/microscope`):**

```
scanner/{__init__,schema,api_check,facts,hypotheses,detectors,runner,patcher,report}.py
scanner/templates/{reentrancy_attack.t.sol.j2, access_attack.t.sol.j2, *_regression.t.sol.j2}
tests/{test_facts.py, test_hypotheses.py, test_mutations.py, test_runner.py, conftest.py}
tests/cases/*.sol          # synthetic contracts for rule tests (see §10)
bench/                     # later phase
runs/<run_id>/             # local artifacts (git-ignored; source removed by default after analysis)
app.py  KNOWN_LIMITATIONS.md  README.md  requirements.lock.txt
```

**Module contracts:** each module is a pure function of its inputs + files; each writes JSON into `runs/<run_id>/`. CLI entry points: `python -m scanner.facts <file.sol>`, `python -m scanner.hypotheses <file.sol>`, `python -m scanner.run <file.sol>` (full pipeline, later).

---

## 5. Schema (`scanner/schema.py`)

```python
from dataclasses import dataclass, field, asdict
from enum import Enum

class Tri(str, Enum):           # three-valued evidence
    TRUE = "true"; FALSE = "false"; UNKNOWN = "unknown"

class Protection(str, Enum):
    PROTECTED = "protected"       # a recognised authorization guard was found
    UNPROTECTED = "unprotected"   # no recognised guard AND nothing unclassifiable
    UNKNOWN = "unknown"           # something we cannot classify (see reasons)

class Status(str, Enum):         # finding states (static layer only uses first two)
    CANDIDATE="candidate"; INCONCLUSIVE="inconclusive"
    REPRODUCED="reproduced"; NOT_REPRODUCED="not_reproduced"
    MITIGATED_IN_TEST="mitigated_in_test"; REGRESSION_FAILURE="regression_failure"

@dataclass
class SourceRef: path: str; start_line: int; end_line: int

@dataclass
class ProtectionFact:
    verdict: Protection
    guards: list[dict]            # [{kind:"sender_eq_state"|"sender_role_mapping", function, lines, state_var, via:"body"|"modifier:<n>"}]
    unknown_reasons: list[str]    # e.g. "condition@L12 depends on call to _checkRole"
    slither_is_protected: bool    # comparison only — NOT used for decisions

@dataclass
class FunctionFacts:
    id: str                       # canonical_name
    contract: str; name: str; visibility: str; payable: bool
    entry_point: bool             # public/external, implemented, not constructor
    src: SourceRef
    protection: ProtectionFact
    state_writes_all: list[str]   # canonical var names, recursive (callees + modifiers)
    eth_calls: list[dict]         # [{node_id, lines, kind:"low_level_call_value", via_internal:str|None}]
    writes_after_eth_call: list[dict]   # [{call_node, var, read_before:true, write_lines}]
    sink_flags: dict              # {"selfdestruct":Tri, "delegatecall":Tri}
    reentrancy_guard: dict        # {"kind":"lock_like_modifier"|"none"|"unknown", "detail":...}
    uses_assembly: bool
    detector_hits: list[str]      # corroboration only
    analysis_errors: list[str]

@dataclass
class Facts:
    schema_version: str; fixture: bool
    mode: str                     # "api" | "cli_json_only"
    tool_versions: dict           # slither, solc, python, crytic_compile
    source_sha256: str
    privileged_vars: dict         # {"C.owner": {"kind":"address_eq"|"role_mapping","evidence":[SourceRef...]}}
    functions: list[FunctionFacts]
    detector_hits: list[dict]     # raw normalised CLI hits
    api_warnings: list[str]
    contract_notes: list[dict]    # contract-level notices: [{contract, code, message}], e.g. code="no_privileged_var_inferred"

@dataclass
class Suspect:
    id: str; category: str        # "access_control" | "reentrancy"
    status: Status                # candidate | inconclusive only at this stage
    function_id: str; src: SourceRef
    rule: str                     # which rule fired (e.g. "AC-1")
    evidence: list[str]           # human-readable facts that justify it
    assumptions: list[str]
    unknown_reasons: list[str]
    detector_corroboration: Tri   # did Slither also flag it?
    template_support: Tri         # can §7 templates attack it? (unknown until T2)
```

Serialize with `asdict` + a custom encoder for enums.

---

## 6. Analysis rules (the heart of Phase 1)

### 6.1 Closure of a function
`closure(F)` = `F` ∪ every `Modifier` in `F.modifiers` ∪ every user-defined function reachable via internal calls (transitively, cycle-safe). Use `all_internal_calls()` / `node.internal_calls`; also include modifiers of callees. Ignore `SolidityFunction`/builtins.

### 6.2 Condition classification (applies to every `node.is_conditional(include_loop=False)` node in every function of the closure)

For each conditional node, in this order:

1. **AUTH-EQ guard** — it is a `require`/`assert` node (a `SolidityCall` whose `function.name` starts with `require` or `assert`) AND its IR has a `Binary` with type EQUAL/NOT_EQUAL where one operand is `msg.sender` (`SolidityVariableComposed`) and the other is a `StateVariable` of address/contract type. → guard `{kind:"sender_eq_state", state_var:<canonical>}`. Note for `!=` the require is written differently (`require(msg.sender != x)` is *not* auth) → only EQUAL inside require counts; NOT_EQUAL counts only inside an if-revert (optional enhancement §6.2a).
2. **AUTH-ROLE guard** — it is a `require`/`assert` node whose IR indexes a `StateVariable` of type `mapping(address => bool)` using `msg.sender` as key, and the indexed value feeds the require. → guard `{kind:"sender_role_mapping", state_var:<canonical>}`.
3. **UNKNOWN triggers** (each appends a reason; never produce a guard):
   - the condition node contains an `InternalCall`, `HighLevelCall`, or `LibraryCall` to a non-Solidity-builtin function (auth helper pattern: `hasRole`, `_checkOwner()`, `registry.isAdmin(...)`).
   - an EQUAL/NOT_EQUAL against a state address where the other operand is not `msg.sender` (e.g. sender stored in a local first).
   - the condition reads `tx.origin`.
   - the condition reads `msg.sender` but matches neither pattern above and is not a plain mapping balance/allowance check (e.g. `require(balances[msg.sender] >= x)` is **not** auth and **not** unknown — it is classified `non_auth_sender_use` and ignored).
4. Otherwise: ignore (plain input validation, e.g. `require(amount > 0)`).

Additional UNKNOWN triggers at function level: `Function.contains_assembly` anywhere in closure; `analysis_errors` from API failures.

#### 6.2a Optional enhancement (only if time): if-revert guards
An `if (msg.sender != owner) revert …;` is a very common pattern. Recognise: IF node with `NOT_EQUAL(msg.sender, state_addr)` whose true-branch son path reaches a `SolidityCall` named `revert*` before any other state write. Until implemented, such functions fall under UNKNOWN trigger #3 (acceptable, conservative).

### 6.3 Protection verdict
```
if guards:                      PROTECTED   (guard may be in a modifier or body)
elif unknown_reasons:           UNKNOWN
else:                           UNPROTECTED # = "no recognised sender authorization"
```
Known limitation to put in KNOWN_LIMITATIONS.md: **a guard anywhere in the closure counts; we do not prove it dominates every path to the write** (e.g. a guard inside one `if` branch). Execution testing is the backstop.
Also: for a modifier guard, optionally verify the guard node reaches the `PLACEHOLDER` node via `sons`; if the modifier has no PLACEHOLDER or the guard is not before it → downgrade to UNKNOWN with reason.

### 6.4 Privileged variables
`privileged_vars` = union of `state_var`s from all guards found in all functions of the contract (including modifier guards). Key = canonical name. **No name heuristics.** If a contract has no guard anywhere, `privileged_vars` is empty and access-control suspects from rule AC-1 are impossible (document: "unguarded owner variable cannot be inferred" → limitation).

**Required notice (plan revision):** if a contract has at least one entry-point, non-constructor function that writes state and `privileged_vars` is empty, add to `facts.contract_notes`:
`{contract: <name>, code: "no_privileged_var_inferred", message: "No authorization guard recognised anywhere in this contract, so rule AC-1 cannot infer a privileged variable. This is NOT evidence of safety."}`
The report and UI must show this as an inconclusive notice, never as "no issues". A silent empty result is not allowed for this case. (This covers the most obviously broken contract shape: no guard anywhere.)

**Optional enhancement AC-1b (only after every §10 case passes and the human approves):** structural, name-free inference of an owner-like variable. A state variable of address type that a constructor assigns from `msg.sender` is added to `privileged_vars` with `kind: "address_eq"` and evidence `via: "constructor_msg_sender"`. Any suspect produced this way stays `candidate`, and its `assumptions` must say the privilege was inferred from the constructor, not from an observed guard. No identifier names may be used, and the rename-mutation tests must still pass. If AC-1b is skipped, the notice above remains the behaviour.

### 6.5 Access-control suspect rules (`hypotheses.py`)

Only for functions with `entry_point == True` and not constructors.

- **AC-1 privileged-state write.** `F.state_writes_all ∩ privileged_vars ≠ ∅`:
  - `F.protection == UNPROTECTED` → `Suspect(status=CANDIDATE)`
  - `F.protection == UNKNOWN` → `Suspect(status=INCONCLUSIVE, unknown_reasons=…)`
  - `PROTECTED` → no suspect.
- **AC-2 dangerous primitive.** In an `UNPROTECTED`/`UNKNOWN` entry function whose closure contains `selfdestruct` or low-level `delegatecall` → suspect (CANDIDATE / INCONCLUSIVE as above). `template_support = FALSE` for now (runner returns inconclusive: "no attack template for this sink").
- Do **not** create suspects from "unprotected + sends ETH" in the MVP (can't separate legitimate `withdraw()` from arbitrary send without intent). List in limitations.
- Attach `detector_corroboration` from CLI hits (`arbitrary-send-eth`, `suicidal`, `unprotected-upgrade` …) as TRUE/FALSE/UNKNOWN — never changes status.

### 6.6 Reentrancy suspect rule (RE-1)

Effective node effects (helper `effects(node)`): direct `state_variables_read/written` plus, for each internal-call at that node, the callee's `all_state_variables_read/written()`; and "has ETH call" if the node (or an internal callee's closure) has a `LowLevelCall` with `function_name == "call"` and `call_value is not None`. (`transfer`/`send` are excluded: 2300 gas. Record them as facts only.)

Algorithm per entry function F (public/external, implemented):
```
E = nodes of F with ETH call
for N in E:
    ancestors = BFS over node.fathers from N (visited set) ∪ {N}
    descendants = BFS over node.sons from N (visited set), excluding N unless reachable via a loop
    R_before = ∪ effects(a).reads for a in ancestors
    W_after  = ∪ effects(d).writes for d in descendants
    conflict = R_before ∩ W_after          # state read before the call, written after it
    if conflict: record {call_node: N, vars: conflict, write_lines}
```
- Guard check: if any modifier in `F.modifiers` is **lock-like** → `reentrancy_guard.kind = "lock_like_modifier"` and **no suspect** (record in facts). *Lock-like* = within the modifier closure, some state variable is read in a conditional node **and** written (before and after the placeholder, or at least once). Structural; never match the name `nonReentrant`.
- If the closure includes `uses_assembly` → `reentrancy_guard.kind = "unknown"` → suspect becomes INCONCLUSIVE.
- Else if `conflict` non-empty → `Suspect(category="reentrancy", status=CANDIDATE, rule="RE-1", evidence=["external ETH call at L<n>", "state var(s) <v> read before and written after the call at L<m>"])`.
- Vars written after the call that were **not** read before it do not create a suspect (counter-only updates).
- Order by CFG only (§3.2). Never use line numbers or node ids for ordering.
- `low-level-calls`, `reentrancy-benign`, `reentrancy-events` hits never create suspects. `reentrancy-eth` hit = corroboration only.

### 6.7 Fallback when the API fails (`mode = "cli_json_only"`)
Run `slither <file> --compile-force-framework solc --json out.json` in the neutral cwd (subprocess, timeout 120 s). Parse detector hits (§3.1). Produce suspects **only** from `reentrancy-eth` hits (CANDIDATE, `rule="DET-reentrancy-eth"`, evidence = detector text, `unknown_reasons=["API facts unavailable"]`). No access-control suspects in this mode — state that in output. Triggers: `Slither(...)` raises, or `api_warnings` count for a function exceeds 0 for the facts needed (then that *function* is UNKNOWN; whole-run fallback only if loading fails).

---

## 7. Attack templates, runner, patcher (Phases 2–3)

### 7.1 Principle: tests log facts, runner decides
Generated Foundry tests **do not assert exploit success**. They run the attack and `console2.log` a single machine-parseable line, e.g.
`MICROSCOPE_RESULT {"class":"reentrancy","attacker_in":"1000000000000000000","attacker_out":"11000000000000000000","exploit_succeeded":true,"steps":[...]}`
The test only reverts/fails for *harness* errors (deploy failed, no funds). The runner parses `decoded_logs` from `forge test --json` (**verify the JSON shape on forge 1.8.5 first**; save a sample to `tests/fixtures/forge_json_sample.json`). Decision:
- harness failure → `inconclusive` (with reason)
- `exploit_succeeded == true` → `reproduced`
- `exploit_succeeded == false` → `not_reproduced` ("not reproduced under this test", never "safe")

The same generated test file is reused against the patched contract by swapping only the import path/contract name.

### 7.2 Reentrancy template (supported shape only)
Needs from facts: contract + path; a payable no-arg function that increases a state mapping by `msg.value` (deposit); the suspect function (no-arg, withdraws caller's balance via the ETH call). If shape doesn't match → `inconclusive: "no template for this shape"` (never guess).
Flow: victim deposits 10 ETH; attacker contract (re-enters the suspect function from `receive()` while vault balance ≥ 1 ETH) deposits 1 ETH and calls the suspect; oracle `attacker_out > attacker_in`.
Reference implementation of this pattern: `test/Exploits.t.sol` (`ReentrancyAttacker`).

### 7.3 Access-control template
Needs: contract + path, suspect function with args, privileged var kind `address_eq` with a public getter (**verify getter exists via facts: public state var or function returning it**), deployment with default constructor args (none/zero) and optional ETH balance (5 ETH). Flow: `vm.prank(RANDOM)` call suspect with `RANDOM` for address params / `1` for ints / empty bytes; oracle `getter() == RANDOM` or `RANDOM.balance` increased after optionally calling any *unprotected-or-now-authorised* withdraw-like function found in facts. Role-mapping kind: record `inconclusive: "role mapping templates not implemented"` unless time permits.

### 7.4 Patcher (deterministic, template-only)
- Access control: insert as first statement of the function body `require(msg.sender == <privileged address var>, "unauthorized");` (the var comes from `privileged_vars`, kind `address_eq`; no var ⇒ no patch, say so).
- Reentrancy: add `bool private _microscopeLock;` and modifier `microscopeNonReentrant() { require(!_microscopeLock, "reentrant"); _microscopeLock = true; _; _microscopeLock = false; }`, apply to the suspect function. (Our own lock-like detector must recognise it — a good self-test.)
- Apply by source-range edits using Slither line ranges; produce `difflib.unified_diff`. Compile patched file; on failure → `compile_failed`.
- Retest: (1) same attack test; (2) regression template: access ⇒ original owner can still call the function; reentrancy ⇒ honest depositor can deposit then withdraw exactly their balance. Status: attack blocked ∧ regression pass ⇒ `mitigated_in_test`; attack still works or regression fails ⇒ `regression_failure`; anything unrunnable ⇒ `inconclusive`.
- `src/fixed/*` are **hand-written reference fixes**, labelled as such. The patcher's output is "our patch".

---

## 8. Data flow & artifacts per run
`runs/<run_id>/` contains `facts.json`, `suspects.json`, `generated/<suspect_id>/Attack.t.sol`, `forge_original.json`, `forge_patched.json`, `trace.txt` (`-vvvv`), `patch.diff`, `findings.json`, `report.md`, and `meta.json` (versions, durations, timeouts, errors). Use a temporary copy of `input.sol` for the run and delete it after analysis unless the user explicitly chooses a local keep-source option. Never upload source to Supabase by default. `run_id` = timestamp + short SHA-256 of source.

### 8.1 Supabase persistence contract
When the user explicitly saves a report, persist only the agreed report fields (run id, owner user id, timestamps, tool versions, findings/statuses, evidence references, assumptions, limitations, and optionally patch diff/report Markdown). Do not persist original Solidity source, secrets, full raw traces, or generated source unless the user is clearly told and explicitly opts in. Keep large artifacts local by default. Enforce RLS policies and test that one user cannot read/update/delete another user's reports. Core analysis must still run if Supabase is not configured or temporarily unavailable; show a clear save/auth error instead of losing the local report.

### 8.2 Gemini explanation contract
Gemini may be called only after deterministic facts and statuses have been assembled. Send a minimal sanitized payload containing the finding category, rule id, status, source line references, evidence strings, assumptions, and unknown reasons. Do not include the whole Solidity file, API keys, private user data, or unneeded trace data by default. Return a short explanation tied to the supplied evidence and label it “AI-generated explanation — not proof.” Treat model output as untrusted text; render safely. A Gemini error or hallucinated statement must never alter facts, statuses, attack outcomes, patch verdicts, or stored evidence. The user must be able to use Microscope without Gemini.

## 9. UI and backend integration (Phase 4 — `app.py`, Streamlit)
Three primary sections: **Scan** (upload or "Load demo fixture", progress log), **Findings** (cards with status badge, rule id, evidence bullets, assumptions, unknown reasons; counts by status; no "SAFE" score), and **Replay + Before/After** (timeline from stored `steps` with balances, diff, same-test results for original vs patched, regression result, limitations expander, replay command, download report). Every analysis panel reads actual local artifacts from `runs/`; missing artifact ⇒ explicit empty state. Contract-level notices (`contract_notes`, e.g. `no_privileged_var_inferred`) appear in **Findings** as an inconclusive notice with the text from §6.4.

Add a restrained **Account / Saved Reports** flow using Supabase Auth and Postgres. Let a signed-in user explicitly save and reopen their report; enforce RLS and display a clear local-only mode when Supabase credentials are absent. Do not require sign-in to run a local scan. Add an optional **Explain finding** action using Gemini only after evidence is available. Clearly label the returned text as AI-generated explanation, and do not let it change evidence or statuses. If time is short, prioritize local scan/replay reliability and basic safe report persistence before Gemini UI polish. Gemini UI is exactly one **Explain finding** button per finding card. On any Gemini error, quota problem or missing key, show a fixed message ("Explanation unavailable — the evidence above is unaffected") and nothing else; the demo must never depend on Gemini.

## 10. Tests (Phase 1 acceptance — all must pass)

Use `pytest`. Tests call the public functions; they never mock Slither. Put synthetic sources in `tests/cases/`.

**Reference fixtures (the 4 existing contracts):**
- T-F1 VulnerableTreasury: `setOwner` → AC-1 CANDIDATE; `withdrawAll` → PROTECTED; no suspect on `withdrawAll`; `receive` no suspect.
- T-F2 SafeTreasury: no suspects; `setOwner` PROTECTED via modifier (guard `via:"modifier:…"`); `slither_is_protected` recorded.
- T-F3 VulnerableVault: `withdraw` → RE-1 CANDIDATE (vars include the mapping); `deposit` no suspect; `reentrancy-eth` corroboration TRUE.
- T-F4 SafeVault: **no RE-1 suspect** although `low-level-calls` fired; corroboration FALSE.

**Mutation / no-name-dependence (critical):** programmatically rename every identifier of the 4 fixtures (contract→`C1`, `owner`→`boss`, `setOwner`→`changeBoss`, `withdraw`→`pullOut`, `balances`→`ledger`, `onlyOwner`→`gate`) and assert **identical** suspect structure. Also copy files to random file names.

**Synthetic cases** (write each as a tiny `.sol`; expected result in brackets):
1. Modifier **named `onlyOwner` with an empty body** protecting a setter, while another function guards the same var with `require(msg.sender == x)` → setter is **UNPROTECTED → CANDIDATE** (proves name not trusted).
2. Custom modifier `gate` with real `require(msg.sender == admin)` → **PROTECTED**, no suspect.
3. Role mapping: `require(admins[msg.sender])` guard; unguarded `grant(address)` writing `admins` → **CANDIDATE** (privileged var kind `role_mapping`; template_support unknown).
4. Auth helper: modifier calls internal `_check()` containing `if (x != msg.sender) revert();` → **UNKNOWN → INCONCLUSIVE** (unless §6.2a implemented ⇒ PROTECTED).
5. Auth via external registry call in `require` → **UNKNOWN → INCONCLUSIVE**.
6. Sender stored in a local, then `require(s == owner)` → **UNKNOWN** (not UNPROTECTED).
7. Function with inline assembly writing a privileged var → **UNKNOWN**.
8. Guard exists but contract has `require(balances[msg.sender] >= x)` only → function not protected by that; privileged vars empty → **no AC-1 suspect** (limitation case).
9. Constructor writes privileged var → **no suspect**.
10. Reentrancy with custom lock modifier (`mutex` using a bool, different name) → **no suspect**, `reentrancy_guard.kind == "lock_like_modifier"`.
11. Write after call to a var never read before (`counter++`) → **no suspect**.
12. `payable(msg.sender).transfer(amount)` before state update → **no suspect** (documented limitation).
13. CEI-correct withdraw using internal helper `_send` that does the ETH call after state zeroing → **no suspect**.
14. Vulnerable pattern with the ETH call inside internal helper `_send`, state zeroed after in caller → **CANDIDATE** (tests `effects()` of internal callees; mark as stretch if it blocks progress, but do not silently skip — `xfail` with reason).
15. Slither API failure path: monkeypatch `facts.Slither` to raise → `mode=="cli_json_only"`, reentrancy-eth hit still produces a CANDIDATE with `unknown_reasons`, no access-control suspects.
16. Missing `solc`/compile error file → clear `analysis_errors`, `status` inconclusive, no crash.
17. No guard anywhere: contract with a state-writing setter, an address variable assigned from `msg.sender` in the constructor, and no `require(msg.sender …)` in any function → **no AC-1 suspect**, but `facts.contract_notes` contains `no_privileged_var_inferred` (never a silent empty result). Run this case under the rename mutation too. If AC-1b is implemented, the setter becomes a CANDIDATE whose `assumptions` mention constructor inference.

**Acceptance for Phase 1:** `pytest -q` green (stretch cases may be `xfail`, listed in the report); `python -m scanner.hypotheses src/vulnerable/VulnerableTreasury.sol` prints exactly the AC-1 suspect; fixed contracts print none; case 17 emits the `no_privileged_var_inferred` notice.

---

## 11. Phases, time boxes, stop-gates (10-hour plan)

Time boxes **include** the human's 10–15 minute stop-gate review. Total: 10:00.

| Phase | Scope | Time box | Clock | Stop-gate (human reviews) |
|---|---|---|---|---|
| **P0** | Documentation audit (`ANTIGRAVITY_FIRST_PROMPT.txt`), conflict resolution, `git status`, confirm `forge test` baseline | 0:30 | 0:30 | Audit report, conflicts resolved |
| **P1** | `schema.py`, `api_check.py`, `facts.py`, `detectors.py` (CLI JSON), `hypotheses.py`, `contract_notes`, tests §10 (incl. case 17) | 2:00 | 2:30 | `pytest -q` output + `facts.json` for Vault & Treasury + suspect list for all 4 fixtures |
| **P2** | Templates (reentrancy + access), `runner.py`, parse forge JSON, `scanner.run` up to original result | 2:00 | 4:30 | Generated test file + `findings.json` for both vulnerable fixtures (`reproduced`) and `not_reproduced`/no suspect for fixed ones |
| **P3** | `patcher.py`, retest, regression templates, diff | 1:30 | 6:00 | Diffs + `mitigated_in_test` JSON; patcher's lock recognised by our own detector |
| **CHECKPOINT** | At least one supported contract shows: candidate → reproduced → patched → same attack blocked → regression passes | — | 6:00 | Go / no-go for P4b and P4c |
| **P4a** | Streamlit UI (local only, renders stored JSON) + report download | 1:15 | 7:15 | Local scan works with no cloud credentials |
| **P4b** | Supabase Auth, explicit save/open report, RLS, two-user isolation test, local fallback | 1:00 | 8:15 | RLS test output; app still works with Supabase unconfigured |
| **P4c** | Gemini **Explain finding** button, fixed error state | 0:30 | 8:45 | Gemini cannot change statuses; app works with Gemini unavailable |
| **P5** | Mini-benchmark (§12) + one unseen demo contract | 0:45 | 9:30 | Results CSV, wrong cases listed |
| **P6** | README, KNOWN_LIMITATIONS, backup demo recording, privacy/security check, final run-through | 0:30 | 10:00 | Final run-through |

### Hard cutoffs
- **Checkpoint at 6:00.** If the evidence chain is not working end to end by **6:30**, skip P4b and P4c entirely. Spend the time finishing the chain, a simple report page rendered from JSON (P4a), and the benchmark.
- Any phase passing 1.5x its time box: stop, report, and decide what to cut (rule 12).
- Do not start P4b or P4c before the checkpoint passes.

### Cut order (first to last)
1. **Gemini (P4c).** One button; cut it first. Nothing else depends on it.
2. **Benchmark shrinks** from 6 contracts to the 4-contract minimum (§12) and says so on the slide.
3. **Supabase (P4b), all or nothing.** Do not ship saved reports without a passing two-user RLS test. If cut, report download stays and the UI says "local-only mode".

Earlier cut ladder (still applies): P1 slips → fixtures + detector JSON only. P2 reentrancy fails → ship access control only. P3 patcher unreliable → use `src/fixed/*` as labelled reference patches but still run the same attack. UI behind → render a simple report page from JSON. **Never fabricate numbers.**

### Demo readiness
The demo depends on WSL2, Slither, solc and forge working live. The P6 backup recording must be a **real recorded run** of the tool (never staged output), plus pre-generated `runs/` artifacts kept locally. Start the recording no later than 9:30.

---

## 12. Benchmark (P5) rules

**Mini-benchmark (planned, 6 contracts, modern Solidity, in `bench/` with `labels.json` as truth):**
1 reentrancy-buggy, 2 reentrancy-safe lookalikes (e.g. CEI, custom lock), 1 access-buggy, 2 access-safe lookalikes (e.g. modifier, constructor-only). Include tricky safes so false positives are possible.

**Minimum if time is short (4 contracts):** one buggy and one safe lookalike per class. Say so on the slide.

**Integrity rule:** freeze the scanner code *before* writing the bench contracts (local git tag with human approval, or a recorded SHA-256 of `scanner/`), then run once. All contracts are held-out; do not tune rules on them. If a result is bad, report it and list the wrong cases.

**Stretch (only if everything else is done):** the original 12-contract set (3 buggy + 3 safe per class), tuned on 6 and reported on the other 6.

Per contract record: did Slither alone detect the right bug? false alarm? Microscope status; exploit-confirmed?; Slither alarms we downgraded to `not_reproduced`. Slide caveat: self-authored, tiny, illustrative, not statistically significant. Do not claim Microscope is more accurate than Slither; the claim is "Slither tells us where to look; executed tests decide."

### 12.1 Unseen demo contract
The human supplies one contract that is **not** one of the four fixtures (`fixture: false`), written or chosen without tuning rules on it. Run it live in the demo and show whatever result comes out: reproduced and patched, or `inconclusive` with a visible reason. Its purpose is to show the pipeline is not hardcoded; an honest `inconclusive` is an acceptable outcome, a faked success is not.

---

## 13. Safety & claims
Run `slither`/`forge` via `subprocess.run([...], timeout=..., cwd=tempdir, env=minimal)`; no `shell=True`; no network access from the analysis worker after install; reject uploads > 200 KB, non-`.sol`, path traversal. Supabase calls are limited to auth and report persistence, with RLS tested; no service-role key in the app. Keep secrets in local environment variables and `.env` ignored by Git. Any Gemini call is explanation-only, sends minimal sanitized facts, ignores instructions in code comments/model output, and is labelled "AI-generated explanation — not proof". Never let model text modify the evidence-derived status.
**Allowed claims:** "Slither tells us where to look; executed tests decide"; "we reproduce the attack and rerun the same attack on the patch"; "not reproduced ≠ safe". **Forbidden:** "finds all bugs", "guarantees safety", "more accurate than Slither", numbers not produced by a real run.

## 14. Report-back format (Codex → human, at every stop-gate)
1. What was built (file list). 2. Commands run + full pass/fail output. 3. Which §10 cases pass / xfail and why. 4. Anything that deviated from this spec and why. 5. Any attribute that behaved differently than §3 predicted. 6. Known limitations added. 7. Elapsed time vs the §11 time box. 8. Proposed next step (wait for go-ahead).

---

## 15. Copy-paste prompts for Codex

**Prompt P1:**
> Read `AGENTS.md` and `CODEX_BUILD_SPEC.md` fully. Implement **Phase P1 only** (§§3–6, §10): `scanner/schema.py`, `api_check.py`, `facts.py`, `detectors.py`, `hypotheses.py`, plus `tests/`. Use real Slither 0.11.6 via `Slither(path, cwd=<neutral tmp>, compile_force_framework="solc")`. Do not use `Function.is_protected()` for decisions (store it only as `slither_is_protected`). Order nodes via `entry_point`/`sons`, never `node_id`. No detection logic may depend on identifier names; implement the rename-mutation tests. Do not touch `src/**` or `test/Exploits.t.sol`. Implement `facts.contract_notes` and the `no_privileged_var_inferred` notice (§6.4) with synthetic case 17; skip AC-1b unless I approve it. Do not integrate or call Supabase/Gemini in P1. Report elapsed time against the §11 time box. When done, run `pytest -q` and report in the §14 format. Stop.

**Prompt P2:** (after P1 approved)
> Implement **Phase P2** (§7.1–7.3, §8): Jinja templates, `runner.py`, and `python -m scanner.run`. First run `forge test --json` on the existing reference tests and save a sample JSON to `tests/fixtures/forge_json_sample.json`; build the parser from that real shape. Generated tests must log a `MICROSCOPE_RESULT` JSON line and must not assert exploit success. Unsupported shapes ⇒ `inconclusive` with a reason. Report per §14. Stop.

**Prompt P3** (after P2 approved)
> Implement **Phase P3** (§7.4): `patcher.py`, regression templates, retest of the *same* attack on the patched source, and `patch.diff`. Our own lock detector must recognise the patcher's lock. Unpatchable shapes ⇒ precise reason, no mitigation claim. Report per §14, including elapsed time. Stop. Then I will check the §11 checkpoint.

**Prompt P4a** (only after the checkpoint passes)
> Implement **Phase P4a** (§9, local parts only): Streamlit `app.py` with Scan, Findings (including `contract_notes`) and Replay + Before/After, plus report download. Render stored artifacts only; empty states for anything missing. No Supabase or Gemini yet. Must work with no cloud credentials. Report per §14. Stop.

**Prompt P4b** (only if the checkpoint passed and P4a is approved)
> Implement **Phase P4b** (§8.1 and `SUPABASE_GEMINI_INTEGRATION.md`): Supabase Auth, an explicit "Save report" action that first shows exactly which fields will be stored, "Open saved reports", the `reports` table with RLS (`user_id = auth.uid()`), and a two-user isolation test. Publishable/anon key only; no service-role key anywhere; source is never uploaded. Without Supabase credentials the app runs in a clearly labelled local-only mode. Time box 1:00; if RLS cannot be demonstrated, say so and stop. Report per §14.

**Prompt P4c** (only if P4b is approved or deliberately skipped)
> Implement **Phase P4c** (§8.2): one **Explain finding** button per finding card. Send the minimal sanitized payload only, label output "AI-generated explanation — not proof", render it as plain text, and show the fixed error message on any failure. Prove with a test that Gemini output cannot alter any status. Time box 0:30. Report per §14.

**Prompt P5** (§12)
> Implement **Phase P5**: freeze the scanner (record the hash), then write and run the 6-contract mini-benchmark in `bench/` (4 minimum), with `labels.json` and a results CSV. Do not tune on it. List every wrong case. Add the human-supplied unseen demo contract as `fixture: false` and run it once, reporting the result unedited. No invented numbers. Report per §14.

**Prompt P6**
> Implement **Phase P6**: update README and `KNOWN_LIMITATIONS.md` with verified results only, run the privacy/security checklist (§13, no secrets in repo, `.env.example` placeholders only, no source uploaded), and prepare the demo run-through. Do not stage or edit outputs for the recording. Report per §14.
