# P5 mini-benchmark

This is a six-contract, self-authored held-out illustration. `labels.json` is the ground truth and is not loaded by the scanner. The scanner fingerprint was recorded before these contracts were authored; the runner checks it before execution and refuses a repeat run.

Cases include one vulnerable and two safe lookalikes for each supported family: ETH reentrancy and privileged-state access control. Each run is `fixture: false`. Raw artifacts are stored under `raw_runs/`; `results.csv` and `results.json` are produced from those actual artifacts and list any cases whose end-to-end exploit outcome disagrees with the label. The runner requires the separate human-supplied demo at `unseen/human_demo.sol`, runs it once with `fixture: false`, and stores its unedited finding artifact in `unseen_demo_result.json`.

For Slither, the direct target detector comparison is defined only for reentrancy (`reentrancy-eth`). Slither has no generic detector for the benchmark's ordinary admin-setter access-control pattern, so that direct-detection comparison is recorded as unavailable for access-control cases; all raw detector names are still recorded. Any Slither corroboration followed by an actual `not_reproduced` Microscope test is listed separately.

This benchmark is intentionally small and self-authored. It is not statistically significant and must not support a claim that Microscope is more accurate than Slither. The separately required human-supplied unseen demo contract must be run with `fixture: false`; it is not included in these six benchmark labels.
