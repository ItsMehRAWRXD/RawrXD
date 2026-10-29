# REAP size/size runtime-budget follow-up

Timestamp: 2026-10-29T04:30:00Z  
Source HEAD: `d2b163dde097f1b8a421d239360ef1b9bddd4b68`  
Promotion: `PROMOTE=0`

This receipt records the rebuilt REAP runtime budget path and the model-agent
readiness matrix. It does not authorize model reduction or replace the frozen
product executable.

## Build artifacts

| Artifact | SHA-256 | Result |
|---|---|---|
| `build_ide/bin-msvc/rawr.exe` | `6CE967FDA329B34DCB9939635F08756F80FA7BC3D0C2DB7B2323D1C1FBAE836D` | linked |
| `build_ide/bin-msvc/rawr-reap.exe` | `7B0AAF9E8088F2BB5B69D97533FF8F7C104B246C085A044B1782BD6FDB92D86F` | linked |
| `build_ide/bin-msvc/rawr-reap-runtime-plan-test.exe` | `EB385F12319B4A1B8E1B4F71BF61C8DE5A2188FC077FF820431FB1069CD3047F` | linked |
| `build_ide/rawr-tensor-residency-budget-test.exe` | `B5866F7F6BEED700C55A1036B2B5390EA866F95079B4E077FFD81C4BDD66BCDC` | linked |
| `build_ide/bin/RawrXD-Win32IDE-Native.exe` | `92A4B396F1ED3674152F971B5C4067A644A16EDA8B3FAC2D71591D44DAACCCA2` | linked |

The frozen product authority remains unchanged and was not rebuilt:

`G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe`

SHA-256: `748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145`

## Runtime and test evidence

- `rawr-reap-runtime-plan-test.exe`: `REAP_RUNTIME_PLAN_TEST_PASS`, exit 0.
- `rawr-reap-cli-contract-test.exe`: `REAP_CLI_CONTRACT_PASS`, exit 0.
- `reap-moe-transform-test.exe`: `REAP_MOE_TRANSFORM_PASS`, source unchanged,
  reload, target enforcement, and rollback all passed, exit 0.
- `rawr-tensor-residency-budget`: pass after the Windows `max` macro-safe
  bounds fix; pinned mappings are rejected and released mappings are reclaimed
  within the configured byte budget.
- Full CTest: 25 runnable tests passed; one explicitly skipped
  (`deep2_h11_prefill_parity`), exit 0.
- Plain `rawr run --size 30GB`: rejected with usage exit 2.
- `rawr run __missing_model__ --reap --size 30GB --active-experts 8
  --expert-budget 30GB --quality-floor 0.9`: fail-closed inventory denial,
  exit 4, no output model written.
- Real Kimi K2 runtime (`--target 30GB/8`) loaded all 13 shards and 1,096
  tensors, admitted 384 experts with 8 active experts, and exited 0 with
  `working_set_configured=true`, `streamer_configured=true`, and
  `MOE_ROUTER_TOPK_AND_MULTISHARD_RESIDENCY_BYTE_BUDGET_APPLIED`. The raw
  receipt is `evidence/REAP_SIZE_SIZE_20261029/kimi_runtime_receipt.json`.
- A dense Phi-3 runtime probe with the same target was rejected as
  `DENSE_MODEL_HAS_NO_MOE_EXPERT_TOPOLOGY`, exit 4, with no generation or
  rewrite. This is the required architecture guard, not a synthetic success.

The multi-shard runtime now applies the requested working-set bytes to the
active `TensorResidencyCache`; mapping alignment deltas count toward the exact
resident budget and pinned mappings cannot be evicted.

The documented decimal forms `KB`, `MB`, `GB`, and `TB` are accepted by the
runtime target parser alongside the existing short and binary forms; `30GB/8`
is covered by a regression test.

## Agentic model readiness

The current CLI hash in `evidence/RAWRXD_AGENTIC_MODEL_READINESS_20261029/SUMMARY.json`
matches `rawr.exe` above. Five independent real-model receipts are PASS:

`nemotron-3-nano:4b`, `nemotron-3.5-bolt:latest`,
`nemotron-3.5-lightning:30b`, `flint:latest`, and the `qwen3:8b`
baseline.

Each receipt records real Ollama inference, MOTD authorization,
`readFile -> editFiles -> readFile`, zero tool failures, exactly one changed
file, verified before/after hashes, and `synthetic_success=0`.

## Remaining gates

Production REAP rewrite remains disabled until model-specific calibration,
independent numerical parity, selection, quality-floor, reduced-GGUF reload,
and post-reduction inference evidence pass for the target model. GUI GhostText
and multi-model GUI acceptance remain separate from this CLI agentic matrix.
