# Qwen4Exp executor blocker diagnostic

Date: 2026-10-20
Branch: `local-30b-backend`

## Change verified

`runtime_graph_executor` now records a stable, fail-closed JSON attribution when
binding stops at discovery, tensor binding, graph lowering, or the absence of
executable operations. The receipt is diagnostic only; it does not admit an
unsupported operator and it cannot report execution or certification success.

The exposed fields are:

- `failure_stage`
- `first_blocking_operator`
- `failure_receipt_json`

The JSON contract reports `certification=BLOCKED`, `gpu_dispatches=0`,
`generated_tokens=0`, and `tps=null` for a bind failure.

## Verification

| Check | Result |
| --- | --- |
| `deep2_engine_lib` Release build | PASS |
| `deep2_gdn_reference_contract` | PASS |
| `deep2_qwen4exp_operator_contract` | PASS |
| `git diff --cached --check` | PASS |

## Current production boundary

The Qwen4Exp graph builder still emits `QSA`, `GDN`, `PLE`,
`Hyperconnection`, and `SparseMoE` instructions. `Executor::Bind` rejects those
instructions because their production lowering is not bound, and
`Executor::ExecuteToken` has no cases that can execute them. This is the first
concrete production blocker; it is not a Vulkan queue-family diagnosis.

Therefore the authoritative state remains:

```ini
QWEN4EXP_FULL_MODEL = BLOCKED
FULL_MODEL_EXECUTION = NOT_RUN
CERTIFICATION        = NOT_CERTIFIED
```

The next implementation must bind one complete operator vertical slice through
graph lowering, tensor ownership, command recording/submission, state handling,
and independent full-model parity before any certification state changes.
