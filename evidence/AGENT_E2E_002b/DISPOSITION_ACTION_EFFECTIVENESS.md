# AGENT-E2E-002b — DISPOSITION (action effectiveness)

**Status:** `AGENT-E2E-002b=FAIL` (blocked on tool ladder)  
**ROOT_DOMAIN:** `AGENT_ACTION_EFFECTIVENESS`  
**Date:** 2026-08-29  
**Supersedes:** `DISPOSITION_PRE_TOOL_INFERENCE.md` (first-token path closed)

## Closed

```text
AGENT-FIRST-TOKEN-001 = PASS (frozen)
FIRST_TOKEN / INFERENCE_FRONTEND = CLOSED
```

Do **not** reopen first-token diagnostics unless this exact gate regresses.
See `AGENT_FIRST_TOKEN_001/LOCK.md`.

## Fixture

`04_logic_bug` remains **VALID** (independent proof):

```text
build_exit=0
run_exit=1
stdout=FAIL got=-1 expected=5
```

## Open ladder

```text
MODEL_OUTPUT → TOOL_CALL_PARSED → SCHEMA_VALID → TOOL_DISPATCHED
  → TOOL_RESULT_OK → FILE_BYTES_CHANGED → BUILD/RUN → GOAL_SATISFIED
```

Prior freeze (`AGENT_TOOL_EFFECT_001`): first false = **`SCHEMA_VALID`**
(model bare-key args / unquoted JSON). Fail-closed schema gate is present;
TinyLlama dialect repair is logged as `[TOOL_SCHEMA] REPAIR` before validation.
`RAWRXD_TOOL_ARGS_STRICT=1` disables repair for schema-cert smoke.

## Next gates

1. Re-prove `SCHEMA_VALID` → `TOOL_DISPATCHED` → `FILE_BYTES_CHANGED` on a fresh case transcript
2. Re-freeze `AGENT-TOOL-SCHEMA-002` / `AGENT-TOOL-EFFECT-001`
3. Only then re-run `AGENT-E2E-002b` (`04_logic_bug`)
