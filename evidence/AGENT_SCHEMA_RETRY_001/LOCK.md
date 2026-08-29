# AGENT_SCHEMA_RETRY_001 - LOCK

**Status:** `PASS`  
**Frozen:** 2026-08-29T18:46:50Z  
**Lane:** MODEL_RETRY (`RAWRXD_TOOL_ARGS_STRICT=1`; bare-key repair OFF)

Distinct from SCHEMA-002 lane **R** (deterministic parser repair before dispatch).

```text
AGENT_SCHEMA_RETRY_001=PASS
malformed_rejected=PASS
malformed_side_effect_free=PASS
new_inference_observed=PASS
corrected_call_different=PASS
corrected_call_dispatched=PASS
handler_execution_count=1

FIRST_CALL_SCHEMA_VALID=0
FIRST_CALL_DISPATCHED=0
FIRST_CALL_SIDE_EFFECTS=0
SECOND_CALL_SCHEMA_VALID=1
SECOND_CALL_DISPATCHED=1
TOTAL_HANDLER_EXECUTIONS=1
CORRECTION_REQUIRED_NEW_INFERENCE=1

first_args={path:main.c}
second_args={"path":"main.c"}
```

## Sequence proven

```text
malformed bare-key args
  -> schema_validation, dispatched=false, no side effects
  -> observation returned to model
  -> real Deep2 second inference
  -> corrected strict JSON
  -> dispatch exactly once
  -> tool succeeds
```

## Artifacts

- `AGENT_SCHEMA_RETRY_001.txt`
- `AGENT_SCHEMA_RETRY_001.lock.json`
- `agent.console.txt`
- Regenerator: `scripts/RUN_AGENT_SCHEMA_RETRY_001.ps1`
