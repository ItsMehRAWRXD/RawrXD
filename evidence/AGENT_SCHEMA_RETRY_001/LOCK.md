# AGENT_SCHEMA_RETRY_001 - LOCK

**Status:** `PASS`
**Frozen:** 2026-08-29T20:28:43Z
**Lane:** MODEL_RETRY (RAWRXD_TOOL_ARGS_STRICT=1; bare-key repair OFF)

## Certification rule

```text
native_exe_exit_0         = required
powershell_stderr_record  = irrelevant to native success
schema_retry_assertions   = required
DEEP2_DESTRUCTOR BEGIN+END = required (real teardown)
```

## Harness gates

- `FIRST_INVALID_REJECTED` = PASS
- `FIRST_DISPATCHED_ZERO` = PASS
- `FIRST_SIDE_EFFECTS_ZERO` = PASS
- `MODEL_RETRY_OCCURRED` = PASS
- `CORRECTED_CALL_DIFFERENT` = PASS
- `SECOND_SCHEMA_VALID` = PASS
- `SECOND_DISPATCHED_ONCE` = PASS
- `HANDLER_EXECUTIONS_ONE` = PASS
- `NATIVE_EXIT_ZERO` = PASS
- `TEARDOWN_COMPLETE` = PASS
- `REPORT_PASS_LINE` = PASS

`AGENT_NATIVE_EXIT=0`
`DEEP2_DESTRUCTOR_BEGIN=1`
`DEEP2_DESTRUCTOR_END=1`

## Artifacts

- stdout.txt / stderr.txt (separate; no 2>&1 Tee contamination)
- agent.console.txt (combined)
- AGENT_SCHEMA_RETRY_001.txt (native report)
- HARNESS_GATE.txt
- Regenerator: scripts/RUN_AGENT_SCHEMA_RETRY_001.ps1
