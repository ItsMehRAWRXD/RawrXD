# AGENT-TOOL-EFFECT-001 â€” LOCK

**Status:** `FAIL`
**Frozen:** 2026-08-29T17:35:04Z
**Source run:** `F:\~dev\rawrxd\evidence\AGENT_E2E_002b\01_compile`

## Authority

First false transition: **`SCHEMA_VALID`**
Root domain: **model/tool-call generation (malformed arguments)**

Template/EOS/tokenizer hypothesis: **CLOSED** (not reopened).
Deep2 numerical tracks (Q_PRE_ROPE / O_PROJ): **SEPARATE**.

## Ladder

```text
MODEL_OUTPUT           PASS
TOOL_CALL_DETECTED     PASS
TOOL_CALL_PARSED       PASS
SCHEMA_VALID           FAIL
TOOL_DISPATCHED        PASS
TOOL_RESULT_OK         FAIL
FILE_BYTES_CHANGED     FAIL
BUILD_EXECUTED         PASS
BUILD_EXIT_0           FAIL
PROGRAM_RUN            FAIL
EXPECTED_STDOUT        FAIL
GOAL_SATISFIED         FAIL
```

## Edit invariant (replace_in_file / write_file)

Required: `parser_accept && schema_valid && execution_ok && before_sha != after_sha`

- `call_0`: invariant_pass=False schema_valid=False execution_ok=False mutated=False

## Evidence excerpt

Model emitted tool envelopes, but arguments were **not JSON** (unquoted keys), e.g.:

```text
TOOL_CALL: replace_in_file {path:main.c, search: "DOES_NOT_EXIST", replace: "42"}
```

Dispatcher returned `missing string argument: path` / `command`.
`source_mutated=false` follows directly â€” never reached effective write.

## Classification

| First failure | Root domain |
| --- | --- |
| SCHEMA_VALID | model/tool-call generation (malformed arguments) |

## Artifacts

- `AGENT_TOOL_LADDER_001.txt`
- `AGENT-TOOL-EFFECT-001.lock.json`
- Regenerator: `scripts/FREEZE_AGENT_TOOL_EFFECT_001.ps1`
