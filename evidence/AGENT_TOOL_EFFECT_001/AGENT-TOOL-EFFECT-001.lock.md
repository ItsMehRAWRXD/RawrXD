# AGENT-TOOL-EFFECT-001 â€” LOCK

**Status:** `FAIL`
**Frozen:** 2026-08-29T18:53:16Z
**Source run:** `F:\~dev\rawrxd\evidence\AGENT_E2E_002b\01_compile`

## Authority

First false transition: **`TOOL_RESULT_OK`**
Root domain: **AGENT_TOOL_EXECUTION**

`	ext
SOURCE_MUTATION                = PASS
AGENT_BUILD_EXECUTION          = FAIL
HARNESS_BUILD_VERIFICATION     = PASS
RESULTING_PROGRAM_CORRECT      = PASS
UNSUPPORTED_SUCCESS_CLAIM      = DETECTED
`

Template/EOS/tokenizer hypothesis: **CLOSED** (not reopened).
Deep2 numerical tracks (Q_PRE_ROPE / O_PROJ): **SEPARATE**.
Case `04_logic_bug` disposition: **NOT established by this freeze** (evidence is `01_compile` only).

## Agent ladder (authority)

```text
MODEL_OUTPUT             PASS
TOOL_CALL_DETECTED       PASS
TOOL_CALL_PARSED         PASS
SCHEMA_VALID             PASS
TOOL_DISPATCHED          PASS
TOOL_RESULT_OK           FAIL
FILE_BYTES_CHANGED       PASS
BUILD_AGENT_INVOKED      PASS
BUILD_AGENT_EXIT_0       FAIL
```

## Harness-only ladder (verification; must not promote agent PASS)

```text
BUILD_HARNESS_INVOKED    HARNESS_PASS
BUILD_HARNESS_EXIT_0     HARNESS_PASS
PROGRAM_RUN              HARNESS_PASS
EXPECTED_STDOUT          HARNESS_PASS
GOAL_SATISFIED           HARNESS_PASS
```

## Classification

| Fact | Value |
| --- | --- |
| First failure | TOOL_RESULT_OK |
| Root domain | AGENT_TOOL_EXECUTION |
| Agent repaired source | True |
| Agent build exit 0 | False |
| Harness build exit 0 | True |
| Unsupported success claim | True |

## Invariant

```text
tool failure
    â†’ success claim forbidden

external harness later verifies success
    â†’ harness may establish verified result
    â†’ does NOT retroactively make the earlier agent claim valid
    â†’ does NOT set BUILD_AGENT_EXIT_0 = PASS
```

## Artifacts

- `AGENT_TOOL_LADDER_001.txt`
- `AGENT-TOOL-EFFECT-001.lock.json`
- Regenerator: `scripts/FREEZE_AGENT_TOOL_EFFECT_001.ps1`
