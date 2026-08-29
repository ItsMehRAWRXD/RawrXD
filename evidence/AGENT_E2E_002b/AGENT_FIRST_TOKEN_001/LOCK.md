# AGENT-FIRST-TOKEN-001 — LOCK

**Status:** `PASS`  
**Frozen:** 2026-08-29  
**Do not reopen** unless a later regression fails this exact gate.

## Sticks

| Stick | Family | Token count | First token | RESULT |
|-------|--------|-------------|-------------|--------|
| A_auto | phi3 | 954 | 29903 | PASS |
| B_chatml | chatml | 964 | 29903 | PASS |

```text
overall=PASS
ROOT_DOMAIN=NONE
SCRIPT_EXIT=0
```

## Closed path

```text
model load → render → tokenize → prefill → first decode token
```

Both frontends complete prefill/decode and sample the **same** first token despite different rendered byte/token counts. No first-token blocker attributable to auto-Phi3, forced ChatML, tokenizer, prefill, or decode.

## Reclassification

```text
FIRST_TOKEN / INFERENCE_FRONTEND = CLOSED
AGENT ACTION EFFECTIVENESS        = OPEN
```

## Next authority

Tool-call ladder (see `AGENT_TOOL_EFFECT_001`):

```text
MODEL_OUTPUT → TOOL_CALL_PARSED → SCHEMA_VALID → TOOL_DISPATCHED
  → TOOL_RESULT_OK → FILE_BYTES_CHANGED → BUILD/RUN → GOAL_SATISFIED
```

First false (prior freeze): **`SCHEMA_VALID`** (malformed / unquoted-key arguments).

## Artifacts

- `evidence/AGENT_E2E_002b/AGENT_FIRST_TOKEN_001/VERDICT.md`
- `A_auto/RUN_SUMMARY.txt`, `B_chatml/RUN_SUMMARY.txt`
- `scripts/RUN_AGENT_FIRST_TOKEN_001.ps1`
