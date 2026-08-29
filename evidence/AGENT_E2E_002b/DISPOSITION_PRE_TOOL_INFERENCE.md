# AGENT-E2E-002b — DISPOSITION (frozen) — SUPERSEDED

> **Superseded 2026-08-29:** `AGENT-FIRST-TOKEN-001=PASS`.  
> Current authority: `DISPOSITION_ACTION_EFFECTIVENESS.md`  
> (`FIRST_TOKEN / INFERENCE_FRONTEND = CLOSED`, action effectiveness OPEN).

**Status:** `AGENT-E2E-002b=FAIL`  
**ROOT_DOMAIN:** `PRE_TOOL_INFERENCE` *(historical — closed)*  
**Date:** 2026-08-29

## Fixture

`04_logic_bug` is **VALID** (independent proof):

```text
build_exit=0
run_exit=1
stdout=FAIL got=-1 expected=5
```

Do **not** debug replace_in_file / run_command / workspace permissions until first-token is green.

## Latest opaque run (harness)

```text
agent_exit=-1
elapsed_ms≈197107
tool_log_hits=0
source_mutated=False
demo_break=false
scripted_runtime=false
```

Observed before exit: model catalog + `[ChatTemplate] family=phi3` only (no tool loop).

Harness housekeeping: double `-Force` on Copy-Item was a PowerShell error only; unrelated to agent failure. Canonical script `scripts/RUN_AGENT_E2E_002b.ps1` already uses single `-Force`.

## Ladder (current)

```text
model discovery       PASS
GGUF selection        PASS
chat-template setup   reached (family=phi3 — suspicious vs ChatML expectation)
prompt tokenization   UNKNOWN (prior TOKENIZER-PARITY-002c=PASS on Spm path)
prefill               UNKNOWN
first decode          UNKNOWN / NOT REACHED in opaque run
tool JSON emission    NOT REACHED
tool parsing          NOT REACHED
tool execution        NOT REACHED
source mutation       NOT REACHED
```

## Next gate (do not re-run 002b E2E)

```text
AGENT-FIRST-TOKEN-001
  stick A = auto template (phi3/zephyr)
  stick B = RAWRXD_CHAT_FAMILY=chatml
```

Script: `scripts/RUN_AGENT_FIRST_TOKEN_001.ps1`  
Evidence: `evidence/AGENT_E2E_002b/AGENT_FIRST_TOKEN_001/`

Required markers:

```text
[AGENT] MODEL_READY
[AGENT] PROMPT_RENDERED
[AGENT] TOKENIZED count=...
[AGENT] PREFILL_BEGIN
[AGENT] PREFILL_DONE
[AGENT] DECODE_BEGIN
[AGENT] TOKEN id=...
```

Fail immediately if first token is not established.
