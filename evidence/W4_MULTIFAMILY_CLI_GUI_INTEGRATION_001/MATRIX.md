# W4 MULTIFAMILY_CLI_GUI_INTEGRATION — Matrix

```text
PROMOTE=0 CERTIFIED=0 PCT_HELD=67/48/48
CLI=1BE8F02A… GUI=6754616E… INDEPENDENT=1
METHOD_C/Q6K=RETAINED (exact-SHA evidence; CROSS_SHA=0)
```

## Families

| Family | Model | Arch |
|--------|-------|------|
| tinyllama | tinyllama.gguf | llama |
| gemma3 | gemma3-1b-Q2_K.gguf | gemma3 |
| llama3.2 | llama3.2-3b-Q2_K.gguf | llama |

## CLI (fail-closed)

| Scenario | tinyllama | gemma3 | llama32 |
|----------|-----------|--------|---------|
| model-select | PASS | PASS | PASS |
| inference | PASS (TOK=8) | PASS (TOK=8) | PASS (TOK=1) |
| cancel | PASS | PASS | PASS |
| agent-tool FORCE | PASS (EXEC=2) | PASS (EXEC=2) | PASS (EXEC=2) |
| recovery | PASS | PASS | FAIL |

## GUI (fail-closed rescore)

| Scenario | tinyllama | gemma3 | llama32 |
|----------|-----------|--------|---------|
| model-select+infer | FAIL | FAIL | FAIL |
| cancel | FAIL | PASS | PASS |
| agent-tool HTTP | FAIL | FAIL | FAIL |
| recovery | FAIL | FAIL | FAIL |

`IDENTICAL_PARITY=0` · `W4=PARTIAL` · `PROMOTE=0`
