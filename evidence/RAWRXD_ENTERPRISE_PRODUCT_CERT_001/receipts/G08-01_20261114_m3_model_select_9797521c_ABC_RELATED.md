# G08-01 RELATED — MODEL_SELECTED_AGENT A/B/C on pin 9797521C

ASOF=2026-11-14T10:05:00-05:00  
RESULT=RELATED / MODEL_SELECTED_TOOL=0 / DISPOSITION=FAIL  
PROMOTE=0 · INVENT_PASS=0 · CROSS_SHA_CREDIT=0 · NOT_RUN≠PASS · COMPLETE=0

## Pin
EXE_SHA256=`9797521CEB517B92AC52C518FB2BDB783628ABEA59366DFBE6E784C1A72951A3`  
FORCE_TOOL=ABSENT · tip restored from `rawr_FIX_Q6K_HOST_9797521C.exe` before probes

## Attempts
| Method | Result |
|--------|--------|
| A (`-p` JSON-only / HOST_DECODE) | FAIL — agent decide → Python; parse tool=path / no tool key |
| B (phi3-mini-Q2_K, llama3.2-3b-Q2_K) | FAIL — non-JSON / garbage under frozen agent prompt |
| C (parser allowlist) | NOT_APPLIED — would change EXE SHA off pin |
| Control `rawr run` TinyLlama | emits markdown `{"tool":"read","path":"README.md"}` ≠ agent seal |

## Blocker
`AGENT_DECIDE_PROMPT_NO_QUOTED_TOOL_JSON_ON_9797521C`

## SSOT
`evidence/CLI_AGENT_MODEL_SELECTED_001/` · `evidence/MOVES_1_COMPLETE_001/` (COMPLETE=0; Q6K_SPV=OPEN; REAP=OPEN)
