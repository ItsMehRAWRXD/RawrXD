# G08-01 RELATED — MODEL_SELECTED_AGENT Method C PASS

ASOF=2026-11-14T10:31:45-05:00  
RESULT=RELATED / MODEL_SELECTED_TOOL=1 / DISPOSITION=PASS  
PROMOTE=0 · INVENT_PASS=0 · CROSS_SHA_CREDIT=0 · NOT_RUN≠PASS · COMPLETE=1 · GATE_STOP=1

## Tip (Method C)
EXE_SHA256=`7C9680CBF025FCD78AD48DFE40D26EB45ADB78FB3F9B41321346990C77E42027`  
FORCE_TOOL=ABSENT · EXIT=0 · FILES_READ=1 · AGENT_VERIFIED=1

## Prior pin (numerical seals KEPT)
EXE_SHA256=`9797521CEB517B92AC52C518FB2BDB783628ABEA59366DFBE6E784C1A72951A3`  
Backup: `build_ninja/bin/rawr_FIX_Q6K_HOST_9797521C.exe` SHA_MATCH=1

## Attempts
| Method | Result |
|--------|--------|
| A (`-p` JSON-only / HOST_DECODE) on 9797521C | FAIL — agent decide → Python; parse tool=path |
| B (phi3 / llama3.2) on 9797521C | FAIL — non-JSON / garbage |
| C (prompt + allowlist parser + path resolve) | **PASS** — read→report; MODEL_SELECTED_TOOL=1 |

## Wire
`src/cli/rawr_agent_executor.hpp`  
- Drop manual `<|system|>/<|user|>` (missing `</s>` → alreadyFormatted bypass)  
- Let `generateStream` `formatSingle` apply TinyLlama template (same as `rawr run`)  
- Allowlisted `"tool":"<name>"` only (reject bare Python identifiers)  
- Resolve relative tool paths against workspace

## SSOT
`evidence/CLI_AGENT_MODEL_SELECTED_001/runs/c_method_runtime_template/`  
`evidence/MOVES_1_COMPLETE_001/` (COMPLETE=1; Q6K_SPV=OPEN; REAP=OPEN; PROMOTE=0)
