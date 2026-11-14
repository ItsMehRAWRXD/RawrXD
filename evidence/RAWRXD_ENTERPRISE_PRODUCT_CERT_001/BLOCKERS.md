# Highest-priority blockers → CERT gates

| Priority | Defect | Near GATE | Disposition |
|----------|--------|-----------|-------------|
| P0 | Gemma INFER_STREAM_SEH / M1M2 combine AV | G02-06 G03-08 | Fix AV on AA4F8530 combine; tip-bind qDim |
| P0 | GPU/ref numerical ATTN_PRE_O_1 V_1 | G02-04 G02-05 G03-08 | Tighten V_1 FP16; remasure |
| P0 | Multi-family GUI acceptance | G04-01 G06-06 | Win32 path; no CROSS_SHA |
| P1 | C36 LSP startup hang | G07-01 G07-04 | tip6754 controlling |
| P1 | ConPTY terminal-stop | G05-05 G06-05 | stop/cleanup reliability |
| P1 | M3 MODEL_SELECTED_TOOL | G05-06 G08-01 | force-path ≠ agent select |
| P2 | M4 Authenticode + CLEAN_VM | G12-02 G12-03 | signed MSI; clean install |

PROMOTE=0 until all 128 PASS + sign-off.