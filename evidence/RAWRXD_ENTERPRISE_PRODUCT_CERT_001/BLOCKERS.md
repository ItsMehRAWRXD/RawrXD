# Highest-priority blockers → CERT gates

| Priority | Defect | Near GATE | Disposition |
|----------|--------|-----------|-------------|
| P0 | Gemma INFER_STREAM_SEH / M1M2 combine AV | G02-06 G03-08 | Fix AV on AA4F8530 combine; tip-bind qDim |
| P0 | GPU/ref numerical ATTN_PRE_O_1 V_1 | G02-04 G02-05 G03-08 | Tighten V_1 FP16; remasure |
| P0 | Multi-family GUI acceptance | G04-01 G06-06 | Win32 path; no CROSS_SHA |
| P1 | C36 LSP startup hang | G07-01 G07-04 | cand INIT_OK RELATED; tip6754 RO OPEN |
| P1 | ConPTY terminal-stop | G05-05 G06-05 | cand stop PASS RELATED; matrix NOT_RUN |
| P1 | M3 MODEL_SELECTED_TOOL | G05-06 G08-01 | force-path ≠ agent select |
| P2 | M4 Authenticode + CLEAN_VM | G12-02 G12-03 | signed MSI; clean install |
| P2 | CLI rebuild on candidate SHA | G01-03 | EXIT=2 (missing headers / k2_digest); CLEAN_MACHINE=0 |
| P2 | Submodule remove-refusals absent | G01-01 | declared in .gitmodules; working tree ABSENT |
| P2 | License inventory gaps | G01-02 | vulkan_headers / rawrxd_zlib / root LICENSE incomplete |

PROMOTE=0 until all 128 PASS + sign-off.
