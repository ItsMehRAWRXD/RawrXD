# Highest-priority blockers → CERT gates

| Priority | Defect | Near GATE | Disposition |
|----------|--------|-----------|-------------|
| P0 | Gemma AA4F8530 AV @ HotPatcher::emergencyRollback+0x88 | G02-06 G03-08 | Deep2Engine.obj delta vs 7FD1; remasure addrOk land |
| P0 | GPU/ref ATTN_PRE_O_1 V_1 | G02-04 G02-05 G03-08 | OWNER=ATTN_NORM_1@dim1072 (not Q6); maxULP_f16=1 CLOSE=0 |
| P0 | Multi-family GUI acceptance | G04-01 G06-06 | Win32 path; no CROSS_SHA |
| P1 | C36 LSP startup hang | G07-01 G07-04 | cand INIT_OK RELATED; tip6754 RO OPEN |
| P1 | ConPTY terminal-stop | G05-05 G06-05 | cand stop PASS RELATED; matrix NOT_RUN |
| P1 | M3 MODEL_SELECTED_TOOL | G05-06 G08-01 | force-path ≠ agent select |
| P2 | M4 Authenticode + CLEAN_VM | G12-02 G12-03 | signed MSI; clean install |
| P2 | CLI rebuild on candidate SHA | G01-03 | EXIT=2 (missing headers / k2_digest); CLEAN_MACHINE=0 |
| P2 | Submodule remove-refusals absent | G01-01 | declared in .gitmodules; working tree ABSENT |
| P2 | License inventory gaps | G01-02 | vulkan_headers / rawrxd_zlib / root LICENSE incomplete |

PROMOTE=0 until all 128 PASS + sign-off.
