# Highest-priority blockers → CERT gates

Authority: pasted RAWRXD_ENTERPRISE_PRODUCT_CERT_001 checklist · 0/128 · HELD · PROMOTE=0 · CERTIFIED=0

| Priority | Defect | Near GATE | Disposition |
|----------|--------|-----------|-------------|
| P0 | Gemma AA4F/tip_land AV (Deep2 bisect) | G02-06 G06-06 | CURRENT=mid-VRAM; bak→STREAM_SEH leaf fclose VA=-1 |
| P0 | GPU/ref ATTN_PRE_O_1 / FFN_DOWN cascade | G02-04 G02-05 G03-08 | FFN_ACT_2 CLOSED (SPV 4548BCF1); next LAYER2+/FFN_DOWN_0; PRE_O_1@pos1 OPEN |
| P0 | Multi-family STREAM after OPEN (qdim084) | G02-08 G04-01 G06-06 | keepGPU→bad_alloc 23B5115F; 617F Evict path |
| P1 | C36 LSP startup hangs | G07-01 G07-04 | tip6754 HANG/TIMEOUT RELATED (R70); cand INIT_OK RELATED only |
| P1 | ConPTY terminal-stop reliability | G05-05 G06-05 | tip-era PASS RELATED (R70); cand PASS RELATED; ≠ CERT PASS |
| P1 | M3 MODEL_SELECTED_TOOL / tipbound | G05-06 G08-01 | FORCE PASS; model-select=0 unk; wire SOURCE_WIRED RUNTIME=0 |
| P2 | M4 Authenticode + CLEAN_VM | G12-02 G12-03 | ABSENT / NOT_RUN (no hypervisor) |
| P2 | CLI clean rebuild | G01-03 | EXIT=2 @d88239; k2_digest/stubs; CLEAN_MACHINE=0; SUCCESS_EXE=NONE |
| P2 | Win32 GUI same freeze | G01-04 | NOT_RUN (CLI fail + GUI rebuild too heavy) |
| P2 | Deterministic dual-build | G01-05 | NOT_RUN (blocked by G01-03) |
| P2 | CI Windows + secondary | G01-07 | NOT_RUN (workflows inventoried; not dispatched) |


## llama32 STREAM residual (G02-08 / G06-06 RELATED ≠ PASS)

| Pin | OPEN | STREAM_ENTER | TOK | Note |
|-----|------|--------------|-----|------|
| 617F784E LOCKED | PASS | 0/1 | 0 | no keep-GPU string; Evict embed → EXIT=NULL or AV VA=-1 |
| 1EFF8608 keepGPU | FAIL POST_LOAD | 0 | 0 | keep-GPU regresses session |
| 23B5115F keepGPU | OPEN+pin | 0 | 0 | bad_alloc 0xE06D7363 @ ProductRun before ENTER |

`NEXT_OWNER=PRODUCTRUN_BAD_ALLOC_AFTER_KEEPGPU` · `DURABLE=0` · `CROSS_SHA_CREDIT=0` · `TIP_CLIMB=HOLD`

PROMOTE=0 until all 128 gates PASS with independent sign-off.
