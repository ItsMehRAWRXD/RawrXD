# Highest-priority blockers → CERT gates

Authority: pasted RAWRXD_ENTERPRISE_PRODUCT_CERT_001 checklist · 0/128 · HELD · PROMOTE=0 · CERTIFIED=0

| Priority | Defect | Near GATE | Disposition |
|----------|--------|-----------|-------------|
| P0 | Gemma AA4F/tip_land AV (Deep2 bisect) | G02-06 G06-06 | CURRENT=mid-VRAM; bak→STREAM_SEH leaf fclose VA=-1 |
| P0 | GPU/ref ATTN_PRE_O_1 V_1 + FFN cascade | G02-04 G02-05 G03-08 | V1 OWNER=ATTN_NORM_1@dim1072 CLOSED=0 maxULP=1; pos1 FA CLOSED (1CAEA762) |
| P0 | Multi-family STREAM after OPEN (qdim084) | G02-08 G04-01 G06-06 | keepGPU→bad_alloc 23B5115F; 617F Evict path |
| P1 | C36 LSP startup hangs | G07-01 G07-04 | cand INIT_OK RELATED; tip OPEN |
| P1 | ConPTY terminal-stop reliability | G05-05 G06-05 | cand PASS RELATED; tip remasure OPEN |
| P1 | M3 MODEL_SELECTED_TOOL / tipbound | G05-06 G08-01 | FORCE_TOOL PASS; model-select=0 |
| P2 | M4 Authenticode + CLEAN_VM | G12-02 G12-03 | ABSENT / NOT_RUN (no hypervisor) |
| P2 | CLI clean rebuild | G01-03 | EXIT=2; CLEAN_MACHINE=0 |

## llama32 STREAM residual (G02-08 / G06-06 RELATED ≠ PASS)

| Pin | OPEN | STREAM_ENTER | TOK | Note |
|-----|------|--------------|-----|------|
| 617F784E LOCKED | PASS | 0/1 | 0 | no keep-GPU string; Evict embed → EXIT=NULL or AV VA=-1 |
| 1EFF8608 keepGPU | FAIL POST_LOAD | 0 | 0 | keep-GPU regresses session |
| 23B5115F keepGPU | OPEN+pin | 0 | 0 | bad_alloc 0xE06D7363 @ ProductRun before ENTER |

`NEXT_OWNER=PRODUCTRUN_BAD_ALLOC_AFTER_KEEPGPU` · `DURABLE=0` · `CROSS_SHA_CREDIT=0` · `TIP_CLIMB=HOLD`

PROMOTE=0 until all 128 gates PASS with independent sign-off.
