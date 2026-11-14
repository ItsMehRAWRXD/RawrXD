# Highest-priority blockers → CERT gates

Authority: pasted RAWRXD_ENTERPRISE_PRODUCT_CERT_001 checklist · 0/128 · HELD · PROMOTE=0 · CERTIFIED=0

| Priority | Defect | Near GATE | Disposition |
|----------|--------|-----------|-------------|
| P0 | Gemma AA4F/tip_land AV (addrOk remasure) | G02-06 G06-06 | C9FB0B48 mid-VRAM; isoA bak→STREAM_SEH; AV_CLOSED=0 |
| P0 | GPU/ref numerical (FFN_ACT_2 / ATTN_OUT cascade) | G02-04 G02-05 G03-08 | ATTN_PRE_O@pos1 FA CLOSED (1CAEA762); FFN/OUT still OPEN |
| P0 | Multi-family GUI acceptance (llama32 stream-after-open) | G02-08 G04-01 G06-06 | Elastic+MARS ROOT_CLEAR; DURABLE=0; see STREAM residual |
| P1 | C36 LSP startup hangs | G07-01 G07-04 | cand INIT_OK RELATED; tip OPEN |
| P1 | ConPTY terminal-stop reliability | G05-05 G06-05 | cand PASS RELATED; tip remasure OPEN |
| P1 | M3 MODEL_SELECTED_TOOL / tipbound | G05-06 G08-01 | FORCE_TOOL PASS; model-select=0 |
| P2 | M4 Authenticode + CLEAN_VM | G12-02 G12-03 | ABSENT / NOT_RUN (no hypervisor) |
| P2 | CLI clean rebuild | G01-03 | EXIT=2; CLEAN_MACHINE=0 |

## llama32 STREAM residual (G02-08 / G06-06 RELATED ≠ PASS)

| Pin | OPEN | STREAM_ENTER | TOK | Note |
|-----|------|--------------|-----|------|
| 617F784E LOCKED | PASS | 0 | 0 | embd Alloc→Evict (binary pre-keepPinned); EXIT=NULL after HEADLESS_READY |
| 1EFF8608 keepGPU | FAIL POST_LOAD tensors=31 | 0 | 0 | keep-GPU pin regresses session; do not tip-land |

`NEXT_OWNER=STREAM_AFTER_OPEN` · `DURABLE=0` · `CROSS_SHA_CREDIT=0` · `TIP_CLIMB=HOLD`

PROMOTE=0 until all 128 gates PASS with independent sign-off.
