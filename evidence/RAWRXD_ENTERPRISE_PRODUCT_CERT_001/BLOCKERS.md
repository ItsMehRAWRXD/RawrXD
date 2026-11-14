# Highest-priority blockers → CERT gates

Authority: pasted RAWRXD_ENTERPRISE_PRODUCT_CERT_001 checklist · 0/128 · HELD · PROMOTE=0 · CERTIFIED=0

| Priority | Defect | Near GATE | Disposition |
|----------|--------|-----------|-------------|
| P0 | Gemma AA4F / tip_land AV | G02-06 G06-06 | B8E5 R75 TOK=8 RELATED (314771e525); tip 6754 RO; ≠ CERT PASS |
| P0 | GPU/ref V_1 / ATTN_NORM_1@dim1072 | G02-04 G02-05 G03-08 | CLOSED=1 maxULP=0 F0A8018F RELATED (R78); ≠ matrix PASS |
| P0 | ATTN_PRE_O_1@pos1 FA head11 | G02-04 G03-08 | OPEN 2.754107e-05; FFN_DOWN_2 CLOSED SPV40E76D2A; CLOSE_004 in flight; ≠ PASS |
| P0 | Multi-family STREAM / M1M2 TOK | G02-08 G04-01 G06-06 | 3792BAA7 DURABLE=1 ENTER=1 TOK=2 SEH=0 RELATED (R81); tip RO; 085f TOK=0 |
| P1 | C36 LSP startup hangs | G07-01 G07-04 | tip6754 HANG/TIMEOUT RELATED (R70); cand INIT_OK RELATED only |
| P1 | ConPTY terminal-stop reliability | G05-05 G06-05 | tip-era PASS RELATED (R70); cand PASS RELATED; ≠ CERT PASS |
| P1 | M3 MODEL_SELECTED_TOOL / tipbound | G05-06 G08-01 | FORCE PASS; model-select=0 unk; wire SOURCE_WIRED RUNTIME=0 |
| P2 | M4 Authenticode + CLEAN_VM | G12-02 G12-03 | ABSENT / NOT_RUN (no hypervisor) |
| P2 | CLI clean rebuild | G01-03 | BUILD_OK=1 EXIT=0 EXE A95A1254…; CLEAN_MACHINE=0; EVIDENCE_PARTIAL ≠ PASS |
| P2 | Win32 GUI same freeze | G01-04 | EVIDENCE_PARTIAL BUILD_OK=1 EXIT=0 EXE E4B6A937… (R77 private); tip 6754616E RO; ≠ PASS |
| P2 | Deterministic dual-build | G01-05 | NOT_RUN (need dual-build after successful G01-04 EXE) |
| P2 | CI Windows + secondary | G01-07 | NOT_RUN (workflows inventoried; not dispatched) |


## llama32 STREAM residual (G02-08 / G06-06 RELATED ≠ PASS)

| Pin | OPEN | STREAM_ENTER | TOK | Note |
|-----|------|--------------|-----|------|
| 617F784E LOCKED | PASS | 0/1 | 0 | no keep-GPU string; Evict embed → EXIT=NULL or AV VA=-1 |
| 617F INIMAGE Restore 68CC | RELATED | 0/1 | 0 | RESTORE=1×2 OPEN=1 ENTER=1; soft Restore after onEvict → STREAM_SEH VA=-1 TOK=0 |
| 1EFF8608 keepGPU | FAIL POST_LOAD | 0 | 0 | keep-GPU regresses session |
| 23B5115F keepGPU | OPEN+pin | 0 | 0 | bad_alloc 0xE06D7363 @ ProductRun before ENTER |
| 9181073D keepGPU | PASS auth=1 | 0 | 0 | OPEN closed; STREAM SEH 0xE06D7363 TOK=0 |
| CC621549 keepGPU | PASS auth=1 | 0 | 0 | gemma OPEN closed; stream not durable |
| 330ECC0A keepGPU | PASS auth=1 | 0 | 0 | R73 bad_alloc cleared; STREAM AV VA=-1 ENTER=0 |
| 3792BAA7 keepGPU | PASS | 1 | 2 | R81 durable remasure; SEH=0 EXIT=0 DURABLE=1 RELATED ≠ tip |
| B8E5F6E5 PrivateCand | 1 | 1 | 8 | R75 EXIT=NULL closed; SEH=0 AV_CLOSED=1 RELATED ≠ tip |

`NEXT_OWNER=TIP_ABSORB_AUTH_HOLD` · BR_STREAM_ENTER_DURABLE_R81 · DURABLE=1 RELATED · `TIP_CLIMB=HOLD`

PROMOTE=0 until all 128 gates PASS with independent sign-off.
