# Highest-priority blockers → CERT gates

Authority: pasted RAWRXD_ENTERPRISE_PRODUCT_CERT_001 checklist · 0/128 · HELD · PROMOTE=0 · CERTIFIED=0

| Priority | Defect | Near GATE | Disposition |
|----------|--------|-----------|-------------|
| P0 | Gemma AA4F / tip_land AV | G02-06 G06-06 | B8E5 R75 TOK=8 RELATED (314771e525); tip 6754 RO; ≠ CERT PASS |
| P0 | GPU/ref V_1 / ATTN_NORM_1@dim1072 | G02-04 G02-05 G03-08 | CLOSED=1 maxULP=0 F0A8018F RELATED (R78); ≠ matrix PASS |
| P0 | ATTN_PRE_O_1@pos1 (post R86 PRE_O_0) | G02-04 G03-08 | R86: FA006 PRE_O_0 CLOSED 3.488640e-08; C740 no-FA HOST_SDPA OPEN 2.292544e-05; remaining PRE_O_1 2.754107e-05 head11 RELATED ≠ PASS |
| P0 | FFN_DOWN_10 TRUE_FIRST (post L2 CLOSE) | G02-04 G03-08 | R87: OPEN 1.524854e-05; UP→ACT Q8 amplify NOT_CLOSABLE; SPV40E held; ≠ PASS |
| P0 | ATTN_PRE_O_11@pos0 | G02-04 G03-08 | R88 a92814d8c2: NOT_CLOSABLE 1.98e-04; V Q4K amplify; ≠ PASS |
| P0 | ATTN_OUT_14@pos0 | G02-04 G03-08 | R89: NOT_CLOSABLE 6.035976e-04; OPROJ REFUTED; TRUE_NEXT=FINAL_NORM 2.236689e+00; ≠ PASS |
| P0 | Multi-family STREAM / M1M2 TOK | G02-08 G04-01 G06-06 | F44D053D tip-absorb R82 OPEN=1 ENTER=1 TOK=2 SEH=0 RELATED; tip RO; 085f TOK=0 |
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
| 617F STREAM_REBIND R76 | RELATED | 0/1 | 0 | NOT_CLOSABLE: R74≡R75 SEH; RIP=__std_fs_get_file_id HANDLE=-1 (not embed rebind) |
| 1EFF8608 keepGPU | FAIL POST_LOAD | 0 | 0 | keep-GPU regresses session |
| 23B5115F keepGPU | OPEN+pin | 0 | 0 | bad_alloc 0xE06D7363 @ ProductRun before ENTER |
| 9181073D keepGPU | PASS auth=1 | 0 | 0 | OPEN closed; STREAM SEH 0xE06D7363 TOK=0 |
| CC621549 keepGPU | PASS auth=1 | 0 | 0 | gemma OPEN closed; stream not durable |
| 330ECC0A keepGPU | PASS auth=1 | 0 | 0 | R73 bad_alloc cleared; STREAM AV VA=-1 ENTER=0 |
| 3792BAA7 keepGPU | PASS | 1 | 2 | R81 durable remasure; SEH=0 EXIT=0 DURABLE=1 RELATED ≠ tip |
| F44D053D tip-absorb | PASS | 1 | 2 | R82 PUMP_SKIP ODR private; SEH=0 AUTH_HOLD RELATED ≠ tip |
| B8E5F6E5 PrivateCand | 1 | 1 | 8 | R75 EXIT=NULL closed; SEH=0 AV_CLOSED=1 RELATED ≠ tip |
| non617F 67350F71 R77 | 0 | 0 | 0 | EXIT=NULL partial (superseded by R78) |
| non617F 67350F71 R78 | 1 | 0 | 0 | OPEN_FAIL STREAM_SEH RVA=0x6B0FA (superseded by R79) |
| non617F 1EC00779 R79 | 1 | 1 | 2 | STREAM_SEH CLOSED DURABLE=1 private; tip RO RELATED ≠ CERT PASS |

`NEXT_OWNER` (split): GPU `ATTN_PRE_O_1_POS1` / `ATTN_Q_SPV_BITEXACT_WQ_HEAD11_OR_DUAL_PIPE` (FA006 VERIFIED_R86 RELATED) · llama32 `PRIVATE_CAND_NON617F_67350F71_STREAM_SEH_PRE_ENTER_RVA_6B0FA` (R78) · tip-absorb HOLD · `TIP_CLIMB=HOLD`

PROMOTE=0 until all 128 gates PASS with independent sign-off.
