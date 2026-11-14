# Highest-priority blockers → CERT gates

Authority: pasted RAWRXD_ENTERPRISE_PRODUCT_CERT_001 checklist · 0/128 · HELD · PROMOTE=0 · CERTIFIED=0

| Priority | Defect | Near GATE | Disposition |
|----------|--------|-----------|-------------|
| P0 | Gemma AA4F / tip_land AV | G02-06 G06-06 | B8E5 R75 TOK=8 RELATED (314771e525); tip 6754 RO; ≠ CERT PASS |
| P0 | GPU/ref V_1 / ATTN_NORM_1@dim1072 | G02-04 G02-05 G03-08 | CLOSED=1 maxULP=0 F0A8018F RELATED (R78); ≠ matrix PASS |
| P0 | ATTN_PRE_O_1@pos1 head11 residual | G02-04 G03-08 | OPEN 2.754107e-05 @Q_POST idx747; CLOSE_010 ≠ this gate; AVX≡SPV ulp_spv=0; WQ-only BLOCKED; FFN_NORM cascade OPEN hyp; ≠ PASS |
| P0 | Ornith MoE FFN / inference | G02-08 G04-01 | R101: FFN_NORM ULP_OK vs local oracle (maxULP=2 @L0); vs llama NOT_CLOSABLE (missing blk.40.ssm_conv1d); PACKED_GEMV OPEN (L3+ route/acquire RUNTIME; numeric OPEN); FIRST_DIV=LLAMA_MODEL_LOAD; EXE=E7A7EE9F verified RELATED≠PASS; ≠TinyLlama CLI |
| P0 | FFN_DOWN_10 TRUE_FIRST (post L2 CLOSE) | G02-04 G03-08 | R87: OPEN 1.524854e-05; UP→ACT Q8 amplify NOT_CLOSABLE; SPV40E held; ≠ PASS |
| P0 | ATTN_PRE_O_11@pos0 | G02-04 G03-08 | R88 a92814d8c2: NOT_CLOSABLE 1.98e-04; V Q4K amplify; ≠ PASS |
| P0 | ATTN_OUT_14@pos0 | G02-04 G03-08 | R89: NOT_CLOSABLE 6.035976e-04; OPROJ REFUTED; ≠ PASS |
| P0 | FINAL_NORM@pos0 | G02-04 G03-08 | R90: NOT_CLOSABLE 2.236689e+00; Apply CLOSED bitexact; cascade INPUT; TRUE_NEXT=LOGITS 3.43e-01; ≠ PASS |
| P0 | LOGITS (post FINAL_NORM) | G02-04 G03-08 | R91: FUNCTIONAL_FAIL=1 maxAbs=3.432989e-01 ARGMAX_MATCH=1; residual-budget/ARGMAX-only; Dense HOLD ≠ invent MATCH; TRUE_NEXT=residual-budget |
| P0 | Multi-family STREAM / M1M2 TOK | G02-08 G04-01 G06-06 | F44D053D tip-absorb R82 OPEN=1 ENTER=1 TOK=2 SEH=0 RELATED; tip RO; COMBINE R95 AB1B6B7B MF=4/4 private BOARD_PROPOSAL_ONLY (supersedes 023005C2 column); ≠ tip PASS |
| P0 | Deep2 REAP generation / H2H | G02-08 G04-01 G04-08 | Laguna HEADS CLOSED + peer TOK>0 (R100); Ornith R99 TOK=8 PARTIAL; Laguna R97 SPEEDUP=OBSERVED_ONLY (32 vs 11 tok; 15.7× ≠ certified); H2H_PARITY=OPEN; ≠ invent |
| P1 | C36 tip LSP RUNTIME_REACHED | G07-01 G07-04 | **NEXT_BLOCKER** tip6754 still RUNTIME_REACHED=0; COMBINE R95 AB1B6B7B C36_RUNTIME_REACHED=1 + MF=4/4 SAME_SHA; tip absorb BOARD_PROPOSAL_ONLY (SHA≠6754); CROSS_SHA=0 PROMOTE=0; ≠ tip PASS |
| P1 | ConPTY terminal-stop reliability | G05-05 G06-05 | R94 private PASS; tip first-stop CLOSED R96 STOP 10/10 (BR_TIP_CONPTY_FIRST_STOP_CLOSED_R96); tip tail residual OPEN 1/10; ≠ CERT PASS |
| P1 | M3 MODEL_SELECTED_TOOL / tipbound | G05-06 G08-01 | FORCE PASS; model-select=0 unk; wire SOURCE_WIRED RUNTIME=0 |
| P2 | M4 Authenticode + CLEAN_VM | G12-02 G12-03 | SetupWizard host smoke R96 PASS (zip+install+rollback); Authenticode ABSENT; CLEAN_VM=0 NOT_RUN (no hypervisor) |
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

`NEXT_OWNER` (split): **TinyLlama** `FIRST_INVALID_LAYER` in `forwardGpuMultiMap` vs contiguous GPU (rebuild EXE acceptance OPEN) · **Ornith** `PACKED_GEMV_L3_NUMERIC` / `LLAMA_QWEN35MOE_LOAD_OR_ALT_REF` / PROD_PROVENANCE (R101 FFN_NORM local ULP_OK; vs llama NOT_CLOSABLE) · PRE_O_1 head11 · `LAGUNA_H2H_EQUIV_WORKLOAD` · PERF climb=NONE (`COMPLETE_002` retain 4.329) · `TIP_CLIMB=HOLD`

PROMOTE=0 until all 128 gates PASS with independent sign-off.
