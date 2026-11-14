# RELATED seals (≠ PASS on CERT_001 gates)

Historical / private-cand / partial RUNTIME — cite only. `CROSS_SHA_CREDIT=0`.

| Related artifact | Near gates | Note |
|------------------|------------|------|
| VALUATION_SCOREBOARD_CANON CLI67/GUI48 | — | Maturity floor ≠ checklist |
| tip 6754616E RO | G06 G07 | GUI tip pin |
| CLI 30DCB4B1 | G05 G08 | CLI tip pin (not matched by build_ninja rawr this measure) |
| ABSORB074 0B6229F2 | G02 G06 | MF column EXE |
| tip_land_qdim 7FD1F270 | G02 | STREAM_SEH closed cand; tip bind OPEN |
| M1M2 combine AA4F8530 | G02 G03 | SOURCE_WIRED; gemma AV |
| GPU_PARITY Q_PRE_ROPE + ATTN_PRE_O_0 C72A48E9 | G02 G03 | LIVE_CLOSED cand |
| ATTN_PRE_O_1 | G02-04 G02-05 G03-08 | V_1 FP16 bucket OPEN; CLOSE_001 LIVE_CLOSED=0 maxULP_f16=1 |
| BR_M3 FORCE_TOOL | G05 G08 | force-path only; MODEL_SELECTED=0 |
| M3 FORCE remasure 30DCB4 20261113_222135 | G05-06 | FORCE_TOOL EBT PASS force-path; MODEL_SELECTED=0 |
| M3 MODEL_SELECT attempt 30DCB4 20261113_222135 | G08-01 | MODEL_SELECTED_TOOL=0 (unk parse; timeout) |
| M4 MSI silent | G12 | Authenticode ABSENT; CLEAN_VM NOT_RUN |
| M4 Authenticode remasure 20261113_222135 | G12-02 | NotSigned MSI+SetupWizard; signed-cert blocker |
| M4 CLEAN_VM | G12-03 | NOT_RUN (no hypervisor surface) |
| FIRST_DIVERGE_001 seals | G02 G03 | remasure chain |
| G01-01/02/03 SELF_MEASURE EVIDENCE_PARTIAL @ 3d0928e74888 | G01 | Freeze + license stub + failed CLI rebuild; ≠ PASS |
| build_ninja/bin/rawr.exe E5F2D304… preexisting | G01-03 G01-06 | Stale binary after rebuild EXIT=2; forensics only |
| BR_MARS_DEDUP_LLAMA32_001 @ b61f03972e | G02 G04 | SOURCE_WIRED; remasure TOK |
| G08_M3_ISSUE49_SOURCE_WIRE_001 | G05 G08 | useCliAgent wire; EXE remasure OPEN |
| BR_ATTN_PRE_O_POS1_T2_KERNEL_R60 | G02 G03 | ROOT_CLEAR; CLOSED=0 |
| tip_land avfix082 F5997910 gemma | G02 | INFER_STREAM_SEH=1 TOK=0 |
| qdim083 llama32 E649DF99 | G02 G04 | SEH=0 TOK=0 ENTER=0 |
| qdim084 llama32 4F76D501 | G02 G04 | MARS dedup+keep; OPEN_SEH=0 STREAM_SEH=0 TOK=0 OPEN_PASS=0 |
| tip_land avfix084 gemma 1108BF01 | G02 | MARS dedup+keep; STREAM_SEH=0 TOK=0 OPEN_PASS=0 |
| receipts/G02-08_20261113_MARS_DEDUP_084_REMEASURE_RELATED.md | G02-08 | private 084 remasure RELATED≠PASS |

| cand_c36_conpty 0C6A965A | G07-01 G07-04 G05-05 G06-05 | LSP INIT_OK + ConPTY stop PASS on cand; tip6754 RO unchanged |
| P2 llama32 Elastic+MARS qdim083/084 | G02-08 G06-06 | ROOT_CLEAR; DURABLE TOK=0; RELATED≠PASS |
| receipts/G02-08_20261113_P2_LLAMA32_RELATED.md | G02-08 | private OPEN; CERT NOT_RUN |
| receipts/G06-06_20261113_P2_LLAMA32_RELATED.md | G06-06 | tipbound GEN still OPEN |
| BR_P2_MARS_KEEP_GPU_AMPLIFIER_001 | G02-08 G06-06 | Host-Evict amplifier SOURCE_WIRED |
| BR_ATTN_NORM_1_CASCADE_OWNER_R62 D282E57C | G02-04 G02-05 G03-08 | OWNER=ATTN_NORM_1@dim1072; CLOSE=0 |
| BR_AA4F8530_HOTPATCHER_ROLLBACK_R62 | G02 G03 | AV emergencyRollback+0x88; remasure addrOk |
| AA4F addrOk remasure C9FB0B48 / isoA 21234DAF | G02 G03 | AV_CLOSED=0; bak clears mid-VRAM→STREAM_SEH |
| receipts/G02-06_20261113_C9FB0B48_AA4F_ADDROK_RELATED.md | G02-06 | RELATED≠PASS; tip RO |
| BR_ATTN_PRE_O_POS1_FA_CLOSED_R64 1CAEA762 | G02-04 G02-05 | POS1 CLOSED under TOL 1e-6; matrix ≠ PASS |

Update this index when new RELATED receipts land. Never auto-PASS.

