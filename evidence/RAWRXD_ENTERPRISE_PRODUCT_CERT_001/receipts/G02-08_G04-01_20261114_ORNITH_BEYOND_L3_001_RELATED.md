# G02-08 / G04-01 RELATED — Ornith beyond L3 ULP (≠ CERT PASS)

| Field | Value |
|-------|-------|
| BOARD | `BR_ORNITH_BEYOND_L3_001` |
| SEAL | `evidence/ORNITH_BEYOND_L3_001/` |
| RESULT | RELATED (not PASS) |
| EXE_SHA | 340E56D7… **verified** `probe_rawr.exe.r103_moe.exe` (CROSS_SHA=0) |
| MODEL | ornith REAP194 aaeb640f… |
| R104 ULP | **HELD** ULP_CLOSED_VS_F32_ORACLE — R103 f64 false MISMATCH **not reabsorbed** |
| Prefill | tip_tok8_b L0..L40 **FINITE** (L0≈79 L40≈786) |
| Generation | POST_L40 **HEAP** `0xC0000374` · TOK=0 · stdout empty |
| Semantic | **FAIL** |
| Contention | L0 post-SSM explode under GPU load (POST_ATTN sane) ≠ ULP reopen |
| bak_r92 | TOK=8 degenerate `some`×8 · CROSS_SHA=0 control |
| Peer | HYBRID_LOAD R105 llama PASS ≠ Deep2 SEMANTIC; ORNITH_SEMANTIC_BEYOND_L3_001 FAIL held |
| PROMOTE | 0 |

## Evidence
- `evidence/ORNITH_BEYOND_L3_001/` (tip_tok8_b controlling)
- `evidence/PRODUCTION_MATURITY_TOP25_001/board_receipts/BR_ORNITH_BEYOND_L3_001.txt`
- Prior: R104 / ORNITH_SEMANTIC_BEYOND_L3_001

## Law
`ULP_CLOSED != PREFILL_FINITE != TOKEN_SURVIVED != SEMANTIC_PASS` — PROMOTE=0.
