# G02-08 / G04-01 RELATED — Ornith PACKED_GEMV L3 R104 (≠ CERT PASS)

| Field | Value |
|-------|-------|
| BOARD | `BR_ORNITH_PACKED_GEMV_L3_R104` |
| RESULT | RELATED (not PASS) |
| EXE_SHA | 340E56D7… **verified** `probe_rawr.exe.r103_moe.exe` (CROSS_SHA=0; no rebuild) |
| MODEL | ornith REAP194 aaeb640f… |
| DUMPS | R103 L3 E37/E33 IN/GATE/UP/DOWN (RUNTIME held) |
| ORACLE | Independent CPU Q4_K×Q8_K + Q6_K×Q8_K **f32** (not llama.cpp) |
| vs f32 oracle | **BITEXACT** — E37/E33 maxAbs=0 maxULP=0 |
| R103 root | Oracle f64 accum false MISMATCH (maxULP=4962 ABS_NEAR); product path OK |
| vs llama | NOT_CLOSABLE — `blk.40.ssm_conv1d.weight` **ABSENT_NOT_RENAME** |
| FFN_NORM | PARTIAL held (R101) |
| PACKED_GEMV | ULP_CLOSED_VS_F32_ORACLE |
| PROMOTE | 0 |

## Evidence
- `evidence/PRODUCTION_MATURITY_TOP25_001/board_receipts/BR_ORNITH_PACKED_GEMV_L3_R104.txt`
- `evidence/REAP_STRATA_UNSLOTH_OLLAMA_BENCH_001/deep2_ornith_packed_gemv_l3_r104/`
- Prior dumps: `.../deep2_ornith_packed_gemv_l3_r103/dumps`

## Law
`SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PASS` — ULP closed vs local f32 oracle; REF_LOAD/SEMANTIC still open; PROMOTE=0.
