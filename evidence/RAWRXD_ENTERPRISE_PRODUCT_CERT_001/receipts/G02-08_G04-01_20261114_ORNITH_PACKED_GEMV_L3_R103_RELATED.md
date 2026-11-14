# G02-08 / G04-01 RELATED — Ornith PACKED_GEMV L3 R103 (≠ CERT PASS)

| Field | Value |
|-------|-------|
| BOARD | `BR_ORNITH_PACKED_GEMV_L3_R103` |
| RESULT | RELATED (not PASS) |
| EXE_SHA | 340E56D7… **verified** `probe_rawr.exe.r103_moe.exe` (≠ bak_r92; CROSS_SHA=0) |
| MODEL | ornith REAP194 aaeb640f… |
| FIRST_MOE | L3 experts dumped E37,E33 (IN/GATE/UP/DOWN) |
| ORACLE | Independent CPU Q4_K×Q8_K + Q6_K×Q8_K (not llama.cpp) |
| vs oracle | MISMATCH — E37 maxAbs=4.65e-7 maxULP=4962 (ABS_NEAR, not ULP_OK) |
| vs llama | NOT_CLOSABLE — `blk.40.ssm_conv1d.weight` **ABSENT_NOT_RENAME** |
| FFN_NORM | PARTIAL held (R101) |
| PACKED_GEMV | OPEN |
| PROMOTE | 0 |

## Evidence
- `evidence/PRODUCTION_MATURITY_TOP25_001/board_receipts/BR_ORNITH_PACKED_GEMV_L3_R103.txt`
- `evidence/REAP_STRATA_UNSLOTH_OLLAMA_BENCH_001/deep2_ornith_packed_gemv_l3_r103/`

## Law
`SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PASS` — dumps RUNTIME; numeric ULP not closed; PROMOTE=0.
