# G02-08 / G04-01 RELATED — Ornith SEMANTIC beyond L3 ULP (≠ CERT PASS)

| Field | Value |
|-------|-------|
| BOARD | `BR_ORNITH_SEMANTIC_BEYOND_L3_001` |
| SEAL | `evidence/ORNITH_SEMANTIC_BEYOND_L3_001/` |
| RESULT | RELATED (not PASS) |
| SEMANTIC | **FAIL** |
| EXE_SHA | 340E56D7… **verified** `probe_rawr.exe.r103_moe.exe` |
| TIP | CEBA0DE4… CROSS_SHA=0 |
| MODEL | ornith REAP194 aaeb640f… |
| EXPERIMENTAL_SSM | AUTH_RESUME=1 · PROD_DECODE=0 |
| 8-token remasure | EXIT `0xC0000374` HEAP_CORRUPTION · TOK=0 · stdout empty · INCOMPLETE |
| Prior R101 coherence | TOK=2 stdout `isos️` FAIL (CROSS_SHA=0) |
| L3 ULP | R104 held ULP_CLOSED_VS_F32_ORACLE ≠ SEMANTIC CERT |
| PROD_PROVENANCE | PARTIAL_BIND / OPEN |
| REF_LOAD | BLOCKED (hybrid AFTER 753≠749) |
| PROMOTE | 0 |

## Law
`ULP_CLOSED != SEMANTIC_PASS` · `NOT_RUN != PASS` · this lane RAN → FAIL sealed honestly.
