# G02-08 / G04-01 RELATED — Ornith FFN_NORM / PACKED_GEMV R101 (≠ CERT PASS)

| Field | Value |
| --- | --- |
| BOARD | `BR_ORNITH_FFN_NORM_GEMV_R101` |
| SEAL | `REAP_STRATA_UNSLOTH_OLLAMA_BENCH_001/deep2_ornith_ffn_norm_gemv_r101` |
| EXE_SHA | E7A7EE9F… **verified** bak_r92 |
| MODEL_SHA | aaeb640f… Ornith REAP194 |
| GEOMETRY | FFN=512 qwen35moe L=41 H=2048 |
| TOK | 2 (dump remasure) |
| FFN_NORM vs local oracle | ULP_OK maxULP=2 maxAbs≈3e-7 @L0/pos0 (`post_attention_norm`) |
| FFN_NORM vs llama.cpp | **NOT_CLOSABLE** — load fail `blk.40.ssm_conv1d.weight` |
| PACKED_GEMV | OPEN — route/acquire RUNTIME (L3+; 1408 exec); numeric vs ref NOT_RUN |
| FIRST_DIVERGENCE | `LLAMA_MODEL_LOAD` (earliest vs ref) |
| PROD_PROVENANCE | PARTIAL bind started; PROD_DECODE residual |
| SEMANTIC | OPEN |
| PROMOTE | 0 |

RELATED ≠ CERT PASS. Tip 6754616E RO. PCT held 67/48/48. Enterprise 0/128 unchanged.
