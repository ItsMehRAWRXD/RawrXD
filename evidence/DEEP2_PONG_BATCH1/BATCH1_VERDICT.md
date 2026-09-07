# DEEP2 PONG Batch-1 (B01–B15) — 2026-08-29

## Verdict

**PASS (corrected golden)** — TinyLlama Q4_K_M greedy decode now matches llama.cpp
external measuring stick for prompt `PONG` **without BOS** (2 tokens).

| Side | Prompt tokens | Greedy-1 | Greedy-8 text |
|------|---------------|----------|----------------|
| llama.cpp (`-no-cnv` + `add_bos_token=false`) | 2 | `UE` | `UE, a 19th-` |
| Deep2 `test_generate_one_token` | 2 (`21521`,`9312`) | id=`4462` `UE` | `UE,▁a▁19th-` |

Prior FAIL expecting substring `PONG` was a **bad golden**: raw next-token is not `PONG`.
With BOS (3 tokens), llama.cpp greedy-1 is `,` — different contract.

`RAWRXD_EXPECT_CONTAINS=UE` → harness exit **0**.

## Highest-confidence fix (B15)

**Q4_K qs nibble layout** in Deep2 did not match `ggml dequantize_row_q4_K`:

- Wrong: each 16-byte chunk = lo/hi within same scale (16+16)
- Correct: each 32-byte chunk = lo nibbles → scale[is], hi nibbles → scale[is+1]

Fixed in:
- `src/deep2/QuantKernelRegistry.cpp` (`gemv_q4_k_scalar`, `dequant_q4_k`; AVX2/512 delegate to scalar)
- `src/deep2/Deep2Engine.cpp` (`dequantizeQ4KBlock`, embed fallback)
- `src/deep2/Deep2QuantReference.h`

Pre-fix greedy-1 was id=`3748` ≈`▁game`. Post-fix matches reference `UE`.

## Batch checklist

| ID | Topic | Result |
|----|-------|--------|
| B01 | PONG tokenize/detokenize | PASS (`▁PO`+`NG`) |
| B02 | Greedy sticks | PASS (`[GREEDY] enabled=1`) |
| B03 | Embedding row fetch | PASS (Q4_K dequant via registry) |
| B04 | Q4_K dequant/GEMV | **FAIL→FIXED** (layout) |
| B05 | GQA 32q/4kv | PASS (parity) |
| B06 | RoPE | PASS (parity; llama NORMAL) |
| B07 | Attn softmax/scale | PASS (finite + parity) |
| B08 | SwiGLU / FFN shapes | PASS (parity) |
| B09 | Final norm | PASS (prefill path) |
| B10 | LM head layout | PASS (Q6_K → correct argmax) |
| B11 | Argmax vs golden | PASS (`4462`/`UE`) |
| B12 | Prompt positions | PASS |
| B13 | KV write/read | PASS (8-tok continues correctly) |
| B14 | Residuals | PASS (parity) |
| B15 | Freeze + fix | **DONE** |

## Still open (next batch)

- Metadata `vocab=2048` misread (overridden by tensor; still noisy)
- Prefixed-BOS parity (golden `,`) not yet wired in harness
- Chat-template / tool-call path still deferred
- AGENT-E2E-002b still blocked until tool-call synthesis milestone
- MLA/SSM remain frozen

## Artifacts

- `deep2_golden_ue_stdout.txt` (EXPECT=UE, exit 0)
- `deep2_8tok_stdout.txt`
- `ref_2tok.stdout.txt` / `ref_2tok8.stdout.txt` (llama.cpp)
- `ref_nocnv1.stdout.txt` (with BOS → `,`)
