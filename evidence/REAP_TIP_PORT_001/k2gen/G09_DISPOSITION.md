# G09 disposition — Kimi under `F:\ollamamodels`

`PROMOTE=0` · `CERTIFIED=0` · SHA `EA0371A1019EF10B207E41B42104FCF4ECFF9EA523FFF44FB7868E89BD4EA112`

## Model path (authoritative)

```text
F:\ollamamodels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\
  *.gguf × 13   ← MULTISHARD_SHARDS_INDEXED=13/13
  blobs/ manifests/ Modelfile  ← auxiliary (explains “16 files” listing)
SHARD1=...\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf
```

(`F:\OllamaModels` is the same volume path on Windows.)

## Process gates

| Gate | Result |
|---|---|
| G09 L2 dense SwiGLU | PASS EXIT=0 |
| G09 full 61L host `--reap 30GB/8` ×8 | PASS process EXIT=0 LAYER_COUNT=61 GENERATED_TOKENS=8 ~139–159s |
| L0 DENSE_SWIGLU LIVE | PASS |
| ChatTemplate | Forced deepseek (OllamaModels∋llama false-friend fixed) |
| Output quality | FAIL incoherent |
| Host token IDs (LOGITS_RETURN_OK) | `220,11,220,4275,220,4275,4275,59689` |
| Host deterministic re-run | 8/8 match vs g09_dense_full |
| GPU DualStick 61L ×8 | PASS process; EXPERT_GPU_EXEC=3840 TRUE_RUNTIME=1 |
| Host↔GPU token parity | **FAIL 0/8** (diverges at step 0) |
| Independent ollama/llama.cpp reference | NOT_TESTED (no local kimi-k2 instruct in `ollama list`) |

## Geometry note (open)

```text
GGUF_DYNAMIC hd=576
MLA headDim=192 (qkNope=128 + qkRope=64)
PRODUCT_SEAL HEAD_DIM=112 (=7168/64)
GENERATE_STREAM HEAD_DIM=192
```

Classify 112 vs 192 vs 576 before claiming attention parity.

## Next

1. Wire K2 `DEEP2_GEN_QUALITY_TRACE` (onToken) — in flight.
2. Close host↔GPU first-token divergence (MoE GEMV / DualStick).
3. Import/run independent reference against `F:\ollamamodels\...` same prompt+greedy.
4. Do not PROMOTE while quality FAIL and HOST_GPU_TOKEN_MATCH=0.

```text
G09_L2_PROCESS_PASS=1
G09_FULL_PROCESS_PASS=1
G09_FULL_QUALITY_PASS=0
G09_HOST_GPU_TOKEN_MATCH=0/8
K2_NUMERICAL_PARITY=FAIL_HOST_VS_GPU
K2_REFERENCE_PARITY=NOT_TESTED
CERTIFIED=0
PROMOTE=0
```
