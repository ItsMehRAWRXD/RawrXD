# Deep2 performance + GPU-vs-CPU quality (2026-11-28)

Real measurement on the built `deep2_openai_server.exe` (tinyllama-1.1b-chat Q4_K_M, CPU).

## Throughput (CPU)
```
POST /v1/chat/completions  max_tokens=32
  completion_tokens=32  prompt_tokens=21  elapsed=4.12 s
  => ~7.8 tokens/s (decode incl. prefill)
  content: "In the year 2050, the world was a different place. The skies were filled
            with flying robots, their sleek bodies gle"  (COHERENT)
```
Server log: `[POST /v1/chat/completions] 200  4055.50 ms`.

## Finding: GPU (Vulkan) path produces GARBLED output
Same model, `--vulkan`:
```
content "\nWHEREASPBasedeeding"  (GIBBERISH), 8 tokens / 2.2 s, HTTP 200
```
CPU output is coherent; Vulkan output is garbled. This is a real GPU-path quality/correctness
discrepancy (likely a Vulkan quant-dot / shader dispatch issue), NOT a build defect. Candidate
for a separate Deep2 GPU-kernel correctness fix (cf. Package 9 quant dispatch gaps).

## G15 (150 TPS) status
~7.8 TPS (CPU, tinyllama Q4) is far below the 150 TPS target — consistent with the ledger's
G15 BLOCKED (~4.5 TPS). This is a performance/model gap, not a pipeline defect.

## Narrowed diagnosis (single-GPU reproduces)
Forced single GPU (`DEEP2_GPU_DEVICES=0` -> `DEEP2_EXEC_PATH=SINGLE_GPU`,
`DEVICE_COUNT_OPENED=1`, `COST_WINNER=SOLO`, layers 0-21 on the R9700): output is STILL
garbled ("WHEREASPBluxtentertainmentionized..."). => The dual-GPU handoff is NOT the cause.

The single-GPU GPU forward runs all ops (RMSNORM/QKV/ROPE/ATTN/SOFTMAX/FFN x1144,
`DEEP2_REAL_GPU_FORWARD=1`, `Q4K_PACKED_OPS=6968`) and produces FINITE but numerically
WRONG logits (`[LOGIT_DIAG] top5: 13=22.72 ...`, `nonFiniteLogits=0`) -> wrong token
selection. The CPU reference (same model/quant) is coherent. => Bug is in the single-GPU
Q4_K packed GEMV forward path (shader/kernel numerical divergence), NOT multi-GPU.

## Next focused fix (out of scope here)
Diff the GPU Q4_K packed GEMV (`deep2_qgemv*.spv` / packed path) against the CPU Q4_K GEMV
reference on a single layer to localize the numerical error. This is a GPU-kernel correctness
task (cf. Package 9 quant dispatch), not a build/integrity defect.