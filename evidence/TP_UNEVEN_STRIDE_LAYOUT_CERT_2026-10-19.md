# Deep2 F32 GEMV Stride Optimization Certificate

**Date:** 2026-10-19  
**Decision:** 16-F32-element (64-byte) physical row-stride padding is the fastest tested candidate on both GPUs for this synthetic F32 GEMV sweep. This is a microbenchmark optimization result, not a production tensor-parallel or 150 TPS certification.

## Reproducibility and correctness

The analyzer validated all four isolated receipt/log pairs against the current source, shader, benchmark executable, and SPIR-V hashes. Each run covered 98 shapes (49 balanced and 49 rank-0-plus-one ragged), with 1024 rows and 30 measured repetitions per shape. Every case had zero maximum absolute error against both CPU and single-GPU Vulkan references, and every padded weight tail contained only zeros.

The benchmark changes only the physical F32 weight-row stride. Logical columns and input width remain unchanged; shader accumulation stops at the logical width. Cross-device output reduction is host-staged. Competing GPU benchmark checks were zero immediately before and after each candidate run.

## Timing results

Values are medians of per-shape calibrated GPU medians, in microseconds. The width-2049 row uses the balanced 4098-global-column case; it isolates the local row width from shard imbalance.

| Physical stride multiple | R9700, 49-shape median | RX 7800 XT, 49-shape median | R9700 at width 2049 | RX 7800 XT at width 2049 |
|---:|---:|---:|---:|---:|
| 1 | 237.9 | 289.4 | 354.0 | 443.2 |
| 4 | 140.5 | 169.0 | 167.0 | 202.6 |
| 8 | 121.6 | 144.2 | 141.6 | 166.2 |
| 16 | 114.5 | 138.5 | 120.3 | 140.5 |

At local width 2049, the 16-element candidate reduced calibrated GPU execution time by **66.0% (2.94×)** on the R9700 and **68.3% (3.15×)** on the RX 7800 XT versus contiguous rows.

For the 1024-row width-2049 case, stride 2064 adds 15 F32 values per row (60 bytes per row; 61,440 bytes total), about 0.73% over the logical weight payload. Input vectors stay logical-width.

Pad-16 balanced medians grouped by width modulo four:

- R9700: mod-0/1/2/3 = 114.1 µs, 115.3 µs, 114.9 µs, 114.1 µs; max-minus-min spread 1.2 µs.
- RX 7800 XT: mod-0/1/2/3 = 138.3 µs, 138.7 µs, 138.3 µs, 138.4 µs; max-minus-min spread 0.4 µs.

## Interpretation and scope

The tested pattern supports row-stride sensitivity as the cause of the previous width-2049 slowdown. It does not establish whether cache sectors, memory transactions, compiler code generation, or another hardware mechanism is responsible. RGA 2.15 generated static offline ISA/statistics for `gfx1201` and `gfx1101`; these are not live occupancy, hardware-counter, or RGP timeline measurements.

The stride-aware F32 view and zero-tail preparation helper provide an explicit integration seam. Ordinary GGUF model loading still uses its existing layout unless a caller prepares and supplies a padded F32 view. The strict single-R9700 TinyLlama smoke preserved its recorded control stream (`6000 16000 16000 16000`), executed 4,304 planned GPU GEMVs, and reported zero planned CPU GEMVs, zero unplanned fallbacks, and zero strict violations; it verifies a surrounding runtime path, not automatic GGUF padding. Its single-run 0.1147 TPS is not a performance result.

Gate 10 remains **OPEN / NOT STARTED**: this sweep shards synthetic GEMV columns and reduces on the host. It does not prove model-level tensor parallelism, cross-device activation/reduction transfer, allocation high-water, or full-logit parity. The two-device layer-parallel smoke remains a separate greedy-parity regression.

## Receipts

- `evidence/TP_UNEVEN_WIDTH_SWEEP_2026-10-19_FINAL_PAD1_RGA215/receipt.txt`
- `evidence/TP_UNEVEN_WIDTH_SWEEP_2026-10-19_FINAL_PAD4_RGA215/receipt.txt`
- `evidence/TP_UNEVEN_WIDTH_SWEEP_2026-10-19_FINAL_PAD8_RGA215/receipt.txt`
- `evidence/TP_UNEVEN_WIDTH_SWEEP_2026-10-19_FINAL_PAD16_RGA215/receipt.txt`
- TinyLlama runtime smoke: `evidence/TP_UNEVEN_WIDTH_SWEEP_2026-10-19_FINAL_PAD16_RGA215/tinyllama-gpu-smoke.receipt.txt`
- Multi-GPU layer-parallel regression: `evidence/TP_UNEVEN_MULTI_GPU_LAYER_SMOKE_2026-10-19.receipt.txt`

`MICROBENCH_CERTIFICATE=PASS`  
`PRODUCTION_TENSOR_PARALLEL_CERTIFICATION=NOT_ESTABLISHED`  
`GATE_10=OPEN`
