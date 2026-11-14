# RawrXD Historical Sovereign/Braided Source Recovery

Recovery date: 2026-11-14
Destination: ItsMehRAWRXD/RawrXD, branch `recovery/sovereign-braided-streamer-20261114`
Original repository: ItsMehRAWRXD/RawrXD-IDE-Final
Immutable original ref: `b57a9880825e81dd44c218da23f920629afeafc3`

All files beneath this folder were **copied from the original repository at that ref**, preserving their original relative source paths under `recovered/sovereign-braided-2026/`. No production `src/`, `kernels/`, `tests/`, CMake, or build targets were changed. Original source code was not modified to make it build.

## A. April 26 2026: synthetic streamer / unbraid fingerprint

- `tests/streaming/sovereign_streamer_fingerprint_test.cpp` (original Git blob `db2d23d269e687038827582eb7d138e3ca8ea209`)
- `tests/streaming/build_v2*.bat` (historical machine-specific build scripts)

This is the experiment described as compression -> decompression -> unbraid *before token 1*, 50 GiB **virtual** model, 1/16 synthetic bit-plane storage, 16 KV lanes, speculative co-compression, AVX-512 compute, memory-mapping and Win32 page-fault instrumentation.

Important source audit: it allocates a `MODEL_VIRTUAL_SIZE / 16` byte dummy compressed vector and fills it with `0xAA`; there is no corresponding real GGUF tensor encoding/decoding. Its 'decompress' multiplies activation floats by 4, its 'unbraided' step applies simple elementwise arithmetic, and its model file is a sparse/dummy file capped at 1 GiB rather than an actual 50 GiB checkpoint. Its 'speculative tokens' are loop iterations with synthetic bookkeeping, not model-verified tokens. The old 9,358.91 unbraided TPS / 8,141.39 speculative TPS / 3,649.47 overall TPS figures are therefore **synthetic workload benchmarks, not real inference TPS**.

Do not run blindly: the default compressed vector alone allocates 3.125 GiB, plus a sparse file that may appear up to 1 GiB. The legacy build scripts hard-code `D:\\rawrxd` and `C:\\VS2022Enterprise`. Review and adapt locally before any execution; they are not modern build gates.

## B. Actual 2+2+4 bit-plane quantization and fingerprint

- `src/quantization/BraidedQuantizer.hpp`
- `src/quantization/BraidedQuantizer.cpp`
- `src/quantization/braided_quantizer_fingerprint.hpp`
- `src/quantization/braided_quantizer_fingerprint.cpp`

This distinct implementation quantizes FP32 tensor weights to 8-bit with scale/zero point, then separates the 8-bit symbols into a base 2-bit lane, a 2-bit refinement lane, and a 4-bit detail lane, with partial and full reconstruction and MSE fingerprint tests. Full 8-bit braided storage represents approximately **4:1 vs FP32**, excluding metadata, not 16:1. Its achieved accuracy has not been revalidated on current models.

## C. Multi-precision braided tensor/loader experiments

- `src/BraidedQuantizer.hpp` — large v1.0 BP1/BP2/BP3/BP4/BP6/BP8/F16/F32, BraidManager, forward and KV experiments.
- `src/BraidedModelLoader.h/.cpp` — Win32 GGUF/mmap loader experiment.
- `src/inference/BraidedModelLoader.h/.c` — distinct C loader API.
- `src/ide/BraidedModelLoader.h/.cpp` and `src/ide/SovereignBraidedLoader.h/.cpp` — IDE integration experiments.

These are not automatically one production-ready linked implementation, and multiple similarly named APIs may conflict. Audit actual GGUF metadata/tensor shapes, reconstruction fidelity, and build symbols before integration.

## D. July 9 2026 tunable compression kernel

- `kernels/compression_engine.h/.cpp`
- `tests/compression_engine_test.cpp`
- `COMPRESSION_ENGINE_RESULTS.md`

Historical receipts reported 6.4:1 and 6.7:1 compression profiles with 22.43 ms and 20.67 ms decompression respectively, using synthetic/generated weights. They are separate from the April sovereign fingerprint.

## E. Memory pressure pipeline 'unbraid' (different meaning)

- `include/UnbraidPipeline.h`
- `src/masm/RawrXD_UnbraidPipeline.asm`

These files **bypass and restore execution stages based on memory pressure**, not a weight bit-plane decoder. Keep separate from quantizer unbraiding.

## Recovery disposition

```
ORIGINAL_SOURCE_LOCATED=YES
HISTORICAL_SOURCE_COPIED=YES
CURRENT_PRODUCT_INTEGRATION=NO
CURRENT_BUILD=NOT_RUN
GGUF_WEIGHT_DECOMPRESSION_FROM_STREAMER=NOT_IMPLEMENTED_IN_FINGERPRINT
LEGACY_TPS=SIMULATED_NOT_PRODUCTION
PROMOTE=0
CERTIFIED=0
```

## Suggested safe next step

Keep this directory as immutable research evidence. Identify the original executable/source hash and rerun legacy isolated tests in a disposable scratch directory only. For any production port, implement **actual bounded tensor codec decode**, source GGUF/oracle numerical parity, and a runtime integration test on the exact current CLI executable SHA. Never replace the production loader with synthetic fingerprint logic.
