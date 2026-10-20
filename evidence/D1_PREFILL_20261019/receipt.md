# D1 native multi-token prefill receipt

Date: 2026-10-19
Branch: codex/d1-opmajor
Base commit: 93fe08748cdd6c517fe10f809047dee0344cb3f3
Worktree: F:\rawrxd\.worktrees\codex-d1-opmajor
Build directory: F:\rawrxd\.build_d1_opmajor

## Implementation

The existing Executor::PrefillBatch path was retained and audited. The matrix harness calls PrefillBatch directly; the serial ExecuteToken loop is used only for the reference and the one-token continuation. The executor now rejects unbound/overflow requests and GPU batch CPU replay, fixes Q4_K LM-head rows/columns from GGUF tensor shape, bounds the fused Q4_K path to its supported batch size, and exposes actual batch counters for receipts.

The Q4_K fused Vulkan call takes rows=vocabulary and cols=hidden dimension. GGUF stores this matrix as dims[0]=hidden and dims[1]=vocabulary. The tested TinyLlama model has output.weight type Q6_K (14), shape [2048, 32000], so the Q4_K fused LM-head path was not selected in this real-model run; its counter remained zero. This run verifies the scalar LM-head path and all tested batch lengths. Do not treat the fused Q4_K branch as independently runtime-certified by this receipt.

## Model and executable

Model: F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
Model bytes: 668788096
Model SHA-256: 9fecc3b3cd76bba89d504f29b616eedf7da85b96540e490ca5824d3f7d2776a0
Executable: F:\rawrxd\.build_d1_opmajor\bin\deep2_d1_prefill_parity.exe
Executable SHA-256: 3db78aa51dde2b30c0388ad1b4f8eef00af33505eb20d894e4c9d11e81036c34
GPU device selected: AMD Radeon AI PRO R9700 (Vulkan)

## Commands and results

Configure and build command (exit 0):

    & cmd.exe /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul && cmake -S F:\rawrxd\.worktrees\codex-d1-opmajor -B F:\rawrxd\.build_d1_opmajor -G Ninja -DCMAKE_BUILD_TYPE=Release -DRAWRXD_BUILD_TESTS=OFF -DRAWRXD_BUILD_BENCHMARKS=OFF -DRAWRXD_BUILD_WIN32IDE=OFF -DRAWRXD_BUILD_WIN32IDE_QT=OFF -DFETCHCONTENT_ZLIB=OFF -DENABLE_CUDA=OFF -DENABLE_HIP=OFF -DENABLE_VULKAN=ON -DVULKAN_SDK=C:\VulkanSDK\1.4.357.0 && cmake --build F:\rawrxd\.build_d1_opmajor --target deep2_d1_prefill_parity --config Release --parallel 3'

D1 matrix command (exit 0):

    F:/rawrxd/.build_d1_opmajor/bin/deep2_d1_prefill_parity.exe --model F:/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf

Regression target attempt (failed at link, CMake process exit reported as -1 / 0xFFFFFFFF; linker LNK1120):

    & cmd.exe /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul && cmake --build F:\rawrxd\.build_d1_opmajor --target deep2_parity_trace --config Release --parallel 3'

The existing deep2_parity_trace target omitted src/utils/input_sanitizer.cpp and failed with four unresolved InputSanitizer symbols from gguf_loader.cpp. The D1-specific target includes that required source and builds successfully. No unrelated target was changed.

## Acceptance evidence

The serial 129-token GPU reference produced all 32000 logits at every position with zero CPU fallback. PrefillBatch then passed exact prefix lengths 1, 2, 8, 32, and 128. Every vocabulary logit at every prefilled position matched the serial reference bit-for-bit (max absolute difference 0). Actual K/V payloads for all committed rows in every block matched bit-for-bit (max absolute difference 0), with executor Position, LastToken, and CommittedKvTokens matching each prefix.

Each prefix was continued with the next known serial token. Continuation logits and the new K/V row in every block matched bit-for-bit; state advanced correctly and CPU fallback remained zero.

Aggregate measured counters for the five prefills: 1,034 quant-dot batch submissions, 26,334 batched dots, 5,472,000 compared logit floats, 1,926,144 compared K/V floats, and zero CPU fallbacks. Every row reported GPU-only=YES and grouped-work=YES. Per-run Vulkan submit/wait deltas are recorded in tinyllama_matrix_final.log; totals from process-global Vulkan counters are labeled process totals and are not used as per-run values.

Detailed run output: tinyllama_matrix_final.log. Matrix verdict: PASS, failures=0.

## Process inventory and timing qualification

For the earlier strict run tinyllama_matrix_v2.log, the before/after inventories each contained two deep2_quant_registry_all_types.exe processes from F:\wt_ide1\_s12_parity_build. The PID values changed between snapshots (before: 29048 and 21088; after: 5580 and 23836), so the evidence establishes the same two external test processes by executable/name before and after, not PID continuity. See processes_before.json and processes_after.json. Timing from that overlapped run is unqualified.

For the final rerun, processes_before_final.json and processes_after_final.json both show no deep2_quant_registry_all_types.exe process. The final run was a single correctness run, not a repeated performance study; its elapsed times are not performance acceptance evidence.

## Modified files

- CMakeLists.txt
- src/deep2/runtime_graph_executor.cpp
- src/deep2/runtime_graph_executor.hpp
- tools/deep2_d1_prefill_matrix.cpp
- evidence/D1_PREFILL_20261019/processes_before.json
- evidence/D1_PREFILL_20261019/processes_after.json
- evidence/D1_PREFILL_20261019/processes_before_final.json
- evidence/D1_PREFILL_20261019/processes_after_final.json
- evidence/D1_PREFILL_20261019/tinyllama_matrix_v2.log
- evidence/D1_PREFILL_20261019/tinyllama_matrix_final.log
- evidence/D1_PREFILL_20261019/receipt.md
