# RAWRXD_BATCH056 — Recovery, performance and release truth

Date: 2026-10-24
Branch: `local-30b-backend`
Review PR: https://github.com/ItsMehRAWRXD/RawrXD/pull/54 (DRAFT; not merged)

## Source-level changes (not hardware certification)

- `~dev/rawrxd/src/deep2/Deep2DualRowExecutor.hpp`: isolates two permanent GPU workers and serializes concurrent submissions. Production integration in `Deep2DualGpuRowSplit.cpp`.
- `tests/deep2_dual_row_executor_stress.cpp`: 8 submitters x 100 paired jobs; catches overlapping submitters and lane error propagation.
- `~dev/rawrxd/src/deep2/Deep2Q4KColumnSlices.hpp`: immutable shared packed Q4_K weight snapshots, one-block hysteresis on tensors of at least 64 blocks, size-checked repacks.
- `~dev/rawrxd/src/deep2/Deep2DualGpuRowSplit.cpp`: replaces mutable raw cache pointers; callers retain snapshots for duration of GPU dispatch.
- `~dev/rawrxd/src/deep2/Deep2Engine.cpp`: invalidates packed snapshots across model loading, weight replacement and unloading.
- `tests/deep2_q4k_column_cache_smoke.cpp`: validates byte-exact splits, retained immutable buffers, hysteresis and concurrent reads.
- `tests/deep2_q4k_repack_benchmark.cpp`: reproducible CPU-only repack comparison; never a GPU TPS benchmark.
- `compilers/native_compiler/src/common/Diagnostics.cpp`: validates source IDs, bounds diagnostic caret allocation, prevents out-of-bounds read.
- Recovered four audit scripts from `feature/reap-deepseek-671b-150tps`: `tools/rawrxd_per_file_source_audit.py`, `rawrxd_no_deps_audit.py`, `rawrxd_e2e_source_audit.py`, `rawrxd_cmake_source_admission.py`.
- Recovered `src/parity/Top25ParityMatrix.hpp` and its smoke test; `CertifiedCount` now requires a non-empty receipt reference.

## Observed portable tests (local isolated copies)

The C++20 executor and Q4_K cache were mirrored into an isolated Linux harness. GCC 14.2 and Clang both compiled and passed the concurrency/cache tests with `-Wall -Wextra -Werror -pedantic`.
This validates the independently exercised portable logic, NOT the full project build or GPU runtime.

Synthetic Q4_K CPU repack microbenchmark: 18 MiB weight, 40 alternating split calls (64/65 of 128 blocks).
- Previous behavior modelled by forcing a rebuild: 40 repacks, 109.496 ms
- Snapshot reuse with hysteresis: 1 repack, 21.405 ms
- Observed host-side microbenchmark ratio: 5.12x
- This is NOT a token/s increase and MUST NOT be represented as a 150 TPS receipt.

## GitHub Actions blocker (actual PR execution)

Run https://github.com/ItsMehRAWRXD/RawrXD/actions/runs/40089528728
- Workflow `Local 30B backend certification` returned FAILURE.
- Jobs `dual-row-executor-stress`, `native-elf64-smoke`, `windows-native`: FAILED before executing any steps.
- REST API returned `runner_name: ""`, `steps: []`, and duration approximately 3–4 seconds for all three jobs.
- CI failure is currently classified as **RUNNER UNASSIGNED / EXECUTION NOT STARTED**. It is NOT evidence of an MSVC, GCC or CMake source error.
- Job logs endpoint returned BlobNotFound. Do not mark either build PASS or source compilation FAIL from these results.

## Product source-admission blocker

Root `CMakeLists.txt` builds `deep2_engine_lib` from `src/deep2/Deep2Engine.cpp`.
The modified `~dev/rawrxd/src/deep2/Deep2DualGpuRowSplit.cpp` is declared in the separate `~dev/rawrxd/CMakeLists.txt` tree and in a root standalone `deep2_fused_lmhead_verify` GPU test target; it is **not listed in the root `deep2_engine_lib` sources**.
Therefore no production CLI / IDE 150 TPS improvement is claimed until code-path admission is proved. Do not force-add incompatible duplicated Deep2 engine sources.

## 45 gate audit

### A. Deep2 / GPU (15)
1. GGUF loader: implementation present; final model certification pending.
2. Quant kernels: implementation present; reference parity pending.
3. SSM finite handling: previously patched; rebuilt coherent generation pending.
4. Attention: GPU semantic parity pending.
5. FFN: multi-token dispatch parity pending.
6. GEMV: real-weight numerical parity pending.
7. KV cache: cross-context endurance pending.
8. Slingshot: legacy source found; production wiring pending.
9. Dual-worker submission: source defect fixed; physical GPU certification pending.
10. Q4_K packed-slice ownership: source defect fixed; physical GPU certification pending.
11. Model-lifecycle cache invalidation: source added; runtime certification pending.
12. Transfer/memory residency: physical throughput receipt pending.
13. Synchronization/wait attribution: GPU trace pending.
14. Sustained multi-token decode: physical soak pending.
15. 150 TPS: NOT PROVEN.

### B. Native IDE / toolchain (15)
1. Win32 IDE executable: CMake target present; CI execution blocked.
2. CLI executable: CMake target present; CI execution blocked.
3. Qt removal: incomplete; legacy Qt tree remains.
4. No third-party JSON: incomplete (nlohmann remains).
5. Editor: product behavior certification pending.
6. LSP: handshake + resilience pending.
7. GhostText/FIM: live server verification pending.
8. Terminal: output lifecycle pending.
9. PowerShell: native panel E2E pending.
10. Debugger: step/watch E2E pending.
11. Browser/WebView: navigation/snapshot E2E pending.
12. Agent tool dispatch: local model-tool-result proof pending.
13. Rollback/snapshot: source present, disaster recovery test pending.
14. Native compiler assembler/COFF: source present, broad compatibility pending.
15. PE/ELF/Mach-O Android/Apple: broad emission/link/sign certification pending.

### C. Enterprise / top-25 certification (15)
1. Stable branch strategy: draft PR created; diverged baseline needs review.
2. Windows MSVC build: blocked by CI runner startup.
3. Linux GCC build: only isolated C++20 portable tests observed.
4. Native code security: incomplete.
5. Dependency closure: audit scripts recovered; unresolved.
6. Per-file tracked source audit: script recovered; full report not yet run.
7. CMake source admission: recovered analyzer; report pending.
8. Qt/native feature mapping: partial.
9. Compiler diagnostic bounds: fixed in source; full regression pending.
10. Build artifacts/signing: pending.
11. Rollback/crash handling: pending enterprise soak.
12. Privacy/network controls: pending.
13. Release packaging/update: pending.
14. Top-25 matrix: 25 targets x 20 capabilities = 500 cells; evidence-based, NO 100% claim.
15. Enterprise release receipt: NOT CERTIFIED.

## Required continuation

1. Restore Actions runner execution (check repository Actions settings, quota/billing and runner policy). Re-run the draft PR checks.
2. Rebuild and test Deep2 `deep2_openai_server` on the Windows hardware with latest SSM fix; prove coherent response.
3. Reconcile main/development Deep2 engine trees, choose one canonical production target and wire tested dual-GPU code safely.
4. Benchmark R9700 and RX 7800 XT with identical numerical workloads, record GPU waits/transfers/kernel time/TPS and optimize measured bottleneck.
5. Run recovered source audit; remediate Qt/JSON and compiler/linker gaps file by file.
6. Do not merge draft PR or certify enterprise production until all required tests are green.
