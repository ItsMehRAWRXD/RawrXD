# RAWRXD Batch 024 — 45 acceptance moves (3 × 15)

**Date:** 2026-10-24. **Baseline:** `preservation/source-baseline-20261021` at `7d5106b3b318e59c920d144f760e954d41c11768`.

**Rules:** SOURCE FIXED != COMPILED != TESTED != CERTIFIED. Existing branches and files are evidence, not automatically product-integrated. A failing or unstarted Actions job never counts as a passed gate. This batch is an audited checklist with some implemented infrastructure, **not 45 finished repairs**.

## A — source, compiler, linker and platform integrity

| # | Acceptance move | Status | Proof required or finding |
|---:|---|---|---|
| 01 | Preserve canonical source baseline | BASELINE VERIFIED | 7d5106b3b318e59c920d144f760e954d41c11768; do not rewrite |
| 02 | Restore snapshot engine source | BLOCKER | Root CMake references five missing src/snapshot files; recover exact source with provenance |
| 03 | Run tracked-file hash and per-file static dependency inventory | INTEGRATED; CI UNVERIFIED | tools/rawrxd_per_file_source_audit.py recovered from REAP branch |
| 04 | Audit literal CMake source-path admission | INTEGRATED; CI UNVERIFIED | tools/rawrxd_cmake_source_admission.py recovered from REAP branch |
| 05 | Certify first-party COFF-to-PE32+ linker | IMPLEMENTED; CI UNVERIFIED | Portable fixture-driven cert added; x64 PE only |
| 06 | Make root CTest test discovery non-vacuous | SOURCE FIXED; CI UNVERIFIED | enable_testing() now in phase2_linker parent CMake |
| 07 | Windows MSVC x64 native linker build | CI DEFINED; RUN NOT CERTIFIED | Actions matrix checks rawrxd_link + fixtures |
| 08 | Windows OS loader execution of emitted PE | CI DEFINED; RUN NOT CERTIFIED | ExitProcess 42, tail and call variants |
| 09 | Linux GCC cross-host PE emission | CI DEFINED; RUN NOT CERTIFIED | PE validated; PE execution not claimed on Linux |
| 10 | Linux Clang cross-host PE emission | CI DEFINED; RUN NOT CERTIFIED | PE validated; no ELF emission claim |
| 11 | Add x86 COFF and PE32 test corpus | OPEN | Current root CMake rejects x86 and current test target emits PE32+ x64 |
| 12 | Recover and certify MASM x64 assembler | OPEN | Historical src/asm restore notice explicitly reports rawrxd_scc.asm missing |
| 13 | Recover and certify NASM x86/x64 assembler | OPEN | Assemble real directives, relocations and import cases; compare with NASM |
| 14 | Arbitrary C17/C++20 compilation and linking | OPEN | Compile nontrivial third-party programs in isolation with no project runtime dependencies |
| 15 | Self-hosted compiler bootstrap / ABI certification | OPEN | Repeated generation produces equivalent binary and passes test corpus |

## B — IDE, Qt-to-native recovery, and runtime workflows

| # | Acceptance move | Status | Proof required or finding |
|---:|---|---|---|
| 16 | Identify Qt-only modules and capture testable behavior | OPEN | Qt orchestration, paint, git, terminal remain in source |
| 17 | Verify native editor open/save/reopen and encodings | OPEN | Real Win32 UI smoke on clean install |
| 18 | Verify LSP initialize/capabilities/diagnostics/navigation | OPEN | Server process handshake and workspace changes |
| 19 | Verify native GhostText acceptance/undo/cancel | OPEN | Visible completion in native editor with local model |
| 20 | Verify PowerShell terminal create/stream/exit/cancel | OPEN | Process lifetime, ANSI, UTF-8 and exit codes |
| 21 | Verify debugger launch/breakpoint/step/inspect | OPEN | Native Win32 flow with user program |
| 22 | Verify browser navigation and web-rendering lifecycle | OPEN | WebView2 runtime policy explicitly distinguished from static HTML |
| 23 | Verify extension install/activate/deactivate/remove | OPEN | VSIX and local host lifecycle, capability permissions |
| 24 | Verify agent edit/build/test/verify with actual model | OPEN | Negative-case receipts, bounded execution and tool permissions |
| 25 | Verify transaction rollback on failure and crash | BLOCKED BY SNAPSHOT SOURCE | Restore and compile original snapshot engine before certification |
| 26 | Validate Ollama + Deep2 parallel sessions | OPEN | Independent serving ports, cancellation and resource arbitration |
| 27 | Validate native Deep2 GGUF model route in IDE | OPEN | No simulated-success fallback; correct produced tokens |
| 28 | Verify stale-lock recovery and atomic updates | OPEN | Repeated clean rebuild and running-executable swap |
| 29 | Define cross-platform UI strategy (Linux/macOS) | OPEN | Win32 surface cannot simply be relabeled as a Linux/macOS binary |
| 30 | Deliver Android and Apple platform release targets | OPEN | JNI/Android packaging, macOS Mach-O and signing requirements separated |

## C — Deep2 correctness, 150 TPS, release and parity

| # | Acceptance move | Status | Proof required or finding |
|---:|---|---|---|
| 31 | Freeze model-specific benchmark matrix | OPEN | Same weights, prompts, context, quant, decode count and sampling settings |
| 32 | Capture single-GPU baseline and power telemetry | USER-REPORTED ONLY | Compare local Ryzen/R9700/RX7800XT receipts with same workload |
| 33 | Capture real GPU counters and zero-fallback proof | OPEN | Dispatch count >0, strict violations =0, output correct |
| 34 | Verify 8/32/128/256 multi-token GPU decoding | OPEN | No FFN gate/up failure and no silent host transfer |
| 35 | Verify both GPU devices doing useful work | OPEN | Kernel/queue/fence overlap and correct results |
| 36 | Attribute GPU0 fence wait dependencies | OPEN | Prove redundancy before removing synchronization |
| 37 | Measure PCIe H2D/D2H and residency churn | OPEN | Trace per token and model size |
| 38 | Repair and certify multi-token FFN/GEMV state | OPEN | Against independent FP32 dequantized reference |
| 39 | Sweep Q2/Q3/Q4/Q5/Q6/Q8 quant correctness | OPEN | Token/logit parity on model families |
| 40 | Verify MoE/SSM architecture-specific tensors | OPEN | No NaNs, bad expert routing, or unsupported dimensions |
| 41 | Recover Slingshot GGUF router from historical tree | SOURCE LOCATED; UNINTEGRATED | ~dev/rawrxd/src/core/SpeculativeEngine_GGUFBridge.hpp and router_tree.hpp |
| 42 | Measure speculative decoding with exact acceptance checks | OPEN | Do not report speculative draft rate as accepted decode TPS |
| 43 | Quantify pruning/repacking quality retention | EXPERIMENTAL | REAP branch plan itself says NOT CERTIFIED |
| 44 | Certify >=150 real decoded tokens/sec per declared model | OPEN | Sustained single-stream E2E; identify specific workload/model |
| 45 | Certify production release and top-25 parity | OPEN | No UNKNOWN matrix cells, E2E security/accessibility/recovery evidence |

## Branch recovery and merge safety

- **Canonical preservation:** `preservation/source-baseline-20261021` is the target; no changes were committed there during this batch.
- **REAP / top-25:** `feature/reap-deepseek-671b-150tps` compares as 134 commits ahead, 0 behind baseline at inspection. It adds `src/parity/Top25ParityMatrix.hpp`, `src/deep2/reap/*` and the two auditors copied into this audit branch. Its stated 150 TPS target is EXPERIMENTAL / NOT CERTIFIED.
- **30B / dual GPU:** `local-30b-backend` has diverged (61 ahead, 44 behind). Do not bulk merge; cherry-pick after per-file reviews, correctness tests, and scope checks.
- **Other histories:** `masm-pure` and `agentic-ide-production` returned no common ancestor with baseline through GitHub comparison. Do not force-merge unrelated trees.
- **Slingshot:** historical sources exist under `~dev/rawrxd/src/core/SpeculativeEngine_GGUFBridge.hpp` and `GGUFShardRouter_tree.hpp` on baseline. Validate their transitive includes, API and legal provenance before integration.
- **Snapshot build contradiction:** root `CMakeLists.txt` unconditionally references `src/snapshot/SnapshotStorage.cpp`, `SnapshotJournal.cpp`, `SnapshotEngine.cpp`, `SnapshotCLI.cpp`, and `SnapshotCLIMain.cpp`, but GitHub contents returned 404 for `src/snapshot` in baseline, main, and local-30b-backend. This is a release-stopping source-closure issue, not a solved feature.
- **Portability contradiction:** root CMake unconditionally `enable_language(ASM_MASM)` and enforces 64-bit MSVC. Standalone linker CMake can be tested independently on Linux, but this does not certify the full IDE on Linux.

## GitHub Actions

The new `.github/workflows/native-toolchain-e2e.yml` runs standalone first-party linker smoke builds on Windows/MSVC x64 and Linux GCC/Clang, validates PE32+ headers/imports and deterministic output, and runs emitted executables only on Windows. A separate source-closure job audits tracked files and fails closed if required snapshot sources are absent. The pre-existing first-party PowerShell linker tests are retained; root CTest registration is fixed.

**External runner status:** initial run 40089502286 ended in failure with every job reporting no steps. Job logs were unavailable (BlobNotFound). Therefore no compilation, execution, or CI gate is claimed PASS in this audit. Diagnose Actions runner availability/configuration before interpreting a failure as a compiler defect.

## 150 TPS measurement rule

Do not count header edits, profiling instrumentation, source audits, quant kernel microbenchmarks, speculative drafts or unrelated models as a speedup. Compare **real accepted decode tokens/sec** on the exact same model/quant/prompt/context/output count, with original output correctness and fallback counters. The full 671B quantized model is orders of magnitude larger than either local GPU; physically achieving 150 TPS cannot be assumed from the existence of a REAP branch or 132 TPS synthetic AVX-512 microbenchmark.
