# Batch 057: Branch recovery and throughput audit
Date: 2026-10-24
PR: https://github.com/ItsMehRAWRXD/RawrXD/pull/54 (draft, not merged)

## Measured/implemented
- Q4_K packed-column cache previously copied the whole matrix while holding a global cache mutex. New version performs repacking outside the mutex and publishes with a generation guard.
- Invalidation increments the generation, so an in-progress repack cannot repopulate the cache after clear.
- Concurrent cache invalidation regression added.
- Recovered audit scripts now have a CI source-audit job; top-25 evidence smoke included in Linux job.
- No hardware TPS claim; no verified GPU performance receipt for this batch.

## Branch reconnaissance
The GitHub branches API returned 88 branches. Notable branches:
- `local-30b-backend`: active repair branch and draft PR head.
- `preservation/source-baseline-20261021`: intended canonical product baseline; diverged from active branch.
- `feature/reap-deepseek-671b-150tps`: source-audit scripts and top-25 parity matrix recovered earlier.
- `audit/deep2-build-recovery-20261024`: diverged by 5 commits relative to active branch, with `src/deep2/generic_vulkan_matmul.cpp/.hpp` and CMake changes. Inspect numerical correctness and target admission before selective port.
- `audit/native-linker-cert-20261024`: diverged by 51 commits, includes `.github/workflows/native-toolchain-e2e.yml`, MASM/lexer/compiler sources, and third-party `3rdparty/quickjs_ng`. Do not bulk merge into strict no-new-deps production tree.
- `feature/pure-masm-ide-integration`: no common Git ancestor with active branch; cherry-pick by reviewed source content, not merge.
- `ci/ide-native-build`: separate IDE CI history, inspect for reusable Windows build jobs.
- `perf/deep2-fused-host-gemv-20261020`: alternate throughput experiments; must compare identical numerical workloads.

## 45-gate progression, not 45 certifications
### Throughput (15)
1. GGUF load correctness: pending.
2. Q4_K packed-cache lock contention: source repaired.
3. Q4_K snapshot lifetime: source repaired.
4. Q4_K invalidation generation: source repaired.
5. Dual-worker submission overlap: source repaired in prior batch.
6. Dual-GPU weight residency: pending.
7. GEMV numerical parity: pending.
8. FFN multi-token: pending.
9. SSM finite outputs: pending.
10. Attention correctness: pending.
11. KV cache long context: pending.
12. GPU0 wait attribution: pending.
13. GPU1 load balance: pending.
14. Sustained end-to-end TPS: pending.
15. 150 TPS target: not certified.

### IDE and compiler (15)
1. Canonical source-tree merge: pending.
2. Qt-to-Win32 conversion: pending.
3. Native JSON no third-party dependency: pending.
4. Editor completion: pending.
5. LSP lifecycle: pending.
6. GhostText: pending.
7. Terminal: pending.
8. PowerShell: pending.
9. Debugger: pending.
10. Browser: pending.
11. Agent loop: pending.
12. Snapshot rollback: pending.
13. C/C++20 compiler: broad compatibility pending.
14. MASM/NASM x86/x64: broad compatibility pending.
15. PE/ELF/Mach-O/Android/iOS target support: pending.

### Enterprise release (15)
1. Branch inventory: 88 branch names discovered.
2. Branch diff triage: 5 relevant branches compared.
3. No-deps merge gate: found QuickJS addition in linker-cert branch; reject blind merge.
4. Per-file inventory: script recovered, CI added.
5. CMake source admission: script recovered, CI added.
6. Dependency audit: script recovered, CI added.
7. Top-25 parity matrix: recovered; evidence references mandatory.
8. CI runner execution: blocked on prior observed run.
9. Windows compiler CI: not certified.
10. Linux compiler CI: isolated tests only.
11. Cross-OS packaging: pending.
12. Security review: pending.
13. Performance reproducibility: pending.
14. End-to-end release smoke: pending.
15. Enterprise production certification: not certified.

## Next required action
Restore GitHub Actions job execution, then selectively port the reviewed generic Vulkan matmul and compiler/linker tests, reconcile production Deep2 target, and measure coherent multi-token decode on physical GPUs. Never treat a synthetic host repack microbenchmark as inference TPS.
