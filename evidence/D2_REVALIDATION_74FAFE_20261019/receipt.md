# D2 fresh revalidation on 74fafe

**Date:** 2026-10-19
**Worktree/branch:** `F:\rawrxd\.worktrees\codex-d2-revalidate-74fafe`, `codex/d2-revalidate-74fafe`
**Source base:** `74fafe258498749cbd22d443752f8cc792ac31f9`
**Scope:** same-binary serial (`--no-batch`) versus batched 135-token prefill, plus a one-token decode probe. This is a fresh D2 workload revalidation; it does not certify steady-state decode speed or Gate 12's 150 TPS requirement.

## Result

Both runs used the AMD Radeon AI PRO R9700 through the native Vulkan path. The runner reported zero CPU calls and no fallback in each run. The comparator checked all 135 positions across all 32,000 vocabulary logits (4,320,000 floats); all rows were finite and bit-identical. The SHA-256 manifest independently matches all 135 serial/batched row files, each 128,000 bytes.

| Measurement | Serial | Batched | Change |
| --- | ---: | ---: | ---: |
| GPU submissions | 21,080 | 12,170 | −42.27% |
| Synchronization waits | 21,080 | 12,170 | −42.27% |
| Prefill wall time | 31,142.0 ms | 29,746.5 ms | −4.48% |
| Device timestamp time | 26,422.0 ms | 25,649.9 ms | −2.92% |
| Host submit-call duration | 309.1 ms | 190.0 ms | −38.53% |
| Fence-wait wall duration | 27,988.0 ms | 26,710.6 ms | −4.56% |
| Reported throughput | 4.335 tok/s | 4.538 tok/s | +4.68% |

These are the separate metrics emitted by the executor. Fence-wait wall time overlaps device execution; the durations must not be added. Throughput and wall-time improvements come from one matched pair and are workload observations, not a repeated performance claim. The decode phase is only one token (`--decode 1`), so the result does not establish a sustained decode speedup.

## Inputs and provenance

- Model: `F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`, 668,788,096 bytes; SHA-256 `9FECC3B3CD76BBA89D504F29B616EEDF7DA85B96540E490CA5824D3F7D2776A0`.
- Identical 135-token prompt for both controls: [`tokens.txt`](tokens.txt), SHA-256 `372475B46941263B996341BA871E05F6F872C1CE5B23274514645A68EAFCEC10`.
- Executable used by the measured pair: `F:\rawrxd\.build_d2_revalidate_74fafe\deep2_bench_tps.exe`, SHA-256 `C3DCFEABD86BA874E369A80334A356D5D01610113B60B905E08AF91CEFCB9CEA` (recorded in both run summaries before the subsequent rebuild).
- D2 source file hashes and external shared-GPU checkout provenance: [`source_provenance.json`](source_provenance.json). D2 tree remained at the base commit; the separate Q6 optimization checkout was not merged or copied into this worktree.

## Build and execution evidence

The target was configured and built from this worktree's source. The post-run replay commands and logs are preserved here: `configure_replay_command.txt` / `configure_replay.log` / `configure_replay_exit.txt`, `ggml_build_replay.log` / `ggml_build_replay_exit.txt`, and `deep2_build_command.cmd` / `deep2_build_replay.log` / `deep2_build_replay_exit.txt`. Exit codes were 0 for configure, GGML Release build, and the Deep2 compile/link command. The GGML cache records Visual Studio 2022 x64, Release, `GGML_BUILD_TESTS=OFF`, `GGML_NATIVE=ON`, and `GGML_VULKAN=OFF`; Deep2's own Vulkan executor was active and selected the R9700 in the measured runs.

The clean rebuild after the measured pair linked a different PE SHA-256 (`C93F6C6B2747D3ECA103085A5896CAA55DD36DD08036B07015ACB4F93DB653B5`) than the binary used by that pair. The re-linked executable was not used for these benchmark results. The worktree source hashes remained those recorded at the stated base; no source files were changed by this revalidation.

Exact test arguments are in [`serial_pair_final_command.txt`](serial_pair_final_command.txt) and [`batched_pair_final_command.txt`](batched_pair_final_command.txt); both specify the same model, 135 tokens, `--decode 1`, and logits dump, with `--no-batch` only on serial. Each process exited 0. The runner set the GGML DLL directory on `PATH`.

- [`serial_pair_final.log`](serial_pair_final.log), [`serial_pair_final_summary.json`](serial_pair_final_summary.json), exit 0.
- [`batched_pair_final.log`](batched_pair_final.log), [`batched_pair_final_summary.json`](batched_pair_final_summary.json), exit 0.
- [`comparison_pair_final.json`](comparison_pair_final.json) and [`logit_sha256_manifest.json`](logit_sha256_manifest.json); comparator and hash-manifest commands both exited 0 (`compare_pair_final_exit.txt`, `hash_pair_final_exit.txt`).
- Both filtered competitor-process inventories were empty immediately before and after each run; sampled event counts were zero. See `processes_before_*_pair_final.json`, `processes_after_*_pair_final.json`, `process_samples_*_pair_final.json`, and `process_events_*_pair_final.json`.
- Raw per-position logit dumps are retained in the local worktree under `serial_pair_final_logits/` and `batched_pair_final_logits/`; the committed SHA-256 manifest covers every row.

## Certification decision

This replay verifies full-logit parity, zero reported CPU fallback, and lower actual GPU submissions and synchronization waits for this TinyLlama prefill workload. It supports the existing D2 PASS; it does not upgrade S12, certify sustained decode throughput, or generalize beyond this model/workload. The D2 code itself was not changed.
