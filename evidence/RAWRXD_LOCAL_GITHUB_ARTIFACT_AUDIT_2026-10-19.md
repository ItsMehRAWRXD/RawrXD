# RawrXD local and GitHub artifact audit — 2026-10-19

## Finding

RawrXD already contains a large body of implementation and prototype work. The audit found reusable ROM paging, quantized execution, virtual tensor addressing, batched prefill, GPU submission batching, a local weightless coding prototype, and a newer GitHub dual-device row-split prototype. Several are on different branches or snapshots, and their receipts do not certify the production gates. I found no implementation named NuWeightless and no weight-to-weightless neural compression path in the scanned source trees.

## Scope and snapshot

- Primary checkout: F:/rawrxd, branch local-30b-backend, HEAD 52808a02c7eeceea18a399d59920da21d0790937.
- At the start of the audit, the checkout had 62 modified or untracked paths. The scan did not reset, delete, stage, or overwrite them.
- GitHub local-30b-backend points to bf70b8bfb9618b99b1caf0db50263a3ebe2ddf87; the local branch is 3 commits ahead.
- The main checkout indexes 229,926 tracked paths: 180,747 under evidence and 181,988 with a .bin extension. Most of this volume is generated or binary evidence, so paths were inventoried while the content search focused on readable source, docs, configuration, tests, and receipts.
- The primary repository registers 17 worktrees. Additional related checkouts and detached snapshots sit directly under F: and on G:. Several are heavily dirty; none were cleaned or reconciled during this audit.
- GitHub checks covered the RawrXD default tree (8,714 paths), RawrXD-Artifacts (1,881 paths), rawrxd-recovery-docs (3,850 paths), plus metadata and targeted code searches in RawrXDA, RawrXD-IDE-Final, RawrXD-IDE-Win32-Gui-CLI-HTML, Trap-House, and screenpilot.tech. Relevant non-default HexMag/W0 branches were also checked. Some oversized auxiliary tree requests returned transport errors, so those repositories were searched by targeted file/function terms rather than fully enumerated.
- The exact NuWeightless string was searched across readable source/documentation in all 20 enumerated F: project roots and in GitHub code search. No match was found.

## Existing work and what it proves

| Area | Existing artifact | Evidence and boundary |
| --- | --- | --- |
| D1 batched prefill | Integrated D1/D2 work at commit 2f795322; stronger verifier on codex/d1-opmajor at c3a850c | `Executor::PrefillBatch` and `Deep2Engine::prefillBatched` are present in the current source, and 2f795322 is an ancestor of current HEAD. The Session-3 addendum reports bit-exact full-logit checks on TinyLlama and DeepSeek-V2-Lite. The separate op-major branch adds a TinyLlama/R9700 matrix at lengths 1, 2, 8, 32, and 128, committed K/V payload checks, state, continuation, and zero CPU fallback; that verifier is not integrated into current HEAD, and its `deep2_parity_trace` target fails to link because `input_sanitizer.cpp` is omitted. The ledger’s NOT STARTED row conflicts with its historical PASS addendum. Keep current-HEAD D1 PARTIAL until the required matrix and causal-KV proof are replayed there.
| D2 GPU batching | Integrated historical evidence at 2f795322; separate branch codex/d2-gpu-batching at bbb6712 | The ledger contains two historical measurement sets: its engineering row cites 21,080→12,170 submissions (−42.3%) with 135/135 bit-identical logits and zero CPU fallback; the Session-3 addendum cites 8,835→5,139 submissions/waits (−41.8%). Treat these as distinct runs until their model, binary, and workload provenance is aligned. The separate branch receipt covers batching correctness and queue-failure recovery, but explicitly does not claim performance. Preserve the integrated PASS evidence; do not substitute the separate branch’s correctness-only receipt for throughput evidence.
| Uneven-stride GEMV | F:/rawrxd evidence/TP_UNEVEN_STRIDE_LAYOUT_CERT_2026-10-19.md and four final PAD1/4/8/16 sweeps | 98 synthetic shapes passed CPU and single-GPU exact parity with zero padded tails. PAD16 gave 2.94× R9700 and 3.15× RX 7800 XT at logical width 2049 versus contiguous rows. This certifies a kernel-layout optimization, not tensor-parallel model execution.
| Two-GPU row split | GitHub main has Deep2DualGpuRowSplit, Deep2RowSplitPlan, Batch10_PeerRowSplitCert, and receipt DEEP2_DUAL_PHYSICAL_GPU_FORWARD_001 | The receipt reports 2,432 row-split ops and 2,432 host merges, but GPU_FORWARD_SLOT_0/1 are zero and FULL_MODEL_E2E_PASS=0, PROMOTE=0. It is a useful physical-device arithmetic prototype, not Gate 10 full-model certification.
| Local multi-GPU attempt | F:/rawrxd/evidence/TP_UNEVEN_MULTI_GPU_LAYER_SMOKE_2026-10-19.receipt.txt | Two-device run dispatched GPU GEMVs without CPU fallback but diverged from the single-R9700 stream after token 1 (1/4 token agreement); layer completion counters were zero. Gate 10 remains open.
| ROM and virtual tensor work | GitHub main has `TensorROM`, `Win32RomEmulator`, `gguf2rom_ms`, and a 256-KiB lease/LRU `ShardPager`; the active local branch has VWA and generated TensorROM manifests | These are separate snapshots. The GitHub ROM descriptor carries shard/offset/bytes/dimensions/quantization/device fields, but no encoding, codec version, block directory, or integrity hash. `gguf2rom_ms` writes a manifest pointing at original shard files and estimates tensor byte lengths; it is not a compression-aware ROM packer. ROM test sources exist, but the current ledger has no executed reconstruction-precision receipt for Gate 14.
| Weightless coding prototype | src/deep2w0/W0Engine.cpp, W0Types.hpp, W0HexMagBridge.hpp, and tests/w0_001_cert.cpp on F:/rawrxd_cert, F:/rawrxd-p1-promote, and GitHub branch feat/hexmag-polymorphic-repeat-tuner-masm | W0 is a deterministic no-tensor-weight coding agent. Its inspected transform is a narrow CHANGE_LITERAL rule with structural checks. Its own certificate says the 50+ fixture W0-AGENT-E2E-001 remains future work. This is not compression or reconstruction of neural model weights. The two local copies of W0Engine.cpp, W0Engine.hpp, W0Types.hpp, and w0_001_cert.cpp have identical SHA-256 values; no W0 PASS transcript was found.
| Brutal GZip/DEFLATE | `src/codec/brutal_gzip.cpp`, `brutal_gzip_impl.cpp`, `gzip_brutal_inflate.cpp`, and matching recovery-docs copies | This is general gzip/DEFLATE storage compression, not neural-weight reconstruction. The fallback encoder uses zlib when available and a raw-copy path otherwise; the custom inflater accepts stored DEFLATE blocks only (`BTYPE=0`). Treat codec variants as distinct until roundtrip fixtures prove their compatibility.
| Custom checkpoint MASM codec | `src/asm/RawrXD_Compression.asm` exists in `F:\rawrxd_cert` and `F:\rawrxd-p1-promote`; the active `F:\rawrxd` source path and GitHub main path are absent | The source describes a custom LZ4-like format, not gzip. In the certification snapshot, CMake builds a MASM object as a dependency but does not add it to the `RawrXD_Compression` library sources. Static inspection found a 4096-qword clear against a 4096-DWORD hash table, a hash write indexed by input offset, a match-offset calculation that resolves to zero, and decoder copies that check for one remaining output byte rather than the full copy length. Do not wire this prototype into ROM paging before these issues are repaired and bounded roundtrip tests pass.
| NuWeightless | No matching code or test receipt found | The pasted architecture remains a proposal. Reuse ROM paging, quantized GEMV, and W0 only where their contracts fit; keep them as distinct components. A lossless weightless path needs a precise representation/decoder contract and evidence that the information is preserved.

## Certification status recovered from the authoritative ledger and receipts

| Gate or item | Audited status |
| --- | --- |
| Gate 2 | OPEN in the authoritative ledger, although earlier summaries called it PASS. Manifest-consistency evidence exists; the full primitive-by-primitive provenance audit does not. |
| Gate 5 | PARTIAL; independent llama.cpp comparison was 127/128 token-level agreement, not strict token identity.
| Gate 9 | PARTIAL; agentic loop scaffolding exists, but full IDE tool execution is not certified.
| D1 | PARTIAL on current HEAD; a full correctness matrix passes on a separate, unintegrated branch. Reconcile and replay before PASS.
| D2 | PASS in the historical integrated receipt; preserve it while rechecking current dirty source.
| S07 | OPEN; the supplied 128-token run proposed 12, accepted 0, generated identical tokens, and did not reduce target forwards. No speedup is established.
| Gate 10 | OPEN; neither the local shader sweep nor GitHub’s host-merged row-split witness proves a full two-GPU model forward with logit parity.
| Gate 11 | NOT STARTED; no 671B GGUF is available in the current model inventory.
| S12 / 150 TPS | OPEN/FAIL; measured rates remain far below 150 TPS.
| Gate 14 | NOT STARTED; ROM code exists, reconstruction precision certification does not.
| Gates 16–18 | Gate 16 PARTIAL, Gate 17 PARTIAL, Gate 18 OPEN from the completed audit worker. The UI smoke predates its final File New assertion; relinking was blocked while the running CUA process held the executable. No PASS was reported.
| Gate 20 | NOT STARTED; clean-checkout release certification depends on unresolved gates.

The July GATES_16-20_SUMMARY.md exists in three identical local copies, but its meanings are different: multi-model support, error recovery, benchmarks, integrations, and docs/examples. It is not the current Deep2 release ledger. The K2 Gate 12 scope and Strata S01–S12 matrix are separate ladders. The authoritative file for the current program is evidence/FULL_IDE_COMPLETION_LEDGER.md; its current D1 PARTIAL status now distinguishes the current-HEAD replay requirement from the historical Session-3 PASS claim.

The proposed release scope is documented separately in evidence/RELEASE_ROADMAP_2026-10-13/ROADMAP.md. It explicitly says it is proposed rather than recovered historical ledger definitions. Do not use the July summary or K2 numbering to claim Deep2 Gate 12–20 passage.

## GitHub and repository divergence

- RawrXD main is 033a8acb55d46d2fc22a84428e81f3167a0c3897, which merges the Phase 2 multi-shard work. It contains top-level TensorROM/ROM-emulator tooling and a separate ~dev Deep2 row-split implementation.
- The GitHub comparison reports local-30b-backend and main as diverged: 11 commits exist on main after their merge base and 217 commits exist on the target branch that are absent from main. The local checkout is another 3 commits ahead of the GitHub local-30b branch. This is not a fast-forward situation.
- The HexMag/W0 feature and promotion branches have no common ancestor with main; GitHub compare also reports no common ancestor between the two branches. Treat them as separate source histories and port selected files only after provenance and integration review.
- The main commit’s combined-status endpoint returned an empty status list at audit time, while branch protection lists required checks. The empty response is not CI PASS evidence.
- RawrXD-Artifacts contains old audit tombstones and executables, not a NuWeightless implementation. The exact default-branch URL for `src/asm/RawrXD_Compression.asm` returned 404; its local copies are in separate certification/promotion snapshots.

Relevant GitHub references:

- RawrXD main merge: https://github.com/ItsMehRAWRXD/RawrXD/commit/033a8acb55d46d2fc22a84428e81f3167a0c3897
- RawrXD two-device row-split source: https://github.com/ItsMehRAWRXD/RawrXD/blob/main/~dev/rawrxd/src/deep2/Deep2DualGpuRowSplit.cpp
- Row-split receipt: https://github.com/ItsMehRAWRXD/RawrXD/blob/main/~dev/evidence/RAWRXD_PERFORMANCE_001/DEEP2_DUAL_PHYSICAL_GPU_FORWARD_001/RECEIPT.txt
- ROM source: https://github.com/ItsMehRAWRXD/RawrXD/blob/main/src/TensorROM.hpp
- ROM emulator descriptor: https://github.com/ItsMehRAWRXD/RawrXD/blob/033a8acb55d46d2fc22a84428e81f3167a0c3897/src/Win32RomEmulator.hpp
- GGUF-to-ROM manifest writer: https://github.com/ItsMehRAWRXD/RawrXD/blob/033a8acb55d46d2fc22a84428e81f3167a0c3897/src/gguf2rom_ms.cpp
- Lease-aware page cache: https://github.com/ItsMehRAWRXD/RawrXD/blob/033a8acb55d46d2fc22a84428e81f3167a0c3897/src/ShardPager.hpp
- Default-branch MASM codec path check (404): https://github.com/ItsMehRAWRXD/RawrXD/blob/main/src/asm/RawrXD_Compression.asm
- W0 prototype on non-default branch: https://github.com/ItsMehRAWRXD/RawrXD/blob/feat/hexmag-polymorphic-repeat-tuner-masm/src/deep2w0/W0Engine.cpp
- W0 certificate contract: https://github.com/ItsMehRAWRXD/RawrXD/blob/feat/hexmag-polymorphic-repeat-tuner-masm/tests/w0_001_cert.cpp

## Repository integrity and handling

- The primary checkout has substantial pre-existing dirty work across IDE, security, production, Deep2, tests, and profiling artifacts. The audit did not stage or clean it.
- The local ref/object audit found refs/remotes/rawrxda/HEAD pointing to an all-zero object id and a broken history link from commit 995393e0 to missing commit 786acfad. No ref repair, fetch, prune, reset, or history rewrite was attempted.
- One Git remote URL contains an embedded credential. It was not copied to this report or repeated in later command output. Rotate that credential because it appeared in tool output; this audit did not change the remote configuration.

## Recommended continuation

1. Reconcile the D1 status and integrate only the tested op-major verifier/source delta into local-30b-backend; rebuild and replay the 1/2/8/32/128 logits, K/V, and continuation matrix on the resulting HEAD.
2. Preserve D2’s existing 41.8% submission/wait receipt, then verify it against the same resulting HEAD.
3. Use GitHub’s Deep2DualGpuRowSplit as a design reference for explicit row offsets and device timing, but keep Gate 10 open until the full-model two-device parity contract passes.
4. Keep S07 and S12 open, Gate 14 open until a reconstruction reference harness runs, and Gate 16–18 at the worker’s reported statuses.
5. Treat NuWeightless as a new weight-representation proposal. Start by specifying lossless/approximate semantics, storage and decoder layout, integrity checks, and quality thresholds before wiring it into TensorROM or the Vulkan GEMV path.

## Audit limits

This is a broad source, evidence, worktree, branch, and GitHub-artifact audit. It did not open each of the 181,988 binary .bin files or every generated executable, and some auxiliary GitHub tree listings were unavailable from the connector. Those files were counted and their relevant names indexed, but binary contents and every historical Git object were not certified.

## Post-audit execution update — D1 replay

After the audit snapshot, commit `74fafe258498749cbd22d443752f8cc792ac31f9` on branch `codex/d1-replay-1977e041` replayed D1 from the exact audited primary HEAD `1977e04140a199f23b0cbae9ac26bd2a819eed82`. The TinyLlama/R9700 matrix passed lengths 1, 2, 8, 32, and 128 with bit-exact full logits, committed K/V payloads across all blocks, executor state, and one-token continuation; all CPU fallback counters were zero. The receipt and build/matrix logs are under `evidence/D1_REPLAY_1977E_20261019/` on that branch. This is a verified D1 PASS for the tested TinyLlama path; other model families and the Q4_K fused LM-head path remain unverified. The D1 commit is isolated from the dirty primary checkout pending integration review.

## Post-audit discovery — Q6 packed-byte shader optimization

While the D2 revalidation was being isolated from competing GPU benchmarks, a separate checkout at `F:/wt_ide1` completed and pushed commit `46dcdb171532ef995996d7084d94beee0bbbe7b3` on `rawrxd/s15-tps-panel`. It changes the Q6_K batch shader to decode four-column lanes with two packed-byte loads and includes a mutation script and a dedicated optimization receipt.

The receipt reports a fresh 28.444 TPS control and candidate runs of 17.705, 30.101, and 35.269 TPS (median 30.101 TPS, 1.0583x control), SPIR-V validation PASS, and 24/24 ctest PASS. The first run is explicitly cold and the spread is wide. This is a measured candidate improvement on the stated Qwen route, not a 150 TPS acceptance, cross-model certification, or Gate 10 multi-GPU full-model proof. The source worktree is clean for the shader files; generated benchmark directories and two unrelated modified audit receipts remain modified/untracked there.

The optimization is isolated from the audited `local-30b-backend` and D1/D2 replay worktrees. Do not treat it as integrated until a reviewed port is built and tested on the target branch.
