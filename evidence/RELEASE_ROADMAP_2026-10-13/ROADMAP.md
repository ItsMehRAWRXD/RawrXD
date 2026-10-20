# RawrXD / Deep2 release roadmap — proposed 2026-10-13

Authority: the user supplied this proposed roadmap in the current engineering session. It is not a recovered historical ledger. Historical July, K2, Mamba2 and ModelGenie gate numbers retain their original meanings and evidence.

Use IDs RELEASE_G10 through RELEASE_G20. All start OPEN; evidence from a differently numbered ladder does not confer PASS.

- RELEASE_G10 Multi-GPU orchestration and tensor parallelism: R9700 and RX 7800 XT execute one inference together with real weight/matrix sharding, even and ragged shard-width coverage with explicit offsets, synchronized cross-device activation/reduction transfers, no CPU fallback, full-logit parity against a single-GPU baseline, and per-device Vulkan timing/transfer/allocation receipts. Current backend audit: `evidence/TP_UNEVEN_SHARD_BACKEND_AUDIT_2026-10-19.md`.
- RELEASE_G11 Large-model execution: real DeepSeek 671B weights load and generate through native Deep2.
- RELEASE_G12 Performance acceptance: measure sustained 150 TPS including the real 671B workload. Freeze model hash, quantization, devices, prompt/context, decode length, concurrency and prefill/decode windows. Smaller models cannot certify 671B.
- RELEASE_G13 Million-token context: correct operation at 1,048,576 tokens with measured bounded memory.
- RELEASE_G14 ROM reconstruction integrity: reconstructed weights match defined precision and numerical reference.
- RELEASE_G15 Agent swarm scalability: concurrent Piranha/HexMag agents execute without state corruption.
- RELEASE_G16 Native compiler/linker: reproducibly build, link, debug and execute real projects.
- RELEASE_G17 IDE integration: explorer, editor, terminal, Git, inference, browser and tools operate together.
- RELEASE_G18 Security/isolation: verify tool permissions, sandbox boundaries, authentication and receipt integrity.
- RELEASE_G19 Endurance/recovery: long-running generation, crashes, device loss, cancellation and restart recovery.
- RELEASE_G20 Production release: clean checkout, automated CI, packaging, documentation and final release certification.

Historical October 13 Gate 12–20 ledger: LEDGER_NOT_LOCATED. Searches of current certification/evidence/docs and October 12–13 Git changes found the 96-item BATCH_LEDGER, July 20-gate plan, K2 ladder and A–Z audit closure, but no verified mapping of ledger zones to those historical gate IDs.

Gate 2 remains OPEN pending reconciliation of current evidence. Preserve prior receipts; do not overwrite them or infer release readiness from them.

Each release PASS must include the exact command, exit code, full transcript, source/working-tree provenance, executable hash, model provenance where applicable, measured acceptance results, and independent verification. This document defines scope only; it is not a PASS receipt.
