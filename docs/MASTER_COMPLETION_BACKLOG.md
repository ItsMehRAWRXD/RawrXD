# RawrXD master outstanding backlog

75 outstanding / 0 verified closed. Stable IDs are never renumbered. Remove an item from this outstanding list only after recording commit SHA, build/test evidence and production-path verification in the closure ledger below. Local GPU evidence is required for GPU certification. Work in batches of 17, P0 before P1 before P2. Do not merge unverified release changes.

## P0 GPU execution consolidation

- [ ] RX-001 Inventory both Vulkan implementations
- [ ] RX-002 Capture active pipeline identities
- [ ] RX-003 Inventory all shader loading paths
- [ ] RX-004 Establish authoritative dispatch interfaces
- [ ] RX-005 Unify buffer ownership and lifetime
- [ ] RX-006 Unify descriptor and synchronization contracts
- [ ] RX-007 Restore reproducible shader sources
- [ ] RX-008 Enforce shader ABI validation
- [ ] RX-009 Route production RoPE through authoritative implementation
- [ ] RX-010 Certify interleaved RoPE
- [ ] RX-011 Certify NEOX RoPE
- [ ] RX-012 Certify IMROPE
- [ ] RX-013 Certify partial RoPE
- [ ] RX-014 Certify Q4_0 through production engine
- [ ] RX-015 Resolve Q2_K production divergence
- [ ] RX-016 Resolve MLA-H08 embedding divergence
- [ ] RX-017 Resolve Llama multi-token divergence

## P0 Agent security

- [ ] RX-018 Unify IDE and standalone authorization
- [ ] RX-019 Require authorization for privileged execution
- [ ] RX-020 Enforce subprocess isolation
- [ ] RX-021 Enforce workspace boundaries
- [ ] RX-022 Remove production consent overrides
- [ ] RX-023 Complete authoritative tool schemas
- [ ] RX-024 Implement durable execution receipts
- [ ] RX-025 Verify cancellation and cleanup

## P0 IDE stability

- [ ] RX-026 Fix LSP numeric parsing crash
- [ ] RX-027 Guard IDE initialization
- [ ] RX-028 Restore authoritative exception filter
- [ ] RX-029 Complete native agent panel
- [ ] RX-030 Connect completion model output
- [ ] RX-031 Connect ghost-text rendering
- [ ] RX-032 Complete live chat smoke test

## P1 Inference coverage

- [ ] RX-033 Reconcile Q4_K activation contracts
- [ ] RX-034 Certify Q6_K
- [ ] RX-035 Implement missing GPU quantization paths
- [ ] RX-036 Resolve zero-logit forward
- [ ] RX-037 Complete Qwen3.5
- [ ] RX-038 Complete Qwen3 Next
- [ ] RX-039 Complete Phi3
- [ ] RX-040 Complete DeepSeek V3/V4
- [ ] RX-041 Complete GPT-OSS
- [ ] RX-042 Complete Laguna
- [ ] RX-043 Certify Nemotron SSM
- [ ] RX-044 Certify full MoE/GDN parity
- [ ] RX-045 Complete device-lost recovery
- [ ] RX-046 Complete dynamic KV capacity
- [ ] RX-047 Implement overflow-safe attention addressing

## P1 Build and repository integrity

- [ ] RX-048 Review 183 conditional EXISTS guards
- [ ] RX-049 Review 11 disabled build blocks
- [ ] RX-050 Require mandatory product targets
- [ ] RX-051 Enable mandatory CTest suite
- [ ] RX-052 Integrate orphaned tests
- [ ] RX-053 Correct x64 CI matrix
- [ ] RX-054 Version preserved production source
- [ ] RX-055 Remove tracked generated artifacts
- [ ] RX-056 Pin third-party dependencies
- [ ] RX-057 Complete secret and license scans
- [ ] RX-058 Gate diagnostic instrumentation
- [ ] RX-059 Perform clean-room Release build

## P2 Product completion and optimization

- [ ] RX-060 Complete LTT integration
- [ ] RX-061 Complete MARS integration
- [ ] RX-062 Certify Strata residency
- [ ] RX-063 Complete dual-GPU ownership
- [ ] RX-064 Optimize GPU transfers
- [ ] RX-065 Complete compressed-weight residency
- [ ] RX-066 Complete native agent feedback loop
- [ ] RX-067 Complete HexMag swarm
- [ ] RX-068 Complete MCP integration
- [ ] RX-069 Complete skill system
- [ ] RX-070 Optimize GPU dispatch overhead
- [ ] RX-071 Optimize prefill and decode
- [ ] RX-072 Demonstrate competitive inference performance
- [ ] RX-073 Certify concurrent agents
- [ ] RX-074 Complete independent E2E certification
- [ ] RX-075 Commit and push verified release baseline

## Mandatory architecture constraints

- Native Win32/C++/MASM and existing Vulkan interfaces only; no Qt in production targets.
- No new third-party build or runtime dependencies.
- No placeholder implementations or silent success fallbacks.
- Preserve existing supported toolchain and Vulkan SDK requirements.
- Record dependency and Qt-free build verification before release closure.

## Closure ledger

No verified closures yet. Initial Vulkan hardening commit: 4da76c32d8b878ba49b1886cf101f4d84bc938a2 (unbuilt; no gates closed).
