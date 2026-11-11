# Batch 062: Vulkan-forward authority and remaining certification
Date: 2026-10-24
Branch: local-30b-backend

## Source audit finding
`~dev/rawrxd/src/deep2/Deep2Engine.cpp` previously selected the host-orchestrated dense dual-row forward by default. The GPU-resident `tryGpuTokenForward()` graph was opt-in with `DEEP2_RESIDENT_FIRST=1`. Host forward orchestration must not be mistaken for fully GPU-resident forward.

## Repairs
1. Resident GPU graph is first choice by default for dense Vulkan models; `DEEP2_RESIDENT_FIRST=0` is an explicit diagnostic override in non-strict mode.
2. Strict Vulkan mode now rejects missing Vulkan initialization, MoE/MLA hybrid-only routes, and resident GPU forward failure before host/hybrid execution can run.
3. Strict success requires `gpuFwdCommitted_=true`. Strict failure sets `vulkanStrictViolation_=true` and refuses CPU fallback.
4. Q4_K cache improvements from Batches 057-061 remain host-weight staging optimizations; they are not evidence that a token forward was GPU-resident.

## Certification gates (15 GPU, 15 IDE/toolchain, 15 enterprise)
GPU: [ ] Vulkan-only 50-token decode; [ ] 28-layer resident dispatch; [ ] R9700 dispatch; [ ] RX7800XT dispatch; [ ] no host forward; [ ] no unplanned fallback; [ ] finite logits; [ ] token parity; [ ] FFN correctness; [ ] attention correctness; [ ] SSM/MoE supported path; [ ] KV correctness; [ ] GPU0 waits; [ ] GPU1 utilization; [ ] 150 TPS.
IDE/toolchain: [ ] source tree reconciliation; [ ] native no-Qt build; [ ] agent edit/build/test/rollback; [ ] GhostText; [ ] LSP; [ ] terminal; [ ] debugger; [ ] browser; [ ] Slingshot; [ ] C compiler; [ ] C++20 compiler; [ ] MASM x86/x64; [ ] NASM x86/x64; [ ] PE/ELF linker; [ ] Mach-O/Android/iOS ABI and signing.
Enterprise: [ ] CI runners; [ ] MSVC clean build; [ ] Linux CI; [ ] per-file source inventory; [ ] no-deps audit; [ ] third-party license review; [ ] sanitizer/fuzz tests; [ ] error-path tests; [ ] 24h endurance; [ ] model matrix; [ ] installer; [ ] updates; [ ] signed releases; [ ] top-25 evidence receipts; [ ] release gate.

## Important limitations
These commits are source changes, not a Windows GPU run. No 150 TPS or enterprise parity claim. Strict mode may reject MoE models until a fully device-resident MoE forward exists. The root production `src/deep2/Deep2Engine.cpp` is distinct from this advanced `~dev` source and must be reconciled before release. GitHub PR #54 remains draft/unmergeable; Actions runner assignment has been previously blocked.

## Required next proof
On the physical AMD R9700 and RX 7800 XT, build the actual production binary from a known SHA, enable Vulkan strict-no-CPU-fallback, decode 50+ tokens, capture GPU forward dispatches, zero host forward-layer calls, zero violations and semantic parity, then measure prefill and decode TPS separately. Do not label host-orchestrated GEMV as Vulkan-resident token forward.
