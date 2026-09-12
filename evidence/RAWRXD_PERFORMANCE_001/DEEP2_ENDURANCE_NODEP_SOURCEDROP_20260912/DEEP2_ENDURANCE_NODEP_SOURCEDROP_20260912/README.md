# Deep2 Endurance No-Dependency Source Drop

Concrete C source for the post-TARGET=16 endurance/hardening tranche. It is intentionally separate from the frozen TARGET=64 certification executable.

Implemented, not placeholder-only:

- autoregressive counter/invariant ledger
- zero-sealed enforcement
- fixed arena guard + allocation freeze
- persistent KV write/read/epoch guard
- exact tensor-range bounds validation
- bounded residency accounting/backpressure
- fixed-capacity exact-range queue
- generation/epoch rejection
- resource lifetime parity
- fence submission/signal/recycle state machine
- descriptor generation ring
- device health serial accounting
- progress/stall detection
- deterministic state digest
- constant-memory long-run latency statistics
- append/flush observation journal
- forbidden/stub symbol scanner

## Deliberate boundary

This archive does **not** fake the repository-specific Vulkan/Q4_K/Q6_K kernels, model tensor ABI, dual-GPU dispatcher, tokenizer ABI, or product linker state. Those need the actual RawrXD source tree to implement without inventing incompatible structures. There are no success-return placeholder APIs for those components in this drop.

## MSVC

From a VS x64 developer shell:

```bat
build_msvc.bat
```

Expected smoke output:

```text
DEEP2_ENDURANCE_NODEP_SMOKE=PASS
SEALED_LOGITS_REUSE_COUNT=0
COUNTER_PARITY=1
```

## Integration order

1. Seal the frozen TARGET=64 run first.
2. Add invariant + KV + arena guards around the existing generic executor.
3. Wire existing Vulkan object creation/destruction into `D2Lifetime` ledgers.
4. Replace ad-hoc fence/descriptor recycling with the fixed rings.
5. Feed actual GGUF shard ranges through `D2TensorRange` before dispatch.
6. Enforce residency budgets before any WARM/HOT promotion.
7. Use `D2Journal` only for observations after operations complete.
8. Run the forbidden-symbol scanner over the final MAP/text-symbol export until product stubs are zero.
