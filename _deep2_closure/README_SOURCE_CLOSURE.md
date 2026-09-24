# Deep2Engine source-closure drop

This drop is based on the supplied `Deep2Engine.cpp`.

## Closed in `Deep2Engine_completed.cpp`

- Rectangular attention uses separate `H`, `qDim`, and `kvDim`.
- The pre-`Wo` attention-value vector is `qDim`, while the residual/output vector is `H`.
- `Wo` is required and validated as `qDim -> H`.
- Explicit GGUF `attention.key_length` / `attention.value_length` control head width; `H % heads == 0` is only a metadata fallback requirement.
- Layer parity FIRST8 capture no longer reads past short vectors.
- Top-10 diagnostic works when every logit is negative.
- Dense FFN no longer contains a synthetic numerical fallback.
- SSM no longer silently returns its input unchanged.
- MARS no longer reports enabled without a real controller provider.
- Sovereign feature flags no longer silently imply initialized providers.
- Profiling no longer reports enabled while `ProductionProfiler` is an empty provider.
- Stale comments labeling delegated GPU implementations as stubs are corrected.

## Provider work still required for genuine feature completion

The source evidence does **not** provide enough real provider implementation to truthfully synthesize these pieces inside `Deep2Engine.cpp`:

1. **SSM/Mamba provider**
   - bind architecture-specific SSM tensors from GGUF;
   - derive `ssmStateDim` and convolution kernel geometry;
   - allocate/clear per-layer recurrent and convolution state;
   - route SSM layers from `forwardLayer`;
   - implement causal convolution + selective scan + output projection;
   - add parity checkpoints and finite checks.

2. **MARS controller**
   - the connected `MARSController.hpp` is itself a placeholder;
   - implement VRAM budgets, leases, placement, migration, hotpatch, rebalance,
     dynamic parity, tensor-fault recovery, and GPU-failure evacuation;
   - then `enableMARS()` may truthfully set `marsEnabled_ = true`.

3. **ProductionProfiler**
   - the connected provider is an empty class;
   - implement token begin/end timestamps and kernel/GPU counters;
   - wire records into `profileHistory_`.

4. **Sovereign providers**
   - Chamber, ToroidalKV, PlasmaGovernor, and SovereignOutOfCoreRuntime require
     real initialization contracts before `enableAllEnhancements()` can mark them enabled.

This package deliberately fails closed at those provider boundaries rather than
creating fake PASS behavior that would violate `STUB_FALLBACKS=0`.
