# Deep2 Runtime IR Bridge — source drop

A **real, compiling C++20 runtime graph/binding validator**, not a complete
ModelGenie executor replacement. Feed the validated GGUF tensor directory and
per-layer classifier output into `deep2bridge::build`.

It explicitly distinguishes layer 0 dense FFN from layers 1–26 MoE, validates
tensor identities, dtype-kernel readiness, file bounds, operator availability,
and emits ordered graph nodes with stable tensor handles and dataflow handles.
It refuses unsupported MLA, MoE and SSM kernels before execution.

## Build/test
```
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Remaining integration work (NOT claimed complete)
1. Adapt `RawrXDGgufReader` tensor directory and `deep2_plan` block descriptors
   to these structs; do not invent names or use model-level dtype.
2. Replace generated ROM dispatch in `ModelGenieExecutor` with dynamic nodes.
3. Supply real arena liveness, buffer sizes, shape inference and allocator.
4. Implement kernel calls for each op, including correct MLA cache, attention,
   RoPE, routed/shared expert math, SSM scan and residual ordering.
5. Preserve architecture-specific layer order and norms; this prototype's
   generic node ordering is NOT a validated DeepSeek numerical graph.
6. Bind tokenization, embedding and output projection with real model metadata.
7. Compare prefill and 64-token logits against an independent reference.
8. Integrate CPU/Vulkan dispatch, resource admission and cancellation.
9. Run real-model tests on Windows; this package is independently testable
   on Linux with C++20 but is not certified against your 56 GGUF files.

No fake execution or fabricated TPS. Tests use synthetic descriptors only
and verify graph construction, not model inference.
