# Deep2 AutoTune integration

This is a native, dependency-free **tuning core**, not a standalone inference executable.
It will not claim working inference until a real Deep2 Runtime adapter is supplied.

1. Add `add_subdirectory(tools/deep2_autotune)` to the existing CMake project.
2. Link `deep2_autotune` to the existing Deep2 executable.
3. Implement `deep2::tune::Runtime` against your native GGUF loader and inference engine.
4. `supports` must reject unsupported KV formats, GPU layer allocations, unavailable kernels, and overcommitted devices.
5. `benchmark` must execute real prompt prefill + >=16 decoded tokens; measure actual elapsed decode time, prefill TPS and peak committed memory; perform independent reference parity and multi-run stability checks. Never fabricate these values.
6. `activate` must install the winning configuration into the actual runtime and verify the runtime is ready to serve.
7. Pass a writable per-model profile path and a conservative verified memory budget.

Example caller:

```cpp
std::string diagnostic;
auto hardware = deep2::tune::discover_hardware();
auto decision = deep2::tune::autotune(runtime, hardware,
    "F:\\rawrxd\\profiles\\model.autotune", budget_bytes, false, diagnostic);
if (!decision) { /* fail closed, log diagnostic */ }
```

## Known boundaries

- No GPU VRAM detection: display enumeration does not report reliable dedicated memory. Provide GPU budgets through the actual Vulkan device/heap telemetry in the adapter.
- No multi-GPU assignment search: candidate `gpu_layers=999` is a request for maximum GPU offload, not a guarantee or a per-device plan.
- No automatic million-token context expansion: context fixed to 4096 until runtime-backed memory/context probes are integrated.
- No speculative decoding search or per-quant kernel selection: these require runtime-owned knobs and verified support.
- No concurrent tuning-process locking. Use one tuning coordinator per profile path.
- Runtime model fingerprints must be cryptographically strong if adversarial file substitution matters; the cache key hash is not cryptographic.
- A crash in an in-process benchmark can terminate the host; production isolation requires a worker process and watchdog.
- `activate` is assumed transactional; the adapter must restore prior runtime state on activation failure.
- Cached profiles are re-benchmarked for correctness before reuse; this favors safety over startup latency.
