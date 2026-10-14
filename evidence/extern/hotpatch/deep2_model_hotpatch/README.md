# Deep2 Model Hotpatch — native C++17 source drop

This is a dependency-free **integration core**, not a replacement inference engine. It reads GGUF metadata and tensor descriptors, identifies architecture and quant types, validates a native plugin's operator and quant support, and pins a versioned plugin object to each session. Registry replacement is atomic under a mutex; already bound sessions retain their previous plugin, preventing mid-token ABI swaps. It deliberately rejects unknown architectures and missing compute hooks.

## Build

MSVC: `cl /std:c++17 /EHsc /c deep2_model_hotpatch.cpp`
GCC/Clang: `c++ -std=c++17 -Wall -Wextra -pedantic -c deep2_model_hotpatch.cpp`

## Wire into F:\\rawrxd

1. At GGUF ingest/stream-open call `inspect_gguf(path, spec, error)` once before tensor materialization. For sharded GGUF, resolve and validate the shard manifest in the existing loader first.
2. At native engine initialization, register one `Plugin` per **implemented** architecture. Set `contract.required_ops` to real graph operator names, `supported_tensor_types` to the quantizations actually supported by the selected backend, and `hooks.execute_token` to an adapter calling the actual `Executor::ExecuteToken` implementation. No simulated success.
3. Before creating a generation session, call `Registry::bind(spec, actual_available_ops, error)`. Retain the resulting `SessionBinding` for the session's entire lifetime.
4. For a hotpatch, validate a new plugin against reference parity and run-time ABI compatibility before `install()`. The new plugin replaces the active architecture entry for **new sessions only**. Existing sessions continue using their pinned immutable plugin.
5. Run existing Deep2 CPU/GPU parity, KV/SSM endurance, quantization, fallback and failure-injection tests before promoting any plugin to production.

## Boundaries

This module does not implement Vulkan kernels, DLL loading, GGUF shard aggregation, Safetensors, operator discovery, executable JIT synthesis, arbitrary reverse-engineering of new mathematical architectures, model streaming, or reference parity. Those need real existing Deep2 integration points. The current parser rejects unknown GGUF value types and limits metadata allocation. It does not independently validate every tensor data offset or payload integrity; that must remain the loader's responsibility.
