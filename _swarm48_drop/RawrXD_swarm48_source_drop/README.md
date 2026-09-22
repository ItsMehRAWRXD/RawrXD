# RawrXD Swarm48 source drop

C++20, no third-party dependencies.

Purpose: allow dozens of simultaneous **logical agents** to share a small number of resident model-weight images across the R9700 and RX 7800 XT, while keeping per-agent KV/session/tool state independent.

This package is intentionally inference-backend agnostic. `IInferenceAdapter` must be wired to RawrXD's existing Deep2/ModelRegistry/continuous-batching authority. The included fake backend is only a contract self-test and is not a Deep2 performance receipt.

Standalone contract test:

```text
cmake -S . -B build
cmake --build build --config Release
./build/swarm48_selftest
```

Expected final line: `RAWRXD_SWARM48_CORE=PASS`.
