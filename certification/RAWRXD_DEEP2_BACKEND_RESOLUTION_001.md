# RAWRXD_DEEP2_BACKEND_RESOLUTION_001 — Resolution Record

**Date:** 2026-10-11
**Status:** RESOLVED (authentic backend, no shims)

## The problem

`deep2_token_profiler` failed to link with unresolved externals:

```
ggml_backend_cpu_init
ggml_backend_tensor_set
ggml_backend_tensor_memset
ggml_backend_graph_compute
ggml_critical_section_start / _end
```

## Why the naive fix was wrong

The missing symbols are part of ggml's **backend abstraction** — allocation,
buffer lifetime, and execution semantics. Supplying enough symbols to satisfy
the linker does not reproduce those semantics. A partial backend shim would
have produced a binary that links and then behaves incorrectly, which is worse
than a build failure.

I attempted such a shim, got the struct layouts right against
`ggml-backend-impl.h` (the real `ggml_backend_buffer` is
`{iface, buft, context, size, usage}`, not `{data, size, api}`), and matched the
real `ggml_backend_i` member order. It still did not link. I stopped rather
than commit a partial shim.

## Resolution: the authentic backend was in the repository all along

The assumption that ggml-backend was missing was wrong. HEAD contains:

```
src/ggml-backend.cpp              88857 bytes
src/ggml-backend-reg.cpp
src/ggml-backend-impl.h
3rdparty/ggml/src/ggml-backend.cpp
3rdparty/ggml/src/ggml-backend-reg.cpp
3rdparty/ggml/src/ggml-threading.cpp
3rdparty/ggml/src/ggml-cpu/ggml-cpu.c
3rdparty/ggml/src/ggml-cpu/ggml-cpu.cpp    (defines ggml_backend_cpu_init)
```

A stale working-tree copy caused the earlier "not found" conclusion. Restoring
from HEAD resolved it.

The earlier attempt also linked the wrong files: `3rdparty/ggml/src/ggml.c`
instead of `src/ggml.c`, and omitted `ggml-cpu.cpp` (which holds
`ggml_backend_cpu_init`) and `ggml-threading.cpp`.

## Correct build sequence

Build the authentic libraries through the project's own CMake configuration
(`add_subdirectory(3rdparty/ggml)`), then link:

```powershell
cmake -B build_cmake -G "Visual Studio 17 2022" -A x64 `
      -DRAWRXD_BUILD_TESTS=OFF -DRAWRXD_BUILD_IDE=OFF `
      -DENABLE_VULKAN=OFF -DGGML_VULKAN=OFF -DUSE_ZLIB_FETCHCONTENT=OFF
cmake --build build_cmake --config Release --target ggml
```

Produces `ggml.lib`, `ggml-cpu.lib`, `ggml-base.lib` — all authentic.

Link requirements discovered:
- `/MD` — the CMake build uses dynamic release CRT; `/MT` fails with LNK2038
- `advapi32.lib` — `ggml-cpu.cpp` reads the Windows registry for CPU topology
- Vulkan SDK include path — `vulkan_compute.h` -> `vulkan/vulkan_core.h`

## Verified result

Real model, real weights, authentic ggml:

```
model: F:\OllamaModels\gguf\nemotron-3.5-lightning-30b-Q4_K_M.gguf
  embedding dim=2688  vocab=131072  emb_quant=q5_0  out_quant=q8_0
  embedding 231.0 MiB, output 357.0 MiB

tokens generated      : 8
total decode time     : 613.89 ms
throughput            : 13.03 tok/s
avg ms per token      : 76.737 ms
weight bytes / token  : 8568.01 MiB
effective bandwidth   : 13.63 GiB/s
phase breakdown (avg ms/token):
  embedding           :    0.362
  attention           :   60.744
  feed-forward        :    7.784
  output-norm         :    0.077
  output-projection   :    7.713
  sampling            :    0.057
dominant phase        : attention
failed ggml ops       : 0
```

`failed ggml ops: 0` — every ggml operation against the real quantized weights
succeeded. Attention dominates per-token cost, consistent with the 8.5 GiB of
Q5_0/Q8_0 weights swept per token.

## Not claimed

This is a **profiler** measurement of the attention/output-projection path, not
coherent token generation from a full transformer forward pass. The tool says
so explicitly: attention and FFN phases sweep the real output weight tensor, so
their byte counts are an upper bound, not a per-layer measurement.

Vocab is 131072 but sampling covers the first 32768 logits; the output
projection still sweeps the full real weight tensor.

## Repository integrity

The parallel Deep2 workstream owns `runtime_graph_executor.cpp`. My restore
brought the ggml sources to exactly HEAD, leaving that workstream untouched
(`git diff` against those paths is empty). Nothing was overwritten.

The CanonicalTokenizer restoration from `62ade66df5` remains in place.
