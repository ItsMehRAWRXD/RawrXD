# Deep2 Residency-Aware Persistent Token Graph — no dependencies

This source drop reverses the execution unit from:

    host loop
      -> generic tensor op
      -> queue wait
      -> next op
      -> reload/translate tensor
      -> next op

into:

    persistent token graph
      -> exact packed tensor ranges
      -> residency layer
      -> fixed device views
      -> packed kernels
      -> one token completion boundary

It is deliberately a side drop. It does not modify the current timed TPS binary,
does not mint product authority, and does not set PROMOTE.

## Core ideas

### 1. ResidencyLayer is the owner of where tensors live

Each tensor has:
- stable tensor id
- GGUF shard id
- exact file offset and byte size
- codec
- flags / preferred tier
- lifetime within the persistent token graph

The layer maps the exact source range into a fixed GPU slot and returns a `PackedView`.
No decoded FP16/F32 weight buffer is required by this API.

### 2. Persistent graph is the decode unit

A token is compiled as a graph of operations:
- embedding
- packed QKV GEMV
- RoPE/KV append
- attention
- packed output projection
- packed FFN
- tiled LM-head reduction
- sampler/token commit

Graph topology does not change per token. `TokenContext` supplies only dynamic token
state such as position and token id.

### 3. No heap allocation in the token loop

All tensors, nodes, actions, slots, and views are fixed-capacity arrays.
`run_token()` performs no `new`, `malloc`, `std::vector`, or other heap allocation.

### 4. No GPU SDK dependency

The layer includes no Vulkan, CUDA, ROCm, D3D12, llama.cpp, or Ollama headers.
Deep2/SsVk binds four opaque callbacks:

- `load_exact`
- `evict`
- `dispatch`
- `token_sync`

This allows the real product bind to translate `PackedView` directly into existing
SsVk buffer/device-memory objects.

## Production binding shape

    GGUF resolver
        |
        v
    TensorDesc(shard, offset, bytes, codec)
        |
        v
    ResidencyGraph
        |
        +--> GPU0 fixed slot / PackedView
        |
        +--> GPU1 fixed slot / PackedView
        |
        +--> exact-range load only when not resident
        |
        v
    persistent NodeDesc graph
        |
        v
    SsVk packed kernels
        |
        v
    one token sync
        |
        v
    token commit

## Intended invariants

    PACKED_NATIVE_WEIGHTS=1
    MATERIALIZED_DEQUANT_WEIGHT_BUFFER=0
    EXACT_RANGE_BIND=1
    PER_TOKEN_HEAP_ALLOCATIONS=0
    PERSISTENT_GRAPH=1
    TOKEN_SYNC_BOUNDARIES=1
    HOST_LOGITS_REQUIRED=0       # when LM-head backend is device-reduced
    PRODUCT_AUTHORITY_MINT=0     # this side drop cannot mint it
    PROMOTE=0

## What remains product-specific

This drop intentionally does not implement:
- Vulkan allocation/import
- Q2_K shader/ISA
- real timeline semaphore scheduling
- cross-GPU reductions
- real KV page table
- actual sampler
- cert receipt writing

Those bind behind the callback ABI so the residency/graph policy remains independent
of the GPU API implementation.

## Build

MSVC x64:
    build_msvc.bat

Portable smoke:
    g++ -std=c++17 -O2 -Iinclude src/d2_residency_graph.cpp src/selftest.cpp -o selftest

## Authority boundary

This is an additive optimization source drop only.

    PRODUCT_LINKED_INTO_CERT=0
    FULL_MODEL_TPS_AUTHORITY=0
    CERT_BINARY_TOUCHED=0
    PROMOTE=0

Only the live `DEEP2_FULL_MODEL_TPS_AUTHORITY_001` QPC receipt may establish the
baseline performance authority.
