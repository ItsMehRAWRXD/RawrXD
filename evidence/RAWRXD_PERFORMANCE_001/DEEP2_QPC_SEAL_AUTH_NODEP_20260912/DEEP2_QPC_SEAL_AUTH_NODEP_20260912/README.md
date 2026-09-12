# Deep2 QPC Seal Authority — dependency-free source

Purpose: turn a real Windows `QueryPerformanceCounter` full-model decode observation into
a sealed receipt that is eligible to mint `FULL_MODEL_TPS_AUTHORITY=1`.

This is intentionally **not linked into the currently-running baseline binary**.
It is source for the next authority-capable product bind or a future rerun.

## Trust chain

    Authority Grant
        ↓
    Gate ID + exact 64-char cert SHA-256
        ↓
    Win32 QPC provider
        ↓
    token_begin()
        ↓
    REAL full-forward token
        ↓
    token_end()
        ↓
    × target tokens
        ↓
    close()
        ↓
    cardinality + QPC + predicate validation
        ↓
    metrics
        ↓
    SHA-256 receipt seal
        ↓
    mint_tps_authority()
        ↓
    FULL_MODEL_TPS_AUTHORITY=1

## Direct QPC binding without windows.h

`src/d2_qpc_win32.cpp` imports only:

- `QueryPerformanceCounter`
- `QueryPerformanceFrequency`

from Kernel32 using their ABI declarations. There is no `windows.h` include and no third-party
runtime.

## Required live predicates

All must be supplied from actual product observations:

    FULL_MODEL_FORWARD=1
    REAL_AUTOREGRESSIVE_DECODE=1
    WARMUP_EXCLUDED=1
    SEALED_LOGITS_REUSE=0
    SYNTHETIC_LOGITS=0
    DEVICE_LOST=0
    CERT_BINARY_CHANGED=0

The module does not infer or manufacture them.

## Receipt fields

- exact gate id
- exact cert SHA-256
- authority name + nonce
- QPC frequency
- target / observed token count
- every begin/end QPC sample
- generation wall time
- token min/max/mean/P50/P95
- nanosecond conversions
- sustained TPS
- predicates
- SHA-256 seal

## No dependencies

    C++17
    no Vulkan
    no CUDA
    no ROCm
    no llama.cpp
    no Ollama
    no OpenSSL/libsodium
    no windows.h

The only Windows runtime imports for the live adapter are the OS QPC functions.

## Current live-run boundary

For the existing `DEEP2_FULL_MODEL_TPS_AUTHORITY_001` process, do not inject this module
mid-run. The current measured binary must remain byte-identical through its own 64/64 seal.

Use this drop after the current baseline has sealed, or build it into an intentionally
new measurement binary whose cert hash is bound before observation starts.

## Selftest

The portable selftest uses an injected deterministic clock so it can validate the entire
seal/mint state machine without pretending to be live QPC authority. Its TPS result is synthetic.
