# DEEP2_ROOFLINE_ENHANCEMENTS_NODEP_20260912

Dependency-free roofline/locality planner for the Deep2 decode path.

The core source:
- allocates no heap memory,
- calls no OS API,
- calls no Vulkan API,
- calls no Ollama/llama.cpp/external runtime,
- uses integer/fixed-point arithmetic only,
- emits no synthetic product authority.

It is intended to sit beside the existing packed dual-GPU execution path.

## Why this exists

For giant MoE decode, the governing optimization is not total model size:

```text
TOTAL_MODEL_BYTES
```

It is:

```text
BYTES_NOT_ALREADY_LOCAL_PER_TOKEN
```

and then:

```text
TOKEN_CRITICAL_NS =
    max(GPU0_USEFUL_END_NS, GPU1_USEFUL_END_NS)
  + UNHIDDEN_REMOTE_SERVICE_NS
```

This drop converts those quantities into deterministic per-token plans and
auditable receipts.

## Build

### MSVC

Run from a VS x64 developer prompt:

```bat
build_msvc.bat
```

### GCC/Clang

```sh
cc -std=c99 -O2 -Wall -Wextra -Werror -pedantic \
  selftest.c d2_roofline.c -o selftest
./selftest
```

Expected:

```text
DEEP2_ROOFLINE_SELFTEST=PASS
TOP15_ENHANCEMENTS=15/15
CORE_NO_HEAP=1
CORE_NO_OS_CALLS=1
CORE_NO_VULKAN_CALLS=1
CORE_NO_EXTERNAL_RUNTIME=1
LIVE_PRODUCT_RUN=NOT_RUN
PROMOTE=0
```

See:
- `TOP15.md`
- `PRODUCT_BIND_MAP.md`
- `LAW.txt`
