# Deep2 expert-locality + exact-range streaming + dual-GPU residency

Source-only C99 drop. No llama.cpp, Ollama, STL, Boost, task system, allocator library, Vulkan helper library, or background service dependency.

The subsystem deliberately does **not** own Vulkan. It owns scheduling and residency truth, and exposes an opaque device I/O ABI that the existing Deep2 / `SsVk` implementation can bind to. That keeps this drop source-only and prevents fake GPU success stubs.

## Components

- `d2_range`: validated tensor byte ranges, alignment, merge, exact range set construction.
- `d2_stream`: bounded exact-range request queue with tickets and observed completion accounting.
- `d2_locality`: per-expert recency/frequency/bytes scoring driven only by observed router selections.
- `d2_residency`: bounded per-device residency ledger and deterministic eviction.
- `d2_dual_gpu`: two-device placement using live budgets, bandwidth weights, locality, and transfer costs.
- `d2_plan`: builds one current-token execution plan from selected experts and their exact tensor ranges.
- `d2_runtime`: ties the three engines together and exposes a small integration API.

## Core invariant

The scheduler may retain or evict weights based on observed locality, but it never invents an expert activation. The router-selected expert IDs are authoritative for the current token.

## Build smoke

Windows:

```bat
build_msvc.bat
```

POSIX/GCC:

```sh
./build_gcc.sh
```

Smoke validates range merging, router-driven locality, budgeted dual-GPU placement, deterministic eviction, and bounded streaming queue behavior.

## Integration

Bind `D2DeviceIo` callbacks to the existing Deep2 Vulkan layer. A callback returning failure prevents residency promotion; this library does not fabricate device success.
