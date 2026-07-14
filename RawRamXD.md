# RawRamXD - Software-Defined AI Memory Fabric

## Overview

**RawRamXD** is a software-defined memory fabric that unifies VRAM, RAM, and storage into one predictive, scheduler-controlled resource for AI inference. It transforms memory from a passive resource into an active, AI-scale substrate.

## The 10 Principles

1. **Reverse engineer memory into RawRamXD**—a scheduler-controlled AI memory fabric that decides where every byte lives.

2. **Reverse engineer allocation into residency**, where every tensor exists independently of VRAM, RAM, or storage.

3. **Reverse engineer paging into predictive migration**, moving data before compute ever waits for it.

4. **Reverse engineer storage into active memory** by treating NVMe as an intelligent tensor reservoir instead of a passive filesystem.

5. **Reverse engineer VRAM limits with dynamic tensor residency**, keeping only hot working sets on the GPU.

6. **Reverse engineer DMA into a continuous streaming fabric** that overlaps loading, migration, and execution.

7. **Reverse engineer page faults into user-space AI residency events** that transparently promote and demote tensors.

8. **Reverse engineer memory hierarchy into a single telemetry-driven optimization loop** that continuously adapts placement decisions.

9. **Reverse engineer inference around data movement**, ensuring compute follows residency instead of residency following compute.

10. **Reverse engineer heterogeneous memory into RawRamXD**—a sovereign AI memory fabric where VRAM, RAM, and storage operate as one scheduler-directed resource.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    RawrXD Inference Engine                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   Model     │  │   KV Cache  │  │     Activations         │  │
│  │   Weights   │  │             │  │                         │  │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘  │
│         │                │                      │               │
│         └────────────────┼──────────────────────┘               │
│                          │                                      │
│         ┌────────────────▼────────────────┐                    │
│         │      RawRamXD Fabric API         │                    │
│         │  allocate() / ensureVRAM() / touch()                  │
│         └────────────────┬────────────────┘                    │
└──────────────────────────┼──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                    Residency Engine                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   Policy    │  │  Telemetry  │  │    Migration Queue      │  │
│  │   Engine    │  │   Loop      │  │    (Priority)           │  │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘  │
│         │                │                      │               │
│         └────────────────┼──────────────────────┘               │
│                          │                                      │
│         ┌────────────────▼────────────────┐                    │
│         │      Scheduler Thread            │                    │
│         │  decidePlacement() / executeMigration()               │
│         └────────────────┬────────────────┘                    │
└──────────────────────────┼──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                    Physical Tier Manager                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │  VRAM    │  │   RAM    │  │   NVMe   │  │      HDD         │  │
│  │  Tier 0  │  │  Tier 1  │  │  Tier 2  │  │     Tier 3       │  │
│  │ (48GB)   │  │ (128GB)  │  │  (2TB)   │  │     (4TB)        │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Core Concepts

### RawRamXD Handle

Every allocation gets a **RawRamXD Handle** - a virtual reference that exists independently of physical location:

```cpp
// Allocate 100MB tensor
rawramxd::Handle handle = rawramxd::RawRamXDFabric::instance().allocate(
    100 * 1024 * 1024,  // size
    "layer_0_weights",  // name
    rawramxd::AccessPattern::WEIGHTS  // pattern
);
```

### Residency States

- **UNMAPPED**: Not allocated
- **RESIDENT**: In current tier, ready
- **MIGRATING**: Moving between tiers
- **EVICTED**: In lower tier
- **PREFETCHING**: Loading proactively
- **FAULTING**: On-demand load in progress

### Access Patterns

- **WEIGHTS**: Read-mostly, large (start in RAM)
- **KV_CACHE**: Read-write, medium lifetime (promote to VRAM)
- **ACTIVATIONS**: Short-lived, compute-heavy (keep in VRAM)
- **SCRATCH**: Temporary buffers (VRAM)
- **UNIFORM**: Unknown/generic

## API Reference

### C++ API

```cpp
#include "RawRamXD.hpp"

// Initialize fabric
rawramxd::RawRamXDFabric::instance().initialize(
    48ULL * 1024 * 1024 * 1024,  // 48GB VRAM
    128ULL * 1024 * 1024 * 1024, // 128GB RAM
    2ULL * 1024 * 1024 * 1024 * 1024 // 2TB NVMe
);

// Allocate tensor
auto handle = rawramxd::RawRamXDFabric::instance().allocate(
    size, name, pattern
);

// Ensure residency before compute
rawramxd::RawRamXDFabric::instance().ensureInVRAM(handle);

// Mark as used (updates access stats)
rawramxd::RawRamXDFabric::instance().touch(handle);

// Get VRAM pointer for kernel
void* gpu_ptr = rawramxd::RawRamXDFabric::instance().vramPtr(handle);
launch_kernel(gpu_ptr);

// Cleanup
rawramxd::RawRamXDFabric::instance().deallocate(handle);
```

### C API

```c
#include "RawRamXD.h"

// Initialize
rawramxd_init(48ULL*1024*1024*1024, 128ULL*1024*1024*1024, 2ULL*1024*1024*1024*1024);

// Allocate
uint64_t handle = rawramxd_alloc(size, "weights", RAWRAMXD_PATTERN_WEIGHTS);

// Ensure residency
rawramxd_ensure_vram(handle);

// Get pointer
void* ptr = rawramxd_vram_ptr(handle);

// Cleanup
rawramxd_free(handle);
```

### RAII Wrapper

```cpp
// Automatic lifecycle management
{
    rawramxd::RawRamXDTensor tensor(100*1024*1024, "weights", 
                                    rawramxd::AccessPattern::WEIGHTS);
    
    // Ensure VRAM residency
    tensor.ensureVRAM();
    
    // Get pointer
    void* ptr = tensor.vram();
    
    // Automatic cleanup on scope exit
}
```

## Residency Engine

The Residency Engine is the "brain" of RawRamXD. It decides where each tensor lives based on:

- **Access Pattern**: Weights vs KV cache vs activations
- **Recency**: Time since last access
- **Frequency**: Number of accesses
- **Tier Pressure**: Current utilization of each tier
- **Target TPS**: Performance goals

### Default Policy

```cpp
// Hot data (high recency + frequency) → VRAM
if (heat > 0.8) {
    return Tier::VRAM;
}

// Warm data → RAM
if (heat > 0.4) {
    return Tier::RAM;
}

// Cold data → NVMe
return Tier::NVMe;
```

### Custom Policy

```cpp
class MyResidencyEngine : public rawramxd::ResidencyEngine {
    Tier decidePlacement(const RawRamXDHandle* handle) override {
        // Custom logic
        if (is_critical_layer(handle)) {
            return Tier::VRAM;
        }
        return Tier::RAM;
    }
    // ... other methods
};

rawramxd::RawRamXDFabric::instance().setResidencyEngine(
    std::make_unique<MyResidencyEngine>()
);
```

## Integration with RawrXD

### Model Loading

```cpp
// Before: Direct allocation
void* weights = cudaMalloc(size);

// After: RawRamXD allocation
auto handle = rawramxd::RawRamXDFabric::instance().allocate(
    size, "layer_weights", rawramxd::AccessPattern::WEIGHTS
);

// Load from disk to NVMe (cold)
load_from_disk_to_handle(handle, filepath);

// Prefetch to RAM (warm)
rawramxd::RawRamXDFabric::instance().prefetch(handle);

// Ensure in VRAM before first use (hot)
rawramxd::RawRamXDFabric::instance().ensureInVRAM(handle);
```

### Inference Loop

```cpp
for (int token = 0; token < max_tokens; token++) {
    // 1. Ensure KV cache is resident
    rawramxd::RawRamXDFabric::instance().ensureInVRAM(kv_cache_handle);
    
    // 2. Ensure layer weights are resident
    for (auto& handle : layer_handles) {
        rawramxd::RawRamXDFabric::instance().ensureInVRAM(handle);
    }
    
    // 3. Launch compute
    launch_transformer_layer(...);
    
    // 4. Mark as used (updates stats)
    for (auto& handle : layer_handles) {
        rawramxd::RawRamXDFabric::instance().touch(handle);
    }
    rawramxd::RawRamXDFabric::instance().touch(kv_cache_handle);
}
```

## Telemetry

RawRamXD continuously collects metrics:

```cpp
auto stats = rawramxd::RawRamXDFabric::instance().stats();

std::cout << "VRAM Usage: " << stats.tiers[0].usedBytes / (1024*1024) << " MB" << std::endl;
std::cout << "Migrations: " << stats.migrationsCompleted << std::endl;
std::cout << "Avg Migration Time: " << stats.avgMigrationTimeMs << " ms" << std::endl;
std::cout << "Current TPS: " << stats.currentTPS << std::endl;
```

## Performance Characteristics

| Operation | Latency | Bandwidth |
|-----------|---------|-----------|
| VRAM Access | ~10 ns | 1 TB/s |
| RAM Access | ~100 ns | 50 GB/s |
| NVMe Read | ~10 μs | 7 GB/s |
| Migration (NVMe→RAM) | ~50 ms/GB | 20 GB/s |
| Migration (RAM→VRAM) | ~10 ms/GB | 100 GB/s |

## Building

```bash
# Compile
g++ -std=c++17 -O3 -o rawramxd.o RawRamXD.cpp -lpthread

# Link with RawrXD
g++ -std=c++17 -O3 -o rawrxd rawrxd.cpp RawRamXD.cpp \
    -lcuda -lcudart -ld3d12 -ldxgi -lpthread
```

## Future Enhancements

1. **GPU Direct Storage**: Bypass CPU for NVMe→VRAM
2. **Peer-to-Peer**: Multi-GPU tensor sharing
3. **Compression**: On-the-fly weight compression
4. **Prediction**: ML-based access prediction
5. **NUMA Awareness**: Optimize for multi-socket systems

## License

MIT License - See LICENSE file