# Patch: Replace Hardcoded CPU Backend with Smart Selection

## Problem
`ai_model_caller_real.cpp` line ~355 has:
```cpp
g_ctx.backend = ggml_rxd_backend_cpu_init();
```

This forces CPU-only execution regardless of GPU availability.

## Solution
Replace with backend selector that probes hardware and chooses optimal backend.

## Changes Required

### 1. Add Include
At top of `ai_model_caller_real.cpp`:
```cpp
#include "inference/backend_selector_real.hpp"
```

### 2. Replace Backend Initialization

**OLD (line ~355):**
```cpp
// Initialize backend
if (!g_ctx.backend) {
    g_ctx.backend = ggml_rxd_backend_cpu_init();
    if (!g_ctx.backend) {
        std::cerr << "Failed to initialize CPU backend\n";
        return false;
    }
}
```

**NEW:**
```cpp
// Initialize backend with smart selection
if (!g_ctx.backend) {
    using namespace RawrXD::Inference;
    
    // Get config from environment
    BackendConfig config = GetBackendConfigFromEnvironment();
    
    // Probe and select optimal backend
    BackendCapabilities caps = ProbeSystemCapabilities();
    BackendType selected = SelectOptimalBackend(config, caps);
    
    // Initialize based on selection
    switch (selected) {
        case BackendType::MEDUSA_GPU:
            // Medusa has custom execution path
            std::cout << "[ModelCaller] Using Medusa GPU speculative decoding\n";
            // Store Medusa backend pointer for custom path
            g_ctx.backend = nullptr; // Signal to use Medusa path
            g_ctx.use_medusa = true;
            break;
            
        case BackendType::VULKAN:
            std::cout << "[ModelCaller] Using Vulkan GPU backend\n";
            // TODO: g_ctx.backend = ggml_rxd_backend_vulkan_init();
            g_ctx.backend = ggml_rxd_backend_cpu_init(); // Fallback for now
            break;
            
        case BackendType::CPU:
        default:
            std::cout << "[ModelCaller] Using CPU backend\n";
            g_ctx.backend = ggml_rxd_backend_cpu_init();
            break;
    }
    
    if (!g_ctx.backend && !g_ctx.use_medusa) {
        std::cerr << "Failed to initialize backend\n";
        return false;
    }
}
```

### 3. Add to ggml_rxd_context struct
In header file, add:
```cpp
struct ggml_rxd_context {
    // ... existing fields ...
    bool use_medusa = false;  // Flag for Medusa custom path
    // ...
};
```

## Environment Variables

Control backend selection via environment:

```bash
# Force CPU
set RAWRXD_BACKEND=cpu

# Force Vulkan
set RAWRXD_BACKEND=vulkan

# Force Medusa (if available)
set RAWRXD_BACKEND=medusa

# Configure Medusa heads (1-16)
set RAWRXD_MEDUSA_HEADS=8

# Set context size
set RAWRXD_CONTEXT=32768

# Disable Medusa even if available
set RAWRXD_NO_MEDUSA=1

# Set VRAM budget in MB
set RAWRXD_VRAM_BUDGET=14000
```

## Build Instructions

Add to CMakeLists.txt or build command:

```cmake
target_sources(rawrxd PRIVATE
    src/inference/backend_selector_real.cpp
    src/inference/model_caller_integration.cpp
    src/inference/medusa_gpu_engine.cpp
)

target_link_libraries(rawrxd PRIVATE
    vulkan-1  # For Vulkan probing
)
```

## Validation Steps

1. **Build test:**
   ```bash
   g++ -std=c++17 -I. src/inference/test_backend_real.cpp \
       src/inference/backend_selector_real.cpp \
       -lvulkan -o test_backend.exe
   ```

2. **Run test:**
   ```bash
   test_backend.exe
   ```

3. **Verify GPU detection:**
   ```bash
   set RAWRXD_BACKEND=medusa
   rawrxd.exe --probe
   ```

4. **Profile actual performance:**
   ```bash
   # Don't claim performance numbers without this!
   rawrxd.exe --benchmark --tokens 1000 --context 32768
   ```

## Important Notes

- **NO PERFORMANCE CLAIMS** until GPU kernels are implemented and benchmarked
- Medusa backend currently returns `nullptr` to signal custom execution path
- Real Vulkan backend needs `ggml_rxd_backend_vulkan_init()` implementation
- CPU backend remains fallback for all cases
