# SEG - Sovereign Execution Graph

A unified 7-layer execution system for sovereign AI inference.

## Architecture

SEG unifies 5 unlock domains into a single declarative execution graph:

1. **Node Layer** (`seg_node.hpp/cpp`) - 70+ node types covering transformer ops, GPU ops, and agentic ops
2. **Graph Layer** (`seg_graph.hpp/cpp`) - DAG structure with topological sort, cycle detection, builder API
3. **Scheduler Layer** (`seg_scheduler.hpp/cpp`) - Parallel execution with thread pool, async support
4. **Memory Layer** (`seg_memory.hpp/cpp`) - Unified memory pools (KV cache, tensor mmap, temp, GPU staging, agent scratch, telemetry)
5. **Executor Layer** (`seg_executor.hpp/cpp`) - Multi-backend dispatch (MASM AVX-512, GPU/DMA, Agentic)
6. **Agent Layer** (`seg_agent.hpp/cpp`) - Self-optimizing telemetry and decision system
7. **Runtime Layer** (`seg_runtime.hpp/cpp`) - Unified API with C/C++ bindings

## Quick Start

```cpp
#include "seg_runtime.hpp"

// Configure
seg::SEGRuntimeConfig config;
config.thread_count = 8;
config.use_gpu = true;
config.enable_agentic = true;

// Initialize
seg::SEGRuntime runtime;
runtime.Initialize(config);

// Generate
auto result = runtime.Generate("Hello, world!");
std::cout << result.text << "\n";
std::cout << result.tokens_per_second << " tokens/sec\n";
```

## Building

```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

## MASM Integration

Link your MASM kernels by placing `.obj` files in `../masm_kernels/`:

```cpp
// In seg_executor.cpp, kernels are auto-registered:
void SEGMASMBackend::RegisterDefaultKernels() {
    RegisterKernel(SEGNodeType::RMSNORM, MASM_RMSNorm);
    RegisterKernel(SEGNodeType::ATTENTION_HEAD, MASM_Attention);
    // ... etc
}
```

## Node Types

### Transformer Ops
- `RMSNORM`, `RMSNORM_INPLACE` - Layer normalization
- `QKV_PROJECT` - Query/key/value projection
- `ATTENTION_HEAD`, `ATTENTION_FLASH` - Self-attention
- `MLP_GATE`, `MLP_UP`, `MLP_DOWN`, `MLP_SWIGLU` - Feed-forward
- `RESIDUAL_ADD` - Residual connections

### Quantization Ops
- `DEQUANT_Q4_0`, `DEQUANT_Q4_1`, `DEQUANT_Q4_K`, `DEQUANT_Q4_K_M`
- `DEQUANT_Q8_0`, `DEQUANT_Q8_K`, `DEQUANT_Q2_K`, `DEQUANT_NF4`

### GPU Ops
- `GPU_DMA_H2D`, `GPU_DMA_D2H`, `GPU_DMA_D2D` - Memory transfers
- `GPU_NF4_DEQUANT`, `GPU_MATMUL`, `GPU_ATTENTION`, `GPU_RMSNORM`

### Agentic Ops
- `AGENT_THINK`, `AGENT_ACT`, `AGENT_PLAN`, `AGENT_REFLECT`, `AGENT_DECIDE`, `AGENT_OPTIMIZE`

## Memory Regions

- `KV_CACHE` - Persistent KV cache
- `TENSOR_MMAP` - Memory-mapped GGUF tensors
- `TEMPORARY` - Computation buffers
- `GPU_STAGING` - GPU upload/download staging
- `AGENT_SCRATCH` - Agentic workspace
- `TELEMETRY_RING` - Circular telemetry buffer

## License

Sovereign AI Platform - All Rights Reserved
