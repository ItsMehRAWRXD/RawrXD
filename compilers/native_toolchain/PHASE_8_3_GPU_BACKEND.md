# Phase 8.3: GPU Backend Implementation

**Status:** IN PROGRESS  
**Goal:** Add hardware acceleration (Vulkan/DirectML/CUDA) to the validated inference pipeline  
**Priority:** Vulkan Compute first (RX 7800 XT), then DirectML, then CUDA

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              SOVEREIGN RUNTIME (Phase 8.1)                  │
│                   (CPU Execution Path)                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              GPU BACKEND ABSTRACTION (Phase 8.3)            │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Vulkan    │  │  DirectML   │  │    CUDA     │         │
│  │   Compute   │  │   (WinML)   │  │  (NVIDIA)   │         │
│  │  (Primary)  │  │  (Windows)  │  │  (Optional) │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              GPU DEVICE LAYER                               │
│  ├─ Memory Allocation (VRAM)                              │
│  ├─ Command Queue Management                              │
│  ├─ Shader/Kernel Compilation                             │
│  └─ Synchronization Primitives                            │
└─────────────────────────────────────────────────────────────┘
```

---

## Implementation Gates

### G12: Vulkan Compute Backend
**Requirement:** Functional Vulkan compute shaders for transformer ops

| Operation | Status | Shader |
|-----------|--------|--------|
| RMSNorm | ⏳ | `rmsnorm.comp` |
| RoPE | ⏳ | `rope.comp` |
| Attention | ⏳ | `attention.comp` |
| MatMul (Q4_0) | ⏳ | `matmul_q4.comp` |
| Softmax | ⏳ | `softmax.comp` |
| SwiGLU | ⏳ | `swiglu.comp` |

### G13: DirectML Backend
**Requirement:** Windows ML integration for cross-platform GPU

| Feature | Status | Notes |
|---------|--------|-------|
| Device Creation | ⏳ | `DMLCreateDevice` |
| Operator Graph | ⏳ | MatMul, Softmax, LayerNorm |
| Tensor Binding | ⏳ | D3D12 resources |
| Execution | ⏳ | Command recording |

### G14: CUDA Backend (Optional)
**Requirement:** NVIDIA GPU support

| Feature | Status | Notes |
|---------|--------|-------|
| Context Management | ⏳ | `cuCtxCreate` |
| Kernel Launch | ⏳ | `cuLaunchKernel` |
| Memory Transfers | ⏳ | `cuMemcpyHtoD/DtoH` |
| cuDNN Integration | ⏳ | Optional acceleration |

---

## File Structure

```
src/gpu/
├── gpu_backend.h              # Common GPU backend interface
├── gpu_backend.cpp            # Backend factory/dispatch
├── vulkan/
│   ├── vulkan_backend.h       # Vulkan-specific headers
│   ├── vulkan_backend.cpp     # Vulkan device/context
│   ├── vulkan_kernels.cpp     # Shader management
│   ├── shaders/
│   │   ├── rmsnorm.comp       # RMSNorm compute shader
│   │   ├── rope.comp          # RoPE compute shader
│   │   ├── attention.comp     # Attention shader
│   │   ├── matmul_q4.comp     # Quantized matmul
│   │   ├── softmax.comp       # Softmax shader
│   │   └── swiglu.comp        # SwiGLU FFN shader
│   └── shader_compiler.bat    # Compile .comp → .spv
├── directml/
│   ├── directml_backend.h     # DirectML headers
│   ├── directml_backend.cpp   # DirectML implementation
│   └── directml_operators.cpp # Operator graph builder
└── cuda/
    ├── cuda_backend.h         # CUDA headers
    ├── cuda_backend.cpp       # CUDA implementation
    └── cuda_kernels.cu        # CUDA kernels
```

---

## Build Commands

```bash
# Vulkan backend
g++ -O3 -shared -o vulkan_backend.dll src/gpu/vulkan/*.cpp \
    -lvulkan -DGPU_BACKEND_VULKAN

# DirectML backend
g++ -O3 -shared -o directml_backend.dll src/gpu/directml/*.cpp \
    -ldirectml -ld3d12 -dxgi -DGPU_BACKEND_DIRECTML

# CUDA backend (requires nvcc)
nvcc -O3 -shared -o cuda_backend.dll src/gpu/cuda/*.cu \
    -lcudart -lcublas -DGPU_BACKEND_CUDA
```

---

## Integration Points

### From Truth Gate 003
```cpp
// In transformer_executor.cpp, add GPU path:

TransformerExecutor* TransformerExecutor_Init(...) {
    // Try GPU backends in order: Vulkan -> DirectML -> CUDA -> CPU
    GPUBackend* gpu = GPUBackendCreate(GPU_BACKEND_VULKAN);
    if (!gpu) gpu = GPUBackendCreate(GPU_BACKEND_DIRECTML);
    if (!gpu) gpu = GPUBackendCreate(GPU_BACKEND_CUDA);
    
    if (gpu) {
        executor->use_gpu = true;
        executor->gpu_backend = gpu;
    }
}
```

### Kernel Dispatch
```cpp
bool ExecuteLayerGPU(TransformerExecutor* exec, int layer_idx) {
    GPUBackend* gpu = exec->gpu_backend;
    
    // Upload tensors if needed
    if (!exec->tensors_on_gpu) {
        gpu->UploadTensors(exec->model_tensors);
        exec->tensors_on_gpu = true;
    }
    
    // Dispatch kernels
    gpu->RMSNorm(...);
    gpu->RoPE(...);
    gpu->Attention(...);
    gpu->MatMul(...);
    
    // Download results if needed
    if (layer_idx == last_layer) {
        gpu->DownloadResults(exec->output_logits);
    }
    
    return true;
}
```

---

## Success Criteria

| Metric | Target | Measurement |
|--------|--------|-------------|
| Speedup vs CPU | >2x | Time inference pass |
| Memory bandwidth | >80% | GPU profiler |
| Numerical accuracy | <0.1% error | vs CPU reference |
| Device compatibility | RX 7800 XT | Primary target |

---

## Implementation Order

1. **Week 1:** Vulkan backend foundation
   - Device enumeration
   - Memory allocation
   - Command buffers

2. **Week 2:** Core shaders
   - RMSNorm, RoPE
   - Attention kernel
   - MatMul (Q4_0)

3. **Week 3:** Integration
   - Transformer executor GPU path
   - Truth Gate 003 GPU validation

4. **Week 4:** DirectML fallback
   - Windows-specific path
   - Wider compatibility

5. **Week 5+:** CUDA (optional)
   - NVIDIA support
   - cuDNN integration
