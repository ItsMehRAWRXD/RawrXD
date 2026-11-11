# GPU Acceleration Roadmap - 7800XT

**Date**: 2026-07-09  
**Hardware**: AMD Radeon RX 7800 XT (detected)  
**Status**: ROCm/HIP not installed

---

## Current State

### ✅ Hardware Present
- **AMD Radeon RX 7800 XT**: 16GB VRAM, 60 CUs, ~45 TFLOPS FP16
- **Driver**: 32.0.31021.5001 (Adrenalin)

### ❌ Software Missing
- **ROCm**: Not installed
- **HIP Runtime**: Not installed
- **hiprt64.dll / amdhip64.dll**: Not found

---

## Option 1: Install ROCm (Recommended)

### Steps
1. Download ROCm 6.0+ for Windows
2. Install HIP SDK
3. Verify `amdhip64.dll` is in PATH
4. Rebuild with HIP support

### Expected Performance
- **FP16 Compute**: ~45 TFLOPS
- **Memory BW**: ~960 GB/s
- **Q4_0 Inference**: ~200-400 tok/s (30B model)
- **32K Context**: Feasible with 16GB VRAM

### Pros
- Native AMD GPU support
- Best performance for 7800XT
- Full tensor core utilization

### Cons
- ROCm Windows support is newer/less mature
- May require specific driver versions

---

## Option 2: Vulkan Compute (Fallback)

### Current Status
- **Vulkan Loader**: Available (`vulkan-1.dll`)
- **Compute Shaders**: Can be implemented
- **Cross-Platform**: Works on all GPUs

### Expected Performance
- **Compute**: ~10-20 TFLOPS (less than HIP)
- **Memory BW**: ~400-600 GB/s
- **Q4_0 Inference**: ~50-100 tok/s

### Implementation
```cpp
// Use existing vulkan_compute_real.cpp
// Write compute shaders for:
// - Q4_0 dequantization
// - MatMul
// - Attention
```

### Pros
- Already partially implemented
- No additional drivers needed
- Works today

### Cons
- Lower performance than HIP
- More complex shader programming

---

## Option 3: DirectML (Windows Only)

### Status
- **DirectML**: Available via DirectX 12
- **Integration**: Can use existing DML backend

### Expected Performance
- **Compute**: ~15-25 TFLOPS
- **Q4_0 Inference**: ~80-150 tok/s

### Pros
- Windows-native
- Good tooling
- Automatic optimizations

### Cons
- Windows-only
- Less control over kernels

---

## Recommended Path

### Phase 1: Immediate (Today)
1. **Verify Vulkan works** - Use existing `vulkan_compute_real.cpp`
2. **Implement Q4_0 Vulkan shaders** - `shader_matmul.comp`
3. **Benchmark actual GPU performance**

### Phase 2: Short-term (This week)
1. **Install ROCm 6.0**
2. **Build HIP backend**
3. **Compare Vulkan vs HIP performance**

### Phase 3: Optimization
1. **FlashAttention for 32K context**
2. **PagedAttention for KV cache**
3. **Multi-GPU if available**

---

## Quick Test: Vulkan

Let's see if Vulkan compute works right now:

```bash
cd d:\rawrxd\build-ninja
ninja vulkan_compute_test
```

If Vulkan works, we can get GPU acceleration TODAY without installing ROCm.

---

## Performance Targets (7800XT)

| Metric | CPU (AVX-512) | Vulkan | HIP/ROCm |
|--------|---------------|--------|----------|
| MatMul GFLOPS | ~100 | ~500 | ~2000+ |
| 30B tok/s | ~4 | ~50-100 | ~200-400 |
| 32K Context | Slow | Moderate | Fast |
| VRAM Usage | N/A | 16GB | 16GB |

---

## Next Action

**Choose one:**

1. **Test Vulkan now** (5 minutes) - See if existing Vulkan code works
2. **Install ROCm** (30 minutes) - Get maximum performance
3. **Use DirectML** (15 minutes) - Windows-native path

Which would you like to pursue?
