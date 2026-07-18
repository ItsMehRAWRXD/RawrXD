# RawrXD Hardware Capability Matrix

**Version:** 1.0  
**Date:** 2026-07-17  
**Status:** Active

---

## CPU Capabilities

| Feature | Detection | Status | Notes |
|---------|-----------|--------|-------|
| AVX2 | CPUID | ✅ Required | Baseline for all kernels |
| AVX-512 | CPUID | ⚠️ Optional | 512-bit vectors (future) |
| FMA3 | CPUID | ✅ Required | Fused multiply-add |
| BMI2 | CPUID | ⚠️ Optional | Bit manipulation |
| LZCNT | CPUID | ⚠️ Optional | Leading zero count |

### Tested CPUs

| CPU | AVX2 | AVX-512 | Status |
|-----|------|---------|--------|
| AMD Ryzen (Zen 3+) | ✅ | ❌ | Primary test platform |
| Intel Core (Haswell+) | ✅ | ⚠️ | AVX-512 on HEDT only |
| AMD EPYC | ✅ | ✅ | Server target |

---

## GPU Capabilities

| Vendor | Architecture | Status | Backend |
|--------|------------|--------|---------|
| AMD | RDNA3 (gfx1101) | ✅ Tested | Vulkan Compute |
| AMD | RDNA4 (gfx1201) | ⚠️ Target | Vulkan Compute |
| AMD | CDNA3 | ⚠️ Future | ROCm |
| NVIDIA | Ampere | ⚠️ Future | CUDA |
| NVIDIA | Ada | ⚠️ Future | CUDA |
| Intel | Arc | ⚠️ Future | Vulkan/SYCL |

### Tested GPUs

| GPU | VRAM | Status | Notes |
|-----|------|--------|-------|
| AMD RX 7800 XT | 16GB | ✅ Tested | Primary test platform |
| AMD Radeon AI Pro R9700 | 64GB | ⚠️ Target | Production target |

---

## Memory Requirements

| Component | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| System RAM | 8GB | 32GB | For 7B models |
| GPU VRAM | 8GB | 16GB+ | For 7B models |
| Disk | 10GB | 50GB | Model storage |

---

## Capability Detection

```cpp
// Runtime capability query
RawrXD_CapabilityReport QueryCapabilities() {
    RawrXD_CapabilityReport report;
    report.abi_version = 1;
    report.kernel_interface_version = 1;
    
    // CPU detection via CPUID
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    report.has_avx2 = (cpuInfo[2] & (1 << 28)) != 0;
    report.has_fma = (cpuInfo[2] & (1 << 12)) != 0;
    
    // Extended CPUID for AVX-512
    __cpuidex(cpuInfo, 7, 0);
    report.has_avx512 = (cpuInfo[1] & (1 << 16)) != 0;
    
    // GPU detection via Vulkan
    report.has_gpu = VulkanEnumerateDevices() > 0;
    report.gpu_vendor = DetectGPUVendor();
    
    // Memory
    report.system_memory_mb = GetSystemMemoryMB();
    report.gpu_memory_mb = GetGPUMemoryMB();
    
    return report;
}
```

---

## Validation Matrix

| Hardware Config | RMSNorm | Softmax | SiLU | Full Inference |
|----------------|---------|---------|------|----------------|
| AMD Ryzen + RX 7800 XT | ✅ | ✅ | ✅ | ⚠️ Target |
| Intel Core + RTX 4090 | ⚠️ | ⚠️ | ⚠️ | ⚠️ Target |
| AMD EPYC + MI300X | ⚠️ | ⚠️ | ⚠️ | ⚠️ Target |

---

## Recommended Backend Selection

```
IF GPU_AVAILABLE AND GPU_MEMORY >= MODEL_SIZE * 1.5:
    USE GPU_BACKEND
ELSE IF CPU_HAS_AVX512 AND MODEL_SIZE <= 4B:
    USE AVX512_BACKEND
ELSE:
    USE AVX2_BACKEND
```

---

## Future Targets

| Target | Timeline | Requirements |
|--------|----------|--------------|
| RDNA4 Support | Q3 2026 | gfx1201 ISA |
| AVX-512 Kernels | Q3 2026 | Intel Sapphire Rapids |
| Unified Memory | Q4 2026 | AMD MI300X, Apple Silicon |
| Multi-GPU | Q4 2026 | NVLink, PCIe P2P |
