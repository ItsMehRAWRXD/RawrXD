# RawrXD Performance Optimization

## Overview

This directory contains performance tuning and optimization tooling for RawrXD. These scripts analyze hardware capabilities and automatically tune kernels, memory, and inference parameters for maximum performance.

---

## Performance Phases

| Phase | Component | Purpose | Status |
|-------|-----------|---------|--------|
| **J.1** | `hardware_profiler.ps1` | Analyze hardware and generate recommendations | ✅ Complete |
| **J.2** | `kernel_tuner.ps1` | Auto-tune kernels for detected hardware | ✅ Complete |
| **J.3** | `memory_optimizer.ps1` | Optimize memory configuration | ✅ Complete |

---

## Phase J.1: Hardware Profiler

**File:** `phase_j1_hardware_profiler/hardware_profiler.ps1`

**Purpose:** Analyze system hardware and generate RawrXD optimization recommendations

**Analyzes:**
- System information (manufacturer, model, OS)
- CPU (cores, threads, AVX/AVX2/AVX512 support)
- GPU (VRAM, tier, compute APIs)
- Memory (total, available, modules, speed)
- Storage (drive types, free space)

**Outputs:**
- `hardware_profile_{timestamp}.json` — Machine-readable profile
- `hardware_report_{timestamp}.md` — Human-readable report
- `rawrxd.config.json` — Optimized configuration (with `-GenerateConfig`)

**Usage:**
```powershell
# Analyze hardware
.\phase_j1_hardware_profiler\hardware_profiler.ps1

# Generate optimized config
.\phase_j1_hardware_profiler\hardware_profiler.ps1 -GenerateConfig

# Run with benchmarks
.\phase_j1_hardware_profiler\hardware_profiler.ps1 -Benchmark
```

---

## Phase J.2: Kernel Tuner

**File:** `phase_j2_kernel_tuner/kernel_tuner.ps1`

**Purpose:** Automatically tune RawrXD kernels for optimal performance

**Tests:**
- AVX2 kernels (128, 256, 512 tile sizes)
- AVX512 kernels (128, 256, 512 tile sizes)
- Thread scaling (4, 8, 16, 32 threads)
- Performance vs efficiency trade-offs

**Outputs:**
- `kernel_tuning_results.json` — All benchmark results
- `kernel_optimization.json` — Optimal configuration
- `kernel_tuning_report.md` — Human-readable report

**Usage:**
```powershell
# Tune kernels using latest hardware profile
.\phase_j2_kernel_tuner\kernel_tuner.ps1

# Use specific profile
.\phase_j2_kernel_tuner\kernel_tuner.ps1 -ProfilePath ".\hardware_profiles\profile.json"

# Adjust benchmark duration
.\phase_j2_kernel_tuner\kernel_tuner.ps1 -BenchmarkDuration 60
```

---

## Phase J.3: Memory Optimizer

**File:** `phase_j3_memory_optimizer/memory_optimizer.ps1`

**Purpose:** Optimize memory configuration for maximum throughput and stability

**Analyzes:**
- Model size requirements (3B, 7B, 13B, 30B, 70B)
- Quantization options (FP16, Q8_0, Q4_0)
- Context length feasibility
- Batch size optimization
- KV cache strategy

**Outputs:**
- `memory_optimization.json` — Optimized memory configuration
- `memory_optimization_report.md` — Human-readable report

**Usage:**
```powershell
# Optimize for 7B model
.\phase_j3_memory_optimizer\memory_optimizer.ps1 -ModelSize 7B

# Optimize for 70B model with specific tuning
.\phase_j3_memory_optimizer\memory_optimizer.ps1 `
    -ModelSize 70B `
    -TuningPath ".\kernel_tuning\kernel_optimization.json"
```

---

## Quick Start

```powershell
# 1. Profile hardware
.\phase_j1_hardware_profiler\hardware_profiler.ps1 -GenerateConfig

# 2. Tune kernels
.\phase_j2_kernel_tuner\kernel_tuner.ps1

# 3. Optimize memory
.\phase_j3_memory_optimizer\memory_optimizer.ps1 -ModelSize 7B

# 4. Apply configurations
Copy-Item .\hardware_profiles\rawrxd.config.json ..
Copy-Item .\kernel_tuning\kernel_optimization.json ..
Copy-Item .\memory_optimization\memory_optimization.json ..
```

---

## Integration with Other Phases

| Phase | Output | J Phase Usage |
|-------|--------|---------------|
| **G.1** | Production benchmarks | Baseline for tuning |
| **L.6** | Security validation | Pre-tuning validation |
| **L.7** | Reproducible builds | Consistent test environment |
| **L.8** | Deployment profiles | Hardware-specific configs |

---

## Performance Tuning Workflow

```
Hardware Profiler (J.1)
    |
    v
Kernel Tuner (J.2) ←→ Benchmarks (G.1)
    |
    v
Memory Optimizer (J.3)
    |
    v
Optimized Configuration
    |
    v
Validation (L.6)
    |
    v
Deployment (L.8)
```

---

## Success Criteria

✅ **J.1** — Hardware profile with optimization recommendations  
✅ **J.2** — Kernel tuning with performance benchmarks  
✅ **J.3** — Memory optimization for model size  

---

## Next Steps

After running all three phases:

1. Review generated reports
2. Apply optimized configurations
3. Run validation gates (Phase L.6)
4. Deploy with optimized settings (Phase L.8)

**RawrXD is now tuned for your specific hardware!** 🚀
