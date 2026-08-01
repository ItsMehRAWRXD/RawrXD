# Renderer Pipeline — MASM x64 + Vulkan GDI

## Pipeline Overview

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  Vertex   │───▶│  Shader  │───▶│  Raster  │───▶│  Output  │
│  Fetch    │    │  (MASM)  │    │  (MASM)  │    │  (Vulkan)│
└──────────┘    └──────────┘    └──────────┘    └──────────┘
```

## MASM Kernel Pipeline

| Stage | Kernel | SIMD | Description |
|-------|--------|------|-------------|
| Vertex transform | `matmul_f32_avx2.asm` | AVX2/AVX512 | Model-view-projection matrix multiply |
| Rasterization | `rasterize_tri.asm` | Scalar | Triangle setup, edge equations |
| Fragment shading | `shader_gouraud.asm` | AVX2 | Per-pixel color interpolation |
| Depth test | `depth_test.asm` | Scalar | Early-Z, hierarchical Z |
| Output merger | `blend_alpha.asm` | AVX2 | Alpha blending, color output |

## Vulkan GDI Bridge

```
MASM Render Buffer
       │
       ▼
Vulkan Buffer (VK_BUFFER_USAGE_STORAGE_BUFFER_BIT)
       │
       ▼
Vulkan Compute Shader (copy to swapchain image)
       │
       ▼
Vulkan Present (vkQueuePresentKHR)
```

## Performance Targets

| Resolution | Triangle Rate | Fill Rate | Frame Time |
|------------|--------------|-----------|------------|
| 1080p | 2M tris/frame | 60 MPix/s | 16ms |
| 1440p | 1.5M tris/frame | 45 MPix/s | 16ms |
| 4K | 800K tris/frame | 30 MPix/s | 33ms |

## Competitive Comparison

| Metric | Sunshine (MASM) | Unreal (D3D12) | Godot (Vulkan) |
|--------|----------------|----------------|----------------|
| Draw calls | ~500/frame | ~5000/frame | ~2000/frame |
| Triangle throughput | ~2M/frame | ~10M/frame | ~5M/frame |
| Driver overhead | **Minimal** | Moderate | Moderate |
| Binary size | **~50KB** | ~5MB | ~2MB |
| GPU portability | Vulkan | D3D12/Vulkan | Vulkan/D3D |
