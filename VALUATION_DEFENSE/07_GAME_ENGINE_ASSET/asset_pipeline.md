# Asset Pipeline — GGUF + MASM + Vulkan

## Pipeline Overview

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  Source   │───▶│  Import  │───▶│  Process │───▶│  Runtime │
│  Assets   │    │  (GGUF)  │    │  (MASM)  │    │  (Vulkan)│
└──────────┘    └──────────┘    └──────────┘    └──────────┘
```

## Asset Types

| Type | Source Format | Runtime Format | Pipeline |
|------|--------------|----------------|----------|
| 3D Mesh | OBJ/GLTF | Custom binary | Vertex transform, tangent calc |
| Texture | PNG/TGA | Raw RGBA | Mipmap generation, compression |
| Material | JSON | Binary struct | Shader parameter packing |
| Animation | FBX/GLTF | Keyframe array | Curve resampling, compression |
| Audio | WAV/OGG | PCM buffer | Resample, format conversion |
| Model (AI) | GGUF | MASM tensor | Q4_0 quantization, weight layout |

## GGUF Model Pipeline

```
GGUF File
   │
   ▼
gguf_reader.asm (memory-mapped)
   │
   ▼
Tensor extraction (CreateFileMappingA)
   │
   ▼
Q4_0 dequant (avx2_dequant_q4_0.asm)
   │
   ▼
MASM tensor buffer (aligned to 64 bytes)
   │
   ▼
Inference engine (inference_engine.asm)
```

## Performance

| Asset Type | Import Time | Memory | Notes |
|------------|-------------|--------|-------|
| 7B GGUF model | ~500ms | ~4GB | Memory-mapped |
| 1M triangle mesh | ~50ms | ~50MB | Custom binary |
| 4K texture | ~20ms | ~16MB | Raw RGBA |
| 60s audio | ~10ms | ~5MB | PCM 44.1kHz |
