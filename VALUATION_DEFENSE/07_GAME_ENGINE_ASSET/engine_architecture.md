# Engine Architecture — Sunshine Engine / RawrXD Runtime

## Overview

The Sunshine Engine is a **from-scratch MASM x64 native game engine** with zero external dependencies. It runs directly on the Windows kernel via Win32 API calls — no middleware, no runtime libraries, no engine licensing fees.

## Architecture Layers

```
┌─────────────────────────────────────────────┐
│              Game Layer                      │
│  Entity/Component System, Scene Graph,      │
│  Scripting (MASM macros + AI agent)         │
├─────────────────────────────────────────────┤
│              Runtime Layer                   │
│  Physics, Animation, Audio, Asset Pipeline  │
├─────────────────────────────────────────────┤
│              Renderer Layer                  │
│  Vulkan GDI, MASM x64 rasterizer, Swapchain │
├─────────────────────────────────────────────┤
│              Platform Layer                  │
│  Win32 Window, Input, File I/O, Thread Pool │
├─────────────────────────────────────────────┤
│              Hardware Layer                  │
│  CPU (AVX2/AVX512), GPU (Vulkan), Memory    │
└─────────────────────────────────────────────┘
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **MASM x64 only** | Zero dependencies, full control, smallest binary |
| **Vulkan GDI** | Cross-vendor GPU access, no D3D lock-in |
| **Flat memory model** | No GC, no allocator overhead, deterministic |
| **Agent-native scripting** | AI generates + compiles game logic at runtime |
| **Swappable backends** | Build/deploy via PowerShell or BareMetal |

## Current Capability Status

| Component | Status | Notes |
|-----------|--------|-------|
| Renderer | ✅ MASM kernels | Vulkan dispatch layer exists |
| Scene graph | 🔧 In progress | Entity tree with transform hierarchy |
| ECS | 🔧 In progress | Component pools, system iteration |
| Physics | 🔧 In progress | Rigid body, collision detection (MASM) |
| Animation | 📋 Planned | Skeletal animation, blend trees |
| Audio | 📋 Planned | WASAPI or XAudio2 bridge |
| Scripting | ✅ Agent pipeline | MASM code gen via AI agent |
| Asset pipeline | 🔧 In progress | GGUF models, mesh loading |
| Editor tooling | ✅ RawrXD IDE | Full IDE with AI agent integration |

## Competitive Position

| Feature | Sunshine Engine | Unreal Engine | Godot | Unity |
|---------|---------------|---------------|-------|-------|
| License | **Proprietary (owned)** | Royalty 5% | MIT | Per-seat |
| Runtime deps | **None** | ~500MB | ~100MB | ~200MB |
| Binary size | **~200KB** | ~50MB+ | ~20MB+ | ~30MB+ |
| AI-native | **Yes** | No | No | No |
| Agent scripting | **Native** | No | No | No |
| MASM kernels | **Full stack** | No | No | No |
| GPU backend | Vulkan | Vulkan/D3D | Vulkan/D3D | Vulkan/D3D |
| Platform | Windows | Multi | Multi | Multi |
