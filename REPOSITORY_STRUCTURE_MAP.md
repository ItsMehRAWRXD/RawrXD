# RawrXD Repository Structure Map

**Generated:** 2026-06-21  
**Purpose:** Phase 17B Codebase Audit - Repository Mapping

---

## Repository Overview

This document maps the three primary repositories containing RawrXD source code and their respective roles.

---

## Repository 1: `ItsMehRAWRXD/RawrXD` (Primary)

**Branch:** `copilot/vscode-mlyextom-3zgo-phase7a`  
**Default:** `main`  
**Local Path:** `d:\rawrxd`

### Purpose
Primary C++ implementation of the RawrXD IDE, inference engine, and all core components.

### Key Directories

```
d:\rawrxd\
├── src/
│   ├── semantic_index/          # Phase 17: Vector search
│   │   ├── SemanticCodeIndex.cpp
│   │   ├── SemanticCodeIndex.h
│   │   ├── CodeEmbedder.cpp
│   │   └── CodeEmbedder.h
│   ├── win32ide/                # Win32 IDE components
│   │   ├── GhostOverlay.cpp
│   │   └── ExecModeToolbar.cpp
│   ├── KeywordHashTable.cpp     # Legacy Trie autocomplete
│   ├── ghost_text_renderer.cpp  # Inline completion UI
│   ├── ide_completion.cpp       # IDE completion engine
│   └── CompletionEngine.cpp     # Modern completion
├── build-ninja/                 # Primary build output
├── CMakeLists.txt               # Main build configuration
└── [1000+ other files...]
```

### Critical Files for Phase 17

| File | Purpose | Status |
|------|---------|--------|
| `src/semantic_index/SemanticCodeIndex.cpp` | Vector index implementation | ✅ Complete |
| `src/semantic_index/CodeEmbedder.cpp` | ONNX embedding | ✅ Complete |
| `src/KeywordHashTable.cpp` | Legacy Trie (to bridge) | ⚠️ Legacy |
| `src/ide_completion.cpp` | IDE integration point | 🎯 Target |
| `src/ghost_text_renderer.cpp` | Ghost text UI | 🎯 Target |

---

## Repository 2: `ItsMehRAWRXD/-` (MASM Implementation)

**Branch:** `main`  
**Default:** `main`  
**Local Path:** `d:\` (mapped to `-` repo)

### Purpose
Pure MASM x64 implementations of performance-critical components. Zero dependencies, maximum speed.

### Key Directories

```
-
├── src/
│   └── asm/
│       ├── RawrXD_CopilotGapCloser.asm      # HNSW vector DB
│       ├── ghost_text_ranker.asm            # Context ranking
│       ├── ai_completion_provider_masm.asm  # Completion provider
│       ├── RAWRXD_PE32_EMITTER_MONOLITHIC.asm  # IDE state machine
│       ├── RawrXD_SovereignTokenizerCore.asm   # Tokenizer
│       └── [50+ other .asm files...]
├── include/
│   └── rawrxd_internal_protos.inc           # MASM prototypes
└── [build scripts...]
```

### Critical Files for Phase 17

| File | Purpose | Lines | Status |
|------|---------|-------|--------|
| `RawrXD_CopilotGapCloser.asm` | HNSW vector database | ~1000 | ✅ Complete |
| `ghost_text_ranker.asm` | Semantic ranking | ~300 | ✅ Complete |
| `ai_completion_provider_masm.asm` | Completion provider | ~400 | ✅ Complete |
| `RAWRXD_PE32_EMITTER_MONOLITHIC.asm` | IDE state machine | ~5000 | ✅ Complete |

### MASM Vector DB API

```asm
; From RawrXD_CopilotGapCloser.asm
PUBLIC VecDb_Init
PUBLIC VecDb_Insert
PUBLIC VecDb_Search
PUBLIC VecDb_Delete
PUBLIC VecDb_L2Distance_AVX2
```

---

## Repository 3: `ItsMehRAWRXD/cloud-hosting` (Deployment)

**Branch:** `copilot/courageous-rodent`  
**Default:** `main`  
**Local Path:** `g:\cloud-hosting` (mapped)

### Purpose
Cloud deployment configurations, MASM64 Vulkan implementations, and infrastructure code.

### Key Directories

```
g:\cloud-hosting\
├── masm64/                      # MASM64 Vulkan/compute
│   ├── vulkan/
│   ├── compression/
│   ├── crypto/
│   └── tests/
├── deploy/
│   ├── docker/
│   ├── terraform/
│   └── scripts/
└── [deployment configs...]
```

### Key Components

| Component | Purpose | Status |
|-----------|---------|--------|
| `masm64/vulkan/` | Vulkan compute in MASM | ✅ Complete |
| `masm64/compression/` | Zlib/Zstd in MASM | ✅ Complete |
| `deploy/docker/` | Container deployment | ✅ Complete |
| `deploy/terraform/` | Infrastructure as Code | ✅ Complete |

---

## Cross-Repository Dependencies

### Phase 17 Integration Points

```
┌─────────────────────────────────────────────────────────────────┐
│                    Phase 17 Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐      ┌──────────────┐      ┌─────────────┐ │
│  │   RawrXD     │      │      -       │      │ cloud-hosting│ │
│  │   (C++)      │◄────►│   (MASM)     │      │   (Deploy)   │ │
│  └──────┬───────┘      └──────────────┘      └─────────────┘ │
│         │                                                       │
│         │  semantic_index/                                      │
│         ▼                                                       │
│  ┌──────────────┐                                               │
│  │ SemanticCode │◄─── Optional: MASM L2 kernel from `-` repo    │
│  │    Index     │                                               │
│  └──────┬───────┘                                               │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────┐                                               │
│  │   FAISS/     │◄─── Can use Vulkan compute from cloud-hosting │
│  │    HNSW      │                                               │
│  └──────────────┘                                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Build System Mapping

### Primary Build (RawrXD)

```bash
# Location: d:\rawrxd\build-ninja\
# Generator: Ninja
# Toolchain: MSVC 14.50.35717 (VS2022)

# Key targets:
# - RawrXD-Win32IDE.exe
# - RawrXD_Main.exe
# - [test suites...]
```

### MASM Build (-)

```bash
# Location: d:\src\asm\
# Assembler: ml64.exe (VS2022)
# Linker: link.exe

# Key outputs:
# - RawrXD_ToolExecutor_Complete.obj
# - [individual .obj files...]
```

### Cloud-Hosting Build

```bash
# Location: g:\cloud-hosting\masm64\
# Build: Makefile / build.bat

# Key outputs:
# - vulkan_masm.lib
# - compression_masm.lib
# - crypto_masm.lib
# - gpu_masm.lib
```

---

## Git Workflow for Phase 17

### Recommended Branch Strategy

```
main (RawrXD)
  └── copilot/vscode-mlyextom-3zgo-phase7a (current)
        └── phase17-semantic-integration (new)
              ├── feature/semantic-router
              ├── feature/code-embedder
              └── feature/hybrid-completion
```

### Commit Message Convention

```
Phase 17B: <component> - <action>

- <detail 1>
- <detail 2>

Refs: <file paths>
```

Example:
```
Phase 17B: SemanticCodeIndex - Add hybrid search

- Implement weighted fusion of Trie + Semantic results
- Add latency budget enforcement (10ms)
- Update CMake for FAISS detection

Refs: src/completion/completion_router.cpp
```

---

## File Size Summary

| Repository | Files | Code Lines | Primary Language |
|------------|-------|------------|------------------|
| RawrXD | ~2000 | ~500K | C++ |
| - | ~100 | ~50K | MASM x64 |
| cloud-hosting | ~50 | ~10K | MASM/Shell |
| **Total** | **~2150** | **~560K** | **Mixed** |

---

## Next Steps

1. ✅ Phase 17B: Codebase Audit (COMPLETE)
2. 🔄 Phase 17C: Semantic Index Integration (NEXT)
3. ⏳ Phase 17D: Performance Optimization (PENDING)
4. ⏳ Phase 18: MASM Acceleration Layer (PENDING)

---

**Document Version:** 1.0  
**Last Updated:** 2026-06-21  
**Author:** GitHub Copilot (Reverse Engineering Agent)
