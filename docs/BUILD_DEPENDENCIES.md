# Build Dependencies: Phase 17

## Overview
Phase 17 introduces vector-based semantic search capabilities requiring additional native libraries. This document outlines the dependency tree and build configuration.

## Required Libraries

### FAISS (Facebook AI Similarity Search)
- **Purpose:** High-performance IVFPQ vector indexing
- **Install:** `conda install -c pytorch faiss-cpu` or build from source
- **CMake:** `find_package(faiss)` with `FetchContent` fallback
- **Memory:** ~140MB for 100k vectors @ 384d
- **License:** MIT

### ONNX Runtime
- **Purpose:** Neural network inference for code embeddings
- **Install:** Download from Microsoft/GitHub releases
- **CMake:** `find_package(onnxruntime)` or manual `find_library`
- **Models:** CodeBERT, all-MiniLM-L6-v2 (384d output)
- **License:** MIT

### OpenMP
- **Purpose:** Parallel IVFPQ search and batch embedding
- **Status:** Required for FAISS performance
- **MSVC:** Included with Visual Studio
- **GCC/Clang:** `-fopenmp` flag

### HNSW (Header-Only Fallback)
- **Purpose:** Graceful degradation when FAISS unavailable
- **Integration:** `FetchContent_Declare` from GitHub
- **Advantage:** No BLAS dependency, single header
- **License:** Apache 2.0

## CMake Configuration

### Detection Logic
```cmake
# FAISS detection
find_package(faiss QUIET)
if(faiss_FOUND)
    target_compile_definitions(semantic_index PRIVATE RAWR_HAS_FAISS=1)
    target_link_libraries(semantic_index PRIVATE faiss)
else()
    # Fallback to HNSW
    FetchContent_Declare(hnsw ...)
endif()

# ONNX Runtime detection
find_package(onnxruntime QUIET)
if(onnxruntime_FOUND)
    target_compile_definitions(semantic_index PRIVATE RAWR_HAS_ONNXRUNTIME=1)
endif()
```

### Build Flags

| Flag | Values | Description |
|------|--------|-------------|
| `RAWR_HAS_FAISS` | 0, 1 | Enable FAISS IVFPQ backend |
| `RAWR_HAS_ONNXRUNTIME` | 0, 1 | Enable ONNX embedding inference |
| `USE_FAISS_BACKEND` | defined/undefined | Select FAISS vs HNSW at compile time |
| `RAWRXD_SEMANTIC_INDEX_PARALLEL` | 0, 1 | Enable OpenMP parallel search |

### Example Build Commands

**With FAISS (Recommended):**
```powershell
cmake -B build -S . -DFAISS_ROOT="C:/faiss"
ninja -C build RawrXD-Win32IDE
```

**Without FAISS (HNSW fallback):**
```powershell
cmake -B build -S . -DUSE_HNSW_FALLBACK=ON
ninja -C build RawrXD-Win32IDE
```

**Minimal (stub embedder):**
```powershell
cmake -B build -S . -DUSE_STUB_EMBEDDER=ON
ninja -C build RawrXD-Win32IDE
```

## Dependency Matrix

| Configuration | FAISS | ONNX | OpenMP | HNSW | Binary Size | Features |
|--------------|-------|------|--------|------|-------------|----------|
| Full | ✓ | ✓ | ✓ | ✓ | +~50MB | All capabilities |
| No FAISS | ✗ | ✓ | ✓ | ✓ | +~5MB | HNSW index only |
| No ONNX | ✓ | ✗ | ✓ | ✓ | +~2MB | Pre-computed embeddings |
| Minimal | ✗ | ✗ | ✗ | ✗ | +0MB | Trie-only fallback |

## Runtime Requirements

### Model Files
Required for ONNX inference:
```
models/
├── all-MiniLM-L6-v2.onnx      # ~80MB
├── codebert-base.onnx         # ~400MB
└── vocab.txt                  # Tokenizer vocabulary
```

### Environment Variables
- `RAWRXD_SEMANTIC_MODEL_PATH` — Override model location
- `RAWRXD_SEMANTIC_INDEX_PATH` — Persisted index directory
- `RAWRXD_SEMANTIC_DISABLE` — Disable semantic features entirely

## Troubleshooting

### "FAISS not found"
**Solution:** Install via conda or set `FAISS_ROOT` CMake variable

### "ONNX Runtime initialization failed"
**Solution:** Verify `onnxruntime.dll` is in PATH or executable directory

### "OpenMP not available"
**Solution:** Install OpenMP runtime or disable with `-DUSE_OPENMP=OFF`

### "Training buffer overflow"
**Cause:** Adding vectors faster than training triggers
**Solution:** Call `index.train()` manually or increase buffer size

## Platform Notes

### Windows (MSVC)
- Requires Visual Studio 2019+ for C++17
- OpenMP included with MSVC
- FAISS: Use prebuilt conda packages

### Linux (GCC/Clang)
- OpenMP: `libgomp` package required
- FAISS: Build from source or use conda
- ONNX: Download from GitHub releases

### macOS
- OpenMP: `brew install libomp`
- FAISS: Conda recommended
- ONNX: Universal2 binaries available

## References
- `src/semantic_index/CMakeLists.txt`
- `cmake/FindFAISS.cmake`
- `cmake/FindONNXRuntime.cmake`
