# Nemotron-3.5-Lightning:30b Native Deep2 Loading Fix

## Model Location (FOUND)
- **Path**: `G:\~dev\rawrxd\models\_matrix_f\blobs\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3`
- **Size**: 25.43 GB
- **Format**: Valid GGUF (magic bytes verified)
- **Ollama**: `nemotron-3.5-lightning:30b` (ID e7a64ff15fb1) — available on `:11434`

## Problem
Deep2 fails to load with:
```
[Deep2Engine] ROPE_ARCH=nemotron_h_moe
[Deep2Engine] layer 0 missing transformer norm tensors
FAIL=loadModel
```

**Root cause**: `Deep2Engine.cpp` line 1202 checks `arch == "nemotron_h"` but the GGUF uses `"nemotron_h_moe"`.

## Fix Applied
File: `F:\~dev\rawrxd\src\deep2\Deep2Engine.cpp` line 1202
```cpp
// BEFORE:
const bool isNemotronH = (arch == "nemotron_h");

// AFTER:
const bool isNemotronH = (arch == "nemotron_h" || arch == "nemotron_h_moe");
```

## Build Status
- **CMake reconfigure fails** with "No SOURCES given to target" errors
- The `F:\~dev\rawrxd` source tree appears incomplete (CMakeLists.txt references source files that don't exist)
- Previous binary exists: `F:\~dev\rawrxd\build\bin\Release\test_generate_313_tokens.exe` (Gemma3 works, CPU-only)

## What Works Now
- **Gemma3 1B**: Loads and generates tokens (~1.67 TPS on CPU)
- **Ollama-served Nemotron**: ~127 TPS via API

## Next Steps
1. **Fix the CMake build** — likely requires a clean re-checkout or fixing source paths in CMakeLists.txt
2. **Rebuild** `test_generate_313_tokens` with the architecture fix
3. **Test** nemotron loading with `test_generate_313_tokens.exe <path-to-blob>`
4. **Enable Vulkan** — `engine.enableVulkan(true)` is already in the source, but the binary hasn't been rebuilt with it

## Command for testing once rebuilt
```
F:\~dev\rawrxd\build\bin\Release\test_generate_313_tokens.exe "G:\~dev\rawrxd\models\_matrix_f\blobs\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3"
```
