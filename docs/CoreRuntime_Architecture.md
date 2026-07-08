# RawrXD-CoreRuntime Architecture

## Purpose

CoreRuntime is the **symbol governance layer** that establishes a "truth baseline" for the entire RawrXD system. It forces clean architectural boundaries and prevents the linker oscillation between LNK2019 (missing) and LNK2005 (duplicate) errors.

## The Problem CoreRuntime Solves

### Before CoreRuntime

The build system had **multiple competing truth sources** for the same symbols:

1. **MASM prebuilt objects** - defined `asm_*` symbols
2. **C++ core implementations** - defined `InferenceEngine`, `GGUFLoader`
3. **Generated stubs** - defined placeholder implementations
4. **Legacy gold modules** - defined overlapping symbol sets
5. **Conditional compilation variants** - created different symbol sets per config

Result: The linker saw "valid answers from multiple contradictory realities"

### After CoreRuntime

**Single authority per symbol domain:**

| Symbol Domain | Owner | Location |
|--------------|-------|----------|
| `InferenceEngine_*` | CoreRuntime | `src/inference/` |
| `GGUFLoader_*` | CoreRuntime | `src/gguf/` |
| `asm_*` kernels | ASM domain | `src/asm/` (prebuilt) |
| `Win32IDE_*` | UI domain | `src/win32app/` |
| `UI_*` | UI domain | `src/ui/` |
| `Stub_*` | Debug only | Never in Core/Release |

## CoreRuntime Boundaries

### What IS Included

- Inference engine (model → graph → execution → memory loop)
- GGUF loader (headless, no UI)
- Embedding engine
- Transaction journal
- Agentic task graph (headless)
- Minimal memory layer (arena/pool allocators)
- Math kernels (AVX-512, AVX2)
- Core utilities (string, file I/O, time)

### What is EXPLICITLY EXCLUDED

- ❌ Win32IDE / UI layer
- ❌ Codex / dialogs / panels
- ❌ QuickJS / scripting layer
- ❌ Marketplace / plugins
- ❌ Agent UI bridge
- ❌ Visualization / rendering
- ❌ Optional experimental engines

## Symbol Ownership Enforcement

### Compile-Time Guards

The `symbol_ownership.h` header provides:

```cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"

// This will FAIL if CoreRuntime accidentally includes UI headers:
// - Windows UI headers (_WINDOWS_)
// - Qt (Q_OBJECT)
// - QuickJS (JS_VERSION)
```

### CMake Validation

The `CoreRuntime.cmake` module:

1. Defines `CORE_RUNTIME_FORBIDDEN_LIBS` - libraries CoreRuntime cannot link
2. Defines `CORE_RUNTIME_FORBIDDEN_INCLUDES` - paths that trigger errors
3. Calls `validate_core_runtime_isolation()` at configure time
4. Generates build failures on policy violations

## Build Target Hierarchy

```
RawrXD-CoreRuntime (STATIC library)
    ├── src/inference/         # Inference engine
    ├── src/gguf/              # GGUF loader
    ├── src/embeddings/        # Embedding engine
    ├── src/journal/           # Transaction journal
    ├── src/agentic/           # Task graph (headless)
    ├── src/memory/            # Memory allocators
    ├── src/kernels/           # Math kernels
    └── src/core/              # Core utilities

RawrXD-CoreRuntime-Test (executable)
    └── Tests CoreRuntime without any UI deps

RawrXD-Win32IDE (executable)
    └── Links against RawrXD-CoreRuntime
        └── Can use Core symbols, Core cannot use UI symbols
```

## Dependency Direction

```
┌─────────────────────────────────────────┐
│           RawrXD-Win32IDE               │
│  (UI layer - depends on CoreRuntime)    │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│        RawrXD-CoreRuntime               │
│  (Truth baseline - no UI deps)          │
│                                         │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐ │
│  │Inference│  │  GGUF   │  │ Memory  │ │
│  │ Engine  │  │ Loader  │  │  Pool   │ │
│  └─────────┘  └─────────┘  └─────────┘ │
└─────────────────────────────────────────┘
```

**Rule:** Dependencies flow DOWN only. CoreRuntime knows nothing about UI.

## Testing Strategy

### CoreRuntime-Test

- Runs inference loop without any UI dependencies
- Validates GGUF loading headlessly
- Tests memory tracking
- Verifies AVX-512 detection
- **If this test fails, the system is broken at the core level**

### Smoke Tests

- `RawrXD-CoreRuntime-Smoke`: Validates Core in isolation
- `RawrXD-Win32IDE-Smoke`: Validates UI + Core integration

## Migration Path

### Phase 1: CoreRuntime Extraction (Current)

- [x] Create `cmake/CoreRuntime.cmake`
- [x] Define `RawrXD-CoreRuntime` target
- [x] Create `symbol_ownership.h` guards
- [x] Implement `inference_engine.cpp` (real code, no stubs)
- [x] Create `test_inference_loop.cpp` (truth baseline test)

### Phase 2: Dependency Revelation

- [ ] Build CoreRuntime in isolation
- [ ] Compare dependency graph vs full build
- [ ] Document hidden coupling
- [ ] Fix accidental includes

### Phase 3: Capability-Gated Architecture

- [ ] Enforce Core → UI dependency direction
- [ ] Make optional modules compile-time switches
- [ ] Remove stub generation from release builds

## Key Insight

> The system is NOT incomplete - it is not GOVERNED.

CoreRuntime provides that governance layer. It establishes:

1. **Single definition per symbol** (no duplicates)
2. **Explicit ownership** (no ambiguity)
3. **Compile-time enforcement** (no runtime surprises)
4. **Truth baseline** (Core works = system works)

## Files Created

| File | Purpose |
|------|---------|
| `cmake/CoreRuntime.cmake` | Target definition with isolation rules |
| `include/core_runtime/inference_engine.h` | Public API (no UI deps) |
| `include/core_runtime/symbol_ownership.h` | Compile-time guards |
| `src/inference/inference_engine.cpp` | Real implementation (no stubs) |
| `tests/core_runtime/test_inference_loop.cpp` | Truth baseline test |
| `docs/CoreRuntime_Architecture.md` | This document |

## Next Steps

1. **Build CoreRuntime**: `cmake --build . --target RawrXD-CoreRuntime`
2. **Run Core Tests**: `cmake --build . --target RawrXD-CoreRuntime-Test`
3. **Validate Isolation**: Ensure no UI symbols leak into Core
4. **Link Win32IDE to Core**: Make IDE depend on CoreRuntime library

## Success Criteria

- [ ] CoreRuntime builds in < 2 minutes
- [ ] CoreRuntime-Test passes without any UI dependencies
- [ ] Win32IDE links against CoreRuntime (not duplicates symbols)
- [ ] No LNK2005 errors when building either target
- [ ] Adding a UI feature doesn't require rebuilding Core
