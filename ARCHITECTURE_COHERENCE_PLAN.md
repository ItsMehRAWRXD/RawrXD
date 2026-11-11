# RawrXD Architecture Coherence Plan
## From Fragmented Implementation to Unified System

**Date:** 2026-07-08  
**Status:** Critical - Architecture Requires Consolidation  
**Scope:** Make existing code coherent, not add features

---

## Executive Summary

The RawrXD codebase has grown organically through multiple phases. Before restructuring, we must establish an evidence-based inventory rather than relying on estimates.

**Goal:** Consolidate into a coherent 6-layer architecture with clear contracts, automated enforcement, and measurable exit criteria.

**Success Definition:**
- One implementation per subsystem
- Zero architectural violations in automated checks
- Clean dependency graph (auto-generated)
- All integration tests passing
- Reproducible builds from clean checkout

---

## Phase 0: Evidence-Based Inventory (Prerequisite)

Before any consolidation, generate an automated inventory from the repository itself.

### 0.1 Inventory Generation

```python
#!/usr/bin/env python3
"""Generate repository inventory for architecture planning."""

import json
import hashlib
from pathlib import Path
from collections import defaultdict

def generate_inventory(repo_root: Path) -> dict:
    """Generate complete file inventory with classification."""
    inventory = {
        'generated_at': datetime.now().isoformat(),
        'files': [],
        'duplicates': defaultdict(list),
        'components': defaultdict(list)
    }
    
    for filepath in repo_root.rglob('*'):
        if not filepath.is_file():
            continue
            
        content = filepath.read_bytes()
        file_hash = hashlib.sha256(content).hexdigest()[:16]
        
        entry = {
            'path': str(filepath.relative_to(repo_root)),
            'size': len(content),
            'hash': file_hash,
            'lines': content.decode('utf-8', errors='ignore').count('\n'),
            'classification': classify_file(filepath, content)
        }
        
        inventory['files'].append(entry)
        inventory['duplicates'][file_hash].append(entry['path'])
        
        # Extract component names from content
        components = extract_components(content)
        for comp in components:
            inventory['components'][comp].append(entry['path'])
    
    return inventory

def classify_file(filepath: Path, content: bytes) -> str:
    """Classify file by behavior, not just name."""
    name = filepath.name.lower()
    
    # Check content markers
    text = content.decode('utf-8', errors='ignore')
    
    if 'TODO: implement' in text or 'stub' in text.lower():
        return 'scaffold'
    elif 'deprecated' in text.lower() or 'legacy' in name:
        return 'deprecated'
    elif 'experimental' in name or 'test_' in name:
        return 'experimental'
    elif 'production' in name or 'real' in name:
        return 'production_candidate'
    else:
        return 'reference'

def extract_components(content: bytes) -> list:
    """Extract class/function names to find duplicates."""
    text = content.decode('utf-8', errors='ignore')
    components = []
    
    # Find class definitions
    import re
    classes = re.findall(r'class\s+(\w+)', text)
    components.extend(classes)
    
    return components

# Output: repo_audit/file_inventory.json, repo_audit/duplicates.json
```

### 0.2 Classification by Behavior

Instead of merging by filename, classify by maturity:

| Classification | Criteria | Action |
|----------------|----------|--------|
| **Reference** | Stable, tested, documented | Keep as canonical |
| **Production Candidate** | Feature-complete, under test | Evaluate for promotion |
| **Experimental** | New features, may be unstable | Archive if superseded |
| **Prototype** | Proof-of-concept | Archive |
| **Deprecated** | Marked obsolete, has replacement | Archive after verification |
| **Scaffold** | Placeholder/stub implementation | Delete or implement |

### 0.3 Inventory Artifacts

Generate these files before any consolidation:

```
repo_audit/
├── file_inventory.json          # All files with classification
├── duplicates.json                # Exact duplicates by hash
├── component_matrix.json          # Which files define which classes
├── include_graph.json             # #include relationships
├── dependency_graph.json          # Module dependencies
└── complexity_report.json         # Metrics per file
```

---

## Current State Analysis (Post-Inventory)

**Note:** The following figures are placeholders until Phase 0 inventory completes.

### 1. Duplication Matrix (To Be Verified)

| Component | Files Found | Classification | Consolidation Strategy |
|-----------|-------------|----------------|------------------------|
| CPUInferenceEngine | [TBD] | [TBD] | Keep reference, archive others |
| AgenticEngine | [TBD] | [TBD] | Merge by behavior, not name |
| ExecutionScheduler | [TBD] | [TBD] | Evaluate production candidates |
| ModelLoader | [TBD] | [TBD] | Single unified implementation |

### 3. Architectural Layer Violations

```
Current (Chaotic):
  UI (Win32IDE) → Agentic → Inference → GGML → Hardware
       ↓              ↓          ↓         ↓
  Direct calls bypassing layers
  Mixed concerns in single files
  Circular dependencies

Target (Clean):
  UI Layer → Agentic API → Inference API → GGML API → Hardware
     ↓           ↓            ↓            ↓
  Strict contracts, no bypassing
```

---

## Coherence Strategy: 6-Layer Architecture

### Revised Layer Structure

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 5: Applications (Win32IDE, CLI, Server)               │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: Agentic Core (Task orchestration, tools)         │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Inference Engine (Model loading, generation)     │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Platform (Filesystem, networking, threading)       │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: GGML Adapter (Clean interface to GGML)             │
├─────────────────────────────────────────────────────────────┤
│ Layer 0: Hardware Abstraction (HAL)                         │
└─────────────────────────────────────────────────────────────┘
         ↓
    External Dependency
    third_party/ggml/
```

### Layer 0: Hardware Abstraction (MASM64 + C)
**Purpose:** Direct hardware access, zero dependencies  
**Location:** `src/hal/`

```
Components:
  - Memory mapping (VirtualProtect, mmap)
  - SIMD kernels (AVX2/AVX-512) 
  - Thread primitives (no std::thread)

Contracts:
  - No C++ STL (pure C)
  - No exceptions
  - No dynamic allocation in hot paths
  - Export: C symbols only
```

### Layer 1: GGML Adapter (C++)
**Purpose:** Clean interface to external GGML dependency  
**Location:** `src/ggml_adapter/`

```
External Dependency:
  third_party/ggml/          # Unmodified upstream GGML
    ├── ggml.c/h
    ├── ggml-backend.c/h
    └── ggml-cuda/, ggml-vulkan/, etc.

Adapter Components:
  - Tensor wrapper (RAII for ggml_tensor)
  - Context manager (ggml_context lifecycle)
  - Backend factory (CPU/CUDA/Vulkan selection)
  - Quantization helpers (Q4, Q8, FP16)

Contracts:
  - C++17 wrapper around C API
  - RAII for all GGML resources
  - No direct ggml_* calls outside adapter
  - Versioned adapter for GGML updates
```

### Layer 2: Platform (C++)
**Purpose:** OS abstraction - keeps inference independent of Win32  
**Location:** `src/platform/`

```
Components:
  - Filesystem (Path, File, Directory)
  - Networking (HTTP client, WebSocket)
  - Threading (ThreadPool, Mutex, ConditionVariable)
  - Process (Spawn, Pipe, Environment)
  - Plugin (Dynamic library loading)
  - Logging (structured, async)

Contracts:
  - Abstract interfaces, OS-specific implementations
  - No Win32 types in public headers
  - Mock implementations for testing
  - Thread-safe by design
```

### Layer 3: Inference Engine (C++)
**Purpose:** Model loading, token generation, sampling  
**Location:** `src/inference/`

**Design Principle:** Small, focused interfaces composed together

```cpp
// src/inference/ModelLoader.h
#pragma once
#include <memory>
#include <string>
#include <vector>

namespace RawrXD {
namespace Inference {

struct ModelLoadConfig {
    std::string path;
    size_t maxContextLength = 4096;
    bool useGPU = true;
    int gpuLayerCount = -1; // -1 = all
};

class ModelLoader {
public:
    virtual ~ModelLoader() = default;
    
    // Load model from GGUF file
    virtual bool Load(const ModelLoadConfig& config) = 0;
    virtual void Unload() = 0;
    virtual bool IsLoaded() const = 0;
    
    // Model metadata
    virtual size_t GetParameterCount() const = 0;
    virtual size_t GetContextLength() const = 0;
    virtual std::string GetArchitecture() const = 0;
    
    static std::unique_ptr<ModelLoader> Create();
};

} // namespace Inference
} // namespace RawrXD
```

```cpp
// src/inference/Tokenizer.h
#pragma once
#include <string>
#include <vector>

namespace RawrXD {
namespace Inference {

class Tokenizer {
public:
    virtual ~Tokenizer() = default;
    
    // Core operations
    virtual std::vector<int> Encode(const std::string& text) = 0;
    virtual std::string Decode(const std::vector<int>& tokens) = 0;
    
    // Special tokens
    virtual int GetBosToken() const = 0;
    virtual int GetEosToken() const = 0;
    virtual int GetPadToken() const = 0;
    
    // Utility
    virtual size_t CountTokens(const std::string& text) = 0;
    
    static std::unique_ptr<Tokenizer> FromModel(const std::string& modelPath);
};

} // namespace Inference
} // namespace RawrXD
```

```cpp
// src/inference/Context.h
#pragma once
#include <vector>
#include <cstddef>

namespace RawrXD {
namespace Inference {

// Manages KV cache and generation state
class Context {
public:
    virtual ~Context() = default;
    
    // Token management
    virtual void AppendTokens(const std::vector<int>& tokens) = 0;
    virtual std::vector<int> GetTokens() const = 0;
    virtual void Clear() = 0;
    
    // State
    virtual size_t GetTokenCount() const = 0;
    virtual size_t GetRemainingSpace() const = 0;
    virtual bool IsFull() const = 0;
    
    static std::unique_ptr<Context> Create(size_t maxLength);
};

} // namespace Inference
} // namespace RawrXD
```

```cpp
// src/inference/Sampler.h
#pragma once
#include <vector>
#include <random>

namespace RawrXD {
namespace Inference {

struct SamplerConfig {
    float temperature = 0.7f;
    int topK = 40;
    float topP = 0.9f;
    float repeatPenalty = 1.0f;
    int repeatPenaltyTokens = 64;
};

class Sampler {
public:
    virtual ~Sampler() = default;
    
    // Sample next token from logits
    virtual int Sample(const std::vector<float>& logits, 
                       const std::vector<int>& context) = 0;
    
    // Update configuration
    virtual void SetConfig(const SamplerConfig& config) = 0;
    
    static std::unique_ptr<Sampler> Create(const SamplerConfig& config);
};

} // namespace Inference
} // namespace RawrXD
```

```cpp
// src/inference/Generator.h
#pragma once
#include <functional>
#include <string>
#include <memory>

namespace RawrXD {
namespace Inference {

// Composed from smaller interfaces
class Generator {
public:
    struct Config {
        std::shared_ptr<ModelLoader> model;
        std::shared_ptr<Tokenizer> tokenizer;
        std::shared_ptr<Sampler> sampler;
        size_t maxTokens = 256;
        std::string stopSequence;
    };
    
    struct Result {
        std::string text;
        std::vector<int> tokens;
        bool stoppedByLimit = false;
        bool stoppedBySequence = false;
        int64_t durationMs = 0;
    };
    
    virtual ~Generator() = default;
    
    // Synchronous generation
    virtual Result Generate(const std::string& prompt) = 0;
    
    // Streaming generation
    virtual void GenerateStreaming(
        const std::string& prompt,
        std::function<void(const std::string&)> onToken) = 0;
    
    static std::unique_ptr<Generator> Create(const Config& config);
};

} // namespace Inference
} // namespace RawrXD
```

### Layer 4: Agentic Core (C++)
**Purpose:** Task orchestration, tool execution, history  
**Location:** `src/agentic/`

**Capability-Based Tool Registry:**

```cpp
// src/agentic/ToolRegistry.h
#pragma once
#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace RawrXD {
namespace Agentic {

enum class Capability {
    Compile,        // Can compile source code
    Assemble,       // Can assemble to object code
    Link,           // Can link objects to executable
    Analyze,        // Can analyze binaries/code
    Test,           // Can run tests
    Format,         // Can format code
    Lint,           // Can lint/check code
    Execute,        // Can execute commands
    FileRead,       // Can read files
    FileWrite,      // Can write files
    Search,         // Can search content
    ModelLoad,      // Can load AI models
    ModelInfer,     // Can run inference
};

struct Tool {
    std::string id;
    std::string version;
    std::vector<Capability> capabilities;
    std::string executablePath;
    
    // Execute with request/response
    using ExecuteFn = std::function<bool(const struct Request&, struct Response&)>;
    ExecuteFn execute;
    
    // Check if tool is available
    using CheckFn = std::function<bool()>;
    CheckFn isAvailable;
};

// Pipelines become data, not hardcoded logic
struct PipelineStage {
    Capability requiredCapability;
    std::string inputKey;      // Key in context
    std::string outputKey;     // Key for result
    bool optional = false;
};

struct Pipeline {
    std::string name;
    std::string description;
    std::vector<PipelineStage> stages;
};

// Example: Compile pipeline as data
static const Pipeline kCompilePipeline = {
    .name = "compile",
    .description = "C/C++ compile pipeline",
    .stages = {
        {Capability::Compile, "source", "assembly", false},
        {Capability::Assemble, "assembly", "object", false},
        {Capability::Link, "object", "executable", false},
    }
};

class ToolRegistry {
public:
    virtual ~ToolRegistry() = default;
    
    // Registration
    virtual void RegisterTool(const Tool& tool) = 0;
    virtual void UnregisterTool(const std::string& id) = 0;
    
    // Discovery by capability
    virtual std::vector<Tool> FindByCapability(Capability cap) = 0;
    virtual Tool* FindBest(Capability cap) = 0; // Best = available + highest version
    
    // Pipeline execution
    virtual bool ExecutePipeline(const Pipeline& pipeline, 
                                  class ExecutionContext& context) = 0;
    
    // Status
    virtual std::vector<Tool> GetAllTools() = 0;
    virtual size_t GetAvailableCount() = 0;
    
    static std::unique_ptr<ToolRegistry> Create();
};

} // namespace Agentic
} // namespace RawrXD
```

### Layer 5: Applications (C++ / MASM64)
**Purpose:** User interfaces, HTTP server, CLI  
**Location:** `src/apps/`

```
Components:
  - Win32IDE (native GUI)
  - CLI (command line)
  - Server (HTTP API)

Contracts:
  - No direct hardware access (use HAL)
  - No direct GGML calls (use Adapter)
  - All operations through Agentic API
  - Platform abstraction via Layer 2
```

---

## Consolidation Plan (Milestone-Based)

**Note:** Calendar estimates replaced with measurable gates. Progress is tracked by verification, not time elapsed.

### Gate A: Inventory Complete
**Entry Criteria:**
- [ ] Phase 0 inventory script executed
- [ ] `repo_audit/file_inventory.json` generated
- [ ] All files classified by behavior (reference/experimental/deprecated/scaffold)
- [ ] Component matrix showing duplicate implementations

**Exit Criteria:**
- [ ] Inventory reviewed and approved
- [ ] Consolidation candidates identified
- [ ] Archive locations defined

---

### Gate B: Single Inference Engine
**Entry Criteria:**
- [ ] Gate A complete
- [ ] Reference implementation identified from inventory
- [ ] Smaller interfaces designed (ModelLoader, Tokenizer, Context, Sampler, Generator)

**Exit Criteria:**
- [ ] One `ModelLoader` implementation compiles
- [ ] One `Tokenizer` implementation compiles
- [ ] One `Sampler` implementation compiles
- [ ] One `Generator` implementation composes above
- [ ] All duplicate inference files archived to `archive/inference/`
- [ ] Integration tests pass:
  - Load model from GGUF
  - Tokenize text
  - Generate tokens
  - Stream output

---

### Gate C: Single Agentic Core
**Entry Criteria:**
- [ ] Gate B complete
- [ ] Reference implementation identified
- [ ] Capability-based ToolRegistry designed

**Exit Criteria:**
- [ ] One `ToolRegistry` with capability discovery
- [ ] One `TaskScheduler` implementation
- [ ] One `Agentic::Core` implementation
- [ ] All duplicate agentic files archived to `archive/agentic/`
- [ ] Integration tests pass:
  - Register tool by capability
  - Execute pipeline by capability chain
  - Submit and execute task
  - Cancel running task

---

### Gate D: Clean Dependency Graph
**Entry Criteria:**
- [ ] Gate C complete
- [ ] All 6 layers implemented
- [ ] Automated dependency graph generator created

**Exit Criteria:**
- [ ] Dependency graph auto-generated after every build
- [ ] CI fails on architectural violations:
  - UI → HAL direct calls
  - Inference → Win32 direct calls
  - Agentic → GGML direct calls (bypassing adapter)
- [ ] Graph shows clean 6-layer hierarchy
- [ ] No circular dependencies detected

**Automated Dependency Graph Generator:**

```python
#!/usr/bin/env python3
"""Generate dependency graph from build artifacts."""

import json
import subprocess
from pathlib import Path

def generate_dependency_graph(build_dir: Path) -> dict:
    """Parse CMake/compilation output to extract dependencies."""
    
    graph = {
        'layers': {
            'hal': {'deps': [], 'files': []},
            'ggml_adapter': {'deps': ['hal'], 'files': []},
            'platform': {'deps': ['hal'], 'files': []},
            'inference': {'deps': ['ggml_adapter', 'platform'], 'files': []},
            'agentic': {'deps': ['inference', 'platform'], 'files': []},
            'apps': {'deps': ['agentic'], 'files': []},
        },
        'violations': []
    }
    
    # Parse object file dependencies from compile_commands.json
    compile_db = build_dir / 'compile_commands.json'
    if compile_db.exists():
        with open(compile_db) as f:
            commands = json.load(f)
        
        for cmd in commands:
            file_path = Path(cmd['file'])
            includes = extract_includes(cmd['command'])
            
            layer = detect_layer(file_path)
            for inc in includes:
                inc_layer = detect_layer_from_include(inc)
                if inc_layer and not is_allowed_dependency(layer, inc_layer):
                    graph['violations'].append({
                        'file': str(file_path),
                        'illegal_include': inc,
                        'from_layer': layer,
                        'to_layer': inc_layer
                    })
    
    return graph

def detect_layer(file_path: Path) -> str:
    """Detect which layer a file belongs to."""
    path_str = str(file_path).replace('\\', '/')
    if '/hal/' in path_str:
        return 'hal'
    elif '/ggml_adapter/' in path_str:
        return 'ggml_adapter'
    elif '/platform/' in path_str:
        return 'platform'
    elif '/inference/' in path_str:
        return 'inference'
    elif '/agentic/' in path_str:
        return 'agentic'
    elif '/apps/' in path_str:
        return 'apps'
    return 'unknown'

# Output: dependency_graph.json, violations.json
# CI fails if violations.json is non-empty
```

---

### Gate E: Archive Legacy Code
**Entry Criteria:**
- [ ] Gate D complete
- [ ] All duplicate implementations consolidated
- [ ] Tests passing on unified implementations

**Exit Criteria:**
- [ ] All deprecated files moved to `archive/` (not deleted)
- [ ] All scaffold files moved to `archive/scaffold/` or implemented
- [ ] All experimental files moved to `archive/experiments/`
- [ ] Original locations contain only reference implementations
- [ ] Build succeeds with archived files excluded

**Archive Structure:**
```
archive/
├── README.md                    # Archive manifest with rationale
├── inference/
│   ├── cpu_inference_engine_Clean.cpp    # [Gate B] superseded
│   ├── cpu_inference_engine_fixed.cpp    # [Gate B] superseded
│   └── ...
├── agentic/
│   ├── agentic_core_win32.h              # [Gate C] superseded
│   └── ...
├── scaffold/
│   └── ...                    # Placeholder implementations
└── experiments/
    └── ...                    # Experimental features
```

---

### Gate F: Unified Build System
**Entry Criteria:**
- [ ] Gate E complete
- [ ] All source files in correct layer locations
- [ ] No duplicate implementations remain

**Exit Criteria:**
- [ ] Single root `CMakeLists.txt` builds all targets
- [ ] All legacy build scripts archived
- [ ] CI builds from clean checkout
- [ ] Build time < 5 minutes (measured)
- [ ] Binary size tracked (regression < 10%)

---

### Gate G: Complexity Metrics Baseline
**Entry Criteria:**
- [ ] Gate F complete
- [ ] Build system stable

**Exit Criteria:**
- [ ] Automated metrics collection in CI:
  - Include depth (average, max)
  - Compile time per translation unit
  - Binary size per module
  - Cyclic dependencies (count = 0)
  - Duplicated code percentage (< 5%)
  - Average function length (< 50 lines)
  - Public API count per layer
- [ ] Metrics stored in `metrics/history.json`
- [ ] Dashboard showing trends over time

**Metrics Collection Script:**

```python
#!/usr/bin/env python3
"""Collect complexity metrics for tracking."""

import json
import subprocess
from pathlib import Path
from datetime import datetime

def collect_metrics(repo_root: Path) -> dict:
    metrics = {
        'timestamp': datetime.now().isoformat(),
        'files': {},
        'summary': {}
    }
    
    # Include depth
    for cpp_file in repo_root.rglob('*.cpp'):
        includes = count_includes(cpp_file)
        metrics['files'][str(cpp_file)] = {
            'include_depth': includes,
            'lines': count_lines(cpp_file),
            'functions': count_functions(cpp_file)
        }
    
    # Summary statistics
    depths = [f['include_depth'] for f in metrics['files'].values()]
    metrics['summary'] = {
        'avg_include_depth': sum(depths) / len(depths) if depths else 0,
        'max_include_depth': max(depths) if depths else 0,
        'total_files': len(metrics['files']),
        'avg_function_length': calculate_avg_function_length(metrics['files'])
    }
    
    return metrics

def count_includes(filepath: Path) -> int:
    """Count #include directives in file."""
    text = filepath.read_text(errors='ignore')
    return text.count('#include')

def count_lines(filepath: Path) -> int:
    """Count lines in file."""
    return len(filepath.read_text(errors='ignore').splitlines())

def count_functions(filepath: Path) -> int:
    """Count function definitions."""
    import re
    text = filepath.read_text(errors='ignore')
    # Simple regex for function definitions
    return len(re.findall(r'^[\w\s:*&]+\s+\w+\s*\([^)]*\)\s*\{', text, re.M))

# Output: metrics/metrics_YYYY-MM-DD.json
# Append to metrics/history.json for trending
```

---

### Gate H: Integration Test Suite
**Entry Criteria:**
- [ ] Gate G complete
- [ ] All layers implemented

**Exit Criteria:**
- [ ] Automated integration tests for all commands:

| Test | Expected Result |
|------|-----------------|
| `help` | Lists all available commands |
| `status` | Reports all layers initialized |
| `build sample.cpp` | Produces executable `sample.exe` |
| `test sample` | Runs tests, reports pass/fail |
| `analyze sample.exe` | Produces analysis output |
| `run gcc --version` | Executes tool, returns version |
| Invalid command | Proper error message, no crash |
| Missing compiler | Graceful failure with clear error |

- [ ] All tests pass in CI
- [ ] Test coverage > 80%

---

### Gate I: Release Candidate
**Entry Criteria:**
- [ ] Gate H complete
- [ ] All previous gates verified

**Exit Criteria:**
- [ ] One implementation per subsystem
- [ ] Zero architectural violations in automated checks
- [ ] Clean dependency graph (auto-generated)
- [ ] All integration tests passing
- [ ] Reproducible builds from clean checkout
- [ ] Stable public APIs with versioning
- [ ] Performance regressions within defined limits (< 5%)
- [ ] Release artifacts generated automatically by CI

---

## Exit Criteria Summary

"Production-ready" is not a label—it is a conclusion supported by evidence:

| Criterion | Evidence | Status |
|-----------|----------|--------|
| One implementation per subsystem | Archive contains all superseded files | ⬜ |
| Zero architectural violations | `violations.json` is empty in CI | ⬜ |
| Clean dependency graph | `dependency_graph.json` shows 6-layer hierarchy | ⬜ |
| All tests passing | CI green, coverage > 80% | ⬜ |
| Reproducible builds | Clean checkout builds successfully | ⬜ |
| Stable public APIs | API versioned, documented | ⬜ |
| Performance within limits | Metrics show < 5% regression | ⬜ |
| Automated release artifacts | CI generates release packages | ⬜ |

When all criteria are met, the architecture is production-ready.

### Risk: Breaking Working Code
**Mitigation:** 
- Keep backups in `.archived_orphans/`
- Incremental consolidation (file by file)
- Comprehensive tests after each phase

### Risk: Lost Features
**Mitigation:**
- Feature matrix before consolidation
- Verify all features in unified implementation
- Stakeholder review at each phase

### Risk: Build Breakage
**Mitigation:**
- Parallel build systems during transition
- CI/CD validation
- Rollback plan

---

## Conclusion

This coherence plan transforms RawrXD from a fragmented codebase into a unified 6-layer architecture. The focus has shifted from adding features to reducing complexity:

### Three Primary Goals

1. **Reduce duplicate implementations** to a single maintained version per subsystem
2. **Enforce architectural boundaries** with automated checks in CI
3. **Measure everything** (tests, dependencies, build times, performance) so future changes are evidence-driven

### Key Improvements Over Previous Plans

| Aspect | Previous | This Revision |
|--------|----------|---------------|
| **Inventory** | Estimated figures (19,935 files) | Evidence-based via automated scripts |
| **Consolidation** | Merge by filename | Classify by behavior, archive not delete |
| **Architecture** | 5 layers | 6 layers with dedicated Platform layer |
| **GGML** | Modified in-tree | External dependency with adapter layer |
| **Interfaces** | Monolithic InferenceEngine | Composed from focused components |
| **Schedule** | Calendar weeks | Measurable gates with exit criteria |
| **Completion** | "Ready for production" label | Evidence-based exit criteria |

### Next Steps

1. **Execute Phase 0** - Generate inventory from actual repository
2. **Reach Gate A** - Complete inventory with classification
3. **Proceed gate-by-gate** - Each gate verified before proceeding
4. **Track metrics** - Complexity trends guide decisions

**Success is not declared—it is demonstrated through passing gates and verified metrics.**
