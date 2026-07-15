# Phase 7: Legacy Archival

## Overview

Phase 7 focuses on archiving legacy code that has been fully migrated to the new unified interfaces. This phase ensures legacy code is preserved for reference while being clearly marked as deprecated.

## Current Status

✅ **Phases 0-6 Complete**:
- Phase 0: Inventory (51,172 files analyzed)
- Phase 1: Unified Headers (Core.h, InferenceEngine.h)
- Phase 2: Adapter Layer (LegacyCoreAdapter, LegacyInferenceAdapter)
- Phase 3: Connected to Legacy (AgenticEngine, GGMLBackend)
- Phase 4: Integration Testing (verified compilation and linking)
- Phase 5: Production Hardening (ErrorHandling, Logger, Config)
- Phase 6: Gradual Migration Framework (strategy, tools, examples)

## Phase 7 Goals

1. **Identify Migrated Code**
   - Find legacy files no longer actively used
   - Verify all references migrated
   - Confirm test coverage

2. **Archive Legacy Code**
   - Move to `.archived/` directory
   - Preserve git history
   - Add deprecation notices

3. **Update Build System**
   - Remove legacy from active build
   - Update CMakeLists.txt
   - Update include paths

4. **Documentation**
   - Archive manifest
   - Migration completion notes
   - Reference documentation

## Archival Strategy

### Step 1: Pre-Archival Checklist

Before archiving legacy code, ensure:

- [ ] All usages migrated to unified interfaces
- [ ] Tests pass without legacy code
- [ ] Documentation updated
- [ ] Team notified
- [ ] Rollback plan documented

### Step 2: Archive Process

```bash
# Create archive directory
mkdir -p .archived/legacy/agentic
mkdir -p .archived/legacy/inference

# Move legacy files (preserving structure)
git mv src/agentic_engine.h .archived/legacy/agentic/
git mv src/agentic_engine.cpp .archived/legacy/agentic/
git mv src/cpu_inference_engine.h .archived/legacy/inference/
git mv src/cpu_inference_engine.cpp .archived/legacy/inference/

# Commit archival
git commit -m "Phase 7: Archive legacy agentic and inference engines

- Moved legacy implementations to .archived/legacy/
- All functionality migrated to unified interfaces
- Adapters maintain backward compatibility
- See ARCHIVAL_MANIFEST.md for details"
```

### Step 3: Deprecation Notices

Add to archived files:

```cpp
// ============================================================================
// DEPRECATED: This file has been archived as of Phase 7
// ============================================================================
// 
// This legacy implementation has been superseded by the unified architecture:
//   - New Agentic Interface: src/agentic/Core.h
//   - New Inference Interface: src/inference/InferenceEngine.h
//   - Migration Guide: MIGRATION_EXAMPLES.md
//
// This file is preserved for reference only. Do not use in new code.
// For migration assistance, see Phase 6 documentation.
//
// Archived: 2026-XX-XX
// ============================================================================
```

## Archival Manifest

### Legacy Agentic Components

| File | Status | Migration Target | Date Archived |
|------|--------|------------------|---------------|
| agentic_engine.h | Ready | Core.h | TBD |
| agentic_engine.cpp | Ready | Core.cpp | TBD |
| agentic_core.h | Ready | Core.h | TBD |
| agentic_core.cpp | Ready | Core.cpp | TBD |
| agentic_executor.h | Ready | Core.h | TBD |
| agentic_executor.cpp | Ready | Core.cpp | TBD |

### Legacy Inference Components

| File | Status | Migration Target | Date Archived |
|------|--------|------------------|---------------|
| cpu_inference_engine.h | Ready | InferenceEngine.h | TBD |
| cpu_inference_engine.cpp | Ready | InferenceEngine.cpp | TBD |
| cpu_inference_engine_*.cpp | Ready | InferenceEngine.cpp | TBD |
| cpu_inference_engine_*.h | Ready | InferenceEngine.h | TBD |

### Duplicate Implementations

| File Pattern | Count | Status | Action |
|--------------|-------|--------|--------|
| *agentic*_clean* | ~5 | Ready | Archive |
| *agentic*_fixed* | ~8 | Ready | Archive |
| *inference*_clean* | ~3 | Ready | Archive |
| *inference*_fixed* | ~6 | Ready | Archive |

## Build System Updates

### CMakeLists.txt Changes

```cmake
# BEFORE: Legacy included in build
set(SOURCES
    src/agentic_engine.cpp
    src/cpu_inference_engine.cpp
    # ...
)

# AFTER: Only unified interfaces
set(SOURCES
    src/agentic/Core.cpp
    src/agentic/LegacyCoreAdapter.cpp
    src/inference/InferenceEngine.cpp
    src/inference/LegacyInferenceAdapter.cpp
    # ...
)

# Legacy archived (not built)
# set(ARCHIVED_SOURCES
#     .archived/legacy/agentic/agentic_engine.cpp
#     .archived/legacy/inference/cpu_inference_engine.cpp
# )
```

### Include Path Updates

```cpp
// BEFORE
#include "agentic_engine.h"
#include "cpu_inference_engine.h"

// AFTER
#include "src/agentic/Core.h"
#include "src/inference/InferenceEngine.h"
```

## Verification

### Post-Archival Checklist

- [ ] Project builds without legacy code
- [ ] All tests pass
- [ ] No references to archived files
- [ ] Documentation updated
- [ ] Archive manifest complete

### Build Verification

```bash
# Clean build
rm -rf build/
mkdir build && cd build
cmake ..
make -j$(nproc)

# Run tests
ctest --output-on-failure

# Verify no legacy references
grep -r "agentic_engine\.h" src/ || echo "No legacy references found"
grep -r "cpu_inference_engine\.h" src/ || echo "No legacy references found"
```

## Documentation Updates

### README.md Updates

```markdown
## Architecture

This project uses a unified 6-layer architecture:

- Layer 6: Applications
- Layer 5: Agentic (Core.h)
- Layer 4: Inference (InferenceEngine.h)
- Layer 3: Platform
- Layer 2: GGML/GGUF
- Layer 1: Hardware

### Legacy Code

Legacy implementations have been archived to `.archived/legacy/`.
See ARCHIVAL_MANIFEST.md for details.
```

### ARCHIVAL_MANIFEST.md

```markdown
# Legacy Code Archive

## Overview

Legacy code archived as part of Phase 7 (Legacy Archival).
All functionality has been migrated to unified interfaces.

## Archive Structure

```
.archived/legacy/
├── agentic/
│   ├── agentic_engine.h (deprecated)
│   ├── agentic_engine.cpp (deprecated)
│   └── ...
└── inference/
    ├── cpu_inference_engine.h (deprecated)
    ├── cpu_inference_engine.cpp (deprecated)
    └── ...
```

## Migration Status

All files in this archive have been migrated.
See MIGRATION_EXAMPLES.md for migration guide.

## Accessing Archived Code

Archived code is preserved for reference but not built.
To view: `cat .archived/legacy/<path>`
```

## Rollback Plan

If issues arise after archival:

1. **Immediate**: Restore from git
   ```bash
   git revert HEAD  # Revert archival commit
   ```

2. **Selective**: Restore specific files
   ```bash
   git show HEAD~1:src/agentic_engine.h > src/agentic_engine.h
   ```

3. **Emergency**: Use backup branch
   ```bash
   git checkout pre-archival-backup
   ```

## Success Criteria

| Criterion | Target | Measurement |
|-----------|--------|-------------|
| Legacy Files Archived | 100% | Count in .archived/legacy/ |
| Build Success | 100% | Clean build |
| Test Pass Rate | 100% | All tests pass |
| No Active References | 0 | grep results |
| Documentation Updated | Yes | Review complete |

## Next Steps

1. Execute archival checklist
2. Move files to .archived/legacy/
3. Update build system
4. Verify clean build
5. Update documentation
6. Proceed to Phase 8

---

**Phase 7 Status**: Ready to archive legacy code.
