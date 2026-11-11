# RawrXD API Freeze v1.0.0

**Status**: FROZEN as of 2026-07-13  
**Version**: v1.0.0-rc1 → v1.0.0-GA  
**Scope**: Public API Surface

---

## Overview

This document defines the frozen public API for RawrXD v1.0.0. Any changes to these interfaces after this date must follow the [Breaking Change Policy](#breaking-change-policy).

---

## Public API Surface

### Stable Headers (Frozen)

The following headers constitute the **stable public API**:

```
include/rawrxd/
├── RawrXD.hpp                 # Main entry point
├── Config.hpp               # Configuration API
├── Session.hpp              # Inference session API
├── Generation.hpp           # Generation parameters/results
├── Agent.hpp                # Agentic framework API
├── Memory.hpp               # Memory subsystem API
├── Metacognitive.hpp        # Metacognitive layer API
├── Plugin.hpp               # Plugin SDK
├── Extension.hpp            # Extension API
├── Version.hpp              # Version information
└── Types.hpp                # Common types
```

### Stability Guarantees

| API Component | Stability Level | Notes |
|--------------|-----------------|-------|
| Core Runtime API | **Stable** | No breaking changes until v2.0 |
| Plugin SDK | **Stable** | Binary compatible within v1.x |
| Extension API | **Stable** | Source compatible within v1.x |
| Agentic API | **Stable** | No breaking changes until v2.0 |
| Memory API | **Stable** | No breaking changes until v2.0 |
| Configuration API | **Stable** | New keys may be added |

---

## Breaking Change Policy

### Semantic Versioning

RawrXD follows [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR** (X.0.0): Breaking changes to public API
- **MINOR** (x.Y.0): New features, backward compatible
- **PATCH** (x.y.Z): Bug fixes, backward compatible

### What Constitutes a Breaking Change

Breaking changes **require** a major version bump:

- Removing or renaming public functions/classes
- Changing function signatures
- Changing behavior of existing functions
- Removing enum values
- Changing default values that affect behavior
- Modifying struct/class layout

Non-breaking changes (minor/patch):

- Adding new functions/classes
- Adding new enum values
- Adding new configuration keys
- Performance improvements
- Bug fixes

### Deprecation Process

1. **Deprecation Notice** (Minor version)
   - Mark API as deprecated with `[[deprecated]]` attribute
   - Document in CHANGELOG
   - Provide migration path

2. **Deprecation Period** (Minimum 2 minor versions)
   - Deprecated API continues to function
   - Warnings emitted at compile/runtime

3. **Removal** (Major version)
   - Deprecated API removed
   - Documented in migration guide

---

## ABI Stability

### C++ ABI

- **Linux**: GCC 11+ with `-fabi-version=16`
- **Windows**: MSVC 2022 with `/Zc:__cplusplus`
- **macOS**: Clang 14+ with libc++

### Plugin ABI

Plugins compiled against v1.0.0 will work with any v1.x release:

```cpp
// Plugin compatibility check
extern "C" uint32_t GetAPIVersion() {
    return RAWRXD_API_VERSION;  // 1 for v1.x
}
```

### Extension ABI

Extensions use COM-like interface versioning:

```cpp
// Extension interface
struct IExtensionAPI {
    static constexpr uint32_t VERSION = 1;
    // ...
};
```

---

## Version Compatibility Matrix

| RawrXD Version | Plugin ABI | Extension API | Notes |
|----------------|------------|---------------|-------|
| v1.0.0 | 1 | 1 | Baseline |
| v1.1.0 | 1 | 1 | Additive only |
| v1.2.0 | 1 | 1 | Additive only |
| v2.0.0 | 2 | 2 | Breaking changes allowed |

---

## Migration Guides

### rc1 → GA

No breaking changes. Update version string only.

### v1.0 → v1.1

No breaking changes. New features available:

```cpp
// New in v1.1 - optional
auto newFeature = RawrXD::GetNewFeature();
```

### v1.x → v2.0

See [MIGRATION_v2.0.md](MIGRATION_v2.0.md) (future document).

---

## Experimental APIs

The following are **not** part of the stable API:

```
src/internal/          # Internal implementation details
src/experimental/      # Experimental features
include/rawrxd/internal/  # Internal headers
```

These may change without notice. Do not depend on them.

---

## API Lifecycle

```
Experimental → Stable → Deprecated → Removed
     ↑            ↓         ↓
   v1.0-rc     v1.0-GA   v2.0-GA
```

---

## Contact

For API questions or proposals:

- GitHub Discussions: https://github.com/ItsMehRAWRXD/RawrXD/discussions
- API Review: api-review@rawrxd.io

---

*Last Updated: 2026-07-13*  
*API Version: 1.0.0*
