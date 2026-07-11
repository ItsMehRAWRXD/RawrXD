# Debugging Guide
## Sovereign IDE Engineering Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

Comprehensive debugging guide for developers working on the Sovereign IDE.

### Debug Configurations

| Configuration | Use Case |
|---------------|----------|
| `Debug` | Development |
| `RelWithDebInfo` | Production debugging |
| `ASan` | Memory debugging |
| `TSan` | Thread debugging |

---

## Debugging Techniques

### Logging

```cpp
// Log levels
LOG_TRACE("Detailed trace");
LOG_DEBUG("Debug information");
LOG_INFO("General information");
LOG_WARNING("Warning message");
LOG_ERROR("Error occurred");
LOG_FATAL("Fatal error");

// Conditional logging
LOG_DEBUG_IF(condition, "Conditional debug");

// Scoped logging
{
    LOG_SCOPE("Analysis");
    RunAnalysis();  // Logs entry and exit
}
```

### Assertions

```cpp
// Debug assertion
SOVEREIGN_ASSERT(ptr != nullptr);

// With message
SOVEREIGN_ASSERT_MSG(index < size, "Index out of bounds");

// Verify (always checked)
SOVEREIGN_VERIFY(result == SUCCESS);
```

### Breakpoints

```cpp
// Conditional breakpoint
if (condition) {
    SOVEREIGN_BREAKPOINT();
}

// Data breakpoint
SOVEREIGN_WATCH_VARIABLE(variable);
```

---

## Memory Debugging

### Address Sanitizer

```bash
# Build with ASan
cmake -B build -DSOVEREIGN_ASAN=ON
cmake --build build

# Run
./build/sovereign
```

### Memory Leak Detection

```cpp
// Track allocations
MemoryTracker tracker;

void* ptr = malloc(100);
tracker.Track(ptr, 100, __FILE__, __LINE__);

// Check for leaks
auto leaks = tracker.GetLeaks();
for (const auto& leak : leaks) {
    LOG_ERROR("Leak at %s:%d", leak.file, leak.line);
}
```

---

## Summary

Debugging Guide provides:

- ✅ **Logging system**
- ✅ **Assertions**
- ✅ **Memory debugging**
- ✅ **Sanitizer support**
- ✅ **Best practices**

**Status:** ✅ Complete
