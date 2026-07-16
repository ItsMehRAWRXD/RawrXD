# RawrXD Native Plugin System

## Overview

The RawrXD Native Plugin System enables third-party developers to extend the IDE using native DLLs written in C, C++, or x64 assembly (MASM). This provides maximum performance and direct hardware access while maintaining IDE stability through SEH exception wrapping.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      RawrXD IDE                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │           NativePluginManager (Singleton)             │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │  RawrXD_API (Function Pointer Table)           │  │  │
│  │  │  ├─ Memory Management (Allocate/Free)          │  │  │
│  │  │  ├─ Editor Operations (Insert/Get Text)        │  │  │
│  │  │  ├─ Document Operations (Open/Save)          │  │  │
│  │  │  ├─ UI Integration (Menus/Status Bar)          │  │  │
│  │  │  ├─ Event System (Hook/Broadcast)            │  │  │
│  │  │  └─ Logging and Settings                       │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
│                          │                                  │
│              LoadLibraryW/GetProcAddress                     │
│                          │                                  │
│  ┌───────────────────────┼───────────────────────┐         │
│  │                       ▼                       │         │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │         │
│  │  │ Plugin A    │  │ Plugin B    │  │ Plugin C│ │         │
│  │  │ (C++)       │  │ (C)         │  │ (MASM)  │ │         │
│  │  │ .dll        │  │ .dll        │  │ .dll    │ │         │
│  │  └─────────────┘  └─────────────┘  └─────────┘ │         │
│  │                                               │         │
│  │  SEH Exception Wrapping: Plugin crashes       │         │
│  │  are caught - IDE remains stable              │         │
│  └───────────────────────────────────────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

## Key Features

### 1. SEH Exception Wrapping (CRITICAL)
All plugin entry points are wrapped in `__try/__except` blocks:

```cpp
__try {
    result = plugin.initializeFunc(&m_api, RAWRXD_API_VERSION, &pluginContext);
}
__except(EXCEPTION_EXECUTE_HANDLER) {
    // Plugin crashed - log error but IDE stays alive
    DWORD exceptionCode = GetExceptionCode();
    LogError("Plugin caused exception 0x%08X - disabled", exceptionCode);
    result = RAWRXD_ERROR_EXCEPTION;
}
```

### 2. ABI Version Checking
The `RawrXD_API` struct starts with three version fields:

```cpp
typedef struct RawrXD_API_ {
    size_t struct_size;      // sizeof(RawrXD_API) - enables forward compatibility
    uint32_t api_version;    // RAWRXD_API_VERSION
    uint32_t abi_version;    // CURRENT_ABI_VERSION
    // ... rest of struct
} RawrXD_API;
```

Plugins can check `struct_size` to determine which fields are available.

### 3. Memory Management
**CRITICAL RULE**: IDE allocates and frees ALL memory. Plugins call IDE-provided functions:

```cpp
// Plugin code (C)
void* myData = api->AllocateMemory(1024, RAWRXD_MEM_ZERO_INIT);
// ... use memory ...
api->FreeMemory(myData);  // Never use free() or delete
```

This prevents heap corruption from mixing different CRTs.

## Plugin API Reference

### Required Exports

Every plugin DLL must export:

```c
// Initialize plugin - REQUIRED
int RawrXD_PluginInitialize(
    RawrXD_API* api,           // IN: Function pointer table
    uint32_t api_version,      // IN: IDE's API version
    void** context             // OUT: Plugin's context pointer
);

// Shutdown plugin - OPTIONAL but recommended
int RawrXD_PluginShutdown(
    void* context              // IN: Plugin context from Initialize
);
```

### Return Codes

```cpp
#define RAWRXD_SUCCESS              0   // Operation succeeded
#define RAWRXD_ERROR_NULL_API       1   // api pointer was null
#define RAWRXD_ERROR_VERSION        2   // API version mismatch
#define RAWRXD_ERROR_ALLOCATION     3   // Memory allocation failed
#define RAWRXD_ERROR_EXCEPTION        4   // Exception occurred (SEH caught)
#define RAWRXD_ERROR_INVALID_PARAM    5   // Invalid parameter
#define RAWRXD_ERROR_NOT_SUPPORTED    6   // Feature not supported
```

### Memory Flags

```cpp
#define RAWRXD_MEM_DEFAULT          0x0000   // Standard allocation
#define RAWRXD_MEM_ZERO_INIT        0x0001   // Zero-initialize memory
#define RAWRXD_MEM_EXECUTABLE       0x0002   // Executable memory (for JIT)
#define RAWRXD_MEM_LARGE_PAGES      0x0004   // Use large pages
```

## Building a Plugin

### C++ Plugin Example

```cpp
// MyPlugin.cpp
#include "RawrXD_PluginAPI.h"

static void* g_context = nullptr;

extern "C" __declspec(dllexport)
int RawrXD_PluginInitialize(RawrXD_API* api, uint32_t version, void** context) {
    // Check API version
    if (version < RAWRXD_API_VERSION) {
        return RAWRXD_ERROR_VERSION;
    }
    
    // Allocate context using IDE allocator
    g_context = api->AllocateMemory(sizeof(MyContext), RAWRXD_MEM_ZERO_INIT);
    if (!g_context) {
        return RAWRXD_ERROR_ALLOCATION;
    }
    
    *context = g_context;
    
    // Log success
    api->Log(RAWRXD_LOG_INFO, "MyPlugin", "Initialized successfully");
    
    return RAWRXD_SUCCESS;
}

extern "C" __declspec(dllexport)
int RawrXD_PluginShutdown(void* context) {
    // Context will be freed by IDE - just cleanup resources
    return RAWRXD_SUCCESS;
}
```

Build:
```bash
cl.exe /LD /FeMyPlugin.dll MyPlugin.cpp /I..\include
```

### MASM Plugin Example

See `plugins/SamplePlugin/SamplePlugin.asm` for a complete working example.

Build:
```bash
ml64.exe /c /W3 /nologo SamplePlugin.asm
link.exe /DLL /OUT:SamplePlugin.dll SamplePlugin.obj /SUBSYSTEM:WINDOWS
```

## Installation

1. Create `plugins/` directory next to RawrXD.exe
2. Copy plugin DLLs into `plugins/`
3. Restart IDE or call `NativePluginManager::DiscoverPlugins()`

## Security Considerations

- Plugins run in-process with full IDE privileges
- SEH wrapping prevents crashes but not malicious code
- Only load plugins from trusted sources
- Future: Out-of-process plugin host for untrusted plugins

## Performance

- Zero overhead: Direct function pointer calls
- No marshaling or IPC for in-process plugins
- Shared memory with IDE (no copies)
- Native speed for compute-intensive operations

## Debugging Plugins

1. Build plugin with debug symbols (.pdb)
2. Attach debugger to RawrXD.exe
3. Set breakpoints in plugin code
4. SEH exceptions will be caught - check Output panel for error codes

## Future Enhancements

- [ ] Plugin settings persistence
- [ ] Hot-reload (unload/reload without IDE restart)
- [ ] Plugin marketplace integration
- [ ] Sandboxed plugin host (out-of-process)
- [ ] Scripting language bindings (Lua, Python)

## API Stability Guarantee

- ABI version 1: Initial release
- New fields added to end of RawrXD_API struct
- `struct_size` field enables forward compatibility
- Deprecated functions kept for 2 major versions

## Support

For plugin development support:
- See `include/RawrXD_PluginAPI.h` for complete API
- Check `plugins/SamplePlugin/` for working examples
- Review `src/win32app/NativePluginManager.cpp` for implementation details
