# RawrXD Native Plugin System

## Overview

The RawrXD Native Plugin System is a **zero-dependency, pure native** extension architecture that allows plugins to be written in any language that compiles to x64 machine code (C, C++, Rust, Zig, Go, or raw MASM assembly).

Unlike VSCode-style extensions that require Node.js/Electron, RawrXD plugins are:
- **Native DLLs** loaded directly via Windows Loader (`LoadLibrary`/`GetProcAddress`)
- **Zero-overhead** - Plugins run at native speed in the same process
- **MASM-compatible** - Can be written in pure x64 assembly
- **Stable ABI** - C-compatible interface guaranteed across versions

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RawrXD IDE (Host)                        │
│  ┌─────────────────────────────────────────────────────┐  │
│  │         NativePluginManager (Singleton)             │  │
│  │  - Scans /plugins/*.dll on startup                  │  │
│  │  - Calls LoadLibraryW for each plugin               │  │
│  │  - Passes RawrXD_API (function pointer table)       │  │
│  └─────────────────────────────────────────────────────┘  │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐  │
│  │              RawrXD_API (Stable ABI)                │  │
│  │  Function pointers to IDE services:                 │  │
│  │  - Editor operations (insert/get text, selection)   │  │
│  │  - Document operations (open, save, get path)       │  │
│  │  - Command registration                               │  │
│  │  - Event hooks (file.open, editor.change, etc.)       │  │
│  │  - UI integration (menus, status bar)                 │  │
│  └─────────────────────────────────────────────────────┘  │
│                          │                                  │
└──────────────────────────┼──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Plugin DLLs                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ SamplePlugin │  │  MyPlugin    │  │  AsmPlugin   │     │
│  │   (MASM)     │  │    (C++)     │  │    (MASM)    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
│  Each plugin exports:                                       │
│  - RawrXD_PluginInitialize() [REQUIRED]                     │
│  - RawrXD_PluginShutdown() [OPTIONAL]                     │
└─────────────────────────────────────────────────────────────┘
```

---

## Plugin Lifecycle

1. **Discovery:** IDE scans `/plugins/*.dll` on startup
2. **Loading:** IDE calls `LoadLibraryW()` on each DLL
3. **Initialization:** IDE calls `GetProcAddress()` for `RawrXD_PluginInitialize`
4. **API Injection:** IDE passes `RawrXD_API*` struct (function pointer table)
5. **Registration:** Plugin registers commands, hooks events via function pointers
6. **Execution:** Plugin callbacks invoked when commands/events triggered
7. **Shutdown:** IDE calls `RawrXD_PluginShutdown()` on exit (if exported)

---

## Writing a Plugin

### Minimal C++ Plugin

```cpp
#include "RawrXD_PluginAPI.h"

extern "C" __declspec(dllexport) int RawrXD_PluginInitialize(
    const RawrXD_API* api,
    uint32_t api_version,
    void** plugin_context
) {
    // Register a command
    api->RegisterCommand(
        "myplugin.hello",           // Command ID
        "Hello World",              // Display name
        "Ctrl+Shift+H",             // Keybinding
        [](void* ctx, const char* args, char* out, size_t out_size) -> int {
            // Command handler
            MessageBoxA(nullptr, "Hello!", "Plugin", MB_OK);
            return 0;
        },
        nullptr                       // Context
    );
    
    return 0; // Success
}
```

### Minimal MASM Plugin

```asm
; Export the initialize function
public RawrXD_PluginInitialize

RawrXD_PluginInitialize proc export
    ; RCX = RawrXD_API* api
    ; RDX = api_version
    ; R8  = void** plugin_context
    
    ; Call api->Log(RAWRXD_LOG_INFO, "MyPlugin", "Hello!")
    mov rbx, rcx                    ; Save API pointer
    mov rcx, 1                      ; RAWRXD_LOG_INFO
    lea rdx, PluginName
    lea r8, HelloMessage
    call qword ptr [rbx]            ; Call Log function
    
    xor eax, eax                    ; Return 0 (success)
    ret
RawrXD_PluginInitialize endp
```

---

## API Reference

### Core Functions

| Function | Description |
|----------|-------------|
| `Log(level, plugin, message)` | Write to IDE log |
| `EditorInsertText(editor, text, pos)` | Insert text at position |
| `EditorGetText(editor, buf, size, start, end)` | Get editor content |
| `DocumentOpen(path)` | Open a file |
| `DocumentSave(doc)` | Save a document |
| `RegisterCommand(id, name, keybind, callback, ctx)` | Register a command |
| `HookEvent(event, callback, ctx)` | Subscribe to events |
| `AddMenuItem(path, name, keybind, callback, ctx)` | Add menu item |
| `ShowMessageBox(title, msg, type)` | Show message dialog |

### Events

| Event | Description |
|-------|-------------|
| `RAWRXD_EVENT_FILE_OPEN` | File opened |
| `RAWRXD_EVENT_FILE_SAVE` | File saved |
| `RAWRXD_EVENT_FILE_CLOSE` | File closed |
| `RAWRXD_EVENT_EDITOR_CHANGE` | Editor content changed |
| `RAWRXD_EVENT_EDITOR_SELECTION` | Selection changed |
| `RAWRXD_EVENT_SHUTDOWN` | IDE shutting down |

---

## Building Plugins

### C++ Plugin

```bash
# Compile
cl.exe /c /W4 /EHsc MyPlugin.cpp /I"path/to/RawrXD/include"

# Link
link.exe /DLL /OUT:MyPlugin.dll MyPlugin.obj

# Install
copy MyPlugin.dll RawrXD/plugins/
```

### MASM Plugin

```bash
# Assemble
ml64.exe /c /W3 /nologo MyPlugin.asm

# Link
link.exe /DLL /OUT:MyPlugin.dll MyPlugin.obj /SUBSYSTEM:WINDOWS

# Install
copy MyPlugin.dll RawrXD/plugins/
```

---

## Security Considerations

- **In-process execution:** Plugins run in the IDE's process space
- **Native speed:** No sandboxing overhead (trade-off for performance)
- **Crash isolation:** Plugin crashes can bring down the IDE
- **Trust model:** Only load plugins from trusted sources

### Future Enhancements
- Optional out-of-process plugin host for isolation
- Code signing verification
- Permission-based API access control

---

## Sample Plugins

### SamplePlugin (MASM)
Location: `plugins/SamplePlugin/SamplePlugin.asm`
- Demonstrates pure assembly plugin
- Registers a command with keybinding
- Shows message boxes
- Handles events

### SamplePluginCpp (C++)
Location: `plugins/SamplePluginCpp/SamplePluginCpp.cpp`
- Demonstrates C++ plugin
- Command registration
- Event hooks
- Status bar integration
- Menu items

---

## Version Compatibility

The API uses semantic versioning:
- **Major version** changes = Breaking changes (plugins must recompile)
- **Minor version** changes = Backward-compatible additions

Current API version: **1.0**

---

## License

[Same as RawrXD IDE]
