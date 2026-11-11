/*===========================================================================
 * DebuggerIntegrationGuide.md
 * RawrXD IDE Debugger Integration Guide
 *===========================================================================*/

# Debugger Integration Architecture

## Overview

The RawrXD IDE now has a complete debugger subsystem with three layers:

```
┌─────────────────────────────────────────────────────────────┐
│                    IDE UI Layer                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Editor    │  │   Toolbar   │  │   Debug Panels      │  │
│  │  (Margin)   │  │  (Buttons)  │  │ (Registers/Memory)  │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
└─────────┼────────────────┼────────────────────┼──────────────┘
          │                │                    │
          ▼                ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│              Debugger Service Layer                          │
│                    DebuggerService                           │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  • Breakpoint Shadow Table (file:line → address)    │    │
│  │  • SPSC Event Ring Buffer (CDB thread → UI thread)  │    │
│  │  • Thread Context Cache                             │    │
│  │  • Source Mapping (address ↔ file:line)             │    │
│  └─────────────────────────────────────────────────────┘    │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│              Core Debugger Engine                            │
│                  SovereignCDB_Engine                         │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  • WaitForDebugEventEx (Event Pump Thread)          │    │
│  │  • Software Breakpoints (int3/0xCC injection)       │    │
│  │  • Memory R/W (ReadProcessMemory/WriteProcessMemory)│    │
│  │  • Register Access (GetThreadContext/SetThreadCtx)│    │
│  │  • Symbol Resolution (DbgHelp)                      │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Files Created

### Core Debugger Engine
- `src/debugger/SovereignCDB_Engine.h` - C API header
- `src/debugger/SovereignCDB_Engine.cpp` - Implementation
- `src/debugger/test_cdb_engine.cpp` - Test harness

### Debugger Service Layer
- `src/ide/DebuggerService.h` - Service API
- `src/ide/DebuggerService.cpp` - Service implementation with SPSC ring buffer

### IDE UI Integration
- `src/ide/IDE_DebuggerIntegration.h` - UI components
- `src/ide/IDE_DebuggerIntegration.cpp` - UI implementation

## Integration Steps

### Step 1: Add to Build System

Update your CMakeLists.txt or build script:

```cmake
# Add debugger sources
target_sources(RawrXD_IDE PRIVATE
    # Core debugger
    src/debugger/SovereignCDB_Engine.cpp
    
    # Service layer
    src/ide/DebuggerService.cpp
    
    # UI integration
    src/ide/IDE_DebuggerIntegration.cpp
)

# Link DbgHelp for symbols
target_link_libraries(RawrXD_IDE PRIVATE
    dbghelp
)
```

### Step 2: Initialize in IDE Startup

In `RawrXD_IDE_Win32.cpp`, add to initialization:

```cpp
#include "ide/IDE_DebuggerIntegration.h"

// In WinMain or initialization function:
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
    // ... existing initialization ...
    
    // Initialize debugger subsystem
    if (!RawrXD::IDE_InitDebugger(g_hMainWnd)) {
        MessageBox(g_hMainWnd, "Failed to initialize debugger", "Error", MB_OK);
    }
    
    // ... rest of initialization ...
}
```

### Step 3: Add Window Message Handling

In your main window procedure:

```cpp
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        // ... existing cases ...
        
        case WM_COMMAND:
            // Handle debug commands first
            if (RawrXD::IDE_HandleDebugCommand(LOWORD(wParam))) {
                return 0;
            }
            // ... existing command handling ...
            break;
            
        case WM_KEYDOWN:
            // Handle debug shortcuts
            if (RawrXD::IDE_HandleDebugKeys((int)wParam, 
                (GetKeyState(VK_CONTROL) < 0),
                (GetKeyState(VK_SHIFT) < 0))) {
                return 0;
            }
            break;
            
        case WM_DEBUG_EVENT:
            // Handle debug events from engine
            RawrXD::IDE_HandleDebugEvent(wParam, lParam);
            return 0;
            
        case WM_DEBUG_UPDATE:
            // Update debug UI
            RawrXD::IDE_UpdateDebugUI();
            return 0;
            
        case WM_DESTROY:
            // Cleanup debugger
            RawrXD::IDE_ShutdownDebugger();
            // ... existing cleanup ...
            break;
    }
    
    return DefWindowProc(hWnd, message, wParam, lParam);
}
```

### Step 4: Add Debug Menu

Add to your menu resource:

```cpp
// In resource file or menu creation:
HMENU hDebugMenu = CreatePopupMenu();
AppendMenu(hDebugMenu, MF_STRING, ID_DEBUG_START, "&Start Debugging\tF5");
AppendMenu(hDebugMenu, MF_STRING, ID_DEBUG_STOP, "&Stop Debugging\tShift+F5");
AppendMenu(hDebugMenu, MF_SEPARATOR, 0, nullptr);
AppendMenu(hDebugMenu, MF_STRING, ID_DEBUG_CONTINUE, "&Continue\tF5");
AppendMenu(hDebugMenu, MF_STRING, ID_DEBUG_PAUSE, "&Break\tCtrl+Break");
AppendMenu(hDebugMenu, MF_SEPARATOR, 0, nullptr);
AppendMenu(hDebugMenu, MF_STRING, ID_DEBUG_STEP_INTO, "Step &Into\tF11");
AppendMenu(hDebugMenu, MF_STRING, ID_DEBUG_STEP_OVER, "Step &Over\tF10");
AppendMenu(hDebugMenu, MF_STRING, ID_DEBUG_STEP_OUT, "Step O&ut\tShift+F11");
AppendMenu(hDebugMenu, MF_SEPARATOR, 0, nullptr);
AppendMenu(hDebugMenu, MF_STRING, ID_DEBUG_TOGGLE_BP, "Toggle &Breakpoint\tF9");
AppendMenu(hDebugMenu, MF_SEPARATOR, 0, nullptr);
AppendMenu(hDebugMenu, MF_STRING, ID_DEBUG_SHOW_REGISTERS, "&Registers");
AppendMenu(hDebugMenu, MF_STRING, ID_DEBUG_SHOW_MEMORY, "&Memory");
AppendMenu(hDebugMenu, MF_STRING, ID_DEBUG_SHOW_CALLSTACK, "&Call Stack");

AppendMenu(hMenuBar, MF_POPUP, (UINT_PTR)hDebugMenu, "&Debug");
```

### Step 5: Add Breakpoint Margin to Editor

In your editor window:

```cpp
// In editor paint routine, before drawing text:
void Editor_Paint(HWND hWnd, HDC hdc) {
    RECT clientRect;
    GetClientRect(hWnd, &clientRect);
    
    // Draw breakpoint margin
    RECT marginRect = { 0, 0, 24, clientRect.bottom };
    
    // Get breakpoint margin from debugger UI
    auto* ui = &RawrXD::DebuggerUIManager::GetInstance();
    // margin.Paint(hdc, marginRect, firstVisibleLine, visibleLineCount);
    
    // ... rest of editor painting ...
}

// In editor mouse handling:
void Editor_OnLButtonDown(HWND hWnd, int x, int y) {
    // Check if click is in margin
    if (x < 24) {
        int line = Editor_GetLineFromY(y);
        auto& svc = RawrXD::DebuggerService::GetInstance();
        svc.ToggleBreakpoint(currentFile, line);
        InvalidateRect(hWnd, nullptr, FALSE);
        return;
    }
    
    // ... normal click handling ...
}
```

## Key Features

### 1. SPSC Ring Buffer Event Bridge

The `DebuggerService` uses a lock-free SPSC (Single-Producer, Single-Consumer) ring buffer to transfer events from the CDB engine thread to the UI thread:

```cpp
// In DebuggerService.cpp
template<typename T, size_t Size>
class SPSCRingBuffer {
    // Lock-free, cache-line aligned
    // Producer: CDB event pump thread
    // Consumer: IDE UI thread (via PollEvents())
};
```

### 2. Breakpoint Shadow Table

The IDE maintains a shadow table of breakpoints that persists across debug sessions:

```cpp
// File:line → BreakpointInfo
struct BreakpointInfo {
    uint32_t id;
    uint64_t address;      // Resolved at runtime
    std::string filePath;
    int lineNumber;
    bool enabled;
    bool resolved;         // Address known?
};
```

Breakpoints are resolved when:
- Process starts (module load events)
- Source mapping is available
- User manually sets by address

### 3. Thread Context Cache

Register values are cached to avoid repeated `GetThreadContext` calls:

```cpp
// Cache invalidated on:
// - Continue execution
// - Step operations
// Cache refreshed on:
// - Breakpoint hit
// - Explicit UI refresh
```

### 4. Memory View Virtualization

The memory viewer only requests visible memory ranges:

```cpp
// User sees 16-32 lines
// We read only 16-32 * 16 bytes = 256-512 bytes
// Not the entire address space
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| F5 | Start / Continue |
| Shift+F5 | Stop |
| F9 | Toggle Breakpoint |
| F10 | Step Over |
| F11 | Step Into |
| Shift+F11 | Step Out |
| Ctrl+Break | Break (Pause) |

## Debug Panels

### Register Viewer
- Shows all x64 registers (RAX-R15, RIP, RSP, etc.)
- Modified registers highlighted in red
- Two-column layout for compactness

### Memory Viewer
- Address input field
- Scrollable hex dump
- ASCII representation
- 16 bytes per line

### Call Stack
- Frame number, address, function name
- Source file and line number
- Double-click to navigate to source

## Usage Example

```cpp
// In your IDE code:

// 1. Start debugging
void OnDebugStart() {
    auto& svc = RawrXD::DebuggerService::GetInstance();
    svc.LaunchProcess("C:\\path\\to\\program.exe");
}

// 2. Set breakpoint
void OnToggleBreakpoint(const std::string& file, int line) {
    auto& svc = RawrXD::DebuggerService::GetInstance();
    svc.ToggleBreakpoint(file, line);
}

// 3. Handle breakpoint hit (in event callback)
void OnBreakpointHit(const DebugEvent& event) {
    // Update register view
    auto& svc = RawrXD::DebuggerService::GetInstance();
    auto regs = svc.GetRegisters(event.threadId);
    
    // Show current line in editor
    std::string file;
    int line;
    if (svc.GetLineForAddress(event.address, file, line)) {
        Editor_GotoLine(file, line);
    }
}

// 4. Read memory
void ShowMemory(uint64_t address) {
    auto& svc = RawrXD::DebuggerService::GetInstance();
    auto mem = svc.ReadMemory(address, 256);
    if (mem.valid) {
        MemoryView_Display(mem.data.data(), mem.data.size());
    }
}
```

## Thread Safety

All public APIs in `DebuggerService` are thread-safe:
- State queries use mutex locks
- Breakpoint operations use mutex locks
- Event queue uses lock-free SPSC ring buffer
- UI updates happen only from main thread

## Next Steps

1. **Symbol Server Integration** - Add Microsoft symbol server support
2. **Expression Evaluation** - Add watch window with expression parsing
3. **Memory Breakpoints** - Hardware breakpoint support
4. **Multi-threading** - Thread list panel
5. **Disassembly** - Mixed source/asm view

## Status

| Component | Status |
|-----------|--------|
| Core CDB Engine | ✅ Complete |
| Debugger Service | ✅ Complete |
| Register Viewer | ✅ Complete |
| Memory Viewer | ✅ Complete |
| Call Stack | ✅ Complete |
| Debug Toolbar | ✅ Complete |
| Breakpoint Margin | ⬜ Needs Editor Integration |
| IDE Wiring | ⬜ Needs RawrXD_IDE_Win32.cpp Updates |

The debugger infrastructure is complete and ready for integration into the main IDE window.
