# Phase 23: Debugger Backend Wiring - Implementation Summary

## Overview
Phase 23 implements the CDB/WinDbg integration that enables RawrXD to debug itself. This is the "Flight Controls"—the infrastructure that makes the IDE self-hosting.

## Architecture

```
RawrXD IDE
    ↓
DebugSession (C++ API)
    ↓
Windows Debugging API (DbgHelp)
    ↓
Debuggee Process (rawrxd.exe)
```

## Components

### 1. DebugSession
Main debugging session manager:
- **Launch/Attach**: Start or attach to processes
- **Execution Control**: Continue, step into/over/out
- **Breakpoint Management**: Set/remove software breakpoints
- **Stack Inspection**: Walk call stack with symbols
- **Register Access**: Read/write x64 registers
- **Event Loop**: Process debug events asynchronously

### 2. Breakpoint Management
Software breakpoints via INT3 (0xCC):
- Set at source line or address
- Enable/disable without removal
- Hit counting for conditional breakpoints
- Automatic original byte restoration

### 3. Symbol Resolution
DbgHelp integration for:
- Source line resolution
- Function name demangling
- Module enumeration
- Stack walking with symbols

### 4. Event System
Asynchronous debug event handling:
- Breakpoint hit
- Step completion
- Exception (AV, divide by zero)
- Module load/unload
- Thread create/exit
- Process exit
- Debug output

## Key Features

| Feature | Implementation |
|---------|---------------|
| **Launch Process** | `CreateProcessW` with `DEBUG_PROCESS` |
| **Attach** | `DebugActiveProcess` |
| **Breakpoints** | Software (INT3) |
| **Stepping** | Trap flag (EFLAGS.TF) |
| **Stack Walk** | `StackWalk64` |
| **Symbols** | `DbgHelp` (dbghelp.lib) |
| **Registers** | `GetThreadContext` |

## Usage Example

```cpp
#include "debugger/Debugger_Backend.h"

using namespace RawrXD::Debugger;

// Create session
DebugSession session;
session.Initialize();

// Set event callback
session.SetEventCallback([](DebugEventType event, const void* data, DebugSession* sess) {
    switch (event) {
        case DebugEventType::Breakpoint:
            std::wcout << L"Breakpoint hit at " 
                      << FormatAddress(sess->GetCurrentInstructionPointer()) << L"\n";
            
            // Show call stack
            auto frames = sess->GetCallStack();
            for (const auto& frame : frames) {
                std::wcout << L"  " << frame.functionName 
                          << L" at " << frame.filePath 
                          << L":" << frame.lineNumber << L"\n";
            }
            break;
    }
});

// Launch debuggee
if (session.LaunchProcess(L"rawrxd.exe", L"--test", L"C:\\Projects")) {
    std::wcout << L"Launched process " << session.GetProcessId() << L"\n";
    
    // Set breakpoint
    auto bp = session.SetBreakpoint(L"main.cpp", 42);
    if (bp) {
        std::wcout << L"Breakpoint set at line 42\n";
    }
    
    // Run event loop (blocks until process exits)
    session.RunEventLoop();
}
```

## Self-Hosting Loop

The ultimate validation:

1. **Build RawrXD** using hardened CMake pipeline
2. **Launch RawrXD** from within RawrXD (F5)
3. **Hit breakpoint** in your code
4. **Inspect stack** showing your own functions
5. **Fix bug** and rebuild
6. **Repeat**—the IDE debugging itself

## Integration with IDE

### UI Components Needed
- **Breakpoint gutter**: Click to set/remove breakpoints
- **Call stack panel**: Show frames, click to navigate
- **Variables panel**: Show locals, registers
- **Debug toolbar**: Continue/Step/Stop buttons
- **Status bar**: Show "Debugging PID: X"

### Menu Integration
```
Debug
├── Start Debugging (F5)
├── Attach to Process...
├── Break All (Ctrl+Break)
├── Step Into (F11)
├── Step Over (F10)
├── Step Out (Shift+F11)
├── Continue (F5)
├── Stop Debugging (Shift+F5)
└── Windows
    ├── Call Stack
    ├── Locals
    ├── Registers
    ├── Memory
    └── Breakpoints
```

## Testing

### Unit Tests
```cpp
TEST(DebugSession, LaunchProcess) {
    DebugSession session;
    EXPECT_TRUE(session.Initialize());
    EXPECT_TRUE(session.LaunchProcess(L"test.exe", L"", L""));
    EXPECT_TRUE(session.IsActive());
    session.Terminate();
}

TEST(DebugSession, SetBreakpoint) {
    DebugSession session;
    session.Initialize();
    session.LaunchProcess(L"test.exe", L"", L"");
    
    auto bp = session.SetBreakpointAtAddress(0x140001000);
    EXPECT_TRUE(bp.has_value());
    EXPECT_EQ(bp->address, 0x140001000);
    
    session.Terminate();
}
```

### Integration Test
1. Build `test_debuggee.exe` (simple console app)
2. Launch from RawrXD debugger
3. Set breakpoint at `main()`
4. Continue and verify breakpoint hit
5. Step through several instructions
6. Verify call stack shows expected frames
7. Detach cleanly

## Dependencies

- **Windows SDK**: DbgHelp.h, debug API
- **Library**: dbghelp.lib (linked automatically)
- **Privileges**: SeDebugPrivilege for attaching to processes

## Security Considerations

- Attaching to processes requires appropriate privileges
- Debug symbols may contain source paths
- Memory inspection can read sensitive data
- Consider sandboxing for untrusted code

## Next Steps

Phase 23 provides the backend. Phase 24 will add:
- **UI Integration**: Debug panels, toolbars
- **Visualizations**: Memory view, register display
- **Advanced Features**: Conditional breakpoints, watch expressions
- **ASM Debugging**: Disassembly view, instruction stepping

## Success Criteria

✅ Launch process under debugger  
✅ Set/remove software breakpoints  
✅ Step into/over/out  
✅ Walk call stack with symbols  
✅ Read registers and memory  
✅ Handle debug events asynchronously  
✅ Self-hosting: Debug RawrXD with RawrXD  

---
*Phase 23 Complete: The IDE can now debug itself.*
