# RawrXD BeaconDebugger - DAP Integration Milestone

## Overview
This milestone implements a **Protocol-First DAP Server** architecture where BeaconDebugger acts as a standalone debug adapter that VS Code can communicate with via the standard Debug Adapter Protocol (DAP).

## Architecture

```
VS Code IDE
    │
    │ DAP over stdio (Content-Length framing)
    ▼
dap-server-launcher.js (Node.js wrapper)
    │
    │ Spawns native process
    ▼
BeaconDebugger.exe (DAP Server)
    │
    │ Internal C++ API calls
    ▼
┌─────────────────────────────────────┐
│  DAPTransport  →  DAPAdapter        │
│  (stdio I/O)    (protocol logic)    │
└─────────────────────────────────────┘
    │
    │ Debug API (CreateProcess, WaitForDebugEvent)
    ▼
Victim.exe (debuggee)
```

## Build Instructions

### Prerequisites
- Visual Studio 2022 with C++ tools
- Windows SDK
- Node.js (for launcher script)

### Build Steps

1. **Open VS Developer Command Prompt**
   ```cmd
   "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
   ```

2. **Build the DAP Server**
   ```cmd
   cd d:\rawrxd
   build_dap_server.bat
   ```

3. **Build Victim.exe (test target)**
   ```cmd
   cd d:\rawrxd\src\debugger
   ml64 Victim.asm /link /out:..\..\Victim.exe
   ```

## VS Code Configuration

The `.vscode/launch.json` contains two configurations:

### 1. "Debug with RawrXD Beacon"
Uses the cppdbg type with custom MIMode to launch Victim.exe through BeaconDebugger.

### 2. "Attach to RawrXD DAP Server"
Uses the Node.js launcher script to spawn BeaconDebugger as a DAP server.

## DAP Protocol Implementation

### Supported Commands
| Command | Status | Description |
|---------|--------|-------------|
| `initialize` | ✅ | Send capabilities, receive client info |
| `launch` | ✅ | Spawn debuggee process |
| `attach` | ✅ | Attach to running process |
| `configurationDone` | ✅ | Acknowledge configuration complete |
| `setBreakpoints` | ✅ | Map source lines to addresses |
| `continue` | ✅ | Resume execution |
| `next` | ✅ | Step over |
| `stepIn` | ✅ | Step into |
| `stepOut` | ✅ | Step out |
| `pause` | ✅ | Break execution |
| `stackTrace` | ✅ | Get call stack |
| `scopes` | 🔄 | Variable scopes (stub) |
| `variables` | 🔄 | Variable values (stub) |
| `evaluate` | 🔄 | Expression evaluation (stub) |

### Line-to-Address Mapping
The `setBreakpoints` handler includes a simple symbol table for Victim.exe:

```cpp
static const LineMapping g_lineMappings[] = {
    {L"Victim.asm", 25, 0x140001000, "__bp_entry_point"},
    {L"Victim.asm", 35, 0x140001020, "__bp_loop_start"},
    {L"Victim.asm", 45, 0x140001040, "__bp_loop_body"},
    {L"Victim.asm", 55, 0x140001060, "__bp_exit_point"},
};
```

In production, this would be replaced with PDB/DWARF symbol parsing.

## Testing the Integration

1. **Start VS Code** in `d:\rawrxd`
2. **Open Victim.asm** in the editor
3. **Set breakpoints** on lines 25, 35, 45, or 55
4. **Press F5** to start debugging
5. **Expected behavior**:
   - VS Code connects to BeaconDebugger
   - Victim.exe launches
   - Execution stops at entry breakpoint
   - Call stack visible in VS Code
   - Step/Continue commands work

## Next Steps

### Priority 1: Complete Breakpoint Support
- Parse PDB files for real line-to-address mapping
- Support conditional breakpoints
- Handle breakpoint removal/modification

### Priority 2: Variable Inspection
- Implement `scopes` command
- Implement `variables` command
- Read memory via `ReadProcessMemory`
- Format values as JSON

### Priority 3: Enhanced Features
- Disassembly view (`disassemble` request)
- Memory read/write (`readMemory`/`writeMemory`)
- Watch expressions
- Exception handling

## Files Created

| File | Purpose |
|------|---------|
| `DAPAdapter.h/cpp` | DAP protocol implementation |
| `DAPTransport.h/cpp` | Content-Length framing over stdio |
| `BeaconDAPServer.cpp` | Standalone DAP server entry point |
| `build_dap_server.bat` | Build automation script |
| `dap-server-launcher.js` | Node.js wrapper for VS Code integration |
| `.vscode/launch.json` | VS Code debug configurations |

## Technical Notes

### Win64 ABI Compliance
All ASM code follows Win64 ABI:
- 32-byte shadow space before API calls
- 16-byte stack alignment at call sites
- Non-volatile register preservation (RBX, RBP, RDI, RSI, R12-R15)

### JSON Serialization
Minimalist JSON implementation without external dependencies:
- Manual string escaping
- Object/array builders
- No parsing library (extracts fields via string search)

### Thread Safety
DAP adapter runs on a dedicated thread:
- Main thread: DAP message loop
- Backend thread: Debug event loop
- Synchronization via Windows events
