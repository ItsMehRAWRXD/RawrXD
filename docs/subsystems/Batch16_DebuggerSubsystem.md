# Batch 16 - Debugger Subsystem
## Sovereign IDE Subsystem Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The Debugger Subsystem provides debugging capabilities for binaries, firmware, and kernel modules. It supports breakpoint management, step/trace execution, register inspection, and memory inspection.

### Key Characteristics

| Attribute | Value |
|-----------|-------|
| **Language** | C++17 |
| **Lines of Code** | ~8,200 |
| **Platforms** | Windows, Linux, macOS |
| **Architectures** | x86, x64, ARM, ARM64 |
| **SEG Nodes** | 1 |
| **MoE Experts** | 1 |

---

## Responsibilities

1. **Breakpoint Management** - Set/remove software/hardware breakpoints
2. **Step/Trace Execution** - Single-step and trace execution
3. **Register Inspection** - Read/write CPU registers
4. **Memory Inspection** - Read/write process memory
5. **Stack Tracing** - Walk call stack

---

## Architecture

```
┌─────────────────────────────────────────────┐
│           Debugger Subsystem                │
├─────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Breakpoint │  │   Execution      │    │
│  │   Manager    │  │   Controller     │    │
│  └──────────────┘  └──────────────────┘    │
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Register   │  │   Memory         │    │
│  │   Inspector  │  │   Inspector      │    │
│  └──────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────┘
```

---

## ABI Surfaces

```cpp
// Debugger initialization
SOVEREIGN_API DebugResult Debug_Initialize();
SOVEREIGN_API void Debug_Shutdown();

// Process control
SOVEREIGN_API DebugResult Debug_Attach(ProcessID pid);
SOVEREIGN_API DebugResult Debug_Detach();
SOVEREIGN_API DebugResult Debug_Launch(const char* executable,
                                        const char* args);
SOVEREIGN_API DebugResult Debug_Terminate();

// Execution control
SOVEREIGN_API DebugResult Debug_Continue();
SOVEREIGN_API DebugResult Debug_StepInto();
SOVEREIGN_API DebugResult Debug_StepOver();
SOVEREIGN_API DebugResult Debug_StepOut();
SOVEREIGN_API DebugResult Debug_Pause();

// Breakpoints
SOVEREIGN_API BreakpointHandle Debug_SetBreakpoint(uint64_t address);
SOVEREIGN_API DebugResult Debug_RemoveBreakpoint(BreakpointHandle bp);
SOVEREIGN_API DebugResult Debug_EnableBreakpoint(BreakpointHandle bp);
SOVEREIGN_API DebugResult Debug_DisableBreakpoint(BreakpointHandle bp);

// Inspection
SOVEREIGN_API uint64_t Debug_ReadRegister(Register reg);
SOVEREIGN_API DebugResult Debug_WriteRegister(Register reg, uint64_t value);
SOVEREIGN_API size_t Debug_ReadMemory(uint64_t address, void* buffer, size_t size);
SOVEREIGN_API DebugResult Debug_WriteMemory(uint64_t address, const void* buffer, size_t size);

// Stack
SOVEREIGN_API StackFrame* Debug_GetCallStack();
```

---

## SEG Nodes

| Node ID | Name | Type | Description |
|---------|------|------|-------------|
| 0x0014 | `SEGNode_DebugControl` | Control | Control debugger execution |

---

## MoE Experts

| Expert Name | Domain | Description |
|-------------|--------|-------------|
| `Expert_DebugInference` | debug | Infer debugging strategies |

---

## Implementation Details

### Breakpoint Manager

```cpp
class BreakpointManager {
public:
    Breakpoint* SetBreakpoint(uint64_t address) {
        // Read original byte
        uint8_t originalByte;
        Debug_ReadMemory(address, &originalByte, 1);
        
        // Write INT3 (0xCC) on x86/x64
        uint8_t int3 = 0xCC;
        Debug_WriteMemory(address, &int3, 1);
        
        // Store breakpoint info
        auto bp = new Breakpoint();
        bp->address = address;
        bp->originalByte = originalByte;
        bp->enabled = true;
        
        m_breakpoints[address] = bp;
        return bp;
    }
    
    void RemoveBreakpoint(Breakpoint* bp) {
        // Restore original byte
        Debug_WriteMemory(bp->address, &bp->originalByte, 1);
        
        m_breakpoints.erase(bp->address);
        delete bp;
    }
    
    void HandleBreakpoint(uint64_t address) {
        auto it = m_breakpoints.find(address);
        if (it != m_breakpoints.end()) {
            auto bp = it->second;
            
            // Restore original instruction
            Debug_WriteMemory(address, &bp->originalByte, 1);
            
            // Step back one instruction
            auto context = GetContext();
            context.Rip--;  // x64
            SetContext(context);
            
            // Notify listeners
            OnBreakpointHit(bp);
            
            // Re-enable breakpoint after stepping
            if (bp->enabled) {
                uint8_t int3 = 0xCC;
                Debug_WriteMemory(address, &int3, 1);
            }
        }
    }
    
private:
    std::unordered_map<uint64_t, Breakpoint*> m_breakpoints;
};
```

### Execution Controller

```cpp
class ExecutionController {
public:
    void StepInto() {
        // Set trap flag for single-step
        auto context = GetContext();
        context.EFlags |= 0x100;  // Trap flag
        SetContext(context);
        
        // Continue execution
        Continue();
    }
    
    void StepOver() {
        // Get current instruction
        auto context = GetContext();
        auto inst = DisassembleAt(context.Rip);
        
        // If it's a call, set breakpoint after
        if (IsCall(inst)) {
            auto returnAddress = inst.address + inst.size;
            auto bp = m_bpManager.SetBreakpoint(returnAddress);
            m_tempBreakpoints.push_back(bp);
            Continue();
        } else {
            // Otherwise step into
            StepInto();
        }
    }
    
    void StepOut() {
        // Set breakpoint on return address
        auto returnAddress = GetReturnAddress();
        auto bp = m_bpManager.SetBreakpoint(returnAddress);
        m_tempBreakpoints.push_back(bp);
        Continue();
    }
    
private:
    BreakpointManager m_bpManager;
    std::vector<Breakpoint*> m_tempBreakpoints;
};
```

---

## Testing

```cpp
TEST(DebuggerSubsystem, SetBreakpoint) {
    Debug_Initialize();
    
    // Launch test process
    auto result = Debug_Launch("test_program.exe", "");
    EXPECT_EQ(result, DEBUG_SUCCESS);
    
    // Set breakpoint
    auto bp = Debug_SetBreakpoint(0x1000);
    EXPECT_NE(bp, nullptr);
    
    // Continue and wait for breakpoint
    Debug_Continue();
    
    // Verify we hit breakpoint
    auto context = GetContext();
    EXPECT_EQ(context.Rip, 0x1001);  // INT3 advances by 1
    
    // Remove breakpoint
    Debug_RemoveBreakpoint(bp);
    
    Debug_Terminate();
    Debug_Shutdown();
}

TEST(DebuggerSubsystem, StepExecution) {
    Debug_Initialize();
    Debug_Launch("test_program.exe", "");
    
    // Get initial address
    auto initialIP = Debug_ReadRegister(REG_RIP);
    
    // Step
    Debug_StepInto();
    
    // Verify we moved
    auto newIP = Debug_ReadRegister(REG_RIP);
    EXPECT_NE(newIP, initialIP);
    
    Debug_Terminate();
    Debug_Shutdown();
}
```

---

## Summary

Batch 16 - Debugger Subsystem provides:

- ✅ **Breakpoint management** (software/hardware)
- ✅ **Step/trace execution**
- ✅ **Register inspection**
- ✅ **Memory inspection**
- ✅ **Stack tracing**

**Status:** ✅ Complete
