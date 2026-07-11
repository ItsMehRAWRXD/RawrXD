# Batch 01 - Core Kernel
## Sovereign IDE Subsystem Documentation

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Complete

---

## Table of Contents

1. [Overview](#overview)
2. [Responsibilities](#responsibilities)
3. [Architecture](#architecture)
4. [ABI Surfaces](#abi-surfaces)
5. [SEG Nodes](#seg-nodes)
6. [MoE Experts](#moe-experts)
7. [IDE Panels](#ide-panels)
8. [Implementation Details](#implementation-details)
9. [Testing](#testing)
10. [References](#references)

---

## Overview

The Core Kernel is the foundational execution layer of the Sovereign IDE. It provides deterministic startup, memory model initialization, subsystem registry creation, and the Sovereign ABI bootstrap.

### Key Characteristics

| Attribute | Value |
|-----------|-------|
| **Language** | MASM x64 + C |
| **Lines of Code** | ~1,050 |
| **Entry Point** | `mainCRTStartup` |
| **Subsystem Count** | 1 |
| **SEG Nodes** | 1 |
| **MoE Experts** | 0 |

---

## Responsibilities

### Core Functions

1. **Entry Point Management**
   - MASM to C ABI transition
   - Stack frame initialization
   - Command line parsing

2. **Memory Initialization**
   - Static data region setup
   - Heap initialization
   - Memory alignment enforcement

3. **Subsystem Registry**
   - Create subsystem registry
   - Register core subsystems
   - Initialize dependency graph

4. **Error Handling Bootstrap**
   - Install exception handlers
   - Set up error reporting
   - Initialize telemetry

5. **Configuration Loading**
   - Load SovereignConfig
   - Validate configuration
   - Apply runtime settings

---

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────┐
│              Core Kernel                     │
├─────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────────┐   │
│  │   MASM Entry │  │   C ABI Layer    │   │
│  │   Point      │──▶│   mainCRTStartup │   │
│  └──────────────┘  └──────────────────┘   │
│         │                    │              │
│         ▼                    ▼              │
│  ┌──────────────────────────────────────┐  │
│  │         Memory Manager               │  │
│  │  ┌──────────┐  ┌──────────────────┐  │  │
│  │  │  Stack   │  │      Heap        │  │  │
│  │  └──────────┘  └──────────────────┘  │  │
│  └──────────────────────────────────────┘  │
│                    │                        │
│                    ▼                        │
│  ┌──────────────────────────────────────┐  │
│  │      Subsystem Registry              │  │
│  │  ┌──────────┐  ┌──────────────────┐  │  │
│  │  │ Config   │  │   Telemetry      │  │  │
│  │  └──────────┘  └──────────────────┘  │  │
│  └──────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

### Execution Flow

```
1. MASM Entry (RawrXD_Main.asm)
   ↓
2. Stack Setup
   ↓
3. Static Data Init
   ↓
4. C ABI Bootstrap
   ↓
5. Subsystem Registry Init
   ↓
6. Configuration Load
   ↓
7. Telemetry Init
   ↓
8. Handoff to Batch 02
```

---

## ABI Surfaces

### Exported Functions

```c
// Kernel initialization
SOVEREIGN_API KernelResult SovereignKernel_Init(
    const KernelConfig* config
);

// Kernel shutdown
SOVEREIGN_API KernelResult SovereignKernel_Shutdown(void);

// Subsystem registration
SOVEREIGN_API KernelResult SovereignKernel_RegisterSubsystem(
    uint32_t batchId,
    const SubsystemInfo* info
);

// Memory allocation (kernel level)
SOVEREIGN_API void* SovereignKernel_Allocate(
    size_t size,
    uint32_t alignment
);

SOVEREIGN_API void SovereignKernel_Free(void* ptr);

// Error handling
SOVEREIGN_API void SovereignKernel_SetErrorHandler(
    ErrorHandler handler
);

// Telemetry
SOVEREIGN_API void SovereignKernel_LogEvent(
    LogLevel level,
    const char* message
);
```

### Data Structures

```c
typedef struct KernelConfig {
    uint32_t version;
    uint32_t flags;
    const char* configPath;
    size_t heapSize;
    size_t stackSize;
} KernelConfig;

typedef struct SubsystemInfo {
    uint32_t batchId;
    const char* name;
    InitFunction init;
    ShutdownFunction shutdown;
    uint32_t dependencies[8];
} SubsystemInfo;

typedef enum KernelResult {
    KERNEL_SUCCESS = 0,
    KERNEL_ERROR_INVALID_CONFIG = 1,
    KERNEL_ERROR_MEMORY_INIT = 2,
    KERNEL_ERROR_SUBSYSTEM_REG = 3,
    KERNEL_ERROR_ALREADY_INIT = 4
} KernelResult;
```

---

## SEG Nodes

### Node Catalog

| Node ID | Name | Type | Description |
|---------|------|------|-------------|
| 0x0001 | `SEGNode_InitKernel` | Initialization | Initializes the core kernel |

### Node Details

#### SEGNode_InitKernel

```cpp
class SEGNode_InitKernel : public SEGNode {
public:
    NodeResult Execute(const ExecutionContext& ctx) override {
        // Initialize kernel
        KernelConfig config = ctx.GetConfig();
        
        // Setup memory
        auto memResult = InitializeMemory(config);
        if (!memResult.success) {
            return NodeResult::Error(memResult.error);
        }
        
        // Create subsystem registry
        auto regResult = CreateSubsystemRegistry();
        if (!regResult.success) {
            return NodeResult::Error(regResult.error);
        }
        
        // Initialize telemetry
        Telemetry::Initialize();
        
        return NodeResult::Success();
    }
};
```

---

## MoE Experts

Batch 01 has no MoE experts as it is a deterministic bootstrap layer.

---

## IDE Panels

### Kernel Status Panel

**Panel ID:** `panel.kernel.status`  
**Location:** Bottom status bar

**Displays:**
- Kernel initialization status
- Memory usage
- Subsystem count
- Uptime

**Implementation:**
```cpp
class KernelStatusPanel : public StatusBarPanel {
public:
    void Update() override {
        SetText("Kernel: OK | Memory: {} MB | Subsystems: {}",
            GetMemoryUsageMB(),
            GetSubsystemCount()
        );
    }
};
```

---

## Implementation Details

### MASM Entry Point

```asm
; RawrXD_Main.asm
; Entry point for Sovereign IDE

EXTERNDEF mainCRTStartup:PROC
EXTERNDEF g_kernel_initialized:QWORD

.CODE

mainCRTStartup PROC FRAME
    ; Save non-volatile registers
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    push rsi
    .pushreg rsi
    
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Initialize static data
    call InitializeStaticData
    
    ; Setup heap
    call InitializeHeap
    
    ; Call C entry point
    call mainCRTStartup
    
    ; Cleanup
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    
    ret
mainCRTStartup ENDP

END
```

### Memory Layout

```
0x0000000000000000 - 0x00007FFFFFFFFFFF  User space
├─ 0x0000000000400000  Code segment
├─ 0x0000000000600000  Data segment
├─ 0x0000000000800000  BSS segment
├─ 0x0000000000A00000  Heap (grows up)
│
│  ... (heap grows) ...
│
├─ 0x00007FFFFFFE0000  Stack (grows down)
└─ 0x00007FFFFFFFFFFF  Stack top
```

---

## Testing

### Unit Tests

```cpp
TEST(CoreKernel, InitializeWithValidConfig) {
    KernelConfig config = {
        .version = 1,
        .flags = 0,
        .configPath = "test_config.json",
        .heapSize = 1024 * 1024 * 1024,  // 1 GB
        .stackSize = 8 * 1024 * 1024     // 8 MB
    };
    
    auto result = SovereignKernel_Init(&config);
    EXPECT_EQ(result, KERNEL_SUCCESS);
    
    // Cleanup
    SovereignKernel_Shutdown();
}

TEST(CoreKernel, DoubleInitFails) {
    KernelConfig config = {};
    
    auto result1 = SovereignKernel_Init(&config);
    EXPECT_EQ(result1, KERNEL_SUCCESS);
    
    auto result2 = SovereignKernel_Init(&config);
    EXPECT_EQ(result2, KERNEL_ERROR_ALREADY_INIT);
    
    SovereignKernel_Shutdown();
}
```

### Integration Tests

```cpp
TEST(CoreKernelIntegration, FullBootstrap) {
    // Test complete bootstrap sequence
    auto result = BootstrapSovereign({});
    EXPECT_TRUE(result.success);
    
    // Verify all subsystems registered
    auto registry = GetSubsystemRegistry();
    EXPECT_GT(registry.GetCount(), 0);
    
    // Verify memory initialized
    EXPECT_GT(GetHeapSize(), 0);
}
```

---

## References

### Internal Documentation

- [SovereignKernel_Manual.md](../core/SovereignKernel_Manual.md)
- [SovereignABI_Reference.md](../core/SovereignABI_Reference.md)
- [SEG_Node_Catalog.md](../seg/SEG_Node_Catalog.md)

### External References

- x64 System V ABI
- Windows x64 Calling Convention
- Intel 64 and IA-32 Architectures Software Developer's Manual

---

## Summary

Batch 01 - Core Kernel provides:

- ✅ **MASM entry point** with proper stack frame
- ✅ **Memory initialization** (stack, heap, static data)
- ✅ **Subsystem registry** creation
- ✅ **Error handling bootstrap**
- ✅ **Telemetry initialization**
- ✅ **Configuration loading**

**Status:** ✅ Complete

---

*End of Batch 01 Documentation*
