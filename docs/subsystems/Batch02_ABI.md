# Batch 02 - ABI Layer
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

The ABI Layer defines the Sovereign ABI surfaces for cross-language compatibility and subsystem interaction. It provides the stable interface between the MASM kernel and higher-level C/C++ components.

### Key Characteristics

| Attribute | Value |
|-----------|-------|
| **Language** | C |
| **Lines of Code** | ~2,500 |
| **Functions** | 150+ |
| **Data Structures** | 80+ |
| **SEG Nodes** | 1 |
| **MoE Experts** | 0 |

---

## Responsibilities

### Core Functions

1. **Calling Convention Enforcement**
   - x64 System V ABI (Linux/macOS)
   - Windows x64 calling convention
   - Register preservation rules

2. **Data Type Definitions**
   - Fixed-width integer types
   - Floating-point types
   - Structure layouts
   - Alignment requirements

3. **Error Code Standardization**
   - Universal error codes
   - Subsystem-specific error ranges
   - Error propagation rules

4. **ABI Compatibility Validation**
   - Version checking
   - Structure size validation
   - Function signature verification

---

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────┐
│              ABI Layer                       │
├─────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────────┐   │
│  │   Core ABI   │  │   SEG ABI        │   │
│  │              │  │                  │   │
│  │  - Init      │  │  - Node Mgmt     │   │
│  │  - Memory    │  │  - Execution     │   │
│  │  - Error     │  │  - Graph Ops     │   │
│  └──────────────┘  └──────────────────┘   │
│  ┌──────────────┐  ┌──────────────────┐   │
│  │   MoE ABI    │  │   SDK ABI        │   │
│  │              │  │                  │   │
│  │  - Routing   │  │  - Capabilities  │   │
│  │  - Experts   │  │  - Extensions    │   │
│  │  - Scoring   │  │  - Panels        │   │
│  └──────────────┘  └──────────────────┘   │
└─────────────────────────────────────────────┘
```

### ABI Layers

```
┌─────────────────────────────────────────┐
│           SDK Layer                     │
│    (C++ wrapper, language bindings)    │
├─────────────────────────────────────────┤
│           ABI Layer (Batch 02)          │
│    (C ABI - stable interface)           │
├─────────────────────────────────────────┤
│           Kernel Layer (Batch 01)       │
│    (MASM + C runtime)                   │
└─────────────────────────────────────────┘
```

---

## ABI Surfaces

### Core ABI

```c
// Initialization
SOVEREIGN_API ABIResult ABI_Initialize(uint32_t version);
SOVEREIGN_API void ABI_Shutdown(void);

// Version
SOVEREIGN_API uint32_t ABI_GetVersion(void);
SOVEREIGN_API const char* ABI_GetVersionString(void);

// Memory
SOVEREIGN_API void* ABI_Allocate(size_t size);
SOVEREIGN_API void* ABI_AllocateAligned(size_t size, size_t alignment);
SOVEREIGN_API void ABI_Free(void* ptr);
SOVEREIGN_API void ABI_FreeAligned(void* ptr);

// Error Handling
SOVEREIGN_API void ABI_SetLastError(ABIError error);
SOVEREIGN_API ABIError ABI_GetLastError(void);
SOVEREIGN_API const char* ABI_GetErrorString(ABIError error);
```

### SEG ABI

```c
// Node Management
SOVEREIGN_API SEGHandle SEG_CreateNode(
    const char* type,
    const SEGConfig* config
);

SOVEREIGN_API void SEG_DestroyNode(SEGHandle node);

SOVEREIGN_API SEGResult SEG_RegisterNodeType(
    const char* type,
    SEGNodeFactory factory
);

// Execution
SOVEREIGN_API SEGResult SEG_ExecuteNode(
    SEGHandle node,
    const SEGContext* context,
    SEGResult* result
);

SOVEREIGN_API SEGResult SEG_ConnectNodes(
    SEGHandle source,
    SEGHandle target,
    uint32_t edgeType
);

// Graph Operations
SOVEREIGN_API SEGHandle SEG_CreateGraph(void);
SOVEREIGN_API void SEG_DestroyGraph(SEGHandle graph);
SOVEREIGN_API SEGResult SEG_ExecuteGraph(
    SEGHandle graph,
    const SEGContext* context
);
```

### MoE ABI

```c
// Expert Management
SOVEREIGN_API MoEResult MoE_RegisterExpert(
    const char* name,
    const char* domain,
    MoEExpertFunctions* functions
);

SOVEREIGN_API MoEResult MoE_UnregisterExpert(const char* name);

// Routing
SOVEREIGN_API MoEResult MoE_Route(
    const MoEInput* input,
    MoEOutput* output
);

SOVEREIGN_API float MoE_CalculateConfidence(
    const char* expertName,
    const MoEInput* input
);
```

### SDK ABI

```c
// Capability Discovery
SOVEREIGN_API SDKResult SDK_DiscoverCapabilities(
    const char* query,
    SDKCapabilityInfo* capabilities,
    uint32_t* count
);

// Capability Invocation
SOVEREIGN_API SDKResult SDK_InvokeCapability(
    const char* name,
    const SDKParameter* params,
    uint32_t paramCount,
    SDKResult* result
);

// Extension Management
SOVEREIGN_API SDKResult SDK_RegisterExtension(
    const char* name,
    const SDKExtensionFunctions* functions
);

SOVEREIGN_API SDKResult SDK_UnregisterExtension(const char* name);
```

---

## SEG Nodes

### Node Catalog

| Node ID | Name | Type | Description |
|---------|------|------|-------------|
| 0x0002 | `SEGNode_ABIValidate` | Validation | Validates ABI compatibility |

### Node Details

#### SEGNode_ABIValidate

```cpp
class SEGNode_ABIValidate : public SEGNode {
public:
    NodeResult Execute(const ExecutionContext& ctx) override {
        // Check ABI version
        uint32_t expectedVersion = ctx.GetExpectedABIVersion();
        uint32_t actualVersion = ABI_GetVersion();
        
        if (actualVersion != expectedVersion) {
            return NodeResult::Error(
                ABI_ERROR_VERSION_MISMATCH,
                "ABI version mismatch: expected {}, got {}",
                expectedVersion, actualVersion
            );
        }
        
        // Validate structure sizes
        auto result = ValidateStructureSizes();
        if (!result.success) {
            return NodeResult::Error(result.error);
        }
        
        // Validate function pointers
        result = ValidateFunctionTable();
        if (!result.success) {
            return NodeResult::Error(result.error);
        }
        
        return NodeResult::Success();
    }
    
private:
    ValidationResult ValidateStructureSizes() {
        // Check critical structure sizes
        static_assert(sizeof(SEGConfig) == EXPECTED_SEG_CONFIG_SIZE);
        static_assert(sizeof(MoEInput) == EXPECTED_MOE_INPUT_SIZE);
        static_assert(sizeof(SDKParameter) == EXPECTED_SDK_PARAM_SIZE);
        
        return ValidationResult::Success();
    }
    
    ValidationResult ValidateFunctionTable() {
        // Verify all ABI functions are present
        if (!ABI_GetVersion || !ABI_Allocate || !ABI_Free) {
            return ValidationResult::Error("Missing core ABI functions");
        }
        
        return ValidationResult::Success();
    }
};
```

---

## MoE Experts

Batch 02 has no MoE experts as it is a foundational layer.

---

## IDE Panels

### ABI Validation Panel

**Panel ID:** `panel.abi.validation`  
**Location:** Debug → ABI Status

**Displays:**
- ABI version
- Structure validation status
- Function table status
- Compatibility warnings

---

## Implementation Details

### Calling Conventions

#### Windows x64

```asm
; Integer/pointer args: RCX, RDX, R8, R9
; Floating-point args: XMM0-XMM3
; Return value: RAX/XMM0
; Stack alignment: 16 bytes

; Example function
MyFunction PROC
    ; Prologue
    push rbp
    mov rbp, rsp
    sub rsp, 32     ; Shadow space
    
    ; Function body
    mov rax, rcx    ; First argument
    add rax, rdx    ; Second argument
    
    ; Epilogue
    mov rsp, rbp
    pop rbp
    ret
MyFunction ENDP
```

#### System V AMD64 ABI

```asm
; Integer/pointer args: RDI, RSI, RDX, RCX, R8, R9
; Floating-point args: XMM0-XMM7
; Return value: RAX/XMM0
; Stack alignment: 16 bytes
```

### Data Structure Layout

```c
// Example: SEGConfig
// Size: 64 bytes
// Alignment: 8 bytes

typedef struct SEGConfig {
    uint32_t version;           // Offset: 0, Size: 4
    uint32_t flags;             // Offset: 4, Size: 4
    uint64_t maxNodes;          // Offset: 8, Size: 8
    uint64_t maxEdges;          // Offset: 16, Size: 8
    void* userData;             // Offset: 24, Size: 8
    char reserved[32];            // Offset: 32, Size: 32
} SEGConfig;                     // Total: 64 bytes

// Static assertions for ABI stability
static_assert(sizeof(SEGConfig) == 64, "SEGConfig size changed");
static_assert(offsetof(SEGConfig, version) == 0, "version offset changed");
static_assert(offsetof(SEGConfig, maxNodes) == 8, "maxNodes offset changed");
```

---

## Testing

### ABI Compatibility Tests

```cpp
TEST(ABILayer, VersionCompatibility) {
    // Initialize ABI
    auto result = ABI_Initialize(SOVEREIGN_ABI_VERSION);
    EXPECT_EQ(result, ABI_SUCCESS);
    
    // Verify version
    EXPECT_EQ(ABI_GetVersion(), SOVEREIGN_ABI_VERSION);
    
    // Cleanup
    ABI_Shutdown();
}

TEST(ABILayer, StructureSizes) {
    // Verify critical structure sizes
    EXPECT_EQ(sizeof(SEGConfig), 64);
    EXPECT_EQ(sizeof(MoEInput), 128);
    EXPECT_EQ(sizeof(SDKParameter), 256);
}

TEST(ABILayer, MemoryAllocation) {
    // Test allocation
    void* ptr = ABI_Allocate(1024);
    EXPECT_NE(ptr, nullptr);
    
    // Test aligned allocation
    void* aligned = ABI_AllocateAligned(1024, 64);
    EXPECT_NE(aligned, nullptr);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(aligned) % 64, 0);
    
    // Cleanup
    ABI_Free(ptr);
    ABI_FreeAligned(aligned);
}
```

### Cross-Language Tests

```cpp
TEST(ABILayer, CppToCInterop) {
    // C++ code calling C ABI
    struct CppObject {
        int value;
    };
    
    CppObject obj{42};
    
    // Pass through ABI
    auto result = ABI_PassObject(&obj, sizeof(obj));
    EXPECT_EQ(result.code, ABI_SUCCESS);
}
```

---

## References

### Internal Documentation

- [SovereignABI_Reference.md](../core/SovereignABI_Reference.md)
- [Batch01_CoreKernel.md](Batch01_CoreKernel.md)
- [SEG_Node_Catalog.md](../seg/SEG_Node_Catalog.md)

### External References

- System V Application Binary Interface AMD64 Architecture Processor Supplement
- Microsoft x64 Calling Convention
- Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2

---

## Summary

Batch 02 - ABI Layer provides:

- ✅ **Stable C ABI** for all subsystems
- ✅ **Cross-platform calling conventions**
- ✅ **Standardized data types and structures**
- ✅ **Error code standardization**
- ✅ **ABI compatibility validation**
- ✅ **Foundation for SDK and language bindings**

**Status:** ✅ Complete

---

*End of Batch 02 Documentation*
