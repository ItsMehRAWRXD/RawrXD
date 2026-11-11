# Sovereign ABI Reference
## Application Binary Interface Documentation

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Complete  

---

## Table of Contents

1. [Overview](#overview)
2. [Calling Conventions](#calling-conventions)
3. [Data Types](#data-types)
4. [Function Signatures](#function-signatures)
5. [Error Codes](#error-codes)
6. [Struct Layouts](#struct-layouts)
7. [Cross-Subsystem ABI](#cross-subsystem-abi)
8. [ABI Stability](#abi-stability)

---

## Overview

The **Sovereign ABI** defines the binary interface between:

- **MASM Kernel** ↔ **C ABI Layer**
- **C ABI Layer** ↔ **C++ Backend**
- **Backend** ↔ **SEG Engine**
- **SEG** ↔ **MoE Experts**
- **All Subsystems** ↔ **Each Other**

### Design Principles

1. **C Compatibility** — Plain C, no C++ features
2. **Fixed Layouts** — `#pragma pack(push, 8)` for consistent alignment
3. **Explicit Sizes** — `uint32_t`, `uint64_t` instead of `int`, `long`
4. **No Exceptions** — Error codes only
5. **No STL** — Pure C structs and arrays

---

## Calling Conventions

### x64 System V AMD64 ABI

**Parameter Passing:**

| Register | Purpose |
|----------|---------|
| RCX | 1st integer/pointer argument |
| RDX | 2nd integer/pointer argument |
| R8 | 3rd integer/pointer argument |
| R9 | 4th integer/pointer argument |
| XMM0-XMM3 | Floating-point arguments |
| RAX | Return value |
| RDX | Upper 64 bits of 128-bit return |

**Stack:**
- 16-byte aligned before CALL
- Shadow space (32 bytes) reserved by caller
- Stack cleaned by caller

**Preserved Registers:**
- RBX, RBP, RDI, RSI, RSP, R12-R15

**Volatile Registers:**
- RAX, RCX, RDX, R8-R11, XMM0-XMM15

### Example

```c
// C declaration
bool MoE_Generate(MoEGenerateInput* input, MoEGenerateOutput* output);

// Assembly equivalent
; RCX = input pointer
; RDX = output pointer
; Returns: RAX = success (1) or failure (0)
```

---

## Data Types

### Primitive Types

| Type | Size | Alignment | Usage |
|------|------|-----------|-------|
| `bool` | 1 byte | 1 byte | Boolean values |
| `uint8_t` | 1 byte | 1 byte | Bytes, small enums |
| `uint16_t` | 2 bytes | 2 bytes | Small integers |
| `uint32_t` | 4 bytes | 4 bytes | Standard integers |
| `uint64_t` | 8 bytes | 8 bytes | Large integers, pointers |
| `float` | 4 bytes | 4 bytes | Single precision |
| `double` | 8 bytes | 8 bytes | Double precision |

### String Types

```c
// Fixed-size strings
char name[128];      // Names, identifiers
char path[MAX_PATH]; // File paths
char description[512]; // Descriptions

// Dynamic strings (length-prefixed)
struct DynamicString {
    uint32_t length;
    char data[];  // Flexible array member
};
```

### Array Types

```c
// Fixed arrays
uint32_t items[256];

// Dynamic arrays
struct Array {
    uint32_t count;
    uint32_t capacity;
    void* data;
};
```

---

## Function Signatures

### Core Kernel Functions

```c
// Initialization
bool SovereignKernel_Init(void);
void SovereignKernel_Shutdown(void);

// Subsystem Management
bool SovereignKernel_LoadSubsystem(uint32_t subsystemId);
bool SovereignKernel_UnloadSubsystem(uint32_t subsystemId);
bool SovereignKernel_IsSubsystemLoaded(uint32_t subsystemId);

// Configuration
bool SovereignKernel_SetConfig(const SovereignConfig* config);
bool SovereignKernel_GetConfig(SovereignConfig* outConfig);
```

### SEG Functions

```c
// Initialization
bool SEG_Init(void);
void SEG_Shutdown(void);

// Node Management
bool SEG_RegisterNode(const SEGNodeDescriptor* descriptor);
bool SEG_UnregisterNode(uint32_t nodeId);
bool SEG_GetNode(uint32_t nodeId, SEGNodeDescriptor* outDescriptor);

// Execution
bool SEG_ExecuteNode(uint32_t nodeId, void* input, void* output);
bool SEG_ExecuteGraph(const SEGGraph* graph, void* context);

// Query
uint32_t SEG_GetNodeCount(void);
bool SEG_GetNodes(SEGNodeDescriptor* outNodes, uint32_t* inOutCount);
```

### MoE Functions

```c
// Initialization
bool MoE_Init(void);
void MoE_Shutdown(void);

// Expert Management
bool MoE_RegisterExpert(const MoEExpertDescriptor* descriptor);
bool MoE_UnregisterExpert(uint32_t expertId);
bool MoE_GetExpert(uint32_t expertId, MoEExpertDescriptor* outDescriptor);

// Routing
bool MoE_Route(const MoEGenerateInput* input, MoEGenerateOutput* output);
bool MoE_RouteToExpert(uint32_t expertId, const MoEGenerateInput* input, MoEGenerateOutput* output);

// Query
uint32_t MoE_GetExpertCount(void);
bool MoE_GetExperts(MoEExpertDescriptor* outExperts, uint32_t* inOutCount);
```

### Subsystem Functions

```c
// Standard Subsystem Interface
typedef bool (*SubsystemInitFunc)(void);
typedef void (*SubsystemShutdownFunc)(void);
typedef bool (*SubsystemIsHealthyFunc)(void);
typedef void (*SubsystemGetStatusFunc)(char* outStatus, uint32_t bufferSize);

struct SubsystemVTable {
    SubsystemInitFunc Init;
    SubsystemShutdownFunc Shutdown;
    SubsystemIsHealthyFunc IsHealthy;
    SubsystemGetStatusFunc GetStatus;
};
```

---

## Error Codes

### Core Error Codes

```c
typedef enum {
    // Success
    SOVEREIGN_OK = 0,
    
    // General Errors (1-99)
    SOVEREIGN_ERROR_UNKNOWN = 1,
    SOVEREIGN_ERROR_INVALID_PARAMETER = 2,
    SOVEREIGN_ERROR_OUT_OF_MEMORY = 3,
    SOVEREIGN_ERROR_NOT_INITIALIZED = 4,
    SOVEREIGN_ERROR_ALREADY_INITIALIZED = 5,
    SOVEREIGN_ERROR_NOT_IMPLEMENTED = 6,
    SOVEREIGN_ERROR_ACCESS_DENIED = 7,
    SOVEREIGN_ERROR_TIMEOUT = 8,
    SOVEREIGN_ERROR_CANCELLED = 9,
    
    // Subsystem Errors (100-199)
    SOVEREIGN_ERROR_SUBSYSTEM_NOT_FOUND = 100,
    SOVEREIGN_ERROR_SUBSYSTEM_LOAD_FAILED = 101,
    SOVEREIGN_ERROR_SUBSYSTEM_INIT_FAILED = 102,
    SOVEREIGN_ERROR_SUBSYSTEM_DEPENDENCY_MISSING = 103,
    SOVEREIGN_ERROR_SUBSYSTEM_CIRCULAR_DEPENDENCY = 104,
    
    // SEG Errors (200-299)
    SOVEREIGN_ERROR_SEG_NODE_NOT_FOUND = 200,
    SOVEREIGN_ERROR_SEG_NODE_ALREADY_EXISTS = 201,
    SOVEREIGN_ERROR_SEG_EXECUTION_FAILED = 202,
    SOVEREIGN_ERROR_SEG_INVALID_GRAPH = 203,
    SOVEREIGN_ERROR_SEG_CYCLE_DETECTED = 204,
    
    // MoE Errors (300-399)
    SOVEREIGN_ERROR_MOE_EXPERT_NOT_FOUND = 300,
    SOVEREIGN_ERROR_MOE_EXPERT_ALREADY_EXISTS = 301,
    SOVEREIGN_ERROR_MOE_ROUTING_FAILED = 302,
    SOVEREIGN_ERROR_MOE_INVALID_INPUT = 303,
    SOVEREIGN_ERROR_MOE_GENERATION_FAILED = 304,
    
    // ABI Errors (400-499)
    SOVEREIGN_ERROR_ABI_MISMATCH = 400,
    SOVEREIGN_ERROR_ABI_VERSION_INCOMPATIBLE = 401,
    SOVEREIGN_ERROR_ABI_STRUCT_ALIGNMENT = 402,
    SOVEREIGN_ERROR_ABI_CALLING_CONVENTION = 403,
    
    // Integration Errors (500-599)
    SOVEREIGN_ERROR_INTEGRATION_PHASE_FAILED = 500,
    SOVEREIGN_ERROR_INTEGRATION_ABI_VERIFY_FAILED = 501,
    SOVEREIGN_ERROR_INTEGRATION_SEG_LINK_FAILED = 502,
    SOVEREIGN_ERROR_INTEGRATION_MOE_REGISTER_FAILED = 503,
    SOVEREIGN_ERROR_INTEGRATION_SUBSYSTEM_BIND_FAILED = 504
} SovereignError;
```

### Error Handling Pattern

```c
SovereignError result = SomeFunction();
if (result != SOVEREIGN_OK) {
    // Handle error
    char errorMsg[256];
    Sovereign_GetErrorString(result, errorMsg, sizeof(errorMsg));
    LogError("Function failed: %s", errorMsg);
    return result;
}
```

---

## Struct Layouts

### MoEExpertInfo

```c
#pragma pack(push, 8)
typedef struct {
    uint32_t expertId;              // Offset 0, Size 4
    char name[128];                 // Offset 4, Size 128
    char description[256];        // Offset 132, Size 256
    uint32_t capabilityFlags;       // Offset 388, Size 4
    float confidenceThreshold;      // Offset 392, Size 4
    uint32_t executionCount;        // Offset 396, Size 4
    uint64_t totalLatencyUs;        // Offset 400, Size 8
    bool isActive;                  // Offset 408, Size 1
    uint8_t padding[7];             // Offset 409, Size 7 (alignment)
} MoEExpertInfo;                    // Total: 416 bytes
#pragma pack(pop)

static_assert(sizeof(MoEExpertInfo) == 416, "MoEExpertInfo size mismatch");
static_assert(offsetof(MoEExpertInfo, expertId) == 0, "expertId offset mismatch");
static_assert(offsetof(MoEExpertInfo, name) == 4, "name offset mismatch");
```

### MoETraceEntry

```c
#pragma pack(push, 8)
typedef struct {
    uint64_t timestamp;             // Offset 0, Size 8
    uint32_t expertId;              // Offset 8, Size 4
    uint32_t tokenId;               // Offset 12, Size 4
    float confidence;               // Offset 16, Size 4
    float kvDensity;                // Offset 20, Size 4
    uint32_t latencyUs;             // Offset 24, Size 4
    uint8_t padding[4];             // Offset 28, Size 4
} MoETraceEntry;                    // Total: 32 bytes
#pragma pack(pop)
```

### MoEGenerateInput

```c
#pragma pack(push, 8)
typedef struct {
    const char* prompt;             // Offset 0, Size 8
    uint32_t promptLength;          // Offset 8, Size 4
    uint32_t maxTokens;             // Offset 12, Size 4
    float temperature;              // Offset 16, Size 4
    float topP;                     // Offset 20, Size 4
    uint32_t seed;                  // Offset 24, Size 4
    uint8_t padding[4];             // Offset 28, Size 4
} MoEGenerateInput;                 // Total: 32 bytes
#pragma pack(pop)
```

### SEGNodeDescriptor

```c
#pragma pack(push, 8)
typedef struct {
    uint32_t nodeId;                // Offset 0, Size 4
    char name[128];                 // Offset 4, Size 128
    uint32_t nodeType;              // Offset 132, Size 4
    uint32_t inputCount;            // Offset 136, Size 4
    uint32_t outputCount;           // Offset 140, Size 4
    uint32_t dependencies[8];       // Offset 144, Size 32
    uint32_t dependencyCount;       // Offset 176, Size 4
    uint8_t padding[4];             // Offset 180, Size 4
    void* executeFunc;              // Offset 184, Size 8
} SEGNodeDescriptor;                // Total: 192 bytes
#pragma pack(pop)
```

---

## Cross-Subsystem ABI

### Binary Analysis → Malware Analysis

```c
// Binary Analysis exports
bool Binary_LoadPE(const char* path, PEImage* outImage);
bool Binary_GetSection(const PEImage* image, uint32_t index, PESection* outSection);
bool Binary_BuildCFG(const PEImage* image, CFG* outCFG);

// Malware Analysis uses
bool Malware_Analyze(const PEImage* image, MalwareReport* outReport);
```

### Debugger → Exploit Development

```c
// Debugger exports
bool Debug_Attach(uint32_t processId);
bool Debug_SetBreakpoint(uint64_t address);
bool Debug_GetRegisters(RegisterState* outState);

// Exploit Development uses
bool ExploitDev_TestExploit(const Exploit* exploit, DebugProcess* process);
```

### Network Protocol → Exploit Development

```c
// Network Protocol exports
bool NetProto_CapturePacket(Packet* outPacket);
bool NetProto_AnalyzeProtocol(const Packet* packet, ProtocolAnalysis* outAnalysis);
bool NetProto_FuzzSequence(const Packet* template, FuzzResult* outResult);

// Exploit Development uses
bool ExploitDev_GenerateNetworkExploit(const ProtocolAnalysis* analysis, Exploit* outExploit);
```

---

## ABI Stability

### Versioning

```c
#define SOVEREIGN_ABI_VERSION_MAJOR 1
#define SOVEREIGN_ABI_VERSION_MINOR 0
#define SOVEREIGN_ABI_VERSION_PATCH 0

#define SOVEREIGN_ABI_VERSION ((SOVEREIGN_ABI_VERSION_MAJOR << 16) | \
                               (SOVEREIGN_ABI_VERSION_MINOR << 8)  | \
                               SOVEREIGN_ABI_VERSION_PATCH)
```

### Compatibility Rules

1. **Major Version** — Breaking changes (struct layout, function signatures)
2. **Minor Version** — Additive changes (new functions, new struct fields at end)
3. **Patch Version** — Bug fixes only

### Version Checking

```c
bool Sovereign_ABI_CheckVersion(uint32_t requiredVersion) {
    uint32_t currentVersion = SOVEREIGN_ABI_VERSION;
    
    // Major version must match
    if ((currentVersion & 0xFF0000) != (requiredVersion & 0xFF0000)) {
        return false;
    }
    
    // Current minor must be >= required minor
    if ((currentVersion & 0x00FF00) < (requiredVersion & 0x00FF00)) {
        return false;
    }
    
    return true;
}
```

---

## Summary

The Sovereign ABI provides:

- ✅ **C-compatible interface**
- ✅ **Fixed struct layouts**
- ✅ **Explicit type sizes**
- ✅ **x64 calling conventions**
- ✅ **Comprehensive error codes**
- ✅ **Version stability guarantees**

**Status:** ✅ Stable

---

*End of Sovereign ABI Reference*
