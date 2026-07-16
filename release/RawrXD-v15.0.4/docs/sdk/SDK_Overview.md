# Sovereign IDE SDK - Overview
## Complete API Reference for Developers

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Complete

---

## Table of Contents

1. [Introduction](#introduction)
2. [SDK Architecture](#sdk-architecture)
3. [Getting Started](#getting-started)
4. [SDK Modules](#sdk-modules)
5. [Common Patterns](#common-patterns)
6. [Error Handling](#error-handling)
7. [Version Compatibility](#version-compatibility)

---

## Introduction

The **Sovereign IDE SDK** provides a comprehensive set of APIs for extending and integrating with the Sovereign IDE platform. With 49 batches of functionality exposed through unified interfaces, developers can build powerful extensions, automation scripts, and custom tools.

### Key Features

- **487+ Capabilities** across 49 batches
- **Multi-language Support** (C, C++, MASM bindings)
- **Unified Interface** consistent API patterns
- **Async/Sync Execution** flexible execution models
- **Memory Safe** bounds-checked APIs
- **Well Documented** comprehensive reference

### SDK Coverage

| Category | Batches | Capabilities |
|----------|---------|--------------|
| Core IDE | 1-10 | 89 |
| AI/Agents | 11-20 | 76 |
| Binary Analysis | 21-30 | 98 |
| Advanced Analysis | 31-40 | 112 |
| Agentic Expansion | 41-49 | 112 |
| **Total** | **49** | **487** |

---

## SDK Architecture

### Layered Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                         │
│         Your extensions, scripts, and tools                │
├─────────────────────────────────────────────────────────────┤
│                      SDK LAYER                               │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ Core API │ │  AI API  │ │ Binary   │ │ Agentic  │       │
│  │          │ │          │ │  API     │ │  API     │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
├─────────────────────────────────────────────────────────────┤
│                   ABSTRACTION LAYER                          │
│         Capability Registry • Action Router                │
│         Memory Management • Error Handling                 │
├─────────────────────────────────────────────────────────────┤
│                   SOVEREIGN IDE CORE                       │
│         49 Batches • 256 SEG Nodes • 128 MoE Experts       │
└─────────────────────────────────────────────────────────────┘
```

### API Organization

```
sdk/
├── core/           # Core IDE APIs (Batches 1-10)
│   ├── editor.h    # Text editor operations
│   ├── workspace.h # Workspace management
│   ├── debugger.h  # Debugging APIs
│   ├── git.h       # Version control
│   └── build.h     # Build system
├── ai/             # AI/Agent APIs (Batches 11-20)
│   ├── inference.h # Model inference
│   ├── router.h    # Model routing
│   ├── chat.h      # Chat system
│   └── agents.h    # Agent management
├── binary/         # Binary Analysis APIs (Batches 21-30)
│   ├── analysis.h  # Binary analysis
│   ├── disasm.h    # Disassembly
│   ├── decomp.h    # Decompilation
│   └── fuzz.h      # Fuzzing
├── advanced/       # Advanced Analysis APIs (Batches 31-40)
│   ├── malware.h   # Malware analysis
│   ├── protocol.h  # Protocol analysis
│   ├── exploit.h   # Exploit development
│   └── crypto.h    # Cryptographic analysis
└── agentic/        # Agentic Expansion APIs (Batches 41-49)
    ├── exploit.h   # Exploit generation
    ├── threat.h    # Threat intelligence
    ├── rewrite.h   # Binary rewriting
    ├── vm.h        # Hypervisor analysis
    ├── kernel.h    # Kernel exploitation
    ├── refactor.h  # Code refactoring
    └── optimize.h  # Runtime optimization
```

---

## Getting Started

### Installation

```cpp
// Include the main SDK header
#include <sovereign/sdk.h>

// Link against the SDK library
// Windows: sovereign_sdk.lib
// Linux: libsovereign_sdk.so
// macOS: libsovereign_sdk.dylib
```

### Initialization

```cpp
#include <sovereign/sdk.h>

int main() {
    // Initialize SDK
    SDKConfig config = {
        .version = SDK_VERSION_1_0,
        .logLevel = LOG_LEVEL_INFO,
        .enableAsync = true,
        .maxConcurrentTasks = 16
    };
    
    SDKHandle sdk;
    SDKResult result = SDK_Initialize(&config, &sdk);
    
    if (result != SDK_SUCCESS) {
        printf("Failed to initialize SDK: %s\n", 
               SDK_GetErrorString(result));
        return 1;
    }
    
    // Use SDK...
    
    // Cleanup
    SDK_Shutdown(sdk);
    
    return 0;
}
```

### First Program

```cpp
#include <sovereign/sdk.h>

int main() {
    SDKHandle sdk;
    SDK_Initialize(NULL, &sdk);
    
    // Get SDK version
    char version[32];
    SDK_GetVersion(sdk, version, sizeof(version));
    printf("Sovereign SDK Version: %s\n", version);
    
    // Discover capabilities
    CapabilityInfo caps[100];
    uint32_t count;
    SDK_DiscoverCapabilities(sdk, "decompile", caps, &count);
    
    printf("Found %u decompilation capabilities:\n", count);
    for (uint32_t i = 0; i < count; i++) {
        printf("  - %s\n", caps[i].name);
    }
    
    SDK_Shutdown(sdk);
    return 0;
}
```

---

## SDK Modules

### Core Module (Batches 1-10)

```cpp
// Editor operations
SDKResult SDK_Editor_OpenFile(SDKHandle sdk, const char* path);
SDKResult SDK_Editor_GetText(SDKHandle sdk, char* buffer, uint32_t* size);
SDKResult SDK_Editor_SetText(SDKHandle sdk, const char* text);
SDKResult SDK_Editor_InsertText(SDKHandle sdk, uint32_t position, const char* text);
SDKResult SDK_Editor_DeleteText(SDKHandle sdk, uint32_t start, uint32_t end);

// Workspace management
SDKResult SDK_Workspace_Open(SDKHandle sdk, const char* path);
SDKResult SDK_Workspace_GetFiles(SDKHandle sdk, char** files, uint32_t* count);
SDKResult SDK_Workspace_Save(SDKHandle sdk);

// Build system
SDKResult SDK_Build_Configure(SDKHandle sdk, const BuildConfig* config);
SDKResult SDK_Build_Start(SDKHandle sdk, const char* target);
SDKResult SDK_Build_GetStatus(SDKHandle sdk, BuildStatus* status);
```

### AI Module (Batches 11-20)

```cpp
// Model inference
SDKResult SDK_AI_LoadModel(SDKHandle sdk, const char* modelPath, ModelHandle* model);
SDKResult SDK_AI_Inference(SDKHandle sdk, ModelHandle model, 
                           const InferenceInput* input, InferenceOutput* output);
SDKResult SDK_AI_UnloadModel(SDKHandle sdk, ModelHandle model);

// Chat system
SDKResult SDK_Chat_CreateSession(SDKHandle sdk, ChatSessionHandle* session);
SDKResult SDK_Chat_SendMessage(SDKHandle sdk, ChatSessionHandle session, 
                               const char* message, ChatResponse* response);
SDKResult SDK_Chat_DestroySession(SDKHandle sdk, ChatSessionHandle session);

// Agent management
SDKResult SDK_Agent_Create(SDKHandle sdk, const AgentConfig* config, AgentHandle* agent);
SDKResult SDK_Agent_ExecuteTask(SDKHandle sdk, AgentHandle agent, 
                                const char* task, TaskResult* result);
SDKResult SDK_Agent_Destroy(SDKHandle sdk, AgentHandle agent);
```

### Binary Module (Batches 21-30)

```cpp
// Binary loading
SDKResult SDK_Binary_Load(SDKHandle sdk, const char* path, BinaryHandle* binary);
SDKResult SDK_Binary_GetInfo(SDKHandle sdk, BinaryHandle binary, BinaryInfo* info);
SDKResult SDK_Binary_Unload(SDKHandle sdk, BinaryHandle binary);

// Disassembly
SDKResult SDK_Disasm_Function(SDKHandle sdk, BinaryHandle binary, 
                              uint64_t address, Disassembly* output);
SDKResult SDK_Disasm_Range(SDKHandle sdk, BinaryHandle binary,
                           uint64_t start, uint64_t end, Disassembly* output);

// Decompilation
SDKResult SDK_Decomp_Function(SDKHandle sdk, BinaryHandle binary,
                              uint64_t address, char* code, uint32_t* size);
```

### Agentic Module (Batches 41-49)

```cpp
// Exploit generation
SDKResult SDK_Exploit_Generate(SDKHandle sdk, const Vulnerability* vuln,
                               ExploitType type, Exploit* output);
SDKResult SDK_Exploit_Test(SDKHandle sdk, const Exploit* exploit, TestResult* result);

// Threat intelligence
SDKResult SDK_Threat_IngestSignal(SDKHandle sdk, const ThreatSignal* signal);
SDKResult SDK_Threat_GetPredictions(SDKHandle sdk, ThreatPrediction* predictions, 
                                    uint32_t* count);

// Binary rewriting
SDKResult SDK_Rewrite_Transform(SDKHandle sdk, BinaryHandle binary,
                                TransformationType type, BinaryHandle* output);

// Runtime optimization
SDKResult SDK_Optimize_StartProfiling(SDKHandle sdk, uint32_t processId, 
                                      ProfilerHandle* profiler);
SDKResult SDK_Optimize_GetHotspots(SDKHandle sdk, ProfilerHandle profiler,
                                   Hotspot* hotspots, uint32_t* count);
```

---

## Common Patterns

### Pattern 1: Capability Discovery and Invocation

```cpp
// Discover capabilities matching a query
CapabilityInfo caps[50];
uint32_t count;
SDK_DiscoverCapabilities(sdk, "analyze binary", caps, &count);

// Select and invoke a capability
for (uint32_t i = 0; i < count; i++) {
    if (strcmp(caps[i].name, "AnalyzeBinary") == 0) {
        // Prepare parameters
        Parameter params[] = {
            { .name = "path", .type = PARAM_STRING, .string = "target.exe" },
            { .name = "depth", .type = PARAM_INT, .integer = 3 }
        };
        
        // Invoke
        ActionResult result;
        SDK_InvokeCapability(sdk, caps[i].id, params, 2, &result);
        
        // Process result
        if (result.success) {
            ProcessResult(&result.output);
        }
        
        break;
    }
}
```

### Pattern 2: Async Execution with Callbacks

```cpp
// Define callback
void OnTaskComplete(TaskHandle task, const TaskResult* result, void* userData) {
    if (result->success) {
        printf("Task completed successfully!\n");
        ProcessResult(result);
    } else {
        printf("Task failed: %s\n", result->error);
    }
    
    // Cleanup
    SDK_ReleaseTask(task);
}

// Execute async
TaskHandle task;
SDK_ExecuteAsync(sdk, "LongRunningAnalysis", params, paramCount,
                OnTaskComplete, userData, &task);

// Continue with other work...

// Or wait for completion
SDK_WaitForTask(task, TIMEOUT_INFINITE);
```

### Pattern 3: Resource Management with RAII

```cpp
class BinaryAnalyzer {
private:
    SDKHandle sdk;
    BinaryHandle binary;
    
public:
    BinaryAnalyzer(SDKHandle sdk, const char* path) : sdk(sdk) {
        SDK_Binary_Load(sdk, path, &binary);
    }
    
    ~BinaryAnalyzer() {
        if (binary) {
            SDK_Binary_Unload(sdk, binary);
        }
    }
    
    // Disable copy
    BinaryAnalyzer(const BinaryAnalyzer&) = delete;
    BinaryAnalyzer& operator=(const BinaryAnalyzer&) = delete;
    
    // Allow move
    BinaryAnalyzer(BinaryAnalyzer&& other) 
        : sdk(other.sdk), binary(other.binary) {
        other.binary = nullptr;
    }
    
    AnalysisResult Analyze() {
        AnalysisResult result;
        SDK_Binary_Analyze(sdk, binary, &result);
        return result;
    }
};

// Usage
void AnalyzeFile(SDKHandle sdk, const char* path) {
    BinaryAnalyzer analyzer(sdk, path);  // Load
    auto result = analyzer.Analyze();     // Analyze
}  // Automatic cleanup
```

### Pattern 4: Batch Operations

```cpp
// Process multiple files
void ProcessFiles(SDKHandle sdk, const char** paths, uint32_t count) {
    // Create batch
    BatchHandle batch;
    SDK_Batch_Create(sdk, &batch);
    
    // Add operations
    for (uint32_t i = 0; i < count; i++) {
        Operation op = {
            .type = OP_ANALYZE,
            .path = paths[i]
        };
        SDK_Batch_AddOperation(batch, &op);
    }
    
    // Execute with progress callback
    SDK_Batch_Execute(batch, OnProgress, nullptr);
    
    // Get results
    BatchResult results[100];
    uint32_t resultCount;
    SDK_Batch_GetResults(batch, results, &resultCount);
    
    // Cleanup
    SDK_Batch_Destroy(batch);
}

void OnProgress(uint32_t completed, uint32_t total, void* userData) {
    printf("Progress: %u/%u\n", completed, total);
}
```

---

## Error Handling

### Error Codes

```cpp
enum SDKResult {
    // Success
    SDK_SUCCESS = 0,
    
    // General errors
    SDK_ERROR_INVALID_PARAMETER = -1,
    SDK_ERROR_OUT_OF_MEMORY = -2,
    SDK_ERROR_NOT_INITIALIZED = -3,
    SDK_ERROR_ALREADY_INITIALIZED = -4,
    
    // Capability errors
    SDK_ERROR_CAPABILITY_NOT_FOUND = -100,
    SDK_ERROR_CAPABILITY_NOT_AVAILABLE = -101,
    SDK_ERROR_INVALID_CAPABILITY_PARAMS = -102,
    
    // Execution errors
    SDK_ERROR_EXECUTION_FAILED = -200,
    SDK_ERROR_EXECUTION_TIMEOUT = -201,
    SDK_ERROR_EXECUTION_CANCELLED = -202,
    
    // Resource errors
    SDK_ERROR_RESOURCE_NOT_FOUND = -300,
    SDK_ERROR_RESOURCE_BUSY = -301,
    SDK_ERROR_RESOURCE_EXHAUSTED = -302,
    
    // System errors
    SDK_ERROR_SYSTEM_ERROR = -1000,
    SDK_ERROR_INTERNAL_ERROR = -1001
};
```

### Error Handling Patterns

```cpp
// Pattern 1: Check and return
SDKResult DoSomething(SDKHandle sdk) {
    SDKResult result = SDK_Operation1(sdk);
    if (result != SDK_SUCCESS) {
        return result;  // Propagate error
    }
    
    result = SDK_Operation2(sdk);
    if (result != SDK_SUCCESS) {
        return result;
    }
    
    return SDK_SUCCESS;
}

// Pattern 2: Check and cleanup
bool DoSomethingWithCleanup(SDKHandle sdk) {
    ResourceHandle resource;
    SDKResult result = SDK_AcquireResource(sdk, &resource);
    if (result != SDK_SUCCESS) {
        LogError("Failed to acquire resource: %s", 
                 SDK_GetErrorString(result));
        return false;
    }
    
    // Use resource...
    result = SDK_UseResource(sdk, resource);
    if (result != SDK_SUCCESS) {
        LogError("Failed to use resource");
        // Cleanup still required
    }
    
    // Always cleanup
    SDK_ReleaseResource(sdk, resource);
    
    return result == SDK_SUCCESS;
}

// Pattern 3: Exception-style (C++)
class SDKException : public std::exception {
private:
    SDKResult code;
    std::string message;
    
public:
    SDKException(SDKResult c, const char* m) : code(c), message(m) {}
    const char* what() const noexcept override { return message.c_str(); }
};

void CheckResult(SDKResult result) {
    if (result != SDK_SUCCESS) {
        throw SDKException(result, SDK_GetErrorString(result));
    }
}

// Usage
try {
    CheckResult(SDK_Operation1(sdk));
    CheckResult(SDK_Operation2(sdk));
} catch (const SDKException& e) {
    printf("SDK Error: %s\n", e.what());
}
```

---

## Version Compatibility

### Versioning Scheme

```
SDK Version: MAJOR.MINOR.PATCH

MAJOR - Breaking API changes
MINOR - New features, backward compatible
PATCH - Bug fixes, backward compatible
```

### Compatibility Matrix

| SDK Version | IDE Version | Compatibility |
|-------------|-------------|---------------|
| 1.0.x | 1.0.x - 1.1.x | ✅ Full |
| 1.1.x | 1.1.x - 1.2.x | ✅ Full |
| 2.0.x | 2.0.x+ | ⚠️ Breaking changes |

### Version Checking

```cpp
// Check SDK version at runtime
uint32_t version = SDK_GetVersionNumber(sdk);
uint32_t major = (version >> 16) & 0xFF;
uint32_t minor = (version >> 8) & 0xFF;
uint32_t patch = version & 0xFF;

printf("SDK Version: %u.%u.%u\n", major, minor, patch);

// Check compatibility
if (major != REQUIRED_MAJOR_VERSION) {
    printf("Incompatible SDK version!\n");
    return 1;
}

if (minor < REQUIRED_MINOR_VERSION) {
    printf("SDK version too old, some features unavailable\n");
}
```

---

## Summary

The Sovereign IDE SDK provides:

- ✅ **487+ capabilities** across 49 batches
- ✅ **Unified API** consistent interface patterns
- ✅ **Multi-language support** C, C++, MASM
- ✅ **Async/Sync execution** flexible models
- ✅ **Comprehensive error handling** detailed error codes
- ✅ **Version compatibility** clear versioning scheme

**Status:** ✅ Complete

---

*End of SDK Overview Documentation*
