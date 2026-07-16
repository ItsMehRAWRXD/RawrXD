# Sovereign IDE — API Reference Index
## Complete API Documentation Suite

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** Complete

---

## Overview

The Sovereign IDE SDK provides a comprehensive set of APIs for building extensions, tools, and integrations. This reference documentation covers all SDK modules with complete function signatures, data structures, and usage examples.

---

## API Reference Files

### Core SDK APIs

| File | Description | Functions |
|------|-------------|-----------|
| [API_Reference_Core.md](API_Reference_Core.md) | Core SDK (Editor, Workspace, Build, Debugger, Git) | 50+ |
| [API_Reference_Agentic.md](API_Reference_Agentic.md) | Agentic SDK (Agents, Capabilities, Actions) | 40+ |
| [API_Reference_Binary.md](API_Reference_Binary.md) | Binary Analysis SDK (Loader, Disasm, CFG) | 35+ |
| [API_Reference_AI.md](API_Reference_AI.md) | AI SDK (Models, Inference, Tokenization) | 45+ |
| [API_Reference_SEG.md](API_Reference_SEG.md) | SEG SDK (Grid, Nodes, Tasks) | 40+ |
| [API_Reference_MoE.md](API_Reference_MoE.md) | MoE SDK (Governor, Experts, Quantization) | 35+ |

**Total API Functions:** 245+

---

## Quick Reference by Category

### Editor Operations
```cpp
// From API_Reference_Core.md
SDK_Editor_CreateDocument()
SDK_Editor_OpenDocument()
SDK_Editor_SaveDocument()
SDK_Editor_CloseDocument()
SDK_Editor_SetCursorPosition()
SDK_Editor_GetSelection()
SDK_Editor_InsertText()
SDK_Editor_DeleteText()
SDK_Editor_Undo()
SDK_Editor_Redo()
```

### Agent Management
```cpp
// From API_Reference_Agentic.md
SDK_Agent_Create()
SDK_Agent_Destroy()
SDK_Agent_SetState()
SDK_Capability_Register()
SDK_Action_Execute()
SDK_Memory_Store()
SDK_Orchestration_CreateWorkflow()
```

### Binary Analysis
```cpp
// From API_Reference_Binary.md
SDK_Binary_Load()
SDK_Disasm_Disassemble()
SDK_CFG_Build()
SDK_Symbols_GetImports()
SDK_Pattern_Scan()
```

### AI/ML Operations
```cpp
// From API_Reference_AI.md
SDK_Model_Load()
SDK_Inference_Generate()
SDK_Inference_ChatComplete()
SDK_Tokenizer_Tokenize()
SDK_Embeddings_Generate()
SDK_Analysis_Analyze()
```

### Distributed Computing
```cpp
// From API_Reference_SEG.md
SDK_SEG_Init()
SDK_Task_Submit()
SDK_Task_Wait()
SDK_Comm_Send()
SDK_Fault_CreateCheckpoint()
```

### Model Optimization
```cpp
// From API_Reference_MoE.md
SDK_MoE_Init()
SDK_Expert_Select()
SDK_Quantize_Model()
SDK_Stream_Prefetch()
SDK_Hardware_Detect()
```

---

## Common Data Types

### SDK Result Codes
```cpp
typedef enum {
    SDK_OK = 0,
    SDK_ERROR_INVALID_PARAM = 1,
    SDK_ERROR_NOT_INITIALIZED = 2,
    SDK_ERROR_OUT_OF_MEMORY = 3,
    SDK_ERROR_NOT_FOUND = 4,
    SDK_ERROR_ALREADY_EXISTS = 5,
    SDK_ERROR_NOT_SUPPORTED = 6,
    SDK_ERROR_TIMEOUT = 7,
    SDK_ERROR_CANCELLED = 8,
    SDK_ERROR_INTERNAL = 99
} SDKResult;
```

### Handle Types
```cpp
typedef void* SDKHandle;
typedef void* AgentHandle;
typedef void* ModelHandle;
typedef void* SEGHandle;
typedef void* MoEGovernorHandle;
typedef void* BinaryHandle;
typedef void* DisasmHandle;
```

---

## Header File Organization

```
sdk/
├── core/
│   ├── init.h
│   ├── editor.h
│   ├── workspace.h
│   ├── build.h
│   ├── debugger.h
│   └── git.h
├── agentic/
│   ├── agent.h
│   ├── capability.h
│   ├── action.h
│   ├── memory.h
│   └── orchestration.h
├── binary/
│   ├── loader.h
│   ├── disasm.h
│   ├── cfg.h
│   ├── symbols.h
│   └── patterns.h
├── ai/
│   ├── model.h
│   ├── inference.h
│   ├── tokenizer.h
│   ├── embeddings.h
│   └── analysis.h
├── seg/
│   ├── grid.h
│   ├── node.h
│   ├── task.h
│   ├── comm.h
│   └── fault.h
└── moe/
    ├── governor.h
    ├── expert.h
    ├── quantize.h
    ├── stream.h
    └── hardware.h
```

---

## Usage Patterns

### Basic SDK Initialization
```cpp
#include <sdk/core/init.h>

SDKHandle sdk;
SDK_Initialize(NULL, &sdk);

// Use SDK...

SDK_Shutdown(sdk);
```

### Error Handling
```cpp
SDKResult result = SDK_Editor_OpenDocument(sdk, "file.cpp", &doc);
if (result != SDK_OK) {
    char error[256];
    SDK_GetLastError(sdk, error, sizeof(error));
    printf("Error: %s\n", error);
    return;
}
```

### Resource Management
```cpp
// Always cleanup resources
SDK_Editor_CloseDocument(sdk, doc);
SDK_Model_Unload(sdk, model);
SDK_SEG_Shutdown(sdk, grid);
SDK_MoE_Shutdown(sdk, governor);
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-07-11 | Initial API reference documentation |

---

## See Also

- [SDK Overview](../sdk/SDK_Overview.md) - SDK architecture overview
- [SDK Integration Guide](../sdk/SDK_Integration_Guide.md) - Integration patterns
- [Sovereign Kernel Manual](../core/SovereignKernel_Manual.md) - Core runtime docs

---

*End of API Reference Index*
