# RawrXD Sovereign v1.1.0 - Function Calling Framework

## Overview

The Function Calling Framework is the first major feature of RawrXD v1.1.0, transforming the inference runtime into a true autonomous development environment. This framework enables AI agents to execute tools, interact with the filesystem, compile code, run benchmarks, and perform system operations.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AgentSubsystem                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                │
│  │ Planner  │→│  Coder   │→│ Reflector│                │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘                │
│       │             │             │                        │
│       └─────────────┴─────────────┘                        │
│                     │                                       │
│                     ▼                                       │
│  ┌─────────────────────────────────────────────────────┐  │
│  │         AgentToolIntegration                         │  │
│  │  (Orchestrates Planner/Coder/Reflector with Tools) │  │
│  └────────────────────┬────────────────────────────────┘  │
└───────────────────────┼───────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│              Function Calling Framework                      │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ ToolRegistry │  │ ToolExecutor │  │SchemaValidator │  │
│  │  (Register)  │  │  (Execute)   │  │  (Validate)    │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬───────┘  │
│         │                 │                    │          │
│         └─────────────────┴────────────────────┘          │
│                           │                               │
│                           ▼                               │
│  ┌─────────────────────────────────────────────────────┐ │
│  │         FunctionCallingHandler                       │ │
│  │    (OpenAI-compatible API interface)               │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                    Built-in Tools                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐        │
│  │Filesystem│ │ Compiler │ │ Debugger │ │Benchmark │        │
│  │          │ │          │ │          │ │          │        │
│  │•read     │ │•compile  │ │•breakpoint│ │•run      │        │
│  │•write    │ │•run      │ │•stack    │ │•profile  │        │
│  │•list     │ │•check    │ │•evaluate │ │•measure  │        │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘        │
│  ┌─────────────────────────────────────────────────────┐  │
│  │                      System                          │  │
│  │  • execute_command  • get_system_info  • check_env   │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. ToolRegistry (`ToolRegistry.hpp/cpp`)

Central registry for all available tools.

**Features:**
- Thread-safe tool registration/unregistration
- Tool metadata and schema storage
- Built-in tool definitions (15 tools across 5 categories)
- OpenAI and Claude compatible schema generation

**Key Classes:**
- `ToolRegistry` - Main registry class
- `ToolDefinition` - Tool metadata
- `ToolCall` / `ToolResult` - Execution structures
- `BuiltInTools` - Namespace with predefined tools

### 2. ToolExecutor (`ToolExecutor.hpp/cpp`)

Safe execution environment for tools.

**Features:**
- Synchronous, asynchronous, and batch execution
- Resource limits (memory, timeout, output size)
- Path restrictions and command validation
- Execution sandboxing
- Statistics tracking

**Key Classes:**
- `ToolExecutor` - Main execution class
- `ExecutionContext` - Execution configuration
- `ExecutionStats` - Performance metrics
- `ToolSandbox` - Isolated execution
- `ExecutionQueue` - Concurrent execution management

### 3. SchemaValidator (`SchemaValidator.hpp/cpp`)

JSON schema validation for tool arguments.

**Features:**
- Type validation (string, integer, number, boolean, array, object)
- Constraint validation (min/max length, range, pattern)
- Enum validation
- Sanitization and safe defaults
- OpenAI-compatible schema generation

**Key Classes:**
- `SchemaValidator` - Main validation class
- `ToolSchema` - Schema definition
- `SchemaProperty` - Property constraints
- `ValidationResult` - Validation outcome

### 4. FunctionCallingAPI (`FunctionCallingAPI.hpp/cpp`)

OpenAI-compatible function calling API.

**Features:**
- Full OpenAI API compatibility
- Streaming support
- Function and tool call handling
- Chat message management
- Auto-function calling mode

**Key Classes:**
- `FunctionCallingHandler` - Request processing
- `FunctionCallingRequest` / `FunctionCallingResponse` - API structures
- `ChatMessage` - Message with tool support
- `AutoFunctionCaller` - Automatic tool execution

### 5. AgentToolIntegration (`AgentToolIntegration.hpp/cpp`)

Integration with AgentSubsystem.

**Features:**
- Tool-aware planning
- Tool-using code generation
- Result reflection
- Async tool execution
- Result aggregation

**Key Classes:**
- `AgentToolIntegration` - Main orchestrator
- `ToolEnabledPlanner` - Tool-aware planning
- `ToolEnabledCoder` - Code generation with tools
- `ToolEnabledReflector` - Result reflection
- `ToolResultAggregator` - Result collection

## Built-in Tools

### Filesystem Tools
| Tool | Permission | Description |
|------|------------|-------------|
| `file_read` | READ_ONLY | Read file contents |
| `file_write` | WRITE_SAFE | Write to file |
| `file_list` | READ_ONLY | List files matching pattern |
| `directory_list` | READ_ONLY | List directories |

### Compiler Tools
| Tool | Permission | Description |
|------|------------|-------------|
| `compile_code` | EXECUTE | Compile source code |
| `run_executable` | EXECUTE | Run executable |
| `check_syntax` | READ_ONLY | Check code syntax |

### Debugger Tools
| Tool | Permission | Description |
|------|------------|-------------|
| `set_breakpoint` | WRITE_SAFE | Set debugger breakpoint |
| `get_stack_trace` | READ_ONLY | Get stack trace |
| `evaluate_expression` | READ_ONLY | Evaluate expression |

### Benchmark Tools
| Tool | Permission | Description |
|------|------------|-------------|
| `run_benchmark` | EXECUTE | Run performance benchmark |
| `profile_code` | EXECUTE | Profile code execution |
| `measure_memory` | READ_ONLY | Measure memory usage |

### System Tools
| Tool | Permission | Description |
|------|------------|-------------|
| `execute_command` | EXECUTE | Execute system command |
| `get_system_info` | READ_ONLY | Get system information |
| `check_environment` | READ_ONLY | Check environment variables |

## Usage Example

```cpp
#include <RawrXD/FunctionCalling.hpp>

using namespace RawrXD::FunctionCalling;

// Initialize components
ToolRegistry registry;
ToolExecutor executor;
SchemaValidator validator;
FunctionCallingHandler handler;

// Register built-in tools
registry.RegisterBuiltInTools();

// Initialize handler
handler.Initialize(&registry, &executor);

// Create a tool call
ToolCall call;
call.name = "file_read";
call.arguments = {{"path", "config.json"}};
call.call_id = "call_123";

// Validate
std::string error;
if (registry.ValidateToolCall(call, error)) {
    // Execute
    ToolResult result = registry.ExecuteTool(call);
    
    if (result.success) {
        std::cout << "File content: " << result.data["content"] << std::endl;
    } else {
        std::cerr << "Error: " << result.error_message << std::endl;
    }
}

// OpenAI-compatible API
FunctionCallingRequest request;
request.model = "rawrxd-v1.1.0";
request.messages.push_back(ChatMessage::User("Read config.json"));
request.tools = handler.GetAvailableTools();
request.tool_choice = "auto";

FunctionCallingResponse response = handler.HandleRequest(request);
```

## Safety Features

### Permission Levels
- **READ_ONLY**: Safe operations (read files, list directory)
- **WRITE_SAFE**: Write operations with validation
- **WRITE_UNSAFE**: Potentially destructive operations
- **EXECUTE**: Code execution

### Execution Context
- Memory limits (default: 256MB)
- Timeout (default: 30s)
- Path restrictions
- Network access control
- Command validation

### Validation
- JSON schema validation
- Type checking
- Range validation
- Pattern matching
- Dangerous command detection

## Integration with AgentSubsystem

```cpp
#include <RawrXD/AgentToolIntegration.hpp>

using namespace RawrXD::Agent::FunctionCalling;

// Initialize integration
AgentToolIntegration integration;
integration.Initialize(&registry, &executor, &validator, &handler);

// Configure
integration.SetMaxIterations(10);
integration.SetAutoExecute(true);

// Execute with tools
AgentResult result = integration.ExecuteWithTools(
    "Compile and run the test suite",
    &agent_context
);
```

## Files

| File | Description | Lines |
|------|-------------|-------|
| `ToolRegistry.hpp` | Tool registry interface | 138 |
| `ToolRegistry.cpp` | Tool registry implementation | 500 |
| `ToolExecutor.hpp` | Tool executor interface | 232 |
| `ToolExecutor.cpp` | Tool executor implementation | 603 |
| `SchemaValidator.hpp` | Schema validator interface | 240 |
| `SchemaValidator.cpp` | Schema validator implementation | 600+ |
| `FunctionCallingAPI.hpp` | OpenAI-compatible API interface | 295 |
| `FunctionCallingAPI.cpp` | OpenAI-compatible API implementation | 768 |
| `AgentToolIntegration.hpp` | Agent integration interface | 269 |
| `AgentToolIntegration.cpp` | Agent integration implementation | 772 |

**Total: ~4,400 lines of code**

## Status

✅ **V.1 Function Calling Framework COMPLETE**

- ✅ ToolRegistry with 15 built-in tools
- ✅ ToolExecutor with safety features
- ✅ SchemaValidator with full validation
- ✅ FunctionCallingAPI (OpenAI-compatible)
- ✅ AgentToolIntegration (AgentSubsystem integration)
- ✅ Comprehensive documentation

## Next Steps

- V.2: Model Compatibility (GGUF, ONNX, TensorRT)
- V.3: Vision Models (multimodal support)
- V.4: Quantization (INT8, INT4, GPTQ)
- V.5: Hardening (security, performance)

## License

MIT License - See LICENSE file in repository root.

---

**RawrXD Sovereign v1.1.0** | Function Calling Framework | 2026
