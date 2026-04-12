// ============================================================================
// AGENT_CONTROLLER_INTEGRATION_GUIDE.md
// Step-by-step guide to integrate MinimalAgentController with existing codebase
// ============================================================================

## Overview

The MinimalAgentController provides:
1. **Tool Registry** - 4 built-in tools (file_read, file_write, terminal_execute, search_files)
2. **Agent Loop** - Orchestrates LLM → Tool → LLM → ... cycle
3. **Tool Execution** - Secure execution with allowlist and sandboxing
4. **State Management** - Tracks tool calls and conversation history

## Integration Points

### 1. Initialization (in Win32IDE or main startup)

```cpp
#include "agentic/agentic_controller_wiring.h"

// During Win32IDE initialization, after creating CPU inference engine:
if (cpu_inference_engine_ptr) {
    rawrxd::initializeAgentControllerWiring(cpu_inference_engine_ptr);
}
```

### 2. Routing Agentic Requests (in Win32IDE_AgenticBridge.cpp)

In the `GenerateResponse()` or `ExecuteAgentCommand()` function:

```cpp
std::string AgenticBridge::GenerateResponse(const std::string& prompt) {
    // Check if this is an agentic request
    if (prompt.find("agentic:") == 0 || m_enableAgenticMode) {
        
        // Use minimal agent controller
        if (rawrxd::isAgenticLayerAvailable()) {
            rawrxd::MinimalAgenticRequest req;
            req.message = prompt;
            req.session_id = m_currentSessionId;
            req.model_path = m_currentModelPath;  // Your resolved GGUF path
            req.enable_tools = true;
            
            auto response = rawrxd::processAgenticRequest(req);
            if (response.success) {
                return response.final_message;
            }
            // Fall through to regular inference if agent failed
        }
    }
    
    // Regular inference (existing code)
    return RegularInference(prompt);
}
```

### 3. Tool Extension (add more tools as needed)

In `agent_controller_minimal.cpp`, in `registerDefaultTools()`:

```cpp
// Example: Add git_execute tool
tools_.push_back({
    "git_execute",
    "Execute a git command in the repository",
    {{"command", "git subcommand and args"}},
    [](const std::string& args_json) -> std::string {
        // Implementation here
        return R"({"success":true,"output":"..."})";
    }
});
```

### 4. LLM Integration (customize inference calling)

In `agentic_controller_wiring.cpp`, in `getGlobalLLMResponse()`:

```cpp
std::string getGlobalLLMResponse(...) {
    if (!g_inference_engine) {
        return "Error: Inference engine not available";
    }
    
    // Build prompt - CUSTOMIZE THIS TO MATCH YOUR LLM INTERFACE
    std::string full_prompt = system_prompt + "\n\nUser: " + user_message;
    
    // Call your inference engine API
    // Example (adjust to match your actual API):
    try {
        // Option 1: If CPUInferenceEngine has a Complete() method:
        auto response = g_inference_engine->Complete(full_prompt, model_path);
        return response;
        
        // Option 2: If it uses a different interface:
        InferenceRequest req;
        req.prompt = full_prompt;
        req.model_path = model_path;
        auto result = g_inference_engine->Infer(req);
        return result.text;
        
    } catch (const std::exception& e) {
        LOG_ERROR("LLM call failed: " + std::string(e.what()));
        return "Error: " + std::string(e.what());
    }
}
```

## Files Changed

### New Files
- `src/agentic/agent_controller_minimal.h` - Agent controller interface
- `src/agentic/agent_controller_minimal.cpp` - Agent controller implementation  
- `src/agentic/agentic_controller_wiring.h` - Wiring interface
- `src/agentic/agentic_controller_wiring.cpp` - Wiring implementation

### Modified Files
- `CMakeLists.txt` - Added new sources to WIN32IDE_SOURCES
- `Win32IDE_AgenticBridge.cpp` - Add #include and routing logic (TODO)
- `Win32IDE_AgenticBridge.h` - Add member variables for agentic mode (TODO)

## Build and Test

```bash
# Build with the new agent controller
cd d:/rawrxd/build-ninja
cmake --build . --target RawrXD-Win32IDE -j 8

# Run smoke test with agentic flag
powershell -NoProfile -ExecutionPolicy Bypass -File d:/scripts/smoke_test_chat_pane.ps1 `
  -ExePath d:/rawrxd/build-ninja/bin/RawrXD-Win32IDE.exe `
  -RequireModelResponse `
  -RequireAgentic $true `
  -FailOnWarnings `
  -NoBuild
```

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ Win32IDE Chat Pane                                          │
│ handleCopilotSend(prompt)                                   │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ Win32IDE_AgenticBridge::GenerateResponse()                  │
│ - Detects agentic prefix or mode flag                       │
│ - Routes to agent controller if available                   │
└──────────────────┬──────────────────────────────────────────┘
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
    [AGENTIC]         [REGULAR CHAT]
         │                   │
         ▼                   ▼
    MinimalAgentController   Direct LLM
    - Tool Registry          Call
    - Agent Loop             
    - Tool Execution         
         │
    ┌────┴────┬────────┬─────────┐
    ▼         ▼        ▼         ▼
  file_    file_   terminal_ search_
  read    write   execute   files
    │         │        │         │
    └────┬────┴────────┴─────────┘
         │
         ▼
    LLM Response (via getGlobalLLMResponse)
         │
         ▼
    Return to Chat Pane
```

## Security Considerations

1. **Tool Allowlisting** - terminal_execute only allows: git, cmake, ninja, make, ctest, echo, cat, ls, dir, pwd, cl
2. **Path Traversal Protection** - All file tools check for `..` in paths
3. **Content Size Limits** - File operations capped at reasonable sizes
4. **Timeout Protection** - Agent loop has max_iterations safety limit

## Troubleshooting

### "Agentic layer not initialized" error
- Ensure `initializeAgentControllerWiring()` is called with valid inference engine
- Check that the wiring code is actually being executed during startup

### Tool calls not executing
- Verify tool names match exactly (case-sensitive)
- Check that tool has handler implementation
- Ensure JSON parsing logic handles your LLM's response format

### LLM not being called
- Implement the actual inference engine call in `getGlobalLLMResponse()`
- Add logging to verify the function is being called
- Check model_path is valid and model is loaded

## Next Steps

1. **Immediate**: Hook agentic routing into Win32IDE_AgenticBridge
2. **Short-term**: Implement actual LLM calls in getGlobalLLMResponse()
3. **Medium-term**: Add more tools (git, build, debugging)
4. **Long-term**: Add persistent tool result store, tool composition, safety auditing

