# Sovereign IDE — API Reference: Agentic SDK
## Complete API Documentation for Agentic Surfaces

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** Complete

---

## 1. Overview

The Agentic SDK provides APIs for creating, registering, and orchestrating autonomous agents within the Sovereign IDE. It enables developers to build intelligent agents that can perform complex tasks, coordinate with other agents, and integrate with the full IDE ecosystem.

### 1.1 API Categories

| Category | Description | Header |
|----------|-------------|--------|
| Agent Management | Create and manage agents | `sdk/agentic/agent.h` |
| Capabilities | Register and discover capabilities | `sdk/agentic/capability.h` |
| Actions | Execute actions and tasks | `sdk/agentic/action.h` |
| Memory | Working and long-term memory | `sdk/agentic/memory.h` |
| Orchestration | Multi-agent coordination | `sdk/agentic/orchestration.h` |

---

## 2. Agent Management API

### 2.1 Agent Lifecycle

```cpp
// sdk/agentic/agent.h

/**
 * Agent types
 */
typedef enum {
    AGENT_ASSISTANT = 0,    // Interactive assistant
    AGENT_AUTONOMOUS = 1,   // Fully autonomous
    AGENT_ORCHESTRATOR = 2, // Coordinates other agents
    AGENT_SPECIALIST = 3    // Domain-specific expert
} AgentType;

/**
 * Agent configuration
 */
typedef struct {
    const char* name;
    const char* description;
    AgentType type;
    const char** capabilities;
    uint32_t capabilityCount;
    uint32_t maxTasks;
    uint32_t timeoutMs;
} AgentConfig;

/**
 * Create a new agent
 * @param sdk SDK handle
 * @param config Agent configuration
 * @param outAgent Output agent handle
 * @return SDKResult
 */
SDKResult SDK_Agent_Create(
    SDKHandle sdk,
    const AgentConfig* config,
    AgentHandle* outAgent
);

/**
 * Destroy an agent
 * @param sdk SDK handle
 * @param agent Agent handle
 * @return SDKResult
 */
SDKResult SDK_Agent_Destroy(
    SDKHandle sdk,
    AgentHandle agent
);

/**
 * Get agent information
 * @param sdk SDK handle
 * @param agent Agent handle
 * @param outInfo Output agent info
 * @return SDKResult
 */
SDKResult SDK_Agent_GetInfo(
    SDKHandle sdk,
    AgentHandle agent,
    AgentInfo* outInfo
);

/**
 * Set agent state
 * @param sdk SDK handle
 * @param agent Agent handle
 * @param state New state
 * @return SDKResult
 */
SDKResult SDK_Agent_SetState(
    SDKHandle sdk,
    AgentHandle agent,
    AgentState state
);
```

### 2.2 Agent States

```cpp
/**
 * Agent states
 */
typedef enum {
    AGENT_STATE_IDLE = 0,
    AGENT_STATE_INITIALIZING = 1,
    AGENT_STATE_RUNNING = 2,
    AGENT_STATE_PAUSED = 3,
    AGENT_STATE_ERROR = 4,
    AGENT_STATE_SHUTDOWN = 5
} AgentState;

/**
 * Agent information
 */
typedef struct {
    char agentId[64];
    char name[128];
    char description[256];
    AgentType type;
    AgentState state;
    uint32_t activeTasks;
    uint32_t completedTasks;
    uint64_t uptimeMs;
} AgentInfo;
```

---

## 3. Capability API

### 3.1 Capability Registration

```cpp
// sdk/agentic/capability.h

/**
 * Capability information
 */
typedef struct {
    char name[64];
    char description[256];
    char version[16];
    uint32_t batchId;
    uint32_t cost;
    uint32_t priority;
    CapabilityExecutor executor;
} CapabilityInfo;

/**
 * Capability executor function type
 */
typedef SDKResult (*CapabilityExecutor)(
    const ActionRequest* request,
    ActionResult* result
);

/**
 * Register a capability
 * @param sdk SDK handle
 * @param agent Agent handle
 * @param info Capability information
 * @param outCapabilityId Output capability ID
 * @return SDKResult
 */
SDKResult SDK_Capability_Register(
    SDKHandle sdk,
    AgentHandle agent,
    const CapabilityInfo* info,
    char* outCapabilityId
);

/**
 * Unregister a capability
 * @param sdk SDK handle
 * @param agent Agent handle
 * @param capabilityId Capability ID
 * @return SDKResult
 */
SDKResult SDK_Capability_Unregister(
    SDKHandle sdk,
    AgentHandle agent,
    const char* capabilityId
);

/**
 * Discover capabilities
 * @param sdk SDK handle
 * @param query Search query
 * @param outCapabilities Output capability list
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_Capability_Discover(
    SDKHandle sdk,
    const char* query,
    CapabilityInfo** outCapabilities,
    uint32_t* outCount
);
```

### 3.2 Capability Discovery

```cpp
/**
 * Discover capabilities by agent
 * @param sdk SDK handle
 * @param agent Agent handle
 * @param outCapabilities Output capability list
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_Capability_DiscoverByAgent(
    SDKHandle sdk,
    AgentHandle agent,
    CapabilityInfo** outCapabilities,
    uint32_t* outCount
);

/**
 * Check if capability exists
 * @param sdk SDK handle
 * @param capabilityId Capability ID
 * @param outExists Output exists flag
 * @return SDKResult
 */
SDKResult SDK_Capability_Exists(
    SDKHandle sdk,
    const char* capabilityId,
    bool* outExists
);
```

---

## 4. Action API

### 4.1 Action Execution

```cpp
// sdk/agentic/action.h

/**
 * Parameter types
 */
typedef enum {
    PARAM_STRING = 0,
    PARAM_INT = 1,
    PARAM_FLOAT = 2,
    PARAM_BOOL = 3,
    PARAM_BINARY = 4,
    PARAM_JSON = 5
} ParameterType;

/**
 * Parameter value
 */
typedef union {
    char stringValue[1024];
    int64_t intValue;
    double floatValue;
    bool boolValue;
    struct {
        uint8_t* data;
        uint32_t size;
    } binaryValue;
    char jsonValue[4096];
} ParameterValue;

/**
 * Parameter
 */
typedef struct {
    char name[64];
    ParameterType type;
    ParameterValue value;
} Parameter;

/**
 * Action request
 */
typedef struct {
    char agentId[64];
    char capability[64];
    Parameter params[32];
    uint32_t paramCount;
    ActionOptions options;
} ActionRequest;

/**
 * Action options
 */
typedef struct {
    uint32_t timeoutMs;
    uint32_t priority;
    bool async;
    bool retryOnFailure;
    uint32_t maxRetries;
} ActionOptions;

/**
 * Action result
 */
typedef struct {
    bool success;
    char error[256];
    Parameter output;
    uint64_t executionTime;
    char executorId[64];
} ActionResult;

/**
 * Execute an action synchronously
 * @param sdk SDK handle
 * @param request Action request
 * @param outResult Output result
 * @return SDKResult
 */
SDKResult SDK_Action_Execute(
    SDKHandle sdk,
    const ActionRequest* request,
    ActionResult* outResult
);

/**
 * Execute an action asynchronously
 * @param sdk SDK handle
 * @param request Action request
 * @param callback Completion callback
 * @param userData User data for callback
 * @param outActionId Output action ID
 * @return SDKResult
 */
SDKResult SDK_Action_ExecuteAsync(
    SDKHandle sdk,
    const ActionRequest* request,
    ActionCallback callback,
    void* userData,
    char* outActionId
);

/**
 * Cancel an action
 * @param sdk SDK handle
 * @param actionId Action ID
 * @return SDKResult
 */
SDKResult SDK_Action_Cancel(
    SDKHandle sdk,
    const char* actionId
);

/**
 * Get action status
 * @param sdk SDK handle
 * @param actionId Action ID
 * @param outStatus Output status
 * @return SDKResult
 */
SDKResult SDK_Action_GetStatus(
    SDKHandle sdk,
    const char* actionId,
    ActionStatus* outStatus
);
```

### 4.2 Action Callbacks

```cpp
/**
 * Action callback function type
 */
typedef void (*ActionCallback)(
    const ActionResult* result,
    void* userData
);

/**
 * Action status
 */
typedef enum {
    ACTION_STATUS_PENDING = 0,
    ACTION_STATUS_RUNNING = 1,
    ACTION_STATUS_COMPLETED = 2,
    ACTION_STATUS_FAILED = 3,
    ACTION_STATUS_CANCELLED = 4
} ActionStatus;
```

---

## 5. Memory API

### 5.1 Working Memory

```cpp
// sdk/agentic/memory.h

/**
 * Memory entry
 */
typedef struct {
    char key[128];
    char value[4096];
    uint64_t timestamp;
    uint32_t ttlSeconds;
} MemoryEntry;

/**
 * Store in working memory
 * @param sdk SDK handle
 * @param agent Agent handle
 * @param key Memory key
 * @param value Memory value
 * @param ttlSeconds Time to live
 * @return SDKResult
 */
SDKResult SDK_Memory_Store(
    SDKHandle sdk,
    AgentHandle agent,
    const char* key,
    const char* value,
    uint32_t ttlSeconds
);

/**
 * Retrieve from working memory
 * @param sdk SDK handle
 * @param agent Agent handle
 * @param key Memory key
 * @param outValue Output value
 * @param valueSize Value buffer size
 * @return SDKResult
 */
SDKResult SDK_Memory_Retrieve(
    SDKHandle sdk,
    AgentHandle agent,
    const char* key,
    char* outValue,
    uint32_t valueSize
);

/**
 * Delete from working memory
 * @param sdk SDK handle
 * @param agent Agent handle
 * @param key Memory key
 * @return SDKResult
 */
SDKResult SDK_Memory_Delete(
    SDKHandle sdk,
    AgentHandle agent,
    const char* key
);

/**
 * Clear working memory
 * @param sdk SDK handle
 * @param agent Agent handle
 * @return SDKResult
 */
SDKResult SDK_Memory_Clear(
    SDKHandle sdk,
    AgentHandle agent
);
```

### 5.2 Long-Term Memory

```cpp
/**
 * Store in long-term memory
 * @param sdk SDK handle
 * @param agent Agent handle
 * @param key Memory key
 * @param value Memory value
 * @param metadata Optional metadata
 * @return SDKResult
 */
SDKResult SDK_Memory_StoreLongTerm(
    SDKHandle sdk,
    AgentHandle agent,
    const char* key,
    const char* value,
    const char* metadata
);

/**
 * Search long-term memory
 * @param sdk SDK handle
 * @param agent Agent handle
 * @param query Search query
 * @param outEntries Output entries
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_Memory_SearchLongTerm(
    SDKHandle sdk,
    AgentHandle agent,
    const char* query,
    MemoryEntry** outEntries,
    uint32_t* outCount
);

/**
 * Retrieve from long-term memory
 * @param sdk SDK handle
 * @param agent Agent handle
 * @param key Memory key
 * @param outValue Output value
 * @param valueSize Value buffer size
 * @return SDKResult
 */
SDKResult SDK_Memory_RetrieveLongTerm(
    SDKHandle sdk,
    AgentHandle agent,
    const char* key,
    char* outValue,
    uint32_t valueSize
);
```

---

## 6. Orchestration API

### 6.1 Multi-Agent Coordination

```cpp
// sdk/agentic/orchestration.h

/**
 * Task definition
 */
typedef struct {
    char taskId[64];
    char description[256];
    char* dependencies[16];
    uint32_t dependencyCount;
    uint32_t priority;
    uint32_t timeoutMs;
} TaskDefinition;

/**
 * Workflow definition
 */
typedef struct {
    char workflowId[64];
    char name[128];
    char description[256];
    TaskDefinition* tasks;
    uint32_t taskCount;
} WorkflowDefinition;

/**
 * Create a workflow
 * @param sdk SDK handle
 * @param definition Workflow definition
 * @param outWorkflow Output workflow handle
 * @return SDKResult
 */
SDKResult SDK_Orchestration_CreateWorkflow(
    SDKHandle sdk,
    const WorkflowDefinition* definition,
    WorkflowHandle* outWorkflow
);

/**
 * Execute a workflow
 * @param sdk SDK handle
 * @param workflow Workflow handle
 * @param outResult Output result
 * @return SDKResult
 */
SDKResult SDK_Orchestration_ExecuteWorkflow(
    SDKHandle sdk,
    WorkflowHandle workflow,
    WorkflowResult* outResult
);

/**
 * Cancel a workflow
 * @param sdk SDK handle
 * @param workflow Workflow handle
 * @return SDKResult
 */
SDKResult SDK_Orchestration_CancelWorkflow(
    SDKHandle sdk,
    WorkflowHandle workflow
);

/**
 * Get workflow status
 * @param sdk SDK handle
 * @param workflow Workflow handle
 * @param outStatus Output status
 * @return SDKResult
 */
SDKResult SDK_Orchestration_GetWorkflowStatus(
    SDKHandle sdk,
    WorkflowHandle workflow,
    WorkflowStatus* outStatus
);
```

### 6.2 Agent Communication

```cpp
/**
 * Message structure
 */
typedef struct {
    char senderId[64];
    char recipientId[64];
    char messageType[32];
    char payload[4096];
    uint64_t timestamp;
} AgentMessage;

/**
 * Send message to agent
 * @param sdk SDK handle
 * @param sender Sender agent
 * @param recipient Recipient agent ID
 * @param messageType Message type
 * @param payload Message payload
 * @return SDKResult
 */
SDKResult SDK_Orchestration_SendMessage(
    SDKHandle sdk,
    AgentHandle sender,
    const char* recipient,
    const char* messageType,
    const char* payload
);

/**
 * Register message handler
 * @param sdk SDK handle
 * @param agent Agent handle
 * @param messageType Message type
 * @param handler Message handler
 * @return SDKResult
 */
SDKResult SDK_Orchestration_RegisterHandler(
    SDKHandle sdk,
    AgentHandle agent,
    const char* messageType,
    MessageHandler handler
);

/**
 * Message handler function type
 */
typedef void (*MessageHandler)(
    const AgentMessage* message,
    void* userData
);
```

---

## 7. Usage Examples

### 7.1 Creating a Simple Agent

```cpp
#include <sdk/core/init.h>
#include <sdk/agentic/agent.h>
#include <sdk/agentic/capability.h>
#include <sdk/agentic/action.h>

// Capability executor
SDKResult CodeGenerateExecutor(const ActionRequest* request, ActionResult* result) {
    // Extract parameters
    const char* language = NULL;
    const char* prompt = NULL;
    
    for (uint32_t i = 0; i < request->paramCount; i++) {
        if (strcmp(request->params[i].name, "language") == 0) {
            language = request->params[i].value.stringValue;
        } else if (strcmp(request->params[i].name, "prompt") == 0) {
            prompt = request->params[i].value.stringValue;
        }
    }
    
    // Generate code (simplified)
    strcpy(result->output.value.stringValue, 
           "// Generated code\nvoid example() {\n    // TODO: Implement\n}");
    result->output.type = PARAM_STRING;
    result->success = true;
    result->executionTime = 100;
    
    return SDK_OK;
}

int main() {
    // Initialize SDK
    SDKHandle sdk;
    SDK_Initialize(NULL, &sdk);
    
    // Create agent
    const char* capabilities[] = {"Code.Generate", "Code.Refactor"};
    AgentConfig config = {
        .name = "CodingAssistant",
        .description = "AI coding assistant",
        .type = AGENT_ASSISTANT,
        .capabilities = capabilities,
        .capabilityCount = 2,
        .maxTasks = 10,
        .timeoutMs = 30000
    };
    
    AgentHandle agent;
    SDK_Agent_Create(sdk, &config, &agent);
    
    // Register capability
    CapabilityInfo capInfo = {
        .name = "Code.Generate",
        .description = "Generate code from prompt",
        .version = "1.0.0",
        .batchId = 50,
        .cost = 10,
        .priority = 5,
        .executor = CodeGenerateExecutor
    };
    
    char capId[64];
    SDK_Capability_Register(sdk, agent, &capInfo, capId);
    
    // Execute action
    ActionRequest request = {
        .agentId = "CodingAssistant",
        .capability = "Code.Generate",
        .paramCount = 2
    };
    
    strcpy(request.params[0].name, "language");
    request.params[0].type = PARAM_STRING;
    strcpy(request.params[0].value.stringValue, "cpp");
    
    strcpy(request.params[1].name, "prompt");
    request.params[1].type = PARAM_STRING;
    strcpy(request.params[1].value.stringValue, "Create a hello world function");
    
    request.options = (ActionOptions){
        .timeoutMs = 30000,
        .priority = 5,
        .async = false,
        .retryOnFailure = true,
        .maxRetries = 3
    };
    
    ActionResult result;
    SDK_Action_Execute(sdk, &request, &result);
    
    if (result.success) {
        printf("Generated code:\n%s\n", result.output.value.stringValue);
    } else {
        printf("Error: %s\n", result.error);
    }
    
    // Cleanup
    SDK_Agent_Destroy(sdk, agent);
    SDK_Shutdown(sdk);
    
    return 0;
}
```

### 7.2 Multi-Agent Workflow

```cpp
#include <sdk/agentic/orchestration.h>

void createMultiAgentWorkflow(SDKHandle sdk) {
    // Define tasks
    TaskDefinition tasks[3] = {
        {
            .taskId = "analyze",
            .description = "Analyze code structure",
            .dependencies = {},
            .dependencyCount = 0,
            .priority = 1,
            .timeoutMs = 60000
        },
        {
            .taskId = "refactor",
            .description = "Refactor code",
            .dependencies = {"analyze"},
            .dependencyCount = 1,
            .priority = 2,
            .timeoutMs = 120000
        },
        {
            .taskId = "test",
            .description = "Run tests",
            .dependencies = {"refactor"},
            .dependencyCount = 1,
            .priority = 3,
            .timeoutMs = 60000
        }
    };
    
    // Create workflow
    WorkflowDefinition workflow = {
        .workflowId = "refactor-workflow",
        .name = "Code Refactoring",
        .description = "Analyze, refactor, and test code",
        .tasks = tasks,
        .taskCount = 3
    };
    
    WorkflowHandle handle;
    SDK_Orchestration_CreateWorkflow(sdk, &workflow, &handle);
    
    // Execute workflow
    WorkflowResult result;
    SDK_Orchestration_ExecuteWorkflow(sdk, handle, &result);
    
    if (result.success) {
        printf("Workflow completed successfully!\n");
    } else {
        printf("Workflow failed: %s\n", result.error);
    }
}
```

---

## Summary

The Agentic SDK API provides:

- ✅ Complete agent lifecycle management
- ✅ Capability registration and discovery
- ✅ Synchronous and asynchronous action execution
- ✅ Working and long-term memory
- ✅ Multi-agent orchestration
- ✅ Inter-agent communication
- ✅ Workflow management

**Status:** Complete

---

*End of API Reference: Agentic SDK*
