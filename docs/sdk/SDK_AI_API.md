# Sovereign IDE SDK - AI API Reference
## Batches 11-20: Model Inference, Routing, Chat, Agents

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Complete

---

## Table of Contents

1. [Model Inference API](#model-inference-api)
2. [Model Router API](#model-router-api)
3. [Chat API](#chat-api)
4. [Agent API](#agent-api)
5. [Data Types](#data-types)
6. [Constants](#constants)

---

## Model Inference API

### Overview

The Model Inference API provides access to AI model execution, supporting local and remote models with various backends (llama.cpp, ONNX Runtime, custom).

### Functions

#### SDK_AI_LoadModel

Loads a model for inference.

```cpp
SDKResult SDK_AI_LoadModel(
    SDKHandle sdk,
    const char* modelPath,
    const ModelConfig* config,
    ModelHandle* outModel
);
```

**Parameters:**
- `sdk` - SDK handle
- `modelPath` - Path to model file
- `config` - Model configuration
- `outModel` - Output model handle

**Returns:** `SDK_SUCCESS` on success

**Example:**
```cpp
ModelConfig config = {
    .backend = BACKEND_LLAMA_CPP,
    .contextSize = 4096,
    .gpuLayers = 33,
    .threads = 8,
    .batchSize = 512
};

ModelHandle model;
SDKResult result = SDK_AI_LoadModel(sdk, "models/llama-7b.gguf", 
                                     &config, &model);
```

---

#### SDK_AI_UnloadModel

Unloads a model.

```cpp
SDKResult SDK_AI_UnloadModel(
    SDKHandle sdk,
    ModelHandle model
);
```

**Parameters:**
- `sdk` - SDK handle
- `model` - Model handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_AI_Inference

Runs inference on a model.

```cpp
SDKResult SDK_AI_Inference(
    SDKHandle sdk,
    ModelHandle model,
    const InferenceInput* input,
    InferenceOutput* output
);
```

**Parameters:**
- `sdk` - SDK handle
- `model` - Model handle
- `input` - Inference input
- `output` - Inference output

**Returns:** `SDK_SUCCESS` on success

**Example:**
```cpp
InferenceInput input = {
    .prompt = "What is the capital of France?",
    .maxTokens = 256,
    .temperature = 0.7f,
    .topP = 0.9f,
    .stopSequences = { "\n", "." }
};

InferenceOutput output;
SDK_AI_Inference(sdk, model, &input, &output);

printf("Response: %s\n", output.text);
```

---

#### SDK_AI_InferenceStreaming

Runs inference with streaming output.

```cpp
SDKResult SDK_AI_InferenceStreaming(
    SDKHandle sdk,
    ModelHandle model,
    const InferenceInput* input,
    StreamCallback callback,
    void* userData
);
```

**Parameters:**
- `sdk` - SDK handle
- `model` - Model handle
- `input` - Inference input
- `callback` - Callback for streaming tokens
- `userData` - User data passed to callback

**Returns:** `SDK_SUCCESS` on success

**Example:**
```cpp
void OnToken(const char* token, void* userData) {
    printf("%s", token);
    fflush(stdout);
}

SDK_AI_InferenceStreaming(sdk, model, &input, OnToken, NULL);
```

---

#### SDK_AI_GetModelInfo

Gets information about a loaded model.

```cpp
SDKResult SDK_AI_GetModelInfo(
    SDKHandle sdk,
    ModelHandle model,
    ModelInfo* outInfo
);
```

**Parameters:**
- `sdk` - SDK handle
- `model` - Model handle
- `outInfo` - Output model information

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_AI_Embed

Generates embeddings for text.

```cpp
SDKResult SDK_AI_Embed(
    SDKHandle sdk,
    ModelHandle model,
    const char* text,
    float* embedding,
    uint32_t* embeddingSize
);
```

**Parameters:**
- `sdk` - SDK handle
- `model` - Model handle (embedding model)
- `text` - Input text
- `embedding` - Output embedding vector
- `embeddingSize` - On input: buffer size; on output: actual size

**Returns:** `SDK_SUCCESS` on success

---

## Model Router API

### Overview

The Model Router API manages model selection and routing based on workload, capabilities, and performance requirements.

### Functions

#### SDK_Router_Initialize

Initializes the model router.

```cpp
SDKResult SDK_Router_Initialize(
    SDKHandle sdk,
    const RouterConfig* config,
    RouterHandle* outRouter
);
```

**Parameters:**
- `sdk` - SDK handle
- `config` - Router configuration
- `outRouter` - Output router handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Router_RegisterModel

Registers a model with the router.

```cpp
SDKResult SDK_Router_RegisterModel(
    SDKHandle sdk,
    RouterHandle router,
    const char* modelId,
    const ModelCapabilities* capabilities,
    const ModelEndpoint* endpoint
);
```

**Parameters:**
- `sdk` - SDK handle
- `router` - Router handle
- `modelId` - Unique model identifier
- `capabilities` - Model capabilities
- `endpoint` - Model endpoint configuration

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Router_SelectModel

Selects the best model for a request.

```cpp
SDKResult SDK_Router_SelectModel(
    SDKHandle sdk,
    RouterHandle router,
    const RoutingRequest* request,
    char* outModelId,
    uint32_t modelIdSize
);
```

**Parameters:**
- `sdk` - SDK handle
- `router` - Router handle
- `request` - Routing request
- `outModelId` - Buffer to receive selected model ID
- `modelIdSize` - Buffer size

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Router_RouteRequest

Routes a request to the appropriate model.

```cpp
SDKResult SDK_Router_RouteRequest(
    SDKHandle sdk,
    RouterHandle router,
    const RoutingRequest* request,
    RoutingResult* outResult
);
```

**Parameters:**
- `sdk` - SDK handle
- `router` - Router handle
- `request` - Routing request
- `outResult` - Output routing result

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Router_GetStats

Gets router statistics.

```cpp
SDKResult SDK_Router_GetStats(
    SDKHandle sdk,
    RouterHandle router,
    RouterStats* outStats
);
```

**Parameters:**
- `sdk` - SDK handle
- `router` - Router handle
- `outStats` - Output statistics

**Returns:** `SDK_SUCCESS` on success

---

## Chat API

### Overview

The Chat API provides access to the IDE's chat system, enabling conversational AI interactions.

### Functions

#### SDK_Chat_CreateSession

Creates a new chat session.

```cpp
SDKResult SDK_Chat_CreateSession(
    SDKHandle sdk,
    const ChatConfig* config,
    ChatSessionHandle* outSession
);
```

**Parameters:**
- `sdk` - SDK handle
- `config` - Chat configuration
- `outSession` - Output session handle

**Returns:** `SDK_SUCCESS` on success

**Example:**
```cpp
ChatConfig config = {
    .modelId = "llama-7b",
    .systemPrompt = "You are a helpful coding assistant.",
    .maxHistory = 20,
    .enableContext = true
};

ChatSessionHandle session;
SDK_Chat_CreateSession(sdk, &config, &session);
```

---

#### SDK_Chat_DestroySession

Destroys a chat session.

```cpp
SDKResult SDK_Chat_DestroySession(
    SDKHandle sdk,
    ChatSessionHandle session
);
```

**Parameters:**
- `sdk` - SDK handle
- `session` - Session handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Chat_SendMessage

Sends a message in a chat session.

```cpp
SDKResult SDK_Chat_SendMessage(
    SDKHandle sdk,
    ChatSessionHandle session,
    const char* message,
    ChatResponse* outResponse
);
```

**Parameters:**
- `sdk` - SDK handle
- `session` - Session handle
- `message` - User message
- `outResponse` - Output response

**Returns:** `SDK_SUCCESS` on success

**Example:**
```cpp
ChatResponse response;
SDK_Chat_SendMessage(sdk, session, 
                     "Explain this code:", &response);

printf("Assistant: %s\n", response.text);
```

---

#### SDK_Chat_SendMessageStreaming

Sends a message with streaming response.

```cpp
SDKResult SDK_Chat_SendMessageStreaming(
    SDKHandle sdk,
    ChatSessionHandle session,
    const char* message,
    ChatStreamCallback callback,
    void* userData
);
```

**Parameters:**
- `sdk` - SDK handle
- `session` - Session handle
- `message` - User message
- `callback` - Stream callback
- `userData` - User data

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Chat_GetHistory

Gets the chat history.

```cpp
SDKResult SDK_Chat_GetHistory(
    SDKHandle sdk,
    ChatSessionHandle session,
    ChatMessage* messages,
    uint32_t* messageCount
);
```

**Parameters:**
- `sdk` - SDK handle
- `session` - Session handle
- `messages` - Array to receive messages
- `messageCount` - On input: array size; on output: actual count

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Chat_ClearHistory

Clears the chat history.

```cpp
SDKResult SDK_Chat_ClearHistory(
    SDKHandle sdk,
    ChatSessionHandle session
);
```

**Parameters:**
- `sdk` - SDK handle
- `session` - Session handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Chat_AddContext

Adds context to the chat session.

```cpp
SDKResult SDK_Chat_AddContext(
    SDKHandle sdk,
    ChatSessionHandle session,
    const char* context,
    ContextType type
);
```

**Parameters:**
- `sdk` - SDK handle
- `session` - Session handle
- `context` - Context text
- `type` - Context type (code, file, error, etc.)

**Returns:** `SDK_SUCCESS` on success

---

## Agent API

### Overview

The Agent API provides programmatic control over autonomous agents within the IDE.

### Functions

#### SDK_Agent_Create

Creates a new agent.

```cpp
SDKResult SDK_Agent_Create(
    SDKHandle sdk,
    const AgentConfig* config,
    AgentHandle* outAgent
);
```

**Parameters:**
- `sdk` - SDK handle
- `config` - Agent configuration
- `outAgent` - Output agent handle

**Returns:** `SDK_SUCCESS` on success

**Example:**
```cpp
AgentConfig config = {
    .name = "CodeAnalyzer",
    .type = AGENT_TYPE_AUTONOMOUS,
    .capabilities = { "analyze", "suggest", "refactor" },
    .capabilityCount = 3,
    .modelId = "llama-7b",
    .maxIterations = 10,
    .enablePlanning = true
};

AgentHandle agent;
SDK_Agent_Create(sdk, &config, &agent);
```

---

#### SDK_Agent_Destroy

Destroys an agent.

```cpp
SDKResult SDK_Agent_Destroy(
    SDKHandle sdk,
    AgentHandle agent
);
```

**Parameters:**
- `sdk` - SDK handle
- `agent` - Agent handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Agent_ExecuteTask

Executes a task with an agent.

```cpp
SDKResult SDK_Agent_ExecuteTask(
    SDKHandle sdk,
    AgentHandle agent,
    const char* task,
    const TaskOptions* options,
    TaskResult* outResult
);
```

**Parameters:**
- `sdk` - SDK handle
- `agent` - Agent handle
- `task` - Task description
- `options` - Task options
- `outResult` - Output result

**Returns:** `SDK_SUCCESS` on success

**Example:**
```cpp
TaskOptions options = {
    .timeout = 60000,  // 60 seconds
    .maxSteps = 20,
    .allowFileOperations = true,
    .allowNetworkAccess = false
};

TaskResult result;
SDK_Agent_ExecuteTask(sdk, agent, 
                      "Refactor this function to use modern C++",
                      &options, &result);

if (result.success) {
    printf("Task completed: %s\n", result.summary);
}
```

---

#### SDK_Agent_ExecuteTaskAsync

Executes a task asynchronously.

```cpp
SDKResult SDK_Agent_ExecuteTaskAsync(
    SDKHandle sdk,
    AgentHandle agent,
    const char* task,
    const TaskOptions* options,
    TaskProgressCallback progressCallback,
    TaskCompleteCallback completeCallback,
    void* userData,
    AsyncTaskHandle* outTask
);
```

**Parameters:**
- `sdk` - SDK handle
- `agent` - Agent handle
- `task` - Task description
- `options` - Task options
- `progressCallback` - Progress callback
- `completeCallback` - Completion callback
- `userData` - User data
- `outTask` - Output task handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Agent_CancelTask

Cancels a running task.

```cpp
SDKResult SDK_Agent_CancelTask(
    SDKHandle sdk,
    AsyncTaskHandle task
);
```

**Parameters:**
- `sdk` - SDK handle
- `task` - Task handle

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Agent_GetStatus

Gets agent status.

```cpp
SDKResult SDK_Agent_GetStatus(
    SDKHandle sdk,
    AgentHandle agent,
    AgentStatus* outStatus
);
```

**Parameters:**
- `sdk` - SDK handle
- `agent` - Agent handle
- `outStatus` - Output status

**Returns:** `SDK_SUCCESS` on success

---

#### SDK_Agent_GetCapabilities

Gets agent capabilities.

```cpp
SDKResult SDK_Agent_GetCapabilities(
    SDKHandle sdk,
    AgentHandle agent,
    char** capabilities,
    uint32_t* capabilityCount
);
```

**Parameters:**
- `sdk` - SDK handle
- `agent` - Agent handle
- `capabilities` - Array to receive capability names
- `capabilityCount` - On input: array size; on output: actual count

**Returns:** `SDK_SUCCESS` on success

---

## Data Types

### ModelConfig

```cpp
struct ModelConfig {
    BackendType backend;
    uint32_t contextSize;
    uint32_t gpuLayers;
    uint32_t threads;
    uint32_t batchSize;
    float temperature;
    float topP;
    uint32_t topK;
    float repeatPenalty;
    char modelFormat[32];
};
```

### InferenceInput

```cpp
struct InferenceInput {
    const char* prompt;
    uint32_t maxTokens;
    float temperature;
    float topP;
    uint32_t topK;
    const char** stopSequences;
    uint32_t stopSequenceCount;
    uint32_t seed;
    bool stream;
};
```

### InferenceOutput

```cpp
struct InferenceOutput {
    char* text;
    uint32_t tokenCount;
    uint32_t promptTokens;
    uint64_t generationTime;
    float tokensPerSecond;
    bool truncated;
};
```

### ModelInfo

```cpp
struct ModelInfo {
    char name[128];
    char version[32];
    char architecture[64];
    uint64_t parameterCount;
    uint32_t contextLength;
    uint32_t embeddingLength;
    uint32_t layerCount;
    uint32_t headCount;
    VocabularyInfo vocabulary;
};
```

### RouterConfig

```cpp
struct RouterConfig {
    RoutingStrategy strategy;
    uint32_t maxModels;
    uint32_t timeout;
    bool enableLoadBalancing;
    bool enableFailover;
    float latencyWeight;
    float qualityWeight;
    float costWeight;
};
```

### RoutingRequest

```cpp
struct RoutingRequest {
    const char* prompt;
    uint32_t estimatedTokens;
    ModelRequirements requirements;
    float minQuality;
    float maxLatency;
    float maxCost;
};
```

### RoutingResult

```cpp
struct RoutingResult {
    char modelId[64];
    float confidence;
    float estimatedLatency;
    float estimatedQuality;
    float estimatedCost;
    RoutingDecision decision;
};
```

### ChatConfig

```cpp
struct ChatConfig {
    char modelId[64];
    char systemPrompt[1024];
    uint32_t maxHistory;
    bool enableContext;
    bool enableSuggestions;
    float temperature;
    float topP;
};
```

### ChatMessage

```cpp
struct ChatMessage {
    MessageRole role;
    char content[4096];
    uint64_t timestamp;
    char modelId[64];
    uint32_t tokenCount;
};
```

### ChatResponse

```cpp
struct ChatResponse {
    char text[4096];
    uint32_t tokenCount;
    uint64_t generationTime;
    float tokensPerSecond;
    Suggestion* suggestions;
    uint32_t suggestionCount;
};
```

### AgentConfig

```cpp
struct AgentConfig {
    char name[128];
    AgentType type;
    char* capabilities[32];
    uint32_t capabilityCount;
    char modelId[64];
    uint32_t maxIterations;
    bool enablePlanning;
    bool enableReflection;
    uint32_t timeout;
};
```

### TaskOptions

```cpp
struct TaskOptions {
    uint32_t timeout;
    uint32_t maxSteps;
    bool allowFileOperations;
    bool allowNetworkAccess;
    bool allowCodeExecution;
    char workingDirectory[256];
};
```

### TaskResult

```cpp
struct TaskResult {
    bool success;
    char summary[1024];
    char details[8192];
    Action* actions;
    uint32_t actionCount;
    uint32_t stepsTaken;
    uint64_t executionTime;
};
```

### AgentStatus

```cpp
struct AgentStatus {
    AgentState state;
    char currentTask[256];
    uint32_t progress;
    uint32_t totalSteps;
    uint64_t startTime;
    uint64_t elapsedTime;
};
```

---

## Constants

### BackendType

```cpp
enum BackendType {
    BACKEND_LLAMA_CPP = 0,
    BACKEND_ONNX_RUNTIME = 1,
    BACKEND_TENSORRT = 2,
    BACKEND_CUSTOM = 3
};
```

### RoutingStrategy

```cpp
enum RoutingStrategy {
    ROUTING_LATENCY = 0,
    ROUTING_QUALITY = 1,
    ROUTING_COST = 2,
    ROUTING_BALANCED = 3,
    ROUTING_ADAPTIVE = 4
};
```

### MessageRole

```cpp
enum MessageRole {
    ROLE_SYSTEM = 0,
    ROLE_USER = 1,
    ROLE_ASSISTANT = 2,
    ROLE_TOOL = 3
};
```

### ContextType

```cpp
enum ContextType {
    CONTEXT_CODE = 0,
    CONTEXT_FILE = 1,
    CONTEXT_ERROR = 2,
    CONTEXT_SELECTION = 3,
    CONTEXT_TERMINAL = 4,
    CONTEXT_CUSTOM = 5
};
```

### AgentType

```cpp
enum AgentType {
    AGENT_TYPE_AUTONOMOUS = 0,
    AGENT_TYPE_ASSISTANT = 1,
    AGENT_TYPE_TOOL = 2,
    AGENT_TYPE_ORCHESTRATOR = 3
};
```

### AgentState

```cpp
enum AgentState {
    AGENT_STATE_IDLE = 0,
    AGENT_STATE_PLANNING = 1,
    AGENT_STATE_EXECUTING = 2,
    AGENT_STATE_WAITING = 3,
    AGENT_STATE_REFLECTING = 4,
    AGENT_STATE_ERROR = 5
};
```

---

## Summary

The AI API provides:

- ✅ **Model Inference API** - Load, run, and manage AI models
- ✅ **Model Router API** - Intelligent model selection and routing
- ✅ **Chat API** - Conversational AI with context management
- ✅ **Agent API** - Autonomous agent creation and execution
- ✅ **Streaming support** - Real-time token generation
- ✅ **Comprehensive data types** for all AI operations

**Status:** ✅ Complete

---

*End of AI API Documentation*
