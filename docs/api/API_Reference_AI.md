# Sovereign IDE — API Reference: AI SDK
## Complete API Documentation for AI/ML Functions

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** Complete

---

## 1. Overview

The AI SDK provides APIs for model loading, inference, tokenization, and AI-powered code analysis. It enables integration with local and remote AI models for intelligent code completion, analysis, and generation.

### 1.1 API Categories

| Category | Description | Header |
|----------|-------------|--------|
| Model Management | Load and manage AI models | `sdk/ai/model.h` |
| Inference | Run model inference | `sdk/ai/inference.h` |
| Tokenization | Text tokenization | `sdk/ai/tokenizer.h` |
| Embeddings | Generate embeddings | `sdk/ai/embeddings.h` |
| Code Analysis | AI-powered code analysis | `sdk/ai/analysis.h` |

---

## 2. Model Management API

### 2.1 Model Loading

```cpp
// sdk/ai/model.h

/**
 * Model formats
 */
typedef enum {
    MODEL_FORMAT_GGUF = 0,
    MODEL_FORMAT_GGML = 1,
    MODEL_FORMAT_SAFETENSORS = 2,
    MODEL_FORMAT_ONNX = 3
} ModelFormat;

/**
 * Model types
 */
typedef enum {
    MODEL_TYPE_LLM = 0,
    MODEL_TYPE_CODE = 1,
    MODEL_TYPE_EMBEDDING = 2,
    MODEL_TYPE_MULTIMODAL = 3
} ModelType;

/**
 * Model configuration
 */
typedef struct {
    char modelPath[512];
    ModelFormat format;
    ModelType type;
    uint32_t contextLength;
    uint32_t gpuLayers;
    float temperature;
    float topP;
    uint32_t topK;
    uint32_t maxTokens;
    char device[32];  // "cpu", "cuda", "vulkan"
} ModelConfig;

/**
 * Model information
 */
typedef struct {
    char modelId[64];
    char name[128];
    char version[32];
    uint64_t parameterCount;
    uint32_t vocabSize;
    uint32_t contextLength;
    uint32_t embeddingLength;
    bool quantized;
    uint32_t quantizationBits;
} ModelInfo;

/**
 * Load model
 * @param sdk SDK handle
 * @param config Model configuration
 * @param outModel Output model handle
 * @return SDKResult
 */
SDKResult SDK_Model_Load(
    SDKHandle sdk,
    const ModelConfig* config,
    ModelHandle* outModel
);

/**
 * Unload model
 * @param sdk SDK handle
 * @param model Model handle
 * @return SDKResult
 */
SDKResult SDK_Model_Unload(
    SDKHandle sdk,
    ModelHandle model
);

/**
 * Get model information
 * @param sdk SDK handle
 * @param model Model handle
 * @param outInfo Output model info
 * @return SDKResult
 */
SDKResult SDK_Model_GetInfo(
    SDKHandle sdk,
    ModelHandle model,
    ModelInfo* outInfo
);

/**
 * Check if model is loaded
 * @param sdk SDK handle
 * @param model Model handle
 * @param outLoaded Output loaded flag
 * @return SDKResult
 */
SDKResult SDK_Model_IsLoaded(
    SDKHandle sdk,
    ModelHandle model,
    bool* outLoaded
);
```

### 2.2 Model Discovery

```cpp
/**
 * Model discovery result
 */
typedef struct {
    char modelId[64];
    char name[128];
    char path[512];
    ModelFormat format;
    ModelType type;
    uint64_t size;
    uint64_t modifiedTime;
} ModelDiscoveryResult;

/**
 * Discover available models
 * @param sdk SDK handle
 * @param searchPath Search directory
 * @param outResults Output results array
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_Model_Discover(
    SDKHandle sdk,
    const char* searchPath,
    ModelDiscoveryResult** outResults,
    uint32_t* outCount
);

/**
 * Get loaded models
 * @param sdk SDK handle
 * @param outModels Output model handles
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_Model_GetLoaded(
    SDKHandle sdk,
    ModelHandle** outModels,
    uint32_t* outCount
);
```

---

## 3. Inference API

### 3.1 Text Generation

```cpp
// sdk/ai/inference.h

/**
 * Generation parameters
 */
typedef struct {
    float temperature;
    float topP;
    uint32_t topK;
    uint32_t maxTokens;
    float repeatPenalty;
    uint32_t repeatPenaltyTokens;
    char stopSequences[10][64];
    uint32_t stopSequenceCount;
} GenerationParams;

/**
 * Generation result
 */
typedef struct {
    char text[8192];
    uint32_t tokensGenerated;
    uint32_t tokensPrompt;
    uint64_t generationTimeMs;
    float tokensPerSecond;
    bool truncated;
} GenerationResult;

/**
 * Generate text
 * @param sdk SDK handle
 * @param model Model handle
 * @param prompt Input prompt
 * @param params Generation parameters
 * @param outResult Output result
 * @return SDKResult
 */
SDKResult SDK_Inference_Generate(
    SDKHandle sdk,
    ModelHandle model,
    const char* prompt,
    const GenerationParams* params,
    GenerationResult* outResult
);

/**
 * Generate text with streaming
 * @param sdk SDK handle
 * @param model Model handle
 * @param prompt Input prompt
 * @param params Generation parameters
 * @param callback Token callback
 * @param userData User data
 * @param outResult Output final result
 * @return SDKResult
 */
SDKResult SDK_Inference_GenerateStream(
    SDKHandle sdk,
    ModelHandle model,
    const char* prompt,
    const GenerationParams* params,
    TokenCallback callback,
    void* userData,
    GenerationResult* outResult
);

/**
 * Token callback function type
 */
typedef void (*TokenCallback)(
    const char* token,
    uint32_t tokenIndex,
    bool isLast,
    void* userData
);

/**
 * Cancel generation
 * @param sdk SDK handle
 * @param model Model handle
 * @return SDKResult
 */
SDKResult SDK_Inference_Cancel(
    SDKHandle sdk,
    ModelHandle model
);
```

### 3.2 Chat Completion

```cpp
/**
 * Message role
 */
typedef enum {
    ROLE_SYSTEM = 0,
    ROLE_USER = 1,
    ROLE_ASSISTANT = 2
} MessageRole;

/**
 * Chat message
 */
typedef struct {
    MessageRole role;
    char content[4096];
} ChatMessage;

/**
 * Chat completion request
 */
typedef struct {
    ChatMessage* messages;
    uint32_t messageCount;
    GenerationParams params;
} ChatCompletionRequest;

/**
 * Chat completion result
 */
typedef struct {
    char content[8192];
    MessageRole role;
    uint32_t tokensGenerated;
    uint32_t tokensPrompt;
    uint64_t completionTimeMs;
} ChatCompletionResult;

/**
 * Complete chat
 * @param sdk SDK handle
 * @param model Model handle
 * @param request Chat request
 * @param outResult Output result
 * @return SDKResult
 */
SDKResult SDK_Inference_ChatComplete(
    SDKHandle sdk,
    ModelHandle model,
    const ChatCompletionRequest* request,
    ChatCompletionResult* outResult
);

/**
 * Complete chat with streaming
 * @param sdk SDK handle
 * @param model Model handle
 * @param request Chat request
 * @param callback Message callback
 * @param userData User data
 * @param outResult Output final result
 * @return SDKResult
 */
SDKResult SDK_Inference_ChatCompleteStream(
    SDKHandle sdk,
    ModelHandle model,
    const ChatCompletionRequest* request,
    MessageCallback callback,
    void* userData,
    ChatCompletionResult* outResult
);

/**
 * Message callback function type
 */
typedef void (*MessageCallback)(
    const char* content,
    bool isComplete,
    void* userData
);
```

---

## 4. Tokenization API

### 4.1 Token Operations

```cpp
// sdk/ai/tokenizer.h

/**
 * Token information
 */
typedef struct {
    uint32_t id;
    char text[64];
    bool special;
} TokenInfo;

/**
 * Tokenize text
 * @param sdk SDK handle
 * @param model Model handle
 * @param text Text to tokenize
 * @param outTokens Output token array
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_Tokenizer_Tokenize(
    SDKHandle sdk,
    ModelHandle model,
    const char* text,
    TokenInfo** outTokens,
    uint32_t* outCount
);

/**
 * Detokenize tokens
 * @param sdk SDK handle
 * @param model Model handle
 * @param tokens Token array
 * @param tokenCount Token count
 * @param outText Output text
 * @param textSize Text buffer size
 * @return SDKResult
 */
SDKResult SDK_Tokenizer_Detokenize(
    SDKHandle sdk,
    ModelHandle model,
    const TokenInfo* tokens,
    uint32_t tokenCount,
    char* outText,
    uint32_t textSize
);

/**
 * Count tokens
 * @param sdk SDK handle
 * @param model Model handle
 * @param text Text to count
 * @param outCount Output token count
 * @return SDKResult
 */
SDKResult SDK_Tokenizer_Count(
    SDKHandle sdk,
    ModelHandle model,
    const char* text,
    uint32_t* outCount
);

/**
 * Get vocabulary size
 * @param sdk SDK handle
 * @param model Model handle
 * @param outSize Output vocabulary size
 * @return SDKResult
 */
SDKResult SDK_Tokenizer_GetVocabSize(
    SDKHandle sdk,
    ModelHandle model,
    uint32_t* outSize
);

/**
 * Get token by ID
 * @param sdk SDK handle
 * @param model Model handle
 * @param tokenId Token ID
 * @param outToken Output token info
 * @return SDKResult
 */
SDKResult SDK_Tokenizer_GetToken(
    SDKHandle sdk,
    ModelHandle model,
    uint32_t tokenId,
    TokenInfo* outToken
);
```

---

## 5. Embeddings API

### 5.1 Embedding Generation

```cpp
// sdk/ai/embeddings.h

/**
 * Embedding configuration
 */
typedef struct {
    uint32_t dimensions;
    bool normalize;
    char pooling[16];  // "mean", "cls", "last"
} EmbeddingConfig;

/**
 * Embedding result
 */
typedef struct {
    float* values;
    uint32_t dimensions;
    uint64_t generationTimeMs;
} EmbeddingResult;

/**
 * Generate embedding
 * @param sdk SDK handle
 * @param model Model handle
 * @param text Input text
 * @param config Embedding configuration
 * @param outResult Output result
 * @return SDKResult
 */
SDKResult SDK_Embeddings_Generate(
    SDKHandle sdk,
    ModelHandle model,
    const char* text,
    const EmbeddingConfig* config,
    EmbeddingResult* outResult
);

/**
 * Generate embeddings for multiple texts
 * @param sdk SDK handle
 * @param model Model handle
 * @param texts Text array
 * @param textCount Text count
 * @param config Embedding configuration
 * @param outResults Output results array
 * @return SDKResult
 */
SDKResult SDK_Embeddings_GenerateBatch(
    SDKHandle sdk,
    ModelHandle model,
    const char** texts,
    uint32_t textCount,
    const EmbeddingConfig* config,
    EmbeddingResult** outResults
);

/**
 * Calculate cosine similarity
 * @param sdk SDK handle
 * @param embedding1 First embedding
 * @param embedding2 Second embedding
 * @param outSimilarity Output similarity
 * @return SDKResult
 */
SDKResult SDK_Embeddings_CosineSimilarity(
    SDKHandle sdk,
    const EmbeddingResult* embedding1,
    const EmbeddingResult* embedding2,
    float* outSimilarity
);

/**
 * Free embedding result
 * @param sdk SDK handle
 * @param result Result to free
 * @return SDKResult
 */
SDKResult SDK_Embeddings_Free(
    SDKHandle sdk,
    EmbeddingResult* result
);
```

---

## 6. Code Analysis API

### 6.1 AI-Powered Analysis

```cpp
// sdk/ai/analysis.h

/**
 * Analysis types
 */
typedef enum {
    ANALYSIS_COMPLETE = 0,
    ANALYSIS_SUMMARIZE = 1,
    ANALYSIS_EXPLAIN = 2,
    ANALYSIS_REFACTOR = 3,
    ANALYSIS_OPTIMIZE = 4,
    ANALYSIS_SECURITY = 5,
    ANALYSIS_BUGS = 6
} AnalysisType;

/**
 * Analysis request
 */
typedef struct {
    AnalysisType type;
    char code[16384];
    char language[32];
    char context[4096];
    GenerationParams params;
} AnalysisRequest;

/**
 * Analysis result
 */
typedef struct {
    char result[16384];
    char suggestions[10][512];
    uint32_t suggestionCount;
    float confidence;
    uint64_t analysisTimeMs;
} AnalysisResult;

/**
 * Analyze code
 * @param sdk SDK handle
 * @param model Model handle
 * @param request Analysis request
 * @param outResult Output result
 * @return SDKResult
 */
SDKResult SDK_Analysis_Analyze(
    SDKHandle sdk,
    ModelHandle model,
    const AnalysisRequest* request,
    AnalysisResult* outResult
);

/**
 * Generate code completion
 * @param sdk SDK handle
 * @param model Model handle
 * @param prefix Code prefix
 * @param suffix Code suffix
 * @param language Programming language
 * @param maxTokens Maximum tokens to generate
 * @param outCompletion Output completion
 * @return SDKResult
 */
SDKResult SDK_Analysis_Complete(
    SDKHandle sdk,
    ModelHandle model,
    const char* prefix,
    const char* suffix,
    const char* language,
    uint32_t maxTokens,
    char* outCompletion
);

/**
 * Generate inline completion
 * @param sdk SDK handle
 * @param model Model handle
 * @param code Current code
 * @param cursorPosition Cursor position
 * @param language Programming language
 * @param outCompletion Output completion
 * @return SDKResult
 */
SDKResult SDK_Analysis_CompleteInline(
    SDKHandle sdk,
    ModelHandle model,
    const char* code,
    uint32_t cursorPosition,
    const char* language,
    char* outCompletion
);
```

---

## 7. Usage Examples

### 7.1 Loading and Using a Model

```cpp
#include <sdk/core/init.h>
#include <sdk/ai/model.h>
#include <sdk/ai/inference.h>
#include <sdk/ai/tokenizer.h>

void generateCode(SDKHandle sdk) {
    // Configure model
    ModelConfig config = {
        .modelPath = "models/codellama-7b.Q4_K_M.gguf",
        .format = MODEL_FORMAT_GGUF,
        .type = MODEL_TYPE_CODE,
        .contextLength = 4096,
        .gpuLayers = 35,
        .temperature = 0.7f,
        .topP = 0.9f,
        .topK = 40,
        .maxTokens = 512,
        .device = "cuda"
    };
    
    // Load model
    ModelHandle model;
    SDK_Model_Load(sdk, &config, &model);
    
    // Get model info
    ModelInfo info;
    SDK_Model_GetInfo(sdk, model, &info);
    printf("Loaded: %s (%llu parameters)\n", info.name, info.parameterCount);
    
    // Generate code
    const char* prompt = 
        "// Write a function to calculate factorial in C++\n"
        "unsigned long long factorial(int n) {\n";
    
    GenerationParams params = {
        .temperature = 0.7f,
        .topP = 0.9f,
        .topK = 40,
        .maxTokens = 256,
        .repeatPenalty = 1.1f,
        .repeatPenaltyTokens = 64,
        .stopSequenceCount = 1
    };
    strcpy(params.stopSequences[0], "}\n}");
    
    GenerationResult result;
    SDK_Inference_Generate(sdk, model, prompt, &params, &result);
    
    printf("Generated:\n%s\n", result.text);
    printf("Tokens: %d, Time: %llums, TPS: %.2f\n",
           result.tokensGenerated,
           result.generationTimeMs,
           result.tokensPerSecond);
    
    // Cleanup
    SDK_Model_Unload(sdk, model);
}
```

### 7.2 Streaming Generation

```cpp
void streamCallback(const char* token, uint32_t tokenIndex, 
                    bool isLast, void* userData) {
    printf("%s", token);
    fflush(stdout);
}

void generateWithStreaming(SDKHandle sdk, ModelHandle model) {
    const char* prompt = "Explain quantum computing:";
    
    GenerationParams params = {
        .temperature = 0.8f,
        .topP = 0.95f,
        .maxTokens = 1024
    };
    
    GenerationResult result;
    SDK_Inference_GenerateStream(sdk, model, prompt, &params,
                                  streamCallback, NULL, &result);
    
    printf("\n\nTotal tokens: %d, TPS: %.2f\n",
           result.tokensGenerated,
           result.tokensPerSecond);
}
```

### 7.3 Chat Completion

```cpp
void chatExample(SDKHandle sdk, ModelHandle model) {
    ChatMessage messages[3] = {
        {
            .role = ROLE_SYSTEM,
            .content = "You are a helpful coding assistant."
        },
        {
            .role = ROLE_USER,
            .content = "How do I reverse a linked list in C++?"
        },
        {
            .role = ROLE_ASSISTANT,
            .content = ""
        }
    };
    
    ChatCompletionRequest request = {
        .messages = messages,
        .messageCount = 3,
        .params = {
            .temperature = 0.7f,
            .maxTokens = 512
        }
    };
    
    ChatCompletionResult result;
    SDK_Inference_ChatComplete(sdk, model, &request, &result);
    
    printf("Assistant: %s\n", result.content);
}
```

---

## Summary

The AI SDK API provides:

- ✅ Multi-format model loading (GGUF, GGML, SafeTensors, ONNX)
- ✅ Text generation with streaming support
- ✅ Chat completion API
- ✅ Tokenization and detokenization
- ✅ Embedding generation
- ✅ AI-powered code analysis
- ✅ Code completion

**Status:** Complete

---

*End of API Reference: AI SDK*
