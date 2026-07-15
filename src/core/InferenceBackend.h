//==============================================================================
// InferenceBackend.h - Abstraction layer for LLM inference providers
//
// Supports multiple backends:
// - Native: Your sovereign GGUF runtime (default)
// - Ollama: HTTP API to Ollama server
// - LlamaCpp: Direct llama.cpp integration
// - OpenAI: OpenAI-compatible APIs
//
// Design: Backend-agnostic interface. AgentSubsystem never knows which
// backend is being used.
//==============================================================================

#ifndef INFERENCE_BACKEND_H
#define INFERENCE_BACKEND_H

#include "AgentSubsystem.h"
#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Backend Types
//==============================================================================

typedef enum {
    BACKEND_NATIVE = 0,      // Your sovereign GGUF runtime
    BACKEND_OLLAMA,          // HTTP to Ollama
    BACKEND_LLAMACPP,        // Direct llama.cpp
    BACKEND_OPENAI,          // OpenAI API
    BACKEND_CUSTOM           // User-defined
} InferenceBackendType;

//==============================================================================
// Inference Request
//==============================================================================

typedef struct InferenceRequest {
    const char* prompt;           // Input prompt
    const char* system_prompt;    // Optional system context
    
    // Generation parameters
    int max_tokens;              // Max tokens to generate
    float temperature;           // Sampling temperature
    float top_p;                 // Nucleus sampling
    int top_k;                   // Top-k sampling
    float repeat_penalty;        // Repetition penalty
    
    // Streaming
    int stream;                  // 0 = blocking, 1 = streaming
    void (*stream_callback)(const char* token, void* user_data);
    void* user_data;
} InferenceRequest;

//==============================================================================
// Inference Result
//==============================================================================

typedef struct InferenceResult {
    char* text;                  // Generated text (caller allocates)
    size_t text_capacity;        // Buffer size
    size_t text_len;             // Actual length
    
    // Metadata
    int tokens_generated;
    int tokens_prompt;
    uint64_t duration_ms;
    float tokens_per_second;
    
    // Error
    int success;
    char error_message[256];
} InferenceResult;

//==============================================================================
// Backend Interface (vtable pattern for C)
//==============================================================================

typedef struct IInferenceBackend {
    // Backend metadata
    const char* name;
    InferenceBackendType type;
    
    // Lifecycle
    int (*Initialize)(const AgentConfig* config);
    int (*Shutdown)(void);
    int (*IsReady)(void);
    
    // Generation
    int (*Generate)(const InferenceRequest* request, InferenceResult* result);
    
    // Capabilities
    int (*SupportsStreaming)(void);
    int (*SupportsBatching)(void);
    int (*GetMaxContextLength)(void);
    
    // Model management
    int (*LoadModel)(const char* model_path);
    int (*UnloadModel)(void);
    int (*IsModelLoaded)(void);
    
    // Context caching (for conversation)
    int (*ClearContext)(void);
    int (*SaveContext)(const char* path);
    int (*LoadContext)(const char* path);
} IInferenceBackend;

//==============================================================================
// Backend Factory
//==============================================================================

// Create backend instance
IInferenceBackend* InferenceBackend_Create(InferenceBackendType type);

// Destroy backend instance
void InferenceBackend_Destroy(IInferenceBackend* backend);

// Get backend type from string
InferenceBackendType InferenceBackend_ParseType(const char* type_str);

// Get string from backend type
const char* InferenceBackend_TypeToString(InferenceBackendType type);

//==============================================================================
// Native Backend (Your Sovereign Runtime)
//==============================================================================

// Native backend implementation
IInferenceBackend* NativeBackend_Create(void);

// Native-specific: Access to underlying runtime
void* NativeBackend_GetModelContext(void);
int NativeBackend_GetKVCacheUsage(void);

//==============================================================================
// Ollama Backend
//==============================================================================

IInferenceBackend* OllamaBackend_Create(void);

//==============================================================================
// Global Backend Management
//==============================================================================

// Set global backend (used by AgentSubsystem)
int InferenceBackend_SetGlobal(IInferenceBackend* backend);
IInferenceBackend* InferenceBackend_GetGlobal(void);
int InferenceBackend_ClearGlobal(void);

#ifdef __cplusplus
}
#endif

#endif // INFERENCE_BACKEND_H
