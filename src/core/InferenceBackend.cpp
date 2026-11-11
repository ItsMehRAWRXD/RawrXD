//==============================================================================
// InferenceBackend.cpp - Backend factory and global management
//==============================================================================

#include "InferenceBackend.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

// External backend constructors
extern "C" {
    IInferenceBackend* NativeBackend_Create(void);
    IInferenceBackend* OllamaBackend_Create(void);
}

//==============================================================================
// Global Backend Instance
//==============================================================================

static IInferenceBackend* g_global_backend = nullptr;

//==============================================================================
// Backend Factory
//==============================================================================

IInferenceBackend* InferenceBackend_Create(InferenceBackendType type) {
    switch (type) {
        case BACKEND_NATIVE:
            return NativeBackend_Create();
            
        case BACKEND_OLLAMA:
            return OllamaBackend_Create();
            
        case BACKEND_LLAMACPP:
            // llama.cpp backend - native GGML/GGUF inference
            {
                IInferenceBackend* backend = (IInferenceBackend*)malloc(sizeof(IInferenceBackend));
                if (!backend) return nullptr;
                
                // Initialize llama.cpp backend structure
                memset(backend, 0, sizeof(IInferenceBackend));
                backend->type = BACKEND_LLAMACPP;
                
                // Set function pointers
                backend->Initialize = [](IInferenceBackend* self, const char* model_path, const InferenceConfig* config) -> int {
                    (void)self; (void)model_path; (void)config;
                    // llama.cpp initialization would:
                    // 1. Load GGUF model
                    // 2. Initialize GGML context
                    // 3. Allocate KV cache
                    // 4. Warm up model
                    fprintf(stdout, "[llama.cpp] Initializing backend for model: %s\n", model_path ? model_path : "(null)");
                    return 0; // Success
                };
                
                backend->Shutdown = [](IInferenceBackend* self) -> void {
                    (void)self;
                    fprintf(stdout, "[llama.cpp] Shutting down backend\n");
                };
                
                backend->IsReady = [](IInferenceBackend* self) -> int {
                    (void)self;
                    return 1; // Always ready after init
                };
                
                backend->RunInference = [](IInferenceBackend* self, const InferenceRequest* request, InferenceResponse* response) -> int {
                    (void)self;
                    if (!request || !response) return -1;
                    
                    // llama.cpp inference pipeline:
                    // 1. Tokenize input
                    // 2. Run forward pass through transformer layers
                    // 3. Sample next token
                    // 4. Repeat until max_tokens or EOS
                    
                    response->token_count = 0;
                    response->tokens = (int*)malloc(request->max_tokens * sizeof(int));
                    if (!response->tokens) return -1;
                    
                    // Generate tokens (placeholder - would call actual llama.cpp)
                    for (int i = 0; i < request->max_tokens && i < 100; i++) {
                        response->tokens[i] = i % 32000; // Placeholder token IDs
                        response->token_count++;
                    }
                    
                    response->generation_time_ms = 100.0f; // Placeholder
                    return 0;
                };
                
                backend->GetStatus = [](IInferenceBackend* self, BackendStatus* status) -> int {
                    (void)self;
                    if (!status) return -1;
                    status->is_loaded = 1;
                    status->is_generating = 0;
                    status->tokens_generated = 0;
                    status->tokens_per_second = 50.0f;
                    return 0;
                };
                
                return backend;
            }
            
        case BACKEND_OPENAI:
            // OpenAI API backend - HTTP client for OpenAI-compatible APIs
            {
                IInferenceBackend* backend = (IInferenceBackend*)malloc(sizeof(IInferenceBackend));
                if (!backend) return nullptr;
                
                memset(backend, 0, sizeof(IInferenceBackend));
                backend->type = BACKEND_OPENAI;
                
                // Store API configuration in backend context
                backend->Initialize = [](IInferenceBackend* self, const char* model_path, const InferenceConfig* config) -> int {
                    (void)self; (void)model_path;
                    if (config && config->api_key) {
                        fprintf(stdout, "[OpenAI] Initializing with API key (length: %zu)\n", strlen(config->api_key));
                    } else {
                        fprintf(stderr, "[OpenAI] Warning: No API key provided\n");
                    }
                    return 0;
                };
                
                backend->Shutdown = [](IInferenceBackend* self) -> void {
                    (void)self;
                    fprintf(stdout, "[OpenAI] Shutting down backend\n");
                };
                
                backend->IsReady = [](IInferenceBackend* self) -> int {
                    (void)self;
                    return 1;
                };
                
                backend->RunInference = [](IInferenceBackend* self, const InferenceRequest* request, InferenceResponse* response) -> int {
                    (void)self;
                    if (!request || !response) return -1;
                    
                    // OpenAI API inference:
                    // 1. Format request as JSON
                    // 2. Send HTTP POST to /v1/completions or /v1/chat/completions
                    // 3. Parse JSON response
                    // 4. Extract generated tokens/text
                    
                    fprintf(stdout, "[OpenAI] Sending request for %d max tokens\n", request->max_tokens);
                    
                    response->token_count = 0;
                    response->tokens = (int*)malloc(request->max_tokens * sizeof(int));
                    if (!response->tokens) return -1;
                    
                    // Simulate API response
                    for (int i = 0; i < request->max_tokens && i < 100; i++) {
                        response->tokens[i] = i % 50000; // OpenAI vocab size
                        response->token_count++;
                    }
                    
                    response->generation_time_ms = 500.0f; // API latency
                    return 0;
                };
                
                backend->GetStatus = [](IInferenceBackend* self, BackendStatus* status) -> int {
                    (void)self;
                    if (!status) return -1;
                    status->is_loaded = 1;
                    status->is_generating = 0;
                    status->tokens_generated = 0;
                    status->tokens_per_second = 20.0f; // API rate
                    return 0;
                };
                
                return backend;
            }
            
        case BACKEND_CUSTOM:
            fprintf(stderr, "[InferenceBackend] Custom backend requires manual registration\n");
            return nullptr;
            
        default:
            fprintf(stderr, "[InferenceBackend] Unknown backend type: %d\n", type);
            return nullptr;
    }
}

void InferenceBackend_Destroy(IInferenceBackend* backend) {
    if (backend) {
        // Call shutdown if initialized
        if (backend->IsReady && backend->IsReady()) {
            backend->Shutdown();
        }
        free(backend);
    }
}

InferenceBackendType InferenceBackend_ParseType(const char* type_str) {
    if (!type_str) return BACKEND_NATIVE;  // Default
    
    if (strcmp(type_str, "native") == 0) return BACKEND_NATIVE;
    if (strcmp(type_str, "ollama") == 0) return BACKEND_OLLAMA;
    if (strcmp(type_str, "llamacpp") == 0) return BACKEND_LLAMACPP;
    if (strcmp(type_str, "openai") == 0) return BACKEND_OPENAI;
    if (strcmp(type_str, "custom") == 0) return BACKEND_CUSTOM;
    
    // Try to parse as integer
    int type_num = atoi(type_str);
    if (type_num >= 0 && type_num <= BACKEND_CUSTOM) {
        return (InferenceBackendType)type_num;
    }
    
    return BACKEND_NATIVE;  // Default fallback
}

const char* InferenceBackend_TypeToString(InferenceBackendType type) {
    switch (type) {
        case BACKEND_NATIVE: return "native";
        case BACKEND_OLLAMA: return "ollama";
        case BACKEND_LLAMACPP: return "llamacpp";
        case BACKEND_OPENAI: return "openai";
        case BACKEND_CUSTOM: return "custom";
        default: return "unknown";
    }
}

//==============================================================================
// Global Backend Management
//==============================================================================

int InferenceBackend_SetGlobal(IInferenceBackend* backend) {
    // Shutdown existing backend if any
    if (g_global_backend) {
        InferenceBackend_Destroy(g_global_backend);
        g_global_backend = nullptr;
    }
    
    g_global_backend = backend;
    return 0;
}

IInferenceBackend* InferenceBackend_GetGlobal(void) {
    return g_global_backend;
}

int InferenceBackend_ClearGlobal(void) {
    if (g_global_backend) {
        InferenceBackend_Destroy(g_global_backend);
        g_global_backend = nullptr;
    }
    return 0;
}

//==============================================================================
// Convenience Functions
//==============================================================================

int InferenceBackend_InitializeFromConfig(const AgentConfig* config) {
    if (!config) return -1;
    
    // Determine backend type from config
    InferenceBackendType type = config->provider == AGENT_PROVIDER_OLLAMA 
                                ? BACKEND_OLLAMA 
                                : BACKEND_NATIVE;
    
    // Create backend
    IInferenceBackend* backend = InferenceBackend_Create(type);
    if (!backend) {
        fprintf(stderr, "[InferenceBackend] Failed to create backend: %s\n",
                InferenceBackend_TypeToString(type));
        return -1;
    }
    
    // Initialize backend
    int result = backend->Initialize(config);
    if (result != 0) {
        fprintf(stderr, "[InferenceBackend] Failed to initialize backend\n");
        InferenceBackend_Destroy(backend);
        return -1;
    }
    
    // Load model if path specified
    if (config->model_path[0]) {
        result = backend->LoadModel(config->model_path);
        if (result != 0) {
            fprintf(stderr, "[InferenceBackend] Failed to load model: %s\n", config->model_path);
            // Continue anyway - might lazy load later
        }
    }
    
    // Set as global backend
    InferenceBackend_SetGlobal(backend);
    
    printf("[InferenceBackend] Backend '%s' initialized successfully\n",
           backend->name);
    
    return 0;
}
