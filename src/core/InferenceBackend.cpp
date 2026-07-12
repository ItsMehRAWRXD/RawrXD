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
            // TODO: Implement llama.cpp backend
            fprintf(stderr, "[InferenceBackend] llama.cpp backend not yet implemented\n");
            return nullptr;
            
        case BACKEND_OPENAI:
            // TODO: Implement OpenAI backend
            fprintf(stderr, "[InferenceBackend] OpenAI backend not yet implemented\n");
            return nullptr;
            
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
