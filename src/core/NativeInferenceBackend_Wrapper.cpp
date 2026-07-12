//==============================================================================
// NativeInferenceBackend_Wrapper.cpp - Bridge to RawrXD::CPUInferenceEngine
//
// This file bridges the IInferenceBackend interface to your existing
// CPUInferenceEngine class from cpu_inference_engine_fixed.h
//==============================================================================

#include "InferenceBackend.h"
#include "cpu_inference_engine_fixed.h"  // Your existing header
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

using namespace RawrXD;

//==============================================================================
// Wrapper State
//==============================================================================

typedef struct NativeWrapperState {
    CPUInferenceEngine* engine;
    char model_path[512];
    int is_initialized;
    int is_model_loaded;
    
    // Generation state for streaming
    std::string accumulated_response;
    int tokens_generated;
} NativeWrapperState;

static NativeWrapperState g_wrapper_state = {0};

//==============================================================================
// Streaming Callback
//==============================================================================

static void OnTokenGenerated(const std::string& token, void* user_data) {
    NativeWrapperState* state = (NativeWrapperState*)user_data;
    state->accumulated_response += token;
    state->tokens_generated++;
}

//==============================================================================
// Backend Implementation
//==============================================================================

static int Wrapper_Initialize(const AgentConfig* config) {
    if (g_wrapper_state.is_initialized) {
        return 0;
    }
    
    printf("[NativeBackend] Initializing CPUInferenceEngine wrapper...\n");
    
    // Create engine instance
    g_wrapper_state.engine = new CPUInferenceEngine();
    if (!g_wrapper_state.engine) {
        fprintf(stderr, "[NativeBackend] Failed to create CPUInferenceEngine\n");
        return -1;
    }
    
    // Store model path
    if (config && config->model_path[0]) {
        strncpy(g_wrapper_state.model_path, config->model_path, sizeof(g_wrapper_state.model_path) - 1);
    } else {
        strcpy(g_wrapper_state.model_path, "models/phi4.gguf");
    }
    
    // Set generation parameters from config
    if (config) {
        g_wrapper_state.engine->SetTemperature(config->default_temperature);
    }
    
    g_wrapper_state.is_initialized = 1;
    printf("[NativeBackend] Wrapper initialized. Model path: %s\n", g_wrapper_state.model_path);
    
    return 0;
}

static int Wrapper_Shutdown(void) {
    if (!g_wrapper_state.is_initialized) {
        return 0;
    }
    
    printf("[NativeBackend] Shutting down...\n");
    
    if (g_wrapper_state.engine) {
        delete g_wrapper_state.engine;
        g_wrapper_state.engine = nullptr;
    }
    
    g_wrapper_state.is_model_loaded = 0;
    g_wrapper_state.is_initialized = 0;
    
    printf("[NativeBackend] Shutdown complete.\n");
    return 0;
}

static int Wrapper_IsReady(void) {
    return g_wrapper_state.is_initialized;
}

static int Wrapper_LoadModel(const char* model_path) {
    if (!g_wrapper_state.is_initialized || !g_wrapper_state.engine) {
        return -1;
    }
    
    const char* path = model_path ? model_path : g_wrapper_state.model_path;
    
    printf("[NativeBackend] Loading model: %s\n", path);
    
    bool success = g_wrapper_state.engine->LoadModel(path);
    if (!success) {
        fprintf(stderr, "[NativeBackend] Failed to load model: %s\n", path);
        return -1;
    }
    
    g_wrapper_state.is_model_loaded = 1;
    printf("[NativeBackend] Model loaded successfully.\n");
    printf("[NativeBackend]   Vocab size: %d\n", g_wrapper_state.engine->GetVocabSize());
    printf("[NativeBackend]   Embedding dim: %d\n", g_wrapper_state.engine->GetEmbeddingDim());
    printf("[NativeBackend]   Layers: %d\n", g_wrapper_state.engine->GetNumLayers());
    
    return 0;
}

static int Wrapper_UnloadModel(void) {
    if (g_wrapper_state.engine) {
        g_wrapper_state.engine->ClearCache();
    }
    g_wrapper_state.is_model_loaded = 0;
    return 0;
}

static int Wrapper_IsModelLoaded(void) {
    if (!g_wrapper_state.engine) return 0;
    return g_wrapper_state.engine->IsModelLoaded() ? 1 : 0;
}

static int Wrapper_Generate(const InferenceRequest* request, InferenceResult* result) {
    if (!g_wrapper_state.is_initialized || !g_wrapper_state.engine) {
        snprintf(result->error_message, sizeof(result->error_message),
                 "Native backend not initialized");
        return -1;
    }
    
    // Lazy load model
    if (!g_wrapper_state.is_model_loaded) {
        if (Wrapper_LoadModel(nullptr) != 0) {
            snprintf(result->error_message, sizeof(result->error_message),
                     "Failed to load model: %s", g_wrapper_state.model_path);
            return -1;
        }
    }
    
    uint64_t start_time = GetTickCount64();
    
    // Build full prompt
    std::string full_prompt;
    if (request->system_prompt && request->system_prompt[0]) {
        full_prompt = std::string(request->system_prompt) + "\n\n" + request->prompt;
    } else {
        full_prompt = request->prompt ? request->prompt : "";
    }
    
    // Tokenize
    std::vector<int32_t> input_tokens = g_wrapper_state.engine->Tokenize(full_prompt);
    if (input_tokens.empty()) {
        snprintf(result->error_message, sizeof(result->error_message),
                 "Tokenization failed");
        return -1;
    }
    
    result->tokens_prompt = (int)input_tokens.size();
    
    // Set generation parameters
    if (request->temperature >= 0) {
        g_wrapper_state.engine->SetTemperature(request->temperature);
    }
    if (request->top_k > 0) {
        g_wrapper_state.engine->SetTopK(request->top_k);
    }
    
    // Reset accumulation state
    g_wrapper_state.accumulated_response.clear();
    g_wrapper_state.tokens_generated = 0;
    
    // Generate with streaming
    int max_tokens = request->max_tokens > 0 ? request->max_tokens : 2048;
    
    // For non-streaming, we accumulate in the callback
    if (request->stream && request->stream_callback) {
        // True streaming - call user's callback for each token
        g_wrapper_state.engine->GenerateStreaming(
            input_tokens,
            max_tokens,
            [request](const std::string& token) {
                request->stream_callback(token.c_str(), request->user_data);
            },
            nullptr,  // complete callback
            nullptr   // token id callback
        );
    } else {
        // Blocking generation - accumulate and return
        g_wrapper_state.engine->GenerateStreaming(
            input_tokens,
            max_tokens,
            [](const std::string& token) {
                g_wrapper_state.accumulated_response += token;
                g_wrapper_state.tokens_generated++;
            },
            nullptr,
            nullptr
        );
    }
    
    // Copy result
    if (g_wrapper_state.accumulated_response.length() < result->text_capacity) {
        strcpy(result->text, g_wrapper_state.accumulated_response.c_str());
        result->text_len = g_wrapper_state.accumulated_response.length();
    } else {
        // Truncate if too long
        strncpy(result->text, g_wrapper_state.accumulated_response.c_str(), result->text_capacity - 1);
        result->text[result->text_capacity - 1] = '\0';
        result->text_len = result->text_capacity - 1;
    }
    
    result->tokens_generated = g_wrapper_state.tokens_generated;
    result->duration_ms = GetTickCount64() - start_time;
    result->tokens_per_second = result->duration_ms > 0 
        ? (float)result->tokens_generated / (result->duration_ms / 1000.0f) 
        : 0;
    result->success = 1;
    
    printf("[NativeBackend] Generated %d tokens in %llu ms (%.2f tok/s)\n",
           result->tokens_generated, result->duration_ms, result->tokens_per_second);
    
    return 0;
}

static int Wrapper_SupportsStreaming(void) {
    return 1;  // CPUInferenceEngine supports streaming
}

static int Wrapper_SupportsBatching(void) {
    return 0;  // Not yet supported
}

static int Wrapper_GetMaxContextLength(void) {
    if (!g_wrapper_state.engine) return 4096;
    // This would need to be exposed from CPUInferenceEngine
    return 4096;  // Default
}

static int Wrapper_ClearContext(void) {
    if (g_wrapper_state.engine) {
        g_wrapper_state.engine->ClearCache();
    }
    return 0;
}

static int Wrapper_SaveContext(const char* path) {
    // TODO: Implement KV cache serialization
    (void)path;
    return -1;
}

static int Wrapper_LoadContext(const char* path) {
    // TODO: Implement KV cache deserialization
    (void)path;
    return -1;
}

//==============================================================================
// Backend Factory
//==============================================================================

extern "C" IInferenceBackend* NativeBackend_Create(void) {
    IInferenceBackend* backend = (IInferenceBackend*)malloc(sizeof(IInferenceBackend));
    if (!backend) return nullptr;
    
    memset(backend, 0, sizeof(IInferenceBackend));
    
    backend->name = "native";
    backend->type = BACKEND_NATIVE;
    
    backend->Initialize = Wrapper_Initialize;
    backend->Shutdown = Wrapper_Shutdown;
    backend->IsReady = Wrapper_IsReady;
    
    backend->Generate = Wrapper_Generate;
    
    backend->SupportsStreaming = Wrapper_SupportsStreaming;
    backend->SupportsBatching = Wrapper_SupportsBatching;
    backend->GetMaxContextLength = Wrapper_GetMaxContextLength;
    
    backend->LoadModel = Wrapper_LoadModel;
    backend->UnloadModel = Wrapper_UnloadModel;
    backend->IsModelLoaded = Wrapper_IsModelLoaded;
    
    backend->ClearContext = Wrapper_ClearContext;
    backend->SaveContext = Wrapper_SaveContext;
    backend->LoadContext = Wrapper_LoadContext;
    
    return backend;
}

extern "C" CPUInferenceEngine* NativeBackend_GetEngine(void) {
    return g_wrapper_state.engine;
}

extern "C" int NativeBackend_GetMemoryUsage(void) {
    if (!g_wrapper_state.engine) return 0;
    return (int)g_wrapper_state.engine->GetMemoryUsage();
}
