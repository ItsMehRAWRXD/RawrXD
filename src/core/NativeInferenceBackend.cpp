//==============================================================================
// NativeInferenceBackend.cpp - Your sovereign GGUF inference engine
//
// This backend uses your existing runtime:
// - GGUF loader
// - Tokenizer
// - Transformer kernels
// - KV cache
// - Sampler
// - Vulkan/CPU execution
//
// No HTTP. No external dependencies. Fully sovereign.
//==============================================================================

#include "InferenceBackend.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

// This file is now a wrapper around RawrXD::CPUInferenceEngine
// See NativeInferenceBackend_Wrapper.cpp for the actual implementation
// that bridges to your existing inference runtime.

// Include the wrapper implementation directly
#include "NativeInferenceBackend_Wrapper.cpp"

//==============================================================================
// Native Backend State
//==============================================================================

typedef struct NativeBackendState {
    ModelContext model;
    Tokenizer tokenizer;
    InferenceContext inference;
    
    char model_path[512];
    int max_context_length;
    int is_initialized;
    int is_model_loaded;
} NativeBackendState;

static NativeBackendState g_native_state = {0};

//==============================================================================
// Timing
//==============================================================================

static uint64_t GetTimeMs() {
    return GetTickCount64();
}

//==============================================================================
// Native Backend Implementation
//==============================================================================

static int Native_Initialize(const AgentConfig* config) {
    if (g_native_state.is_initialized) {
        return 0;  // Already initialized
    }
    
    printf("[NativeBackend] Initializing sovereign inference...\n");
    
    // Store configuration
    if (config && config->model_path[0]) {
        strncpy(g_native_state.model_path, config->model_path, sizeof(g_native_state.model_path) - 1);
    } else {
        // Default model path
        strncpy(g_native_state.model_path, "models/phi4.gguf", sizeof(g_native_state.model_path) - 1);
    }
    
    g_native_state.max_context_length = config ? config->context_size : 4096;
    
    // Note: We don't load the model here - lazy load on first use
    // This keeps startup fast
    
    g_native_state.is_initialized = 1;
    printf("[NativeBackend] Initialized. Model will load on first use: %s\n", g_native_state.model_path);
    
    return 0;
}

static int Native_Shutdown(void) {
    if (!g_native_state.is_initialized) {
        return 0;
    }
    
    printf("[NativeBackend] Shutting down...\n");
    
    if (g_native_state.inference) {
        Inference_Destroy(g_native_state.inference);
        g_native_state.inference = nullptr;
    }
    
    if (g_native_state.tokenizer) {
        Tokenizer_Destroy(g_native_state.tokenizer);
        g_native_state.tokenizer = nullptr;
    }
    
    if (g_native_state.model) {
        GGUF_FreeModel(g_native_state.model);
        g_native_state.model = nullptr;
    }
    
    g_native_state.is_model_loaded = 0;
    g_native_state.is_initialized = 0;
    
    printf("[NativeBackend] Shutdown complete.\n");
    return 0;
}

static int Native_IsReady(void) {
    return g_native_state.is_initialized;
}

static int Native_LoadModel(const char* model_path) {
    if (!g_native_state.is_initialized) {
        return -1;
    }
    
    // Unload existing model if any
    if (g_native_state.is_model_loaded) {
        Native_Shutdown();
        Native_Initialize(nullptr);  // Re-initialize
    }
    
    const char* path = model_path ? model_path : g_native_state.model_path;
    
    printf("[NativeBackend] Loading model: %s\n", path);
    
    // Load GGUF model
    g_native_state.model = GGUF_LoadModel(path);
    if (!g_native_state.model) {
        fprintf(stderr, "[NativeBackend] Failed to load model: %s\n", path);
        return -1;
    }
    
    // Create tokenizer (vocab is typically embedded in GGUF)
    // For now, assume vocab is at same path with .json extension
    char vocab_path[512];
    strncpy(vocab_path, path, sizeof(vocab_path) - 1);
    char* ext = strrchr(vocab_path, '.');
    if (ext) {
        strcpy(ext, "_vocab.json");
    }
    
    g_native_state.tokenizer = Tokenizer_Create(vocab_path);
    if (!g_native_state.tokenizer) {
        fprintf(stderr, "[NativeBackend] Failed to create tokenizer\n");
        GGUF_FreeModel(g_native_state.model);
        g_native_state.model = nullptr;
        return -1;
    }
    
    // Create inference context
    g_native_state.inference = Inference_Create(g_native_state.model);
    if (!g_native_state.inference) {
        fprintf(stderr, "[NativeBackend] Failed to create inference context\n");
        Tokenizer_Destroy(g_native_state.tokenizer);
        g_native_state.tokenizer = nullptr;
        GGUF_FreeModel(g_native_state.model);
        g_native_state.model = nullptr;
        return -1;
    }
    
    g_native_state.is_model_loaded = 1;
    printf("[NativeBackend] Model loaded successfully.\n");
    
    return 0;
}

static int Native_UnloadModel(void) {
    if (g_native_state.inference) {
        Inference_Destroy(g_native_state.inference);
        g_native_state.inference = nullptr;
    }
    
    if (g_native_state.tokenizer) {
        Tokenizer_Destroy(g_native_state.tokenizer);
        g_native_state.tokenizer = nullptr;
    }
    
    if (g_native_state.model) {
        GGUF_FreeModel(g_native_state.model);
        g_native_state.model = nullptr;
    }
    
    g_native_state.is_model_loaded = 0;
    return 0;
}

static int Native_IsModelLoaded(void) {
    return g_native_state.is_model_loaded;
}

static int Native_Generate(const InferenceRequest* request, InferenceResult* result) {
    if (!g_native_state.is_initialized) {
        snprintf(result->error_message, sizeof(result->error_message), 
                 "Native backend not initialized");
        return -1;
    }
    
    // Lazy load model on first use
    if (!g_native_state.is_model_loaded) {
        if (Native_LoadModel(nullptr) != 0) {
            snprintf(result->error_message, sizeof(result->error_message),
                     "Failed to load model: %s", g_native_state.model_path);
            return -1;
        }
    }
    
    uint64_t start_time = GetTimeMs();
    
    // Build full prompt with system context
    char full_prompt[AGENT_MAX_PROMPT];
    if (request->system_prompt && request->system_prompt[0]) {
        snprintf(full_prompt, sizeof(full_prompt), "%s\n\n%s",
                 request->system_prompt, request->prompt);
    } else {
        strncpy(full_prompt, request->prompt, sizeof(full_prompt) - 1);
        full_prompt[sizeof(full_prompt) - 1] = '\0';
    }
    
    // Tokenize prompt
    int prompt_tokens[4096];
    int prompt_len = Tokenizer_Encode(g_native_state.tokenizer, full_prompt, 
                                      prompt_tokens, 4096);
    if (prompt_len < 0) {
        snprintf(result->error_message, sizeof(result->error_message),
                 "Tokenization failed");
        return -1;
    }
    
    result->tokens_prompt = prompt_len;
    
    // Generate tokens
    int output_tokens[AGENT_MAX_RESPONSE];
    int max_output = request->max_tokens > 0 ? request->max_tokens : 2048;
    if (max_output > AGENT_MAX_RESPONSE) {
        max_output = AGENT_MAX_RESPONSE;
    }
    
    int generated_len = Inference_Generate(
        g_native_state.inference,
        prompt_tokens, prompt_len,
        output_tokens, max_output,
        request->temperature >= 0 ? request->temperature : 0.7f,
        request->top_p >= 0 ? request->top_p : 0.9f,
        request->top_k > 0 ? request->top_k : 40
    );
    
    if (generated_len < 0) {
        snprintf(result->error_message, sizeof(result->error_message),
                 "Generation failed");
        return -1;
    }
    
    result->tokens_generated = generated_len;
    
    // Detokenize
    int decode_result = Tokenizer_Decode(g_native_state.tokenizer, 
                                          output_tokens, generated_len,
                                          result->text, result->text_capacity);
    if (decode_result < 0) {
        snprintf(result->error_message, sizeof(result->error_message),
                 "Detokenization failed");
        return -1;
    }
    
    result->text_len = strlen(result->text);
    result->duration_ms = GetTimeMs() - start_time;
    result->tokens_per_second = (float)result->tokens_generated / (result->duration_ms / 1000.0f);
    result->success = 1;
    
    printf("[NativeBackend] Generated %d tokens in %llu ms (%.2f tok/s)\n",
           result->tokens_generated, result->duration_ms, result->tokens_per_second);
    
    return 0;
}

static int Native_SupportsStreaming(void) {
    // TODO: Implement streaming generation
    return 0;  // Not yet supported
}

static int Native_SupportsBatching(void) {
    return 0;  // Not yet supported
}

static int Native_GetMaxContextLength(void) {
    return g_native_state.max_context_length;
}

static int Native_ClearContext(void) {
    if (g_native_state.inference) {
        Inference_ClearKVCache(g_native_state.inference);
    }
    return 0;
}

static int Native_SaveContext(const char* path) {
    // TODO: Implement KV cache serialization
    (void)path;
    return -1;  // Not yet implemented
}

static int Native_LoadContext(const char* path) {
    // TODO: Implement KV cache deserialization
    (void)path;
    return -1;  // Not yet implemented
}

//==============================================================================
// Backend Factory
//==============================================================================

IInferenceBackend* NativeBackend_Create(void) {
    IInferenceBackend* backend = (IInferenceBackend*)malloc(sizeof(IInferenceBackend));
    if (!backend) return nullptr;
    
    memset(backend, 0, sizeof(IInferenceBackend));
    
    backend->name = "native";
    backend->type = BACKEND_NATIVE;
    
    backend->Initialize = Native_Initialize;
    backend->Shutdown = Native_Shutdown;
    backend->IsReady = Native_IsReady;
    
    backend->Generate = Native_Generate;
    
    backend->SupportsStreaming = Native_SupportsStreaming;
    backend->SupportsBatching = Native_SupportsBatching;
    backend->GetMaxContextLength = Native_GetMaxContextLength;
    
    backend->LoadModel = Native_LoadModel;
    backend->UnloadModel = Native_UnloadModel;
    backend->IsModelLoaded = Native_IsModelLoaded;
    
    backend->ClearContext = Native_ClearContext;
    backend->SaveContext = Native_SaveContext;
    backend->LoadContext = Native_LoadContext;
    
    return backend;
}

void* NativeBackend_GetModelContext(void) {
    return g_native_state.model;
}

int NativeBackend_GetKVCacheUsage(void) {
    if (!g_native_state.inference) return 0;
    return Inference_GetKVCacheUsage(g_native_state.inference);
}
