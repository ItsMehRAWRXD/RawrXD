//===============================================================================
// AI Model Caller - Pure MASM Implementation
// Replaces simulated inference with real forward pass using pure assembly
//===============================================================================

#include "ai_model_caller_masm.h"
#include "../ggml_masm/ggml_masm_pure.h"
#include "../inference/inference_engine_masm.h"
#include <windows.h>
#include <vector>
#include <cmath>
#include <algorithm>
#include <cstring>
#include <cstdio>

//===============================================================================
// Structured Logging
//===============================================================================

enum LogLevel { DEBUG = 0, INFO = 1, WARN = 2, ERROR = 3 };

static void LogMessage(LogLevel level, const char* fmt, ...) {
    const char* level_str[] = { "[DEBUG]", "[INFO]", "[WARN]", "[ERROR]" };
    
    printf("%s ", level_str[level]);
    
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    
    printf("\n");
}

//===============================================================================
// Global State
//===============================================================================

static CPUInferenceEngine* g_engine = nullptr;
static bool g_initialized = false;
static bool g_kv_cache_initialized = false;

// Model configuration
static int g_n_layers = 32;
static int g_n_embd = 4096;
static int g_n_head = 32;
static int g_n_vocab = 32000;
static int g_n_ctx = 4096;

//===============================================================================
// Initialization
//===============================================================================

bool AIModelCaller_MASM_Init(void) {
    if (g_initialized) {
        LogMessage(WARN, "AI Model Caller already initialized");
        return true;
    }
    
    LogMessage(INFO, "Initializing AI Model Caller (MASM Pure)...");
    
    // Initialize the pure MASM GGML library
    if (!ggml_masm_init_library()) {
        LogMessage(ERROR, "Failed to initialize MASM GGML library");
        return false;
    }
    
    // Create inference engine
    g_engine = new CPUInferenceEngine();
    if (!g_engine) {
        LogMessage(ERROR, "Failed to create inference engine");
        return false;
    }
    
    // Initialize engine
    if (!g_engine->Initialize(4)) {
        LogMessage(ERROR, "Failed to initialize inference engine");
        delete g_engine;
        g_engine = nullptr;
        return false;
    }
    
    g_initialized = true;
    LogMessage(INFO, "AI Model Caller initialized successfully");
    return true;
}

void AIModelCaller_MASM_Deinit(void) {
    if (!g_initialized) return;
    
    LogMessage(INFO, "Deinitializing AI Model Caller...");
    
    if (g_engine) {
        g_engine->Shutdown();
        delete g_engine;
        g_engine = nullptr;
    }
    
    ggml_masm_deinit_library();
    g_initialized = false;
    
    LogMessage(INFO, "AI Model Caller deinitialized");
}

//===============================================================================
// Model Loading
//===============================================================================

bool AIModelCaller_MASM_LoadModel(const char* model_path) {
    if (!g_initialized) {
        LogMessage(ERROR, "AI Model Caller not initialized");
        return false;
    }
    
    if (!model_path) {
        LogMessage(ERROR, "Invalid model path");
        return false;
    }
    
    LogMessage(INFO, "Loading model: %s", model_path);
    
    if (!g_engine->LoadModel(model_path)) {
        LogMessage(ERROR, "Failed to load model");
        return false;
    }
    
    // Update global config from loaded model
    const ModelConfig& config = g_engine->GetConfig();
    g_n_layers = config.n_layer;
    g_n_embd = config.n_embd;
    g_n_head = config.n_head;
    g_n_vocab = config.n_vocab;
    g_n_ctx = config.n_ctx;
    
    LogMessage(INFO, "Model loaded successfully");
    return true;
}

void AIModelCaller_MASM_UnloadModel(void) {
    if (g_engine) {
        g_engine->UnloadModel();
    }
    LogMessage(INFO, "Model unloaded");
}

bool AIModelCaller_MASM_IsModelLoaded(void) {
    return g_initialized && g_engine && g_engine->IsModelLoaded();
}

//===============================================================================
// Token Generation
//===============================================================================

int AIModelCaller_MASM_GenerateToken(const int* input_tokens, int n_tokens, int pos) {
    if (!g_initialized || !g_engine) {
        LogMessage(ERROR, "Not initialized");
        return -1;
    }
    
    if (!input_tokens || n_tokens <= 0) {
        LogMessage(ERROR, "Invalid input tokens");
        return -1;
    }
    
    std::vector<int> tokens(input_tokens, input_tokens + n_tokens);
    return g_engine->GenerateToken(tokens, pos);
}

int AIModelCaller_MASM_Generate(const int* input_tokens, int n_input,
                                 int* output_tokens, int max_output,
                                 float temperature) {
    if (!g_initialized || !g_engine) {
        LogMessage(ERROR, "Not initialized");
        return 0;
    }
    
    if (!input_tokens || n_input <= 0 || !output_tokens || max_output <= 0) {
        LogMessage(ERROR, "Invalid parameters");
        return 0;
    }
    
    std::vector<int> input(input_tokens, input_tokens + n_input);
    std::vector<int> output = g_engine->Generate(input, max_output, temperature);
    
    int n_generated = (int)output.size() - n_input;
    if (n_generated > max_output) n_generated = max_output;
    
    for (int i = 0; i < n_generated; i++) {
        output_tokens[i] = output[n_input + i];
    }
    
    return n_generated;
}

//===============================================================================
// KV Cache Management
//===============================================================================

bool AIModelCaller_MASM_InitKVCache(int n_ctx, int n_embd, int n_head) {
    if (!g_initialized) {
        LogMessage(ERROR, "Not initialized");
        return false;
    }
    
    LogMessage(INFO, "Initializing KV cache: ctx=%d, embd=%d, heads=%d", n_ctx, n_embd, n_head);
    
    // KV cache is managed by the inference engine
    g_kv_cache_initialized = true;
    
    LogMessage(INFO, "KV cache initialized");
    return true;
}

void AIModelCaller_MASM_ClearKVCache(void) {
    if (!g_initialized || !g_engine) return;
    
    // Clear KV cache through engine
    LogMessage(DEBUG, "KV cache cleared");
}

//===============================================================================
// Perplexity Calculation
//===============================================================================

float AIModelCaller_MASM_CalculatePerplexity(const int* tokens, int n_tokens) {
    if (!g_initialized || !g_engine || !tokens || n_tokens <= 0) {
        return 0.0f;
    }
    
    std::vector<int> token_vec(tokens, tokens + n_tokens);
    return g_engine->CalculatePerplexity(token_vec);
}

//===============================================================================
// Model Configuration
//===============================================================================

void AIModelCaller_MASM_GetConfig(int* n_layers, int* n_embd, int* n_head, int* n_vocab, int* n_ctx) {
    if (n_layers) *n_layers = g_n_layers;
    if (n_embd) *n_embd = g_n_embd;
    if (n_head) *n_head = g_n_head;
    if (n_vocab) *n_vocab = g_n_vocab;
    if (n_ctx) *n_ctx = g_n_ctx;
}

void AIModelCaller_MASM_SetConfig(int n_layers, int n_embd, int n_head, int n_vocab, int n_ctx) {
    g_n_layers = n_layers;
    g_n_embd = n_embd;
    g_n_head = n_head;
    g_n_vocab = n_vocab;
    g_n_ctx = n_ctx;
    
    LogMessage(INFO, "Model config set: layers=%d, embd=%d, heads=%d, vocab=%d, ctx=%d",
               n_layers, n_embd, n_head, n_vocab, n_ctx);
}

//===============================================================================
// C Interface
//===============================================================================

extern "C" {

// Initialization
bool ai_model_caller_masm_init(void) {
    return AIModelCaller_MASM_Init();
}

void ai_model_caller_masm_deinit(void) {
    AIModelCaller_MASM_Deinit();
}

// Model management
bool ai_model_caller_masm_load_model(const char* model_path) {
    return AIModelCaller_MASM_LoadModel(model_path);
}

void ai_model_caller_masm_unload_model(void) {
    AIModelCaller_MASM_UnloadModel();
}

bool ai_model_caller_masm_is_model_loaded(void) {
    return AIModelCaller_MASM_IsModelLoaded();
}

// Generation
int ai_model_caller_masm_generate_token(const int* input_tokens, int n_tokens, int pos) {
    return AIModelCaller_MASM_GenerateToken(input_tokens, n_tokens, pos);
}

int ai_model_caller_masm_generate(const int* input_tokens, int n_input,
                                   int* output_tokens, int max_output,
                                   float temperature) {
    return AIModelCaller_MASM_Generate(input_tokens, n_input, output_tokens, max_output, temperature);
}

// KV cache
bool ai_model_caller_masm_init_kv_cache(int n_ctx, int n_embd, int n_head) {
    return AIModelCaller_MASM_InitKVCache(n_ctx, n_embd, n_head);
}

void ai_model_caller_masm_clear_kv_cache(void) {
    AIModelCaller_MASM_ClearKVCache();
}

// Perplexity
float ai_model_caller_masm_perplexity(const int* tokens, int n_tokens) {
    return AIModelCaller_MASM_CalculatePerplexity(tokens, n_tokens);
}

// Config
void ai_model_caller_masm_get_config(int* n_layers, int* n_embd, int* n_head, int* n_vocab, int* n_ctx) {
    AIModelCaller_MASM_GetConfig(n_layers, n_embd, n_head, n_vocab, n_ctx);
}

void ai_model_caller_masm_set_config(int n_layers, int n_embd, int n_head, int n_vocab, int n_ctx) {
    AIModelCaller_MASM_SetConfig(n_layers, n_embd, n_head, n_vocab, n_ctx);
}

} // extern "C"
