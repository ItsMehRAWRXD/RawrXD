// =============================================================================
// sovereign_engine_controller.cpp
// Phase 22: Inference Engine Integration
// Unified controller implementation
// =============================================================================

#include "sovereign_engine_controller.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <vector>
#include <string>
#include <algorithm>

// =============================================================================
// Internal Structures
// =============================================================================

struct SovereignEngine {
    // Configuration
    SovereignLoaderConfig loader_config;
    SovereignInferenceConfig inference_config;
    
    // Components
    SovereignGGUFModelHandle model;
    SovereignKVCacheManagerHandle kv_cache_manager;
    SovereignBlockAllocatorHandle memory_allocator;
    SovereignThreadPoolHandle thread_pool;
    
    // State
    int is_initialized;
    int is_ready;
    uint64_t next_session_id;
    
    // Statistics
    SovereignEngineStats stats;
    
    // Kernel dispatch
    const SovereignKernelDispatch* kernel_dispatch;
    
    // Error
    char last_error[256];
    int debug_mode;
};

struct SovereignInferenceSession {
    SovereignEngine* engine;
    uint64_t session_id;
    
    // KV cache for this session
    SovereignKVCacheHandle kv_cache;
    
    // Token history
    std::vector<SovereignToken> token_history;
    std::vector<float> logits_history;
    
    // Generation state
    uint32_t current_pos;
    uint32_t generation_length;
    int is_generating;
    
    // Timing
    double session_start_time;
    double last_token_time;
};

// =============================================================================
// Default Kernel Dispatch (C++ fallbacks)
// =============================================================================

static void Default_Attention_QK(const float* q, const float* k, float* scores,
                                  uint32_t seq_len, uint32_t head_dim) {
    // Q @ K^T / sqrt(head_dim)
    float scale = 1.0f / sqrtf((float)head_dim);
    for (uint32_t i = 0; i < seq_len; i++) {
        for (uint32_t j = 0; j < seq_len; j++) {
            float dot = 0.0f;
            for (uint32_t d = 0; d < head_dim; d++) {
                dot += q[i * head_dim + d] * k[j * head_dim + d];
            }
            scores[i * seq_len + j] = dot * scale;
        }
    }
}

static void Default_Attention_Softmax(float* scores, uint32_t seq_len) {
    for (uint32_t i = 0; i < seq_len; i++) {
        // Find max
        float max_val = scores[i * seq_len];
        for (uint32_t j = 1; j < seq_len; j++) {
            max_val = fmaxf(max_val, scores[i * seq_len + j]);
        }
        
        // Exp and sum
        float sum = 0.0f;
        for (uint32_t j = 0; j < seq_len; j++) {
            scores[i * seq_len + j] = expf(scores[i * seq_len + j] - max_val);
            sum += scores[i * seq_len + j];
        }
        
        // Normalize
        for (uint32_t j = 0; j < seq_len; j++) {
            scores[i * seq_len + j] /= sum;
        }
    }
}

static void Default_Attention_Out(const float* scores, const float* v, float* out,
                                    uint32_t seq_len, uint32_t head_dim) {
    for (uint32_t i = 0; i < seq_len; i++) {
        for (uint32_t d = 0; d < head_dim; d++) {
            float sum = 0.0f;
            for (uint32_t j = 0; j < seq_len; j++) {
                sum += scores[i * seq_len + j] * v[j * head_dim + d];
            }
            out[i * head_dim + d] = sum;
        }
    }
}

static void Default_FFN_SiLU(const float* gate, const float* up, float* out,
                               uint32_t hidden_dim) {
    for (uint32_t i = 0; i < hidden_dim; i++) {
        // SiLU(x) = x * sigmoid(x)
        float sigmoid = 1.0f / (1.0f + expf(-gate[i]));
        out[i] = gate[i] * sigmoid * up[i];
    }
}

static void Default_FFN_MatMul(const float* a, const float* b, float* c,
                                 uint32_t m, uint32_t n, uint32_t k) {
    for (uint32_t i = 0; i < m; i++) {
        for (uint32_t j = 0; j < n; j++) {
            float sum = 0.0f;
            for (uint32_t l = 0; l < k; l++) {
                sum += a[i * k + l] * b[l * n + j];
            }
            c[i * n + j] = sum;
        }
    }
}

static void Default_RMS_Norm(const float* x, const float* weight, float* out,
                             uint32_t hidden_dim, float eps) {
    // Calculate RMS
    float sum_sq = 0.0f;
    for (uint32_t i = 0; i < hidden_dim; i++) {
        sum_sq += x[i] * x[i];
    }
    float rms = sqrtf(sum_sq / hidden_dim + eps);
    
    // Normalize and scale
    for (uint32_t i = 0; i < hidden_dim; i++) {
        out[i] = x[i] / rms * weight[i];
    }
}

static SovereignKernelDispatch g_default_dispatch = {
    Default_Attention_QK,
    Default_Attention_Softmax,
    Default_Attention_Out,
    Default_FFN_SiLU,
    Default_FFN_MatMul,
    Default_RMS_Norm,
    nullptr,  // dequantize_q4
    nullptr   // quantize_q4
};

// =============================================================================
// Simple BPE Tokenizer (placeholder)
// =============================================================================

static std::vector<SovereignToken> SimpleTokenize(const char* text) {
    std::vector<SovereignToken> tokens;
    
    // Add BOS
    tokens.push_back(SOVEREIGN_TOKEN_BOS);
    
    // Simple word-based tokenization (placeholder)
    // In production, this would use the actual BPE vocabulary
    const char* ptr = text;
    while (*ptr) {
        // Skip whitespace
        while (*ptr && (*ptr == ' ' || *ptr == '\t' || *ptr == '\n')) {
            ptr++;
        }
        
        if (!*ptr) break;
        
        // Simple hash-based token (placeholder)
        uint32_t hash = 0;
        while (*ptr && *ptr != ' ' && *ptr != '\t' && *ptr != '\n') {
            hash = hash * 31 + *ptr;
            ptr++;
        }
        
        // Map to vocab (simplified)
        tokens.push_back((hash % (SOVEREIGN_VOCAB_SIZE - 100)) + 100);
    }
    
    return tokens;
}

static std::string SimpleDetokenize(const std::vector<SovereignToken>& tokens) {
    std::string result;
    
    for (size_t i = 1; i < tokens.size(); i++) {  // Skip BOS
        if (tokens[i] == SOVEREIGN_TOKEN_EOS) break;
        
        // Placeholder: just append token number
        char buf[32];
        snprintf(buf, sizeof(buf), "[%u]", tokens[i]);
        result += buf;
        result += " ";
    }
    
    return result;
}

// =============================================================================
// Sampling Functions
// =============================================================================

static void Softmax(float* logits, uint32_t vocab_size, float temperature) {
    // Apply temperature
    if (temperature != 1.0f) {
        for (uint32_t i = 0; i < vocab_size; i++) {
            logits[i] /= temperature;
        }
    }
    
    // Find max for numerical stability
    float max_logit = logits[0];
    for (uint32_t i = 1; i < vocab_size; i++) {
        if (logits[i] > max_logit) max_logit = logits[i];
    }
    
    // Compute exp and sum
    float sum = 0.0f;
    for (uint32_t i = 0; i < vocab_size; i++) {
        logits[i] = expf(logits[i] - max_logit);
        sum += logits[i];
    }
    
    // Normalize
    for (uint32_t i = 0; i < vocab_size; i++) {
        logits[i] /= sum;
    }
}

// =============================================================================
// Engine Lifecycle
// =============================================================================

__declspec(dllexport) SovereignEngineHandle Sovereign_Engine_Create(
    const SovereignLoaderConfig* loader_config,
    const SovereignInferenceConfig* inference_config) {
    
    if (!loader_config || !inference_config) return nullptr;
    
    auto* engine = new SovereignEngine();
    memset(engine, 0, sizeof(*engine));
    
    // Copy configuration
    engine->loader_config = *loader_config;
    engine->inference_config = *inference_config;
    
    // Initialize components
    engine->model = nullptr;
    engine->kv_cache_manager = nullptr;
    engine->memory_allocator = nullptr;
    engine->thread_pool = nullptr;
    
    // Set default kernel dispatch
    engine->kernel_dispatch = &g_default_dispatch;
    
    // Initialize memory pool
    Sovereign_MemoryPool_Init();
    engine->memory_allocator = Sovereign_BlockAllocator_Create(0);
    
    // Initialize thread pool
    engine->thread_pool = Sovereign_ThreadPool_Init(
        inference_config->num_threads, 0);
    
    engine->next_session_id = 1;
    engine->is_initialized = 0;
    engine->is_ready = 0;
    
    return reinterpret_cast<SovereignEngineHandle>(engine);
}

__declspec(dllexport) void Sovereign_Engine_Destroy(SovereignEngineHandle engine) {
    if (!engine) return;
    
    auto* e = reinterpret_cast<SovereignEngine*>(engine);
    
    // Cleanup components
    if (e->model) {
        Sovereign_UnloadModel(e->model);
    }
    if (e->kv_cache_manager) {
        Sovereign_KVCacheManager_Shutdown(e->kv_cache_manager);
    }
    if (e->thread_pool) {
        Sovereign_ThreadPool_Shutdown(e->thread_pool);
    }
    if (e->memory_allocator) {
        Sovereign_BlockAllocator_Destroy(e->memory_allocator);
    }
    
    Sovereign_MemoryPool_Shutdown();
    
    delete e;
}

__declspec(dllexport) int Sovereign_Engine_Initialize(
    SovereignEngineHandle engine,
    const char* model_path) {
    
    if (!engine || !model_path) return -1;
    
    auto* e = reinterpret_cast<SovereignEngine*>(engine);
    
    double start_time = GetTickCount64();
    
    // Load model
    e->model = Sovereign_LoadModel(model_path, &e->loader_config);
    if (!e->model) {
        snprintf(e->last_error, sizeof(e->last_error),
            "Failed to load model: %s", model_path);
        return -1;
    }
    
    // Get model config
    SovereignModelConfig model_config;
    Sovereign_Model_GetConfig(e->model, &model_config);
    
    // Initialize KV cache manager
    SovereignKVCacheConfig kv_config = {};
    kv_config.num_layers = model_config.num_layers;
    kv_config.num_heads = model_config.num_heads;
    kv_config.head_dim = model_config.head_dim;
    kv_config.block_size = 256;
    kv_config.max_memory_bytes = e->inference_config.max_memory_bytes / 2;
    kv_config.enable_sharing = 1;
    kv_config.enable_lru = 1;
    
    e->kv_cache_manager = Sovereign_KVCacheManager_Init(&kv_config);
    if (!e->kv_cache_manager) {
        snprintf(e->last_error, sizeof(e->last_error),
            "Failed to initialize KV cache");
        return -1;
    }
    
    // Update stats
    SovereignLoadingStats load_stats;
    Sovereign_Model_GetStats(e->model, &load_stats);
    e->stats.load_time_ms = load_stats.load_time_ms;
    e->stats.model_memory_bytes = Sovereign_Model_GetMemoryUsage(e->model);
    
    e->is_initialized = 1;
    e->is_ready = 1;
    
    return 0;
}

__declspec(dllexport) int Sovereign_Engine_IsReady(SovereignEngineHandle engine) {
    if (!engine) return 0;
    auto* e = reinterpret_cast<SovereignEngine*>(engine);
    return e->is_ready;
}

__declspec(dllexport) int Sovereign_Engine_GetStats(
    SovereignEngineHandle engine,
    SovereignEngineStats* stats) {
    
    if (!engine || !stats) return -1;
    
    auto* e = reinterpret_cast<SovereignEngine*>(engine);
    *stats = e->stats;
    
    return 0;
}

// =============================================================================
// Session Management
// =============================================================================

__declspec(dllexport) SovereignSessionHandle Sovereign_Session_Create(
    SovereignEngineHandle engine,
    uint64_t session_id) {
    
    if (!engine) return nullptr;
    
    auto* e = reinterpret_cast<SovereignEngine*>(engine);
    
    auto* session = new SovereignInferenceSession();
    session->engine = e;
    session->session_id = session_id ? session_id : e->next_session_id++;
    
    // Create KV cache for session
    if (e->kv_cache_manager) {
        SovereignModelConfig model_config;
        Sovereign_Model_GetConfig(e->model, &model_config);
        
        session->kv_cache = Sovereign_KVCache_CreateSequence(
            e->kv_cache_manager,
            session->session_id,
            model_config.num_layers,
            model_config.num_heads,
            model_config.head_dim
        );
    }
    
    session->current_pos = 0;
    session->generation_length = 0;
    session->is_generating = 0;
    session->session_start_time = GetTickCount64();
    
    return reinterpret_cast<SovereignSessionHandle>(session);
}

__declspec(dllexport) void Sovereign_Session_Destroy(SovereignSessionHandle session) {
    if (!session) return;
    
    auto* s = reinterpret_cast<SovereignInferenceSession*>(session);
    
    if (s->kv_cache && s->engine->kv_cache_manager) {
        Sovereign_KVCache_DestroySequence(s->engine->kv_cache_manager, s->kv_cache);
    }
    
    delete s;
}

__declspec(dllexport) void Sovereign_Session_Reset(SovereignSessionHandle session) {
    if (!session) return;
    
    auto* s = reinterpret_cast<SovereignInferenceSession*>(session);
    
    s->token_history.clear();
    s->logits_history.clear();
    s->current_pos = 0;
    s->generation_length = 0;
    s->is_generating = 0;
    
    // Reset KV cache
    if (s->kv_cache) {
        // Would clear KV cache here
    }
}

// =============================================================================
// Tokenization
// =============================================================================

__declspec(dllexport) int Sovereign_Tokenize(
    SovereignEngineHandle engine,
    const char* text,
    SovereignToken* tokens,
    uint32_t* num_tokens,
    uint32_t max_tokens) {
    
    if (!engine || !text || !tokens || !num_tokens) return -1;
    
    auto toks = SimpleTokenize(text);
    
    size_t toks_size = toks.size();
    *num_tokens = (uint32_t)((toks_size < max_tokens) ? toks_size : max_tokens);
    for (uint32_t i = 0; i < *num_tokens; i++) {
        tokens[i] = toks[i];
    }
    
    return 0;
}

__declspec(dllexport) int Sovereign_Detokenize(
    SovereignEngineHandle engine,
    const SovereignToken* tokens,
    uint32_t num_tokens,
    char* text,
    uint32_t max_text_len) {
    
    if (!engine || !tokens || !text || max_text_len == 0) return -1;
    
    std::vector<SovereignToken> toks(tokens, tokens + num_tokens);
    std::string result = SimpleDetokenize(toks);
    
    strncpy(text, result.c_str(), max_text_len - 1);
    text[max_text_len - 1] = '\0';
    
    return 0;
}

__declspec(dllexport) const char* Sovereign_GetTokenString(
    SovereignEngineHandle engine,
    SovereignToken token) {
    
    static char buf[32];
    snprintf(buf, sizeof(buf), "[%u]", token);
    return buf;
}

// =============================================================================
// Sampling
// =============================================================================

__declspec(dllexport) SovereignToken Sovereign_Sample_Greedy(
    const float* logits,
    uint32_t vocab_size) {
    
    if (!logits || vocab_size == 0) return SOVEREIGN_TOKEN_UNK;
    
    SovereignToken best_token = 0;
    float best_logit = logits[0];
    
    for (uint32_t i = 1; i < vocab_size; i++) {
        if (logits[i] > best_logit) {
            best_logit = logits[i];
            best_token = i;
        }
    }
    
    return best_token;
}

__declspec(dllexport) SovereignToken Sovereign_Sample_Temperature(
    const float* logits,
    uint32_t vocab_size,
    float temperature) {
    
    if (!logits || vocab_size == 0) return SOVEREIGN_TOKEN_UNK;
    
    // Copy logits (we'll modify them)
    std::vector<float> probs(logits, logits + vocab_size);
    Softmax(probs.data(), vocab_size, temperature);
    
    // Sample
    float r = (float)rand() / RAND_MAX;
    float cumsum = 0.0f;
    
    for (uint32_t i = 0; i < vocab_size; i++) {
        cumsum += probs[i];
        if (r <= cumsum) {
            return i;
        }
    }
    
    return vocab_size - 1;
}

__declspec(dllexport) SovereignToken Sovereign_Sample_TopP(
    const float* logits,
    uint32_t vocab_size,
    float top_p,
    float temperature) {
    
    if (!logits || vocab_size == 0) return SOVEREIGN_TOKEN_UNK;
    
    // Get probabilities
    std::vector<float> probs(logits, logits + vocab_size);
    Softmax(probs.data(), vocab_size, temperature);
    
    // Sort by probability (descending)
    std::vector<std::pair<float, uint32_t>> sorted;
    for (uint32_t i = 0; i < vocab_size; i++) {
        sorted.push_back({probs[i], i});
    }
    std::sort(sorted.begin(), sorted.end(), 
              [](auto& a, auto& b) { return a.first > b.first; });
    
    // Find cutoff
    float cumsum = 0.0f;
    uint32_t cutoff = vocab_size;
    for (uint32_t i = 0; i < vocab_size; i++) {
        cumsum += sorted[i].first;
        if (cumsum >= top_p) {
            cutoff = i + 1;
            break;
        }
    }
    
    // Renormalize and sample from top-p
    float sum = 0.0f;
    for (uint32_t i = 0; i < cutoff; i++) {
        sum += sorted[i].first;
    }
    
    float r = (float)rand() / RAND_MAX * sum;
    cumsum = 0.0f;
    
    for (uint32_t i = 0; i < cutoff; i++) {
        cumsum += sorted[i].first;
        if (r <= cumsum) {
            return sorted[i].second;
        }
    }
    
    return sorted[cutoff - 1].second;
}

__declspec(dllexport) SovereignToken Sovereign_Sample_TopK(
    const float* logits,
    uint32_t vocab_size,
    uint32_t top_k,
    float temperature) {
    
    if (!logits || vocab_size == 0) return SOVEREIGN_TOKEN_UNK;
    
    // Get probabilities
    std::vector<float> probs(logits, logits + vocab_size);
    Softmax(probs.data(), vocab_size, temperature);
    
    // Sort and take top-k
    std::vector<std::pair<float, uint32_t>> sorted;
    for (uint32_t i = 0; i < vocab_size; i++) {
        sorted.push_back({probs[i], i});
    }
    std::sort(sorted.begin(), sorted.end(),
              [](auto& a, auto& b) { return a.first > b.first; });
    
    top_k = (top_k < vocab_size) ? top_k : vocab_size;
    
    // Renormalize top-k
    float sum = 0.0f;
    for (uint32_t i = 0; i < top_k; i++) {
        sum += sorted[i].first;
    }
    
    // Sample from top-k
    float r = (float)rand() / RAND_MAX * sum;
    float cumsum = 0.0f;
    
    for (uint32_t i = 0; i < top_k; i++) {
        cumsum += sorted[i].first;
        if (r <= cumsum) {
            return sorted[i].second;
        }
    }
    
    return sorted[top_k - 1].second;
}

// =============================================================================
// Inference Pipeline
// =============================================================================

__declspec(dllexport) int Sovereign_Session_ProcessPrompt(
    SovereignSessionHandle session,
    const SovereignToken* tokens,
    uint32_t num_tokens) {
    
    if (!session || !tokens) return -1;
    
    auto* s = reinterpret_cast<SovereignInferenceSession*>(session);
    
    // Store prompt tokens
    s->token_history.clear();
    for (uint32_t i = 0; i < num_tokens; i++) {
        s->token_history.push_back(tokens[i]);
    }
    
    s->current_pos = num_tokens;
    s->is_generating = 1;
    
    // In production: run forward pass through all layers
    // For now, just mark as ready
    
    return 0;
}

__declspec(dllexport) int Sovereign_Session_GenerateToken(
    SovereignSessionHandle session,
    SovereignGenerationResult* result) {
    
    if (!session || !result) return -1;
    
    auto* s = reinterpret_cast<SovereignInferenceSession*>(session);
    
    if (!s->is_generating) return -1;
    
    double start_time = GetTickCount64();
    
    // Generate dummy logits (in production: actual forward pass)
    std::vector<float> logits(SOVEREIGN_VOCAB_SIZE);
    for (uint32_t i = 0; i < SOVEREIGN_VOCAB_SIZE; i++) {
        logits[i] = (float)(rand() % 1000) / 100.0f;
    }
    
    // Sample next token
    SovereignToken next_token = Sovereign_Sample_Temperature(
        logits.data(), SOVEREIGN_VOCAB_SIZE, 0.8f);
    
    // Check for EOS
    if (next_token == SOVEREIGN_TOKEN_EOS ||
        s->generation_length >= s->engine->inference_config.max_tokens) {
        result->is_eos = 1;
        s->is_generating = 0;
    } else {
        result->is_eos = 0;
    }
    
    result->token_id = next_token;
    result->logit = logits[next_token];
    result->probability = 1.0f / SOVEREIGN_VOCAB_SIZE;  // Simplified
    result->generation_index = s->generation_length;
    result->generation_time_ms = (GetTickCount64() - start_time);
    
    // Update state
    s->token_history.push_back(next_token);
    s->generation_length++;
    s->current_pos++;
    
    // Update engine stats
    s->engine->stats.tokens_generated++;
    s->engine->stats.total_tokens++;
    
    return 0;
}

__declspec(dllexport) int Sovereign_Session_Generate(
    SovereignSessionHandle session,
    const char* prompt,
    char* response,
    uint32_t max_response_len,
    uint32_t* num_generated_tokens) {
    
    if (!session || !prompt || !response || !num_generated_tokens) return -1;
    
    auto* s = reinterpret_cast<SovereignInferenceSession*>(session);
    
    // Tokenize prompt
    SovereignToken prompt_tokens[1024];
    uint32_t num_prompt_tokens = 0;
    Sovereign_Tokenize(s->engine, prompt, prompt_tokens, &num_prompt_tokens, 1024);
    
    // Process prompt
    Sovereign_Session_ProcessPrompt(session, prompt_tokens, num_prompt_tokens);
    
    // Generate tokens
    std::vector<SovereignToken> generated_tokens;
    for (uint32_t i = 0; i < s->engine->inference_config.max_tokens; i++) {
        SovereignGenerationResult result;
        if (Sovereign_Session_GenerateToken(session, &result) != 0) break;
        
        generated_tokens.push_back(result.token_id);
        
        if (result.is_eos) break;
    }
    
    // Detokenize
    Sovereign_Detokenize(s->engine, generated_tokens.data(), 
        (uint32_t)generated_tokens.size(), response, max_response_len);
    
    *num_generated_tokens = (uint32_t)generated_tokens.size();
    
    return 0;
}

// =============================================================================
// Kernel Dispatch
// =============================================================================

__declspec(dllexport) const SovereignKernelDispatch* Sovereign_GetKernelDispatch(void) {
    return &g_default_dispatch;
}

__declspec(dllexport) void Sovereign_SetKernelDispatch(
    const SovereignKernelDispatch* dispatch) {
    // In production: set global dispatch table
    (void)dispatch;
}

// =============================================================================
// Debug & Diagnostics
// =============================================================================

__declspec(dllexport) void Sovereign_Engine_DumpState(SovereignEngineHandle engine) {
    if (!engine) return;
    
    auto* e = reinterpret_cast<SovereignEngine*>(engine);
    
    printf("\n=== Sovereign Engine State ===\n");
    printf("Initialized: %s\n", e->is_initialized ? "Yes" : "No");
    printf("Ready: %s\n", e->is_ready ? "Yes" : "No");
    printf("Model loaded: %s\n", e->model ? "Yes" : "No");
    printf("KV Cache: %s\n", e->kv_cache_manager ? "Yes" : "No");
    printf("Thread Pool: %s\n", e->thread_pool ? "Yes" : "No");
    printf("Tokens generated: %llu\n", e->stats.tokens_generated);
    printf("============================\n\n");
}

__declspec(dllexport) void Sovereign_Session_DumpState(SovereignSessionHandle session) {
    if (!session) return;
    
    auto* s = reinterpret_cast<SovereignInferenceSession*>(session);
    
    printf("\n=== Session %llu State ===\n", s->session_id);
    printf("Position: %u\n", s->current_pos);
    printf("Generation length: %u\n", s->generation_length);
    printf("Is generating: %s\n", s->is_generating ? "Yes" : "No");
    printf("Token history: %zu tokens\n", s->token_history.size());
    printf("==========================\n\n");
}

__declspec(dllexport) int Sovereign_Engine_Validate(SovereignEngineHandle engine) {
    if (!engine) return -1;
    
    auto* e = reinterpret_cast<SovereignEngine*>(engine);
    
    if (!e->is_initialized) return -1;
    if (!e->is_ready) return -1;
    if (!e->model) return -1;
    if (!e->kernel_dispatch) return -1;
    
    return 0;
}

__declspec(dllexport) const char* Sovereign_Engine_GetLastError(SovereignEngineHandle engine) {
    if (!engine) return "Invalid engine";
    
    auto* e = reinterpret_cast<SovereignEngine*>(engine);
    return e->last_error;
}

__declspec(dllexport) void Sovereign_Engine_SetDebugMode(int enable) {
    if (!enable) return;
    
    auto* e = reinterpret_cast<SovereignEngine*>(nullptr);
    if (e) e->debug_mode = enable;
}
