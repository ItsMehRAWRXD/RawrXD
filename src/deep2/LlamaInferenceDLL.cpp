// ============================================================================
// LlamaInferenceDLL.cpp - Minimal llama.cpp C API wrapper for RawrXD
// Exports: llama_init, llama_load_model, llama_generate_stream, llama_free
// ============================================================================

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>

// llama.cpp C API (from llama.dll)
extern "C" {
    // Backend
    void llama_backend_init();
    void llama_backend_free();
    
    // Model
    struct llama_model;
    struct llama_context;
    struct llama_model_params;
    struct llama_context_params;
    
    llama_model_params llama_model_default_params();
    llama_context_params llama_context_default_params();
    
    llama_model* llama_load_model_from_file(const char* path, llama_model_params params);
    void llama_free_model(llama_model* model);
    
    llama_context* llama_new_context_with_model(llama_model* model, llama_context_params params);
    void llama_free(llama_context* ctx);
    
    // Tokenization
    int llama_n_vocab(const llama_model* model);
    int llama_tokenize(const llama_model* model, const char* text, int32_t* tokens, int max_tokens, bool add_special, bool parse_special);
    int llama_token_to_piece(const llama_model* model, int32_t token, char* buf, int length, bool lstrip, bool special);
    
    // Decoding
    int llama_decode(llama_context* ctx, struct llama_batch batch);
    float* llama_get_logits(llama_context* ctx);
    float* llama_get_logits_ith(llama_context* ctx, int32_t i);
    
    // Batch
    struct llama_batch {
        int32_t n_tokens;
        int32_t* token;
        int32_t* embd;
        float*   logits;
        int32_t* pos;
        int32_t* n_seq_id;
        int32_t** seq_id;
        int8_t*  logits_mask;
    };
    llama_batch llama_batch_init(int32_t n_tokens, int32_t embd, int32_t n_seq_max);
    void llama_batch_free(struct llama_batch batch);
    
    // Sampling
    struct llama_sampler;
    llama_sampler* llama_sampler_init_greedy();
    llama_sampler* llama_sampler_init_temp(float temp);
    llama_sampler* llama_sampler_init_top_k(int k);
    llama_sampler* llama_sampler_init_top_p(float p);
    llama_sampler* llama_sampler_chain_init(llama_sampler** samplers, int n_samplers);
    int32_t llama_sampler_sample(llama_sampler* smpl, llama_context* ctx, int32_t idx);
    void llama_sampler_free(llama_sampler* smpl);
    void llama_sampler_accept(llama_sampler* smpl, int32_t token, bool accept);
}

// ============================================================================
// Engine state
// ============================================================================

struct LlamaEngine {
    llama_model* model = nullptr;
    llama_context* ctx = nullptr;
    llama_sampler* sampler = nullptr;
    std::vector<int32_t> tokens;
    std::mutex mutex;
    bool initialized = false;
};

static LlamaEngine g_engine;
static std::once_flag g_backend_init_flag;

// ============================================================================
// C API Exports
// ============================================================================

extern "C" {

__declspec(dllexport) int LlamaInference_Init() {
    std::call_once(g_backend_init_flag, []() {
        llama_backend_init();
        g_engine.initialized = true;
    });
    return 0;
}

__declspec(dllexport) void LlamaInference_Shutdown() {
    if (g_engine.ctx) {
        llama_free(g_engine.ctx);
        g_engine.ctx = nullptr;
    }
    if (g_engine.model) {
        llama_free_model(g_engine.model);
        g_engine.model = nullptr;
    }
    if (g_engine.sampler) {
        llama_sampler_free(g_engine.sampler);
        g_engine.sampler = nullptr;
    }
    g_engine.tokens.clear();
    llama_backend_free();
    g_engine.initialized = false;
}

__declspec(dllexport) int LlamaInference_LoadModel(const char* modelPath) {
    if (!modelPath || !modelPath[0]) return -1;
    
    std::lock_guard<std::mutex> lock(g_engine.mutex);
    
    // Cleanup existing
    if (g_engine.ctx) {
        llama_free(g_engine.ctx);
        g_engine.ctx = nullptr;
    }
    if (g_engine.model) {
        llama_free_model(g_engine.model);
        g_engine.model = nullptr;
    }
    if (g_engine.sampler) {
        llama_sampler_free(g_engine.sampler);
        g_engine.sampler = nullptr;
    }
    g_engine.tokens.clear();
    
    // Load model
    llama_model_params mparams = llama_model_default_params();
    mparams.n_gpu_layers = -1;  // Use GPU if available
    
    g_engine.model = llama_load_model_from_file(modelPath, mparams);
    if (!g_engine.model) {
        fprintf(stderr, "[LlamaInferenceDLL] Failed to load model: %s\n", modelPath);
        return -2;
    }
    
    // Create context
    llama_context_params cparams = llama_context_default_params();
    cparams.n_ctx = 4096;
    cparams.n_batch = 512;
    cparams.n_threads = 8;
    
    g_engine.ctx = llama_new_context_with_model(g_engine.model, cparams);
    if (!g_engine.ctx) {
        fprintf(stderr, "[LlamaInferenceDLL] Failed to create context\n");
        llama_free_model(g_engine.model);
        g_engine.model = nullptr;
        return -3;
    }
    
    // Create sampler chain (greedy + temp + top-k + top-p)
    llama_sampler* samplers[4] = {
        llama_sampler_init_greedy(),
        llama_sampler_init_temp(0.7f),
        llama_sampler_init_top_k(40),
        llama_sampler_init_top_p(0.9f)
    };
    g_engine.sampler = llama_sampler_chain_init(samplers, 4);
    
    fprintf(stderr, "[LlamaInferenceDLL] Model loaded: %s\n", modelPath);
    return 0;
}

__declspec(dllexport) int LlamaInference_Tokenize(const char* text, int32_t* tokens, int maxTokens, bool addSpecial) {
    if (!g_engine.model || !text) return -1;
    
    std::lock_guard<std::mutex> lock(g_engine.mutex);
    
    int n = llama_tokenize(g_engine.model, text, tokens, maxTokens, addSpecial, true);
    return n;
}

__declspec(dllexport) int LlamaInference_Detokenize(int32_t token, char* buffer, int bufferSize) {
    if (!g_engine.model || !buffer || bufferSize <= 0) return -1;
    
    std::lock_guard<std::mutex> lock(g_engine.mutex);
    
    int n = llama_token_to_piece(g_engine.model, token, buffer, bufferSize, false, false);
    return n;
}

// Callback type for streaming
using TokenCallback = void (__cdecl*)(const char* utf8Fragment, int isLast, void* userData);

__declspec(dllexport) int LlamaInference_GenerateStream(
    const char* prompt,
    int maxTokens,
    TokenCallback onToken,
    void* userData
) {
    if (!g_engine.ctx || !g_engine.sampler || !prompt || !onToken) {
        return -1;
    }
    
    std::lock_guard<std::mutex> lock(g_engine.mutex);
    
    // Tokenize prompt
    g_engine.tokens.clear();
    g_engine.tokens.resize(512);
    int nTokens = llama_tokenize(g_engine.model, prompt, g_engine.tokens.data(), 512, true, true);
    if (nTokens <= 0) {
        onToken("", 1, userData);
        return -2;
    }
    g_engine.tokens.resize(nTokens);
    
    // Create batch
    struct llama_batch batch = llama_batch_init(nTokens, 0, 1);
    for (int i = 0; i < nTokens; i++) {
        batch.token[i] = g_engine.tokens[i];
        batch.pos[i] = i;
        batch.n_seq_id[i] = 1;
        batch.seq_id[i][0] = 0;
    }
    batch.logits_mask[nTokens - 1] = 1;  // Only compute logits for last token
    
    // Decode prompt
    if (llama_decode(g_engine.ctx, batch) != 0) {
        llama_batch_free(batch);
        onToken("", 1, userData);
        return -3;
    }
    llama_batch_free(batch);
    
    // Generation loop
    int generated = 0;
    char piece[256];
    
    while (generated < maxTokens) {
        // Get logits for last position
        float* logits = llama_get_logits_ith(g_engine.ctx, -1);
        if (!logits) {
            break;
        }
        
        // Sample next token
        int32_t nextToken = llama_sampler_sample(g_engine.sampler, g_engine.ctx, -1);
        llama_sampler_accept(g_engine.sampler, nextToken, true);
        
        // Check for EOS
        if (nextToken == llama_token_eos(g_engine.model)) {
            break;
        }
        
        // Detokenize
        int pieceLen = llama_token_to_piece(g_engine.model, nextToken, piece, sizeof(piece), false, false);
        if (pieceLen > 0) {
            piece[pieceLen] = '\0';
            onToken(piece, 0, userData);
        }
        
        // Prepare next batch
        batch = llama_batch_init(1, 0, 1);
        batch.token[0] = nextToken;
        batch.pos[0] = nTokens + generated;
        batch.n_seq_id[0] = 1;
        batch.seq_id[0][0] = 0;
        batch.logits_mask[0] = 1;
        
        // Decode
        if (llama_decode(g_engine.ctx, batch) != 0) {
            llama_batch_free(batch);
            break;
        }
        llama_batch_free(batch);
        
        generated++;
    }
    
    onToken("", 1, userData);
    return 0;
}

__declspec(dllexport) int LlamaInference_GenerateBlocking(
    const char* prompt,
    int maxTokens,
    char* outputBuffer,
    unsigned int outputBufferSize,
    unsigned int* outputRequired
) {
    // Simple blocking version - accumulate all tokens
    std::string accumulated;
    
    auto callback = [](const char* fragment, int isLast, void* userData) {
        std::string* acc = static_cast<std::string*>(userData);
        if (fragment) *acc += fragment;
    };
    
    TokenCallback cb = [](const char* fragment, int isLast, void* userData) {
        std::string* acc = static_cast<std::string*>(userData);
        if (fragment) *acc += fragment;
    };
    
    // We can't easily capture the lambda as a C function pointer
    // For now, return not implemented
    return -99;
}

__declspec(dllexport) int LlamaInference_GetVersion() {
    return 1;
}

__declspec(dllexport) const char* LlamaInference_GetEngineName() {
    return "LlamaInferenceDLL/1.0 (llama.cpp C API wrapper)";
}

} // extern "C"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    return TRUE;
}