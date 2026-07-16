// validation_stubs.cpp
// Stub implementations for RawrXD and llama.cpp APIs
// These allow the validation harness to compile and run in stub mode

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>

// ═══════════════════════════════════════════════════════════════════════════════
// RawrXD API Stubs
// ═══════════════════════════════════════════════════════════════════════════════

struct RawrXD_Context {
    char model_path[256];
    int vocab_size;
    bool loaded;
};

extern "C" {

RawrXD_Context* rawrxd_load_model(const char* path) {
    RawrXD_Context* ctx = new RawrXD_Context();
    strncpy(ctx->model_path, path, sizeof(ctx->model_path) - 1);
    ctx->model_path[sizeof(ctx->model_path) - 1] = '\0';
    ctx->vocab_size = 32000;  // Common default
    ctx->loaded = true;
    printf("[STUB] RawrXD model loaded: %s (vocab_size=%d)\n", path, ctx->vocab_size);
    return ctx;
}

void rawrxd_free_context(RawrXD_Context* ctx) {
    if (ctx) {
        printf("[STUB] RawrXD context freed\n");
        delete ctx;
    }
}

int rawrxd_get_vocab_size(RawrXD_Context* ctx) {
    return ctx ? ctx->vocab_size : 0;
}

int rawrxd_get_logits(RawrXD_Context* ctx, const int* tokens, int n_tokens, float* logits) {
    if (!ctx || !ctx->loaded) {
        return -1;
    }
    
    // STUB: Generate deterministic "fake" logits based on input tokens
    // This simulates inference without actual model execution
    int vocab_size = ctx->vocab_size;
    
    // Seed based on token sequence
    unsigned int seed = 0;
    for (int i = 0; i < n_tokens; i++) {
        seed = seed * 31 + tokens[i];
    }
    
    // Generate logits using simple hash-based PRNG
    float sum = 0.0f;
    for (int i = 0; i < vocab_size; i++) {
        // Simple LCG
        seed = seed * 1103515245 + 12345;
        float val = (float)(seed & 0x7FFF) / 32768.0f;  // 0-1
        logits[i] = (val - 0.5f) * 20.0f;  // Scale to -10 to +10
        sum += expf(logits[i]);
    }
    
    // Normalize to probabilities (softmax)
    for (int i = 0; i < vocab_size; i++) {
        logits[i] = expf(logits[i]) / sum;
    }
    
    // Convert back to log-probabilities
    for (int i = 0; i < vocab_size; i++) {
        logits[i] = logf(fmaxf(logits[i], 1e-10f));
    }
    
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
// llama.cpp API Stubs
// ═══════════════════════════════════════════════════════════════════════════════

struct llama_context {
    char model_path[256];
    int vocab_size;
    bool loaded;
};

llama_context* llama_load_model(const char* path) {
    llama_context* ctx = new llama_context();
    strncpy(ctx->model_path, path, sizeof(ctx->model_path) - 1);
    ctx->model_path[sizeof(ctx->model_path) - 1] = '\0';
    ctx->vocab_size = 32000;
    ctx->loaded = true;
    printf("[STUB] llama.cpp model loaded: %s\n", path);
    return ctx;
}

void llama_free(llama_context* ctx) {
    if (ctx) {
        printf("[STUB] llama.cpp context freed\n");
        delete ctx;
    }
}

int llama_get_vocab_size(llama_context* ctx) {
    return ctx ? ctx->vocab_size : 0;
}

int llama_get_logits(llama_context* ctx, const int* tokens, int n_tokens, float* logits) {
    if (!ctx || !ctx->loaded) {
        return -1;
    }
    
    // STUB: Generate identical logits to RawrXD for perfect match
    // In real implementation, this would run actual llama.cpp inference
    int vocab_size = ctx->vocab_size;
    
    unsigned int seed = 0;
    for (int i = 0; i < n_tokens; i++) {
        seed = seed * 31 + tokens[i];
    }
    
    float sum = 0.0f;
    for (int i = 0; i < vocab_size; i++) {
        seed = seed * 1103515245 + 12345;
        float val = (float)(seed & 0x7FFF) / 32768.0f;
        logits[i] = (val - 0.5f) * 20.0f;
        sum += expf(logits[i]);
    }
    
    for (int i = 0; i < vocab_size; i++) {
        logits[i] = expf(logits[i]) / sum;
    }
    
    for (int i = 0; i < vocab_size; i++) {
        logits[i] = logf(fmaxf(logits[i], 1e-10f));
    }
    
    return 0;
}

} // extern "C"
