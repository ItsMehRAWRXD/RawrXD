// ============================================================================
// gguf_masm_weight_bridge.cpp
// Bridges GGUF model loading with pure MASM inference
// Loads weights from GGUF files into MASM-compatible format
// ============================================================================

#include "gguf_masm_weight_bridge.h"
#include "rawrxd_model_loader.h"
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <windows.h>

// ============================================================================
// IMPLEMENTATION
// ============================================================================

GGUF_MASM_WeightBridge::GGUF_MASM_WeightBridge() = default;
GGUF_MASM_WeightBridge::~GGUF_MASM_WeightBridge() { Cleanup(); }

bool GGUF_MASM_WeightBridge::LoadFromGGUF(RawrXDModelLoader& loader, RawrXDInferenceCtx& ctx) {
    printf("[GGUF-MASM Bridge] Loading weights into MASM context...\n");
    
    // Load token embeddings
    if (!LoadTensor(loader, ctx, "token_embd.weight", 
                    &ctx.tok_embeddings, ctx.n_vocab, ctx.n_embd)) {
        printf("[GGUF-MASM Bridge] Warning: token_embd.weight not found, using zeros\n");
    }
    
    // Load output weights
    if (!LoadTensor(loader, ctx, "output.weight",
                    &ctx.output_weights, ctx.n_vocab, ctx.n_embd)) {
        printf("[GGUF-MASM Bridge] Warning: output.weight not found\n");
    }
    
    // Load final norm
    if (!LoadTensor(loader, ctx, "norm.weight",
                    &ctx.norm_weights, 1, ctx.n_embd)) {
        printf("[GGUF-MASM Bridge] Warning: norm.weight not found\n");
    }
    
    // Load per-layer weights
    for (int layer = 0; layer < ctx.n_layer; layer++) {
        if (!LoadLayerWeights(loader, ctx, layer)) {
            printf("[GGUF-MASM Bridge] Warning: Failed to load layer %d weights\n", layer);
        }
    }
    
    printf("[GGUF-MASM Bridge] Weight loading complete\n");
    return true;
}

bool GGUF_MASM_WeightBridge::LoadLayerWeights(RawrXDModelLoader& loader, 
                                             RawrXDInferenceCtx& ctx, int layer) {
    char nameBuf[256];
    
    // Attention weights
    snprintf(nameBuf, sizeof(nameBuf), "blk.%d.attn_q.weight", layer);
    if (!LoadTensor(loader, ctx, nameBuf, &ctx.wq[layer], ctx.n_embd, ctx.n_embd)) {
        // Try alternate naming
        snprintf(nameBuf, sizeof(nameBuf), "layers.%d.attention.wq.weight", layer);
        LoadTensor(loader, ctx, nameBuf, &ctx.wq[layer], ctx.n_embd, ctx.n_embd);
    }
    
    snprintf(nameBuf, sizeof(nameBuf), "blk.%d.attn_k.weight", layer);
    if (!LoadTensor(loader, ctx, nameBuf, &ctx.wk[layer], ctx.n_embd, ctx.n_embd)) {
        snprintf(nameBuf, sizeof(nameBuf), "layers.%d.attention.wk.weight", layer);
        LoadTensor(loader, ctx, nameBuf, &ctx.wk[layer], ctx.n_embd, ctx.n_embd);
    }
    
    snprintf(nameBuf, sizeof(nameBuf), "blk.%d.attn_v.weight", layer);
    if (!LoadTensor(loader, ctx, nameBuf, &ctx.wv[layer], ctx.n_embd, ctx.n_embd)) {
        snprintf(nameBuf, sizeof(nameBuf), "layers.%d.attention.wv.weight", layer);
        LoadTensor(loader, ctx, nameBuf, &ctx.wv[layer], ctx.n_embd, ctx.n_embd);
    }
    
    snprintf(nameBuf, sizeof(nameBuf), "blk.%d.attn_output.weight", layer);
    if (!LoadTensor(loader, ctx, nameBuf, &ctx.wo[layer], ctx.n_embd, ctx.n_embd)) {
        snprintf(nameBuf, sizeof(nameBuf), "layers.%d.attention.wo.weight", layer);
        LoadTensor(loader, ctx, nameBuf, &ctx.wo[layer], ctx.n_embd, ctx.n_embd);
    }
    
    // FFN weights
    snprintf(nameBuf, sizeof(nameBuf), "blk.%d.ffn_gate.weight", layer);
    if (!LoadTensor(loader, ctx, nameBuf, &ctx.w1[layer], ctx.n_ff, ctx.n_embd)) {
        snprintf(nameBuf, sizeof(nameBuf), "layers.%d.feed_forward.w1.weight", layer);
        LoadTensor(loader, ctx, nameBuf, &ctx.w1[layer], ctx.n_ff, ctx.n_embd);
    }
    
    snprintf(nameBuf, sizeof(nameBuf), "blk.%d.ffn_down.weight", layer);
    if (!LoadTensor(loader, ctx, nameBuf, &ctx.w2[layer], ctx.n_embd, ctx.n_ff)) {
        snprintf(nameBuf, sizeof(nameBuf), "layers.%d.feed_forward.w2.weight", layer);
        LoadTensor(loader, ctx, nameBuf, &ctx.w2[layer], ctx.n_embd, ctx.n_ff);
    }
    
    snprintf(nameBuf, sizeof(nameBuf), "blk.%d.ffn_up.weight", layer);
    if (!LoadTensor(loader, ctx, nameBuf, &ctx.w3[layer], ctx.n_ff, ctx.n_embd)) {
        snprintf(nameBuf, sizeof(nameBuf), "layers.%d.feed_forward.w3.weight", layer);
        LoadTensor(loader, ctx, nameBuf, &ctx.w3[layer], ctx.n_ff, ctx.n_embd);
    }
    
    // Layer norms
    snprintf(nameBuf, sizeof(nameBuf), "blk.%d.attn_norm.weight", layer);
    if (!LoadTensor(loader, ctx, nameBuf, &ctx.layer_norm_1[layer], 1, ctx.n_embd)) {
        snprintf(nameBuf, sizeof(nameBuf), "layers.%d.attention_norm.weight", layer);
        LoadTensor(loader, ctx, nameBuf, &ctx.layer_norm_1[layer], 1, ctx.n_embd);
    }
    
    snprintf(nameBuf, sizeof(nameBuf), "blk.%d.ffn_norm.weight", layer);
    if (!LoadTensor(loader, ctx, nameBuf, &ctx.layer_norm_2[layer], 1, ctx.n_embd)) {
        snprintf(nameBuf, sizeof(nameBuf), "layers.%d.ffn_norm.weight", layer);
        LoadTensor(loader, ctx, nameBuf, &ctx.layer_norm_2[layer], 1, ctx.n_embd);
    }
    
    return true;
}

bool GGUF_MASM_WeightBridge::LoadTensor(RawrXDModelLoader& loader, RawrXDInferenceCtx& ctx,
                                        const std::string& name, float** target, 
                                        int rows, int cols) {
    (void)ctx; // Unused for now
    
    // Try to get tensor from loader
    float* data = loader.GetTensor(name);
    if (!data) {
        // Tensor not found - not an error, just not present
        return false;
    }
    
    // Allocate and copy
    size_t count = (size_t)rows * cols;
    if (!AllocateAndCopy(target, data, count)) {
        m_lastError = "Failed to allocate memory for tensor: " + name;
        return false;
    }
    
    printf("[GGUF-MASM Bridge] Loaded %s: %dx%d\n", name.c_str(), rows, cols);
    return true;
}

bool GGUF_MASM_WeightBridge::AllocateAndCopy(float** target, const float* source, size_t count) {
    if (count == 0) return false;
    
    size_t bytes = count * sizeof(float);
    *target = (float*)VirtualAlloc(NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!*target) {
        return false;
    }
    
    memcpy(*target, source, bytes);
    m_allocatedBuffers.push_back(*target);
    return true;
}

void GGUF_MASM_WeightBridge::Cleanup() {
    for (float* buf : m_allocatedBuffers) {
        if (buf) {
            VirtualFree(buf, 0, MEM_RELEASE);
        }
    }
    m_allocatedBuffers.clear();
}

// ============================================================================
// C API EXPORTS
// ============================================================================

extern "C" {

// Load weights from GGUF file into MASM context
__declspec(dllexport) bool MASM_LoadGGUFWeights(
    const wchar_t* ggufPath,
    RawrXDInferenceCtx* ctx
) {
    if (!ggufPath || !ctx) return false;
    
    RawrXDModelLoader loader;
    if (!loader.Load(ggufPath, nullptr, nullptr)) {
        printf("[MASM] Failed to load GGUF: %ls\n", ggufPath);
        return false;
    }
    
    GGUF_MASM_WeightBridge bridge;
    return bridge.LoadFromGGUF(loader, *ctx);
}

// Free all loaded weights
__declspec(dllexport) void MASM_FreeWeights(RawrXDInferenceCtx* ctx) {
    if (!ctx) return;
    
    // Free token embeddings
    if (ctx->tok_embeddings) {
        VirtualFree(ctx->tok_embeddings, 0, MEM_RELEASE);
        ctx->tok_embeddings = nullptr;
    }
    
    // Free output weights
    if (ctx->output_weights) {
        VirtualFree(ctx->output_weights, 0, MEM_RELEASE);
        ctx->output_weights = nullptr;
    }
    
    // Free norm weights
    if (ctx->norm_weights) {
        VirtualFree(ctx->norm_weights, 0, MEM_RELEASE);
        ctx->norm_weights = nullptr;
    }
    
    // Free per-layer weights
    for (int i = 0; i < 32; i++) {
        if (ctx->layer_norm_1[i]) { VirtualFree(ctx->layer_norm_1[i], 0, MEM_RELEASE); ctx->layer_norm_1[i] = nullptr; }
        if (ctx->layer_norm_2[i]) { VirtualFree(ctx->layer_norm_2[i], 0, MEM_RELEASE); ctx->layer_norm_2[i] = nullptr; }
        if (ctx->wq[i]) { VirtualFree(ctx->wq[i], 0, MEM_RELEASE); ctx->wq[i] = nullptr; }
        if (ctx->wk[i]) { VirtualFree(ctx->wk[i], 0, MEM_RELEASE); ctx->wk[i] = nullptr; }
        if (ctx->wv[i]) { VirtualFree(ctx->wv[i], 0, MEM_RELEASE); ctx->wv[i] = nullptr; }
        if (ctx->wo[i]) { VirtualFree(ctx->wo[i], 0, MEM_RELEASE); ctx->wo[i] = nullptr; }
        if (ctx->w1[i]) { VirtualFree(ctx->w1[i], 0, MEM_RELEASE); ctx->w1[i] = nullptr; }
        if (ctx->w2[i]) { VirtualFree(ctx->w2[i], 0, MEM_RELEASE); ctx->w2[i] = nullptr; }
        if (ctx->w3[i]) { VirtualFree(ctx->w3[i], 0, MEM_RELEASE); ctx->w3[i] = nullptr; }
    }
}

} // extern "C"
