// SovereignKVCache.cpp
// Phase 3.1 — Flat ring-buffer KV cache implementation

#include "SovereignKVCache.hpp"
#include <cstdio>

namespace RawrXD {
namespace AI {

bool SovereignKVCache::Initialize(uint32_t layers, uint32_t ctx, uint32_t embd_k, uint32_t embd_v) {
    Free();

    n_layer = layers;
    n_ctx   = ctx;
    n_embd_k = embd_k;
    n_embd_v = embd_v;
    seq_len = 0;

    size_t k_count = static_cast<size_t>(n_layer) * n_ctx * n_embd_k;
    size_t v_count = static_cast<size_t>(n_layer) * n_ctx * n_embd_v;

    k_cache = AlignedAllocF32(k_count);
    v_cache = AlignedAllocF32(v_count);

    if (!k_cache || !v_cache) {
        fprintf(stderr, "FATAL: KV cache allocation failed (layers=%u ctx=%u)\n", layers, ctx);
        Free();
        return false;
    }

    memset(k_cache, 0, k_count * sizeof(float));
    memset(v_cache, 0, v_count * sizeof(float));

    k_stride_layer_ = static_cast<size_t>(n_ctx) * n_embd_k * sizeof(float);
    v_stride_layer_ = static_cast<size_t>(n_ctx) * n_embd_v * sizeof(float);

    printf("[KVCache] Allocated: K=%.2f MB V=%.2f MB (layers=%u ctx=%u)\n",
           (k_count * sizeof(float)) / (1024.0 * 1024.0),
           (v_count * sizeof(float)) / (1024.0 * 1024.0),
           layers, ctx);
    return true;
}

void SovereignKVCache::Free() {
    AlignedFree(k_cache); k_cache = nullptr;
    AlignedFree(v_cache); v_cache = nullptr;
    n_layer = n_ctx = n_embd_k = n_embd_v = 0;
    seq_len = 0;
    k_stride_layer_ = v_stride_layer_ = 0;
}

void SovereignKVCache::WriteK(uint32_t layer, const float* k_data) {
    if (!k_cache || layer >= n_layer || seq_len >= n_ctx) return;
    float* dst = k_cache + (static_cast<size_t>(layer) * n_ctx + seq_len) * n_embd_k;
    memcpy(dst, k_data, n_embd_k * sizeof(float));
}

void SovereignKVCache::WriteV(uint32_t layer, const float* v_data) {
    if (!v_cache || layer >= n_layer || seq_len >= n_ctx) return;
    float* dst = v_cache + (static_cast<size_t>(layer) * n_ctx + seq_len) * n_embd_v;
    memcpy(dst, v_data, n_embd_v * sizeof(float));
}

const float* SovereignKVCache::ReadK(uint32_t layer, uint32_t pos) const {
    if (!k_cache || layer >= n_layer || pos >= seq_len) return nullptr;
    return k_cache + (static_cast<size_t>(layer) * n_ctx + pos) * n_embd_k;
}

const float* SovereignKVCache::ReadV(uint32_t layer, uint32_t pos) const {
    if (!v_cache || layer >= n_layer || pos >= seq_len) return nullptr;
    return v_cache + (static_cast<size_t>(layer) * n_ctx + pos) * n_embd_v;
}

size_t SovereignKVCache::TotalBytes() const {
    size_t k_count = static_cast<size_t>(n_layer) * n_ctx * n_embd_k;
    size_t v_count = static_cast<size_t>(n_layer) * n_ctx * n_embd_v;
    return (k_count + v_count) * sizeof(float);
}

float* SovereignKVCache::AlignedAllocF32(size_t count) {
    void* p = _aligned_malloc(count * sizeof(float), 512);
    return static_cast<float*>(p);
}

void SovereignKVCache::AlignedFree(void* ptr) {
    _aligned_free(ptr);
}

} // namespace AI
} // namespace RawrXD
