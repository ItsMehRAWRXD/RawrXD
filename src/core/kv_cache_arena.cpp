/**
 * @file kv_cache_arena.cpp
 * @brief KV-Cache Arena C++ Implementation
 * @version 1.0.0
 * 
 * C++ wrapper implementation for the MASM KV-cache arena.
 * 
 * @copyright (c) 2025 RawrXD Project
 */

#include "kv_cache_arena.h"
#include <algorithm>
#include <cstring>

namespace RawrXD::Inference {

// ============================================================================
// KV CACHE ARENA IMPLEMENTATION
// ============================================================================

KVCacheArena::KVCacheArena(uint32_t max_tokens, uint32_t head_dim, uint32_t num_heads)
    : handle_(nullptr)
    , max_tokens_(max_tokens)
    , head_dim_(head_dim)
    , num_heads_(num_heads)
    , pinned_(false) {
    handle_ = KVCache_Arena_Create(max_tokens, head_dim, num_heads);
}

KVCacheArena::~KVCacheArena() {
    if (handle_) {
        KVCache_Arena_Destroy(handle_);
        handle_ = nullptr;
    }
}

KVCacheArena::KVCacheArena(KVCacheArena&& other) noexcept
    : handle_(other.handle_)
    , max_tokens_(other.max_tokens_)
    , head_dim_(other.head_dim_)
    , num_heads_(other.num_heads_)
    , pinned_(other.pinned_) {
    other.handle_ = nullptr;
    other.pinned_ = false;
}

KVCacheArena& KVCacheArena::operator=(KVCacheArena&& other) noexcept {
    if (this != &other) {
        if (handle_) {
            KVCache_Arena_Destroy(handle_);
        }
        handle_ = other.handle_;
        max_tokens_ = other.max_tokens_;
        head_dim_ = other.head_dim_;
        num_heads_ = other.num_heads_;
        pinned_ = other.pinned_;
        other.handle_ = nullptr;
        other.pinned_ = false;
    }
    return *this;
}

bool KVCacheArena::Pin() {
    if (!handle_ || pinned_) {
        return pinned_;
    }
    pinned_ = KVCache_Arena_Pin(handle_) != 0;
    return pinned_;
}

bool KVCacheArena::IsPinned() const {
    return pinned_;
}

bool KVCacheArena::Write(uint32_t token_index, const float* key_data, const float* value_data) {
    if (!handle_) return false;
    return KVCache_Arena_Write(handle_, token_index, key_data, value_data) != 0;
}

bool KVCacheArena::Read(uint32_t token_index, float* key_data, float* value_data) const {
    if (!handle_) return false;
    return KVCache_Arena_Read(handle_, token_index, key_data, value_data) != 0;
}

void KVCacheArena::Clear() {
    if (handle_) {
        KVCache_Arena_Clear(handle_);
    }
}

uint32_t KVCacheArena::GetCurrentSize() const {
    // This would require adding a getter to the MASM side
    // For now, return 0 (placeholder)
    return 0;
}

uint32_t KVCacheArena::GetMaxTokens() const {
    return max_tokens_;
}

uint32_t KVCacheArena::GetHeadDim() const {
    return head_dim_;
}

uint32_t KVCacheArena::GetNumHeads() const {
    return num_heads_;
}

size_t KVCacheArena::GetMemoryUsage() const {
    // Calculate: max_tokens * head_dim * num_heads * 2 (K+V) * sizeof(float)
    return static_cast<size_t>(max_tokens_) * head_dim_ * num_heads_ * 2 * sizeof(float);
}

// ============================================================================
// FACTORY FUNCTIONS
// ============================================================================

KVCacheArenaPtr CreatePinnedCache(uint32_t max_context_length,
                                   uint32_t head_dim,
                                   uint32_t num_heads) {
    auto cache = std::make_unique<KVCacheArena>(max_context_length, head_dim, num_heads);
    if (cache->IsValid()) {
        cache->Pin();
    }
    return cache;
}

size_t CalculateKVCacheSize(uint32_t num_layers,
                            uint32_t max_seq_len,
                            uint32_t head_dim,
                            uint32_t num_heads) {
    // Per layer: max_seq_len * head_dim * num_heads * 2 (K+V) * sizeof(float)
    size_t per_layer = static_cast<size_t>(max_seq_len) * head_dim * num_heads * 2 * sizeof(float);
    return per_layer * num_layers;
}

void PrefetchCacheSlots(const KVCacheArena& arena,
                        uint32_t start_token,
                        uint32_t num_tokens) {
    // Implementation would use _mm_prefetch intrinsics
    // For now, this is a placeholder
    (void)arena;
    (void)start_token;
    (void)num_tokens;
}

} // namespace RawrXD::Inference

// ============================================================================
// METRICS IMPLEMENTATION
// ============================================================================

namespace RawrXD::Metrics {

namespace {
    // Thread-local metrics storage
    thread_local KVCacheMetrics g_metrics = {};
    thread_local bool g_metrics_enabled = false;
}

void EnableKVCacheMetrics() {
    g_metrics_enabled = true;
}

KVCacheMetrics GetKVCacheMetrics() {
    return g_metrics;
}

void ResetKVCacheMetrics() {
    g_metrics = KVCacheMetrics{};
}

} // namespace RawrXD::Metrics
