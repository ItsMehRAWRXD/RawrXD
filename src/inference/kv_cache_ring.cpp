//=============================================================================
// KV Cache Ring Buffer Implementation
// Pinned memory prevents OS swapping (Tier 1 guarantee)
//=============================================================================

#include "kv_cache_ring.hpp"
#include <string>  // For memset

namespace RawrXD {
namespace Inference {

//=============================================================================
// KVCacheRing Implementation
//=============================================================================

bool KVCacheRing::Initialize(int num_layers, int num_heads, int head_dim, size_t max_seq_len) {
    if (cache_) {
        Shutdown();  // Clean up existing
    }
    
    num_layers_ = num_layers;
    num_heads_ = num_heads;
    head_dim_ = head_dim;
    max_seq_len_ = max_seq_len;
    
    // Calculate total entries needed
    size_t total_entries = num_layers * num_heads * max_seq_len;
    
    // Allocate pinned memory
    cache_ = PinnedAllocator<KVCacheEntry>::Allocate(total_entries);
    if (!cache_) {
        OutputDebugStringA("[KVCache] ERROR: Failed to allocate pinned memory\n");
        return false;
    }
    
    // Zero initialize
    memset(cache_, 0, total_entries * sizeof(KVCacheEntry));
    
    write_pos_.store(0, std::memory_order_release);
    cache_size_.store(0, std::memory_order_release);
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "[KVCache] Initialized: %d layers, %d heads, %zu seq_len = %.2f MB (pinned)\n",
        num_layers, num_heads, max_seq_len,
        (total_entries * sizeof(KVCacheEntry)) / (1024.0 * 1024.0));
    OutputDebugStringA(msg);
    
    return true;
}

void KVCacheRing::Shutdown() {
    if (cache_) {
        size_t total_entries = num_layers_ * num_heads_ * max_seq_len_;
        PinnedAllocator<KVCacheEntry>::Free(cache_, total_entries);
        cache_ = nullptr;
        OutputDebugStringA("[KVCache] Shutdown complete\n");
    }
    
    num_layers_ = 0;
    num_heads_ = 0;
    head_dim_ = 0;
    max_seq_len_ = 0;
    write_pos_.store(0);
    cache_size_.store(0);
}

void KVCacheRing::StoreKV(int layer, int head, size_t seq_pos,
                          const float* __restrict k_vec,
                          const float* __restrict v_vec) {
    if (!cache_) return;
    
    size_t offset = GetOffset(layer, head, seq_pos);
    KVCacheEntry* entry = &cache_[offset];
    
    // Copy K and V vectors
    memcpy(entry->k, k_vec, head_dim_ * sizeof(float));
    memcpy(entry->v, v_vec, head_dim_ * sizeof(float));
    entry->seq_pos = static_cast<uint32_t>(seq_pos);
    entry->MarkValid();
    
    // Update write position and cache size
    size_t new_pos = seq_pos + 1;
    size_t current_write = write_pos_.load(std::memory_order_relaxed);
    if (new_pos > current_write) {
        write_pos_.store(new_pos, std::memory_order_release);
    }
    
    size_t current_size = cache_size_.load(std::memory_order_relaxed);
    if (new_pos > current_size) {
        cache_size_.store(new_pos, std::memory_order_release);
    }
}

const float* KVCacheRing::GetK(int layer, int head, size_t seq_pos) const {
    if (!cache_) return nullptr;
    
    size_t offset = GetOffset(layer, head, seq_pos);
    const KVCacheEntry* entry = &cache_[offset];
    
    // Validate entry
    if (!entry->IsValid() || entry->seq_pos != seq_pos) {
        return nullptr;  // Cache miss or stale entry
    }
    
    return entry->k;
}

const float* KVCacheRing::GetV(int layer, int head, size_t seq_pos) const {
    if (!cache_) return nullptr;
    
    size_t offset = GetOffset(layer, head, seq_pos);
    const KVCacheEntry* entry = &cache_[offset];
    
    // Validate entry
    if (!entry->IsValid() || entry->seq_pos != seq_pos) {
        return nullptr;
    }
    
    return entry->v;
}

bool KVCacheRing::HasPosition(int layer, int head, size_t seq_pos) const {
    if (!cache_) return false;
    if (seq_pos >= max_seq_len_) return false;
    
    size_t offset = GetOffset(layer, head, seq_pos);
    const KVCacheEntry* entry = &cache_[offset];
    
    return entry->IsValid() && entry->seq_pos == seq_pos;
}

void KVCacheRing::Clear() {
    if (!cache_) return;
    
    size_t total_entries = num_layers_ * num_heads_ * max_seq_len_;
    memset(cache_, 0, total_entries * sizeof(KVCacheEntry));
    
    write_pos_.store(0, std::memory_order_release);
    cache_size_.store(0, std::memory_order_release);
    
    OutputDebugStringA("[KVCache] Cleared\n");
}

KVCacheRing::MemoryStats KVCacheRing::GetMemoryStats() const {
    MemoryStats stats = {};
    
    if (cache_) {
        stats.allocated_bytes = num_layers_ * num_heads_ * max_seq_len_ * sizeof(KVCacheEntry);
        stats.used_bytes = cache_size_.load(std::memory_order_acquire) * 
                          num_layers_ * num_heads_ * sizeof(KVCacheEntry);
        stats.pinned_bytes = stats.allocated_bytes;
        stats.is_pinned = true;
    }
    
    return stats;
}

//=============================================================================
// KVCacheManager Singleton
//=============================================================================

KVCacheManager& KVCacheManager::Instance() {
    static KVCacheManager instance;
    return instance;
}

bool KVCacheManager::Initialize(int n_layers, int n_heads, int head_dim, size_t max_ctx) {
    if (initialized_) {
        return true;  // Already initialized
    }
    
    if (!cache_.Initialize(n_layers, n_heads, head_dim, max_ctx)) {
        return false;
    }
    
    allocated_bytes_ = n_layers * n_heads * max_ctx * sizeof(KVCacheEntry);
    initialized_ = true;
    
    return true;
}

bool KVCacheManager::CheckMemoryPressure() {
    if (!initialized_) return false;
    
    // Check if we're approaching memory limits
    // This prevents the "hotswap trigger" seen in telemetry
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    
    // If available physical memory is below 10%, signal pressure
    DWORDLONG available_mb = memStatus.ullAvailPhys / (1024 * 1024);
    DWORDLONG total_mb = memStatus.ullTotalPhys / (1024 * 1024);
    
    if (available_mb < (total_mb / 10)) {
        OutputDebugStringA("[KVCache] WARNING: Memory pressure detected\n");
        return true;
    }
    
    return false;
}

size_t KVCacheManager::GetAllocatedBytes() const {
    return allocated_bytes_;
}

} // namespace Inference
} // namespace RawrXD
