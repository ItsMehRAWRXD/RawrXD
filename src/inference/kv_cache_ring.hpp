//=============================================================================
// KV Cache Ring Buffer - Pinned Tier 1 Memory Implementation
// Prevents OS swapping and eliminates hotswap triggers
//=============================================================================
#pragma once

#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <atomic>

namespace RawrXD {
namespace Inference {

//=============================================================================
// Configuration
//=============================================================================

// Maximum sequence length supported (power of 2 for mask optimization)
constexpr size_t kMaxSequenceLength = 4096;  // 4K tokens
constexpr size_t kSequenceMask = kMaxSequenceLength - 1;

// Number of KV heads (can be different from attention heads in GQA)
constexpr int kNumKVHeads = 8;

// Head dimension (common values: 64, 128)
constexpr int kHeadDim = 128;

//=============================================================================
// Pinned Memory Allocator
// Uses VirtualLock to prevent OS swapping
//=============================================================================

template <typename T>
class PinnedAllocator {
public:
    static T* Allocate(size_t count) {
        // Allocate with 64-byte alignment for AVX-512
        size_t bytes = count * sizeof(T);
        T* ptr = static_cast<T*>(_aligned_malloc(bytes, 64));
        
        if (!ptr) return nullptr;
        
        // Pin memory to prevent swapping to disk
        // This ensures KV cache stays in physical RAM (Tier 1)
        if (!VirtualLock(ptr, bytes)) {
            // Fallback: allocation succeeded but pinning failed
            // Log warning but continue (performance will suffer)
            OutputDebugStringA("[KVCache] Warning: VirtualLock failed, cache may swap\n");
        }
        
        return ptr;
    }
    
    static void Free(T* ptr, size_t count) {
        if (ptr) {
            VirtualUnlock(ptr, count * sizeof(T));
            _aligned_free(ptr);
        }
    }
};

//=============================================================================
// KV Cache Entry
// Stores K and V vectors for a single position
//=============================================================================

struct alignas(64) KVCacheEntry {
    float k[kHeadDim];  // Key vector
    float v[kHeadDim];  // Value vector
    uint32_t seq_pos;    // Sequence position (for validation)
    uint32_t valid;      // Validity flag (0xDEADBEEF = valid)
    
    static constexpr uint32_t kMagic = 0xDEADBEEF;
    
    bool IsValid() const { return valid == kMagic; }
    void MarkValid() { valid = kMagic; }
    void Invalidate() { valid = 0; }
};

//=============================================================================
// KV Cache Ring Buffer
// Circular buffer with O(1) slide operation
//=============================================================================

class alignas(64) KVCacheRing {
public:
    KVCacheRing() = default;
    ~KVCacheRing() { Shutdown(); }
    
    // Initialize the ring buffer
    // Must be called once at model load time (prevents inference-time allocation)
    bool Initialize(int num_layers, int num_heads, int head_dim, size_t max_seq_len);
    
    // Shutdown and free memory
    void Shutdown();
    
    // Store K,V for current position - O(1)
    void StoreKV(int layer, int head, size_t seq_pos, 
                 const float* __restrict k_vec, 
                 const float* __restrict v_vec);
    
    // Retrieve K for attention computation
    const float* GetK(int layer, int head, size_t seq_pos) const;
    
    // Retrieve V for attention computation  
    const float* GetV(int layer, int head, size_t seq_pos) const;
    
    // Get window start for sliding window attention
    size_t GetWindowStart(size_t current_pos, size_t window_size) const {
        return (current_pos > window_size) ? (current_pos - window_size) : 0;
    }
    
    // Get current cache size (number of stored positions)
    size_t GetCacheSize() const { return cache_size_.load(std::memory_order_acquire); }
    
    // Check if position is in cache
    bool HasPosition(int layer, int head, size_t seq_pos) const;
    
    // Clear cache (for new sequence)
    void Clear();
    
    // Memory statistics
    struct MemoryStats {
        size_t allocated_bytes;
        size_t used_bytes;
        size_t pinned_bytes;
        bool is_pinned;
    };
    MemoryStats GetMemoryStats() const;
    
private:
    // Layout: [layer][head][seq_pos]
    KVCacheEntry* cache_ = nullptr;
    
    int num_layers_ = 0;
    int num_heads_ = 0;
    int head_dim_ = 0;
    size_t max_seq_len_ = 0;
    
    // Current write position (monotonically increasing)
    alignas(64) std::atomic<size_t> write_pos_{0};
    alignas(64) std::atomic<size_t> cache_size_{0};
    
    // Calculate offset into flat array
    size_t GetOffset(int layer, int head, size_t seq_pos) const {
        return ((layer * num_heads_ + head) * max_seq_len_) + (seq_pos & kSequenceMask);
    }
};

//=============================================================================
// Global KV Cache Instance
// Singleton for model-wide cache management
//=============================================================================

class KVCacheManager {
public:
    static KVCacheManager& Instance();
    
    // Initialize for model
    bool Initialize(int n_layers, int n_heads, int head_dim, size_t max_ctx);
    
    // Get cache for current inference
    KVCacheRing* GetCache() { return &cache_; }
    
    // Memory pressure check (prevents hotswap triggers)
    bool CheckMemoryPressure();
    
    // Get memory stats
    size_t GetAllocatedBytes() const;
    
private:
    KVCacheRing cache_;
    bool initialized_ = false;
    size_t allocated_bytes_ = 0;
};

} // namespace Inference
} // namespace RawrXD
