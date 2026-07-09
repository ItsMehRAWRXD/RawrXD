#pragma once
// ============================================================================
// Optimized KV Cache - Structure of Arrays (SoA) Layout
// ============================================================================
// Improves memory locality and enables vectorized access patterns
// ============================================================================

#include <cstdint>
#include <vector>
#include <memory>
#include <cstring>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// Cache-Optimized KV Cache
// ============================================================================
// Layout: [layer][head][seq][dim] -> SoA for better vectorization
// Each head's K/V stored contiguously to maximize cache line utilization
// ============================================================================

class OptimizedKVCache {
public:
    struct Config {
        uint32_t num_layers = 0;
        uint32_t num_heads = 0;
        uint32_t head_dim = 0;
        uint32_t max_seq_len = 0;
        uint32_t batch_size = 1;
        
        // Tiling for cache efficiency
        uint32_t tile_size = 64;  // Process 64 tokens at a time
    };
    
    OptimizedKVCache();
    ~OptimizedKVCache();
    
    // Disable copy, enable move
    OptimizedKVCache(const OptimizedKVCache&) = delete;
    OptimizedKVCache& operator=(const OptimizedKVCache&) = delete;
    OptimizedKVCache(OptimizedKVCache&&) = default;
    OptimizedKVCache& operator=(OptimizedKVCache&&) = default;
    
    // Initialize with configuration
    bool Initialize(const Config& config);
    
    // Reset cache for new sequence
    void Reset();
    
    // Get cache pointers for a specific position
    // Returns aligned pointer to K and V for the given layer/head/position
    float* GetK(uint32_t layer, uint32_t head, uint32_t seq);
    float* GetV(uint32_t layer, uint32_t head, uint32_t seq);
    
    // Get contiguous block for vectorized operations
    // Returns pointer to K/V for seq_start to seq_end (contiguous in memory)
    float* GetKBlock(uint32_t layer, uint32_t head, uint32_t seq_start, uint32_t seq_len);
    float* GetVBlock(uint32_t layer, uint32_t head, uint32_t seq_start, uint32_t seq_len);
    
    // Prefetch upcoming cache lines (for attention kernels)
    void PrefetchK(uint32_t layer, uint32_t head, uint32_t seq, uint32_t num_lines = 4);
    void PrefetchV(uint32_t layer, uint32_t head, uint32_t seq, uint32_t num_lines = 4);
    
    // Get current sequence length
    uint32_t GetCurrentSeqLen() const { return current_seq_len_; }
    void SetCurrentSeqLen(uint32_t len) { current_seq_len_ = len; }
    
    // Memory statistics
    size_t GetMemoryUsage() const;
    float GetCacheHitRate() const;  // Estimated
    
private:
    Config config_;
    
    // SoA layout: [layer][head][seq][dim] for both K and V
    // K and V stored separately for better prefetching
    std::vector<float> k_cache_;  // Aligned to 64 bytes
    std::vector<float> v_cache_;  // Aligned to 64 bytes
    
    uint32_t current_seq_len_ = 0;
    
    // Strides for indexing
    size_t layer_stride_ = 0;
    size_t head_stride_ = 0;
    size_t seq_stride_ = 0;
    
    // Calculate index into cache
    size_t GetIndex(uint32_t layer, uint32_t head, uint32_t seq) const {
        return layer * layer_stride_ + head * head_stride_ + seq * seq_stride_;
    }
    
    bool initialized_ = false;
};

// ============================================================================
// Tiled KV Cache for FlashAttention-style computation
// ============================================================================
// Processes cache in tiles that fit in L2 cache
// ============================================================================

class TiledKVCache {
public:
    struct TileConfig {
        uint32_t tile_q = 64;   // Query tile size
        uint32_t tile_kv = 64;  // KV tile size
        uint32_t tile_dim = 64; // Head dimension tile
    };
    
    TiledKVCache();
    ~TiledKVCache();
    
    bool Initialize(const OptimizedKVCache::Config& config, 
                    const TileConfig& tile_config);
    
    // Load a tile of KV into L2-friendly buffer
    void LoadKTile(uint32_t layer, uint32_t head, 
                   uint32_t seq_start, uint32_t seq_len,
                   float* output_buffer);
    
    void LoadVTile(uint32_t layer, uint32_t head,
                   uint32_t seq_start, uint32_t seq_len,
                   float* output_buffer);
    
private:
    OptimizedKVCache::Config config_;
    TileConfig tile_config_;
    
    // Reference to underlying cache
    OptimizedKVCache* parent_cache_ = nullptr;
};

// ============================================================================
// Multi-Head Parallel Attention
// ============================================================================
// Parallelizes attention computation across heads
// ============================================================================

class ParallelAttention {
public:
    struct WorkItem {
        uint32_t layer;
        uint32_t head_start;
        uint32_t head_end;
        uint32_t seq_len;
        const float* query;
        const float* key_cache;
        const float* value_cache;
        float* output;
    };
    
    // Process multiple heads in parallel
    // Returns number of threads used
    static uint32_t ComputeAttentionParallel(
        const WorkItem* items,
        uint32_t num_items,
        uint32_t num_threads = 0  // 0 = auto
    );
    
    // Process FFN in parallel (across batch or hidden chunks)
    static uint32_t ComputeFFNParallel(
        const float* input,
        const float* gate_weights,
        const float* up_weights,
        const float* down_weights,
        float* output,
        uint32_t batch_size,
        uint32_t hidden_size,
        uint32_t intermediate_size,
        uint32_t num_threads = 0
    );
};

} // namespace Runtime
} // namespace RawrXD
