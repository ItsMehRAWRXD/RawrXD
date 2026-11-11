//=============================================================================
// Fix 5B: Flash Attention Types and Tile Structures
// RawrXD IDE - High-Performance Inference
//=============================================================================
// Defines aligned tile structures for Flash Attention kernel
// Assumes KV cache is already aligned from Fix 5A
//=============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <immintrin.h>

namespace RawrXD {
namespace Kernels {

//=============================================================================
// Aligned KV Tile Structure
// Used by Flash Attention tile loader
//=============================================================================
struct alignas(64) KVTile {
    float* K;           // Aligned pointer to K vectors
    float* V;           // Aligned pointer to V vectors
    
    uint32_t token_start;   // Starting token index
    uint32_t num_tokens;    // Number of tokens in tile
    uint32_t head_idx;      // Head index
    uint32_t head_dim;      // Dimension per head
    
    // Tile dimensions for blocking
    static constexpr uint32_t TILE_SIZE_M = 64;   // Query block size
    static constexpr uint32_t TILE_SIZE_N = 64;   // Key/value block size
    static constexpr uint32_t TILE_SIZE_K = 128;  // Head dimension blocking
    
    // Validate alignment (for VMOVAPS)
    bool IsAligned() const {
        return ((uintptr_t)K % 64 == 0) && ((uintptr_t)V % 64 == 0);
    }
    
    // Get size in bytes
    size_t GetSizeBytes() const {
        return num_tokens * head_dim * sizeof(float);
    }
};

//=============================================================================
// Query Tile Structure
//=============================================================================
struct alignas(64) QueryTile {
    float* Q;           // Query vectors
    uint32_t num_queries;
    uint32_t head_dim;
    
    bool IsAligned() const {
        return (uintptr_t)Q % 64 == 0;
    }
};

//=============================================================================
// Output Tile Structure
//=============================================================================
struct alignas(64) OutputTile {
    float* O;           // Output vectors
    uint32_t num_tokens;
    uint32_t head_dim;
    
    bool IsAligned() const {
        return (uintptr_t)O % 64 == 0;
    }
};

//=============================================================================
// Online Softmax State
// Maintained in registers during Flash Attention computation
//=============================================================================
struct alignas(64) OnlineSoftmaxState {
    float m;            // Running maximum
    float l;            // Running sum of exponentials
    float scale;        // Scaling factor (1/sqrt(d_k))
    
    // Initialize for new tile
    void Initialize(float scaling_factor) {
        m = -INFINITY;
        l = 0.0f;
        scale = scaling_factor;
    }
    
    // Update with new block
    void Update(float m_new, float l_new) {
        float m_prev = m;
        m = std::max(m, m_new);
        l = l * std::exp(m_prev - m) + l_new;
    }
    
    // Get normalization factor
    float GetNormalization() const {
        return 1.0f / l;
    }
};

//=============================================================================
// Flash Attention Configuration
//=============================================================================
struct FlashAttentionConfig {
    uint32_t seq_len;
    uint32_t num_heads;
    uint32_t head_dim;
    float scale;        // 1/sqrt(head_dim)
    
    // Tiling parameters (tuned for L1/L2 cache)
    uint32_t tile_m = KVTile::TILE_SIZE_M;
    uint32_t tile_n = KVTile::TILE_SIZE_N;
    uint32_t tile_k = KVTile::TILE_SIZE_K;
    
    // Calculate number of tiles
    uint32_t GetNumTilesM() const { return (seq_len + tile_m - 1) / tile_m; }
    uint32_t GetNumTilesN() const { return (seq_len + tile_n - 1) / tile_n; }
    uint32_t GetNumTilesK() const { return (head_dim + tile_k - 1) / tile_k; }
};

//=============================================================================
// Tile Loader Interface
// Connects aligned KV cache to Flash Attention kernel
//=============================================================================
class KVTileLoader {
public:
    // Load tile from aligned KV cache
    // Assumes KV cache uses [token][head][K/V][dim] layout from Fix 5A
    static bool LoadTile(
        const void* kv_cache_base,      // Base of aligned KV cache
        uint32_t token_start,
        uint32_t num_tokens,
        uint32_t head_idx,
        uint32_t head_dim,
        KVTile& out_tile
    );
    
    // Prefetch next tile (for pipelining)
    static void PrefetchNextTile(
        const void* kv_cache_base,
        uint32_t next_token_start,
        uint32_t num_tokens,
        uint32_t head_idx,
        uint32_t head_dim
    );
    
    // Validate tile alignment
    static bool ValidateTile(const KVTile& tile);
};

//=============================================================================
// Inline Tile Loader Implementation
//=============================================================================
inline bool KVTileLoader::LoadTile(
    const void* kv_cache_base,
    uint32_t token_start,
    uint32_t num_tokens,
    uint32_t head_idx,
    uint32_t head_dim,
    KVTile& out_tile
) {
    // Calculate offset into [token][head][K/V][dim] layout
    // Token stride = num_heads * 2 * head_dim (aligned to 64 bytes)
    // Head offset within token = head_idx * 2 * head_dim
    // K offset = 0, V offset = head_dim
    
    const uint32_t num_heads = 32;  // Should come from config
    const size_t token_stride = (num_heads * 2 * head_dim * sizeof(float) + 63) & ~63;
    const size_t head_offset = head_idx * 2 * head_dim * sizeof(float);
    
    const char* base = static_cast<const char*>(kv_cache_base);
    const char* token_base = base + token_start * token_stride;
    
    out_tile.K = (float*)(token_base + head_offset);
    out_tile.V = (float*)(token_base + head_offset + head_dim * sizeof(float));
    out_tile.token_start = token_start;
    out_tile.num_tokens = num_tokens;
    out_tile.head_idx = head_idx;
    out_tile.head_dim = head_dim;
    
    return ValidateTile(out_tile);
}

inline void KVTileLoader::PrefetchNextTile(
    const void* kv_cache_base,
    uint32_t next_token_start,
    uint32_t num_tokens,
    uint32_t head_idx,
    uint32_t head_dim
) {
    KVTile next_tile;
    if (LoadTile(kv_cache_base, next_token_start, num_tokens, head_idx, head_dim, next_tile)) {
        // Prefetch K and V for next tile
        for (uint32_t t = 0; t < num_tokens; t += 4) {
            _mm_prefetch((const char*)next_tile.K + t * head_dim * sizeof(float), _MM_HINT_T0);
            _mm_prefetch((const char*)next_tile.V + t * head_dim * sizeof(float), _MM_HINT_T0);
        }
    }
}

inline bool KVTileLoader::ValidateTile(const KVTile& tile) {
    return tile.IsAligned() && tile.K != nullptr && tile.V != nullptr;
}

} // namespace Kernels
} // namespace RawrXD
