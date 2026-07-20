/**=============================================================================
 * RawrXD_FlashAttention_v2.hpp
 * Memory-Efficient Attention with Online Softmax
 * 
 * Implements Flash Attention v2 algorithm for O(N) memory complexity
 * instead of O(N²) materialized attention matrix.
 * 
 * Reference: Dao et al., "FlashAttention-2: Faster Attention with Better 
 *            Parallelism and Work Partitioning", 2023
 *=============================================================================*/

#ifndef RAWRXD_FLASH_ATTENTION_V2_HPP
#define RAWRXD_FLASH_ATTENTION_V2_HPP

#include <cstdint>
#include <cstddef>
#include <immintrin.h>
#include <math.h>
#include <algorithm>

namespace RawrXD {
namespace Memory {

/**=============================================================================
 * Flash Attention v2 Configuration
 *=============================================================================*/
struct FlashAttentionConfig {
    static constexpr int BLOCK_M = 128;  // Query block size
    static constexpr int BLOCK_N = 128;  // Key/Value block size
    static constexpr int BLOCK_D = 64;   // Head dimension block
    static constexpr float SM_SCALE = 0.125f;  // 1/sqrt(64) = 0.125
    
    // Tile sizes for register-level accumulation
    static constexpr int TILE_M = 4;     // Rows per thread
    static constexpr int TILE_N = 4;     // Columns per thread
};

/**=============================================================================
 * Online Softmax Statistics
 * Tracks running max and sum for numerical stability
 *=============================================================================*/
struct OnlineSoftmaxState {
    float max_val;
    float sum_exp;
    
    OnlineSoftmaxState() : max_val(-INFINITY), sum_exp(0.0f) {}
    
    // Update with new values
    inline void Update(float new_max, float new_sum) {
        if (new_max > max_val) {
            // Rescale existing sum
            sum_exp = sum_exp * expf(max_val - new_max) + new_sum;
            max_val = new_max;
        } else {
            // Scale new sum to current max
            sum_exp += new_sum * expf(new_max - max_val);
        }
    }
    
    // Get normalized probability
    inline float Normalize(float val) const {
        return expf(val - max_val) / sum_exp;
    }
};

/**=============================================================================
 * Flash Attention v2 Implementation
 * 
 * Algorithm:
 * 1. Tile Q, K, V into blocks that fit in SRAM
 * 2. Compute attention in tiles without materializing full N×N matrix
 * 3. Use online softmax for numerical stability
 * 4. Fuse matmul + softmax + matmul into single kernel
 *=============================================================================*/
class FlashAttentionV2 {
public:
    /**=========================================================================
     * Forward pass: Compute attention output
     * 
     * @param Q Query matrix [batch, seq_q, head_dim]
     * @param K Key matrix [batch, seq_kv, head_dim]
     * @param V Value matrix [batch, seq_kv, head_dim]
     * @param O Output matrix [batch, seq_q, head_dim]
     * @param batch_size Number of sequences in batch
     * @param seq_q Query sequence length
     * @param seq_kv Key/Value sequence length
     * @param head_dim Head dimension (typically 64 or 128)
     * @param scale Softmax scale (typically 1/sqrt(head_dim))
     *=========================================================================*/
    static void Forward(
        const float* __restrict Q,
        const float* __restrict K,
        const float* __restrict V,
        float* __restrict O,
        int batch_size,
        int seq_q,
        int seq_kv,
        int head_dim,
        float scale = 0.0f
    ) {
        if (scale == 0.0f) {
            scale = 1.0f / sqrtf((float)head_dim);
        }
        
        // Process each batch
        for (int b = 0; b < batch_size; ++b) {
            const float* Q_batch = Q + (size_t)b * seq_q * head_dim;
            const float* K_batch = K + (size_t)b * seq_kv * head_dim;
            const float* V_batch = V + (size_t)b * seq_kv * head_dim;
            float* O_batch = O + (size_t)b * seq_q * head_dim;
            
            ForwardSingleBatch(
                Q_batch, K_batch, V_batch, O_batch,
                seq_q, seq_kv, head_dim, scale
            );
        }
    }
    
    /**=========================================================================
     * Optimized forward with causal masking (for autoregressive models)
     * Only attends to previous positions
     *=========================================================================*/
    static void ForwardCausal(
        const float* __restrict Q,
        const float* __restrict K,
        const float* __restrict V,
        float* __restrict O,
        int batch_size,
        int seq_len,
        int head_dim,
        float scale = 0.0f
    ) {
        if (scale == 0.0f) {
            scale = 1.0f / sqrtf((float)head_dim);
        }
        
        for (int b = 0; b < batch_size; ++b) {
            const float* Q_batch = Q + (size_t)b * seq_len * head_dim;
            const float* K_batch = K + (size_t)b * seq_len * head_dim;
            const float* V_batch = V + (size_t)b * seq_len * head_dim;
            float* O_batch = O + (size_t)b * seq_len * head_dim;
            
            ForwardSingleBatchCausal(
                Q_batch, K_batch, V_batch, O_batch,
                seq_len, head_dim, scale
            );
        }
    }

private:
    /**=========================================================================
     * Single batch forward pass (non-causal)
     *=========================================================================*/
    static void ForwardSingleBatch(
        const float* __restrict Q,
        const float* __restrict K,
        const float* __restrict V,
        float* __restrict O,
        int seq_q,
        int seq_kv,
        int head_dim,
        float scale
    ) {
        const int BLOCK_M = FlashAttentionConfig::BLOCK_M;
        const int BLOCK_N = FlashAttentionConfig::BLOCK_N;
        
        // Allocate tile buffers (simulated SRAM)
        alignas(64) float q_tile[BLOCK_M * 64];  // Query tile
        alignas(64) float k_tile[BLOCK_N * 64];  // Key tile
        alignas(64) float v_tile[BLOCK_N * 64];  // Value tile
        alignas(64) float s_tile[BLOCK_M * BLOCK_N];  // Attention scores
        alignas(64) float o_tile[BLOCK_M * 64];   // Output accumulator
        
        // Online softmax state per row
        alignas(64) OnlineSoftmaxState row_stats[BLOCK_M];
        
        // Process query blocks
        for (int q_block = 0; q_block < seq_q; q_block += BLOCK_M) {
            const int q_size = std::min(BLOCK_M, seq_q - q_block);
            
            // Initialize output accumulator and softmax state
            for (int i = 0; i < q_size * head_dim; ++i) {
                o_tile[i] = 0.0f;
            }
            for (int i = 0; i < q_size; ++i) {
                row_stats[i] = OnlineSoftmaxState();
            }
            
            // Load Q tile
            LoadTile(Q, q_tile, q_block, 0, seq_q, head_dim, q_size, head_dim);
            
            // Process key/value blocks
            for (int kv_block = 0; kv_block < seq_kv; kv_block += BLOCK_N) {
                const int kv_size = std::min(BLOCK_N, seq_kv - kv_block);
                
                // Load K and V tiles
                LoadTile(K, k_tile, kv_block, 0, seq_kv, head_dim, kv_size, head_dim);
                LoadTile(V, v_tile, kv_block, 0, seq_kv, head_dim, kv_size, head_dim);
                
                // Compute S = Q @ K^T
                ComputeAttentionScores(
                    q_tile, k_tile, s_tile,
                    q_size, kv_size, head_dim, scale
                );
                
                // Online softmax and accumulate
                ApplyOnlineSoftmaxAndAccumulate(
                    s_tile, v_tile, o_tile, row_stats,
                    q_size, kv_size, head_dim
                );
            }
            
            // Normalize and store output
            NormalizeAndStoreOutput(
                o_tile, O, row_stats,
                q_block, seq_q, head_dim, q_size
            );
        }
    }
    
    /**=========================================================================
     * Single batch forward pass (causal)
     *=========================================================================*/
    static void ForwardSingleBatchCausal(
        const float* __restrict Q,
        const float* __restrict K,
        const float* __restrict V,
        float* __restrict O,
        int seq_len,
        int head_dim,
        float scale
    ) {
        const int BLOCK_M = FlashAttentionConfig::BLOCK_M;
        const int BLOCK_N = FlashAttentionConfig::BLOCK_N;
        
        alignas(64) float q_tile[BLOCK_M * 64];
        alignas(64) float k_tile[BLOCK_N * 64];
        alignas(64) float v_tile[BLOCK_N * 64];
        alignas(64) float s_tile[BLOCK_M * BLOCK_N];
        alignas(64) float o_tile[BLOCK_M * 64];
        alignas(64) OnlineSoftmaxState row_stats[BLOCK_M];
        
        for (int q_block = 0; q_block < seq_len; q_block += BLOCK_M) {
            const int q_size = std::min(BLOCK_M, seq_len - q_block);
            
            // Initialize
            for (int i = 0; i < q_size * head_dim; ++i) {
                o_tile[i] = 0.0f;
            }
            for (int i = 0; i < q_size; ++i) {
                row_stats[i] = OnlineSoftmaxState();
            }
            
            LoadTile(Q, q_tile, q_block, 0, seq_len, head_dim, q_size, head_dim);
            
            // Causal masking: only process kv blocks up to current q position
            const int kv_limit = q_block + q_size;
            
            for (int kv_block = 0; kv_block < kv_limit; kv_block += BLOCK_N) {
                const int kv_size = std::min(BLOCK_N, kv_limit - kv_block);
                
                LoadTile(K, k_tile, kv_block, 0, seq_len, head_dim, kv_size, head_dim);
                LoadTile(V, v_tile, kv_block, 0, seq_len, head_dim, kv_size, head_dim);
                
                ComputeAttentionScores(q_tile, k_tile, s_tile, q_size, kv_size, head_dim, scale);
                
                // Apply causal mask within the block
                if (kv_block + kv_size > q_block) {
                    ApplyCausalMask(s_tile, q_block, kv_block, q_size, kv_size);
                }
                
                ApplyOnlineSoftmaxAndAccumulate(s_tile, v_tile, o_tile, row_stats, q_size, kv_size, head_dim);
            }
            
            NormalizeAndStoreOutput(o_tile, O, row_stats, q_block, seq_len, head_dim, q_size);
        }
    }
    
    /**=========================================================================
     * Load tile from global memory
     *=========================================================================*/
    static void LoadTile(
        const float* __restrict src,
        float* __restrict tile,
        int row_start, int col_start,
        int src_stride_row, int src_stride_col,
        int tile_rows, int tile_cols
    ) {
        for (int r = 0; r < tile_rows; ++r) {
            for (int c = 0; c < tile_cols; ++c) {
                tile[r * tile_cols + c] = src[(row_start + r) * src_stride_col + (col_start + c)];
            }
        }
    }
    
    /**=========================================================================
     * Compute attention scores: S = Q @ K^T * scale
     *=========================================================================*/
    static void ComputeAttentionScores(
        const float* __restrict Q_tile,
        const float* __restrict K_tile,
        float* __restrict S_tile,
        int q_size, int kv_size, int head_dim,
        float scale
    ) {
        for (int i = 0; i < q_size; ++i) {
            for (int j = 0; j < kv_size; ++j) {
                float dot = 0.0f;
                for (int d = 0; d < head_dim; ++d) {
                    dot += Q_tile[i * head_dim + d] * K_tile[j * head_dim + d];
                }
                S_tile[i * kv_size + j] = dot * scale;
            }
        }
    }
    
    /**=========================================================================
     * Apply causal mask (for autoregressive attention)
     *=========================================================================*/
    static void ApplyCausalMask(
        float* __restrict S_tile,
        int q_block_start, int kv_block_start,
        int q_size, int kv_size
    ) {
        for (int i = 0; i < q_size; ++i) {
            int q_pos = q_block_start + i;
            for (int j = 0; j < kv_size; ++j) {
                int kv_pos = kv_block_start + j;
                if (kv_pos > q_pos) {
                    S_tile[i * kv_size + j] = -INFINITY;
                }
            }
        }
    }
    
    /**=========================================================================
     * Online softmax and accumulate: O += softmax(S) @ V
     *=========================================================================*/
    static void ApplyOnlineSoftmaxAndAccumulate(
        const float* __restrict S_tile,
        const float* __restrict V_tile,
        float* __restrict O_tile,
        OnlineSoftmaxState* row_stats,
        int q_size, int kv_size, int head_dim
    ) {
        // For each query row
        for (int i = 0; i < q_size; ++i) {
            // Find max in this row
            float row_max = -INFINITY;
            for (int j = 0; j < kv_size; ++j) {
                row_max = std::max(row_max, S_tile[i * kv_size + j]);
            }
            
            // Compute exp and sum
            float row_sum = 0.0f;
            alignas(64) float exp_vals[FlashAttentionConfig::BLOCK_N];
            for (int j = 0; j < kv_size; ++j) {
                exp_vals[j] = expf(S_tile[i * kv_size + j] - row_max);
                row_sum += exp_vals[j];
            }
            
            // Update online softmax state
            row_stats[i].Update(row_max, row_sum);
            
            // Accumulate weighted values
            for (int d = 0; d < head_dim; ++d) {
                float weighted_sum = 0.0f;
                for (int j = 0; j < kv_size; ++j) {
                    weighted_sum += exp_vals[j] * V_tile[j * head_dim + d];
                }
                O_tile[i * head_dim + d] += weighted_sum;
            }
        }
    }
    
    /**=========================================================================
     * Normalize output and store to global memory
     *=========================================================================*/
    static void NormalizeAndStoreOutput(
        const float* __restrict O_tile,
        float* __restrict O,
        const OnlineSoftmaxState* row_stats,
        int row_start, int stride_row, int stride_col,
        int num_rows
    ) {
        for (int i = 0; i < num_rows; ++i) {
            float norm_factor = 1.0f / row_stats[i].sum_exp;
            for (int d = 0; d < stride_col; ++d) {
                O[(row_start + i) * stride_col + d] = O_tile[i * stride_col + d] * norm_factor;
            }
        }
    }
};

/**=============================================================================
 * Standard Attention (for comparison)
 * Materializes full attention matrix
 *=============================================================================*/
class StandardAttention {
public:
    static void Forward(
        const float* __restrict Q,
        const float* __restrict K,
        const float* __restrict V,
        float* __restrict O,
        int batch_size,
        int seq_q,
        int seq_kv,
        int head_dim,
        float scale = 0.0f
    ) {
        if (scale == 0.0f) {
            scale = 1.0f / sqrtf((float)head_dim);
        }
        
        // Allocate full attention matrix (O(N²) memory)
        std::vector<float> attention_matrix((size_t)seq_q * seq_kv);
        
        for (int b = 0; b < batch_size; ++b) {
            const float* Q_batch = Q + (size_t)b * seq_q * head_dim;
            const float* K_batch = K + (size_t)b * seq_kv * head_dim;
            const float* V_batch = V + (size_t)b * seq_kv * head_dim;
            float* O_batch = O + (size_t)b * seq_q * head_dim;
            
            // Compute Q @ K^T
            for (int i = 0; i < seq_q; ++i) {
                for (int j = 0; j < seq_kv; ++j) {
                    float dot = 0.0f;
                    for (int d = 0; d < head_dim; ++d) {
                        dot += Q_batch[i * head_dim + d] * K_batch[j * head_dim + d];
                    }
                    attention_matrix[(size_t)i * seq_kv + j] = dot * scale;
                }
            }
            
            // Softmax
            for (int i = 0; i < seq_q; ++i) {
                float max_val = -INFINITY;
                for (int j = 0; j < seq_kv; ++j) {
                    max_val = std::max(max_val, attention_matrix[(size_t)i * seq_kv + j]);
                }
                
                float sum_exp = 0.0f;
                for (int j = 0; j < seq_kv; ++j) {
                    attention_matrix[(size_t)i * seq_kv + j] = expf(attention_matrix[(size_t)i * seq_kv + j] - max_val);
                    sum_exp += attention_matrix[(size_t)i * seq_kv + j];
                }
                
                for (int j = 0; j < seq_kv; ++j) {
                    attention_matrix[(size_t)i * seq_kv + j] /= sum_exp;
                }
            }
            
            // Compute Attention @ V
            for (int i = 0; i < seq_q; ++i) {
                for (int d = 0; d < head_dim; ++d) {
                    float sum = 0.0f;
                    for (int j = 0; j < seq_kv; ++j) {
                        sum += attention_matrix[(size_t)i * seq_kv + j] * V_batch[j * head_dim + d];
                    }
                    O_batch[i * head_dim + d] = sum;
                }
            }
        }
    }
};

} // namespace Memory
} // namespace RawrXD

#endif // RAWRXD_FLASH_ATTENTION_V2_HPP
