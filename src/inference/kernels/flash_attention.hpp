#pragma once

#include "../../core/common.hpp"
#include <cmath>

namespace rawrxd::inference::kernels {

// Flash Attention configuration
struct FlashAttentionConfig {
    int block_size_q = 128;  // Query block size
    int block_size_kv = 128; // Key/Value block size
    bool causal = true;      // Causal masking
    float softmax_scale = 1.0f;
    bool use_alibi = false;  // ALiBi positional encoding
};

// Flash Attention forward pass
class FlashAttention {
public:
    explicit FlashAttention(const FlashAttentionConfig& config);

    // Compute attention: softmax(Q @ K^T / sqrt(d_k)) @ V
    // Returns attention output and optionally attention weights
    Tensor forward(const Tensor& query,
                   const Tensor& key,
                   const Tensor& value,
                   const std::optional<Tensor>& attention_mask = std::nullopt);

    // Compute with KV cache for autoregressive generation
    Tensor forwardWithKVCache(const Tensor& query,
                               const Tensor& key_cache,
                               const Tensor& value_cache,
                               int cache_len);

    // Memory-efficient attention with tiling
    Tensor forwardTiled(const Tensor& query,
                        const Tensor& key,
                        const Tensor& value);

    // Multi-head attention wrapper
    Tensor multiHeadForward(const Tensor& query,
                            const Tensor& key,
                            const Tensor& value,
                            int num_heads,
                            const std::optional<Tensor>& attention_mask = std::nullopt);

private:
    FlashAttentionConfig config_;

    // Online softmax statistics
    struct OnlineSoftmaxState {
        float max_val = -INFINITY;
        float sum_exp = 0.0f;
    };

    // Kernel implementations
    void computeAttentionBlock(const float* q_block,
                                const float* k_block,
                                const float* v_block,
                                float* output_block,
                                int block_q,
                                int block_kv,
                                int head_dim);

    void onlineSoftmaxUpdate(OnlineSoftmaxState& state,
                              float new_max,
                              float new_sum);

    // Memory-efficient matmul
    void tiledMatmul(const float* A, const float* B, float* C,
                     int M, int N, int K,
                     int tile_m, int tile_n, int tile_k);
};

// Flash Attention v2 (improved parallelism)
class FlashAttentionV2 : public FlashAttention {
public:
    explicit FlashAttentionV2(const FlashAttentionConfig& config);

    // Parallel over sequence length (better GPU utilization)
    Tensor forwardParallel(const Tensor& query,
                           const Tensor& key,
                           const Tensor& value);

    // Split-K for better parallelism on long sequences
    Tensor forwardSplitK(const Tensor& query,
                         const Tensor& key,
                         const Tensor& value,
                         int num_splits);

private:
    // Work distribution across SMs
    void distributeWork(int seq_len, int num_sms);
};

// Flash Decoding (for autoregressive generation)
class FlashDecoding {
public:
    // Optimized attention for single query token
    static Tensor decodeStep(const Tensor& query,        // [1, head_dim]
                              const Tensor& key_cache,   // [seq_len, head_dim]
                              const Tensor& value_cache, // [seq_len, head_dim]
                              int seq_len);

    // Parallel key/value retrieval
    static Tensor decodeParallel(const Tensor& query,
                                  const Tensor& key_cache,
                                  const Tensor& value_cache,
                                  int seq_len,
                                  int num_parallel_chunks);

    // Speculative flash decoding
    static Tensor decodeSpeculative(const Tensor& query,
                                     const Tensor& key_cache,
                                     const Tensor& value_cache,
                                     const std::vector<int>& draft_tokens);
};

// Paged Attention (for continuous batching)
class PagedAttentionKernel {
public:
    static constexpr int BLOCK_SIZE = 16;  // Tokens per block

    // Compute attention with paged KV cache
    static Tensor forward(const Tensor& query,
                          const std::vector<int>& block_tables,  // Block indices per sequence
                          const std::vector<int>& context_lens,  // Context length per sequence
                          const Tensor& key_cache_blocks,      // [num_blocks, block_size, head_dim]
                          const Tensor& value_cache_blocks);

    // Copy KV to cache
    static void copyKVToCache(const Tensor& key,
                               const Tensor& value,
                               Tensor& key_cache,
                               Tensor& value_cache,
                               const std::vector<int>& slot_mapping);

    // Reshape for paged attention
    static std::pair<Tensor, Tensor> reshapeToBlocks(const Tensor& key,
                                                      const Tensor& value,
                                                      int block_size);
};

// Attention kernel factory
std::unique_ptr<FlashAttention> createAttentionKernel(const std::string& version,
                                                       const FlashAttentionConfig& config);

// Performance benchmarks
struct AttentionBenchmark {
    static void benchmarkFlashAttention(int seq_len, int head_dim, int num_heads);
    static void benchmarkStandardAttention(int seq_len, int head_dim, int num_heads);
    static void compareImplementations();
};

} // namespace rawrxd::inference::kernels
