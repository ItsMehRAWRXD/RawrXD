#include "flash_attention_v2.hpp"
#include "telemetry_ids.hpp"
#include "telemetry_masm_bridge.hpp"
#include "../seg/seg_kernel_bridge.hpp"
#include <cmath>
#include <algorithm>
#include <cstring>
#include <limits>

namespace RawrXD {
namespace Runtime {

using namespace Telemetry;
using namespace SEG;

FlashAttentionV2::FlashAttentionV2(const FlashAttentionConfig& config)
    : config_(config) {
    
    // Compute softmax scale
    config_.softmax_scale = 1.0f / std::sqrt(static_cast<float>(config.head_dim));
    
    // Compute optimal block sizes if not specified
    if (config_.block_q == 0 || config_.block_kv == 0) {
        ComputeOptimalBlockSizes(config_.head_dim, config_.block_q, config_.block_kv);
    }
    
    // Allocate workspace
    size_t workspace_size = GetWorkspaceSize();
    workspace_.resize(workspace_size / sizeof(float));
    workspace_ptr_ = workspace_.data();
    workspace_size_ = workspace_size;
}

size_t FlashAttentionV2::GetWorkspaceSize() const {
    // Workspace needed for:
    // - S matrix: block_q * block_kv
    // - m vector: block_q
    // - l vector: block_q
    // - O accumulator: block_q * head_dim
    size_t block_size = config_.block_q * config_.block_kv;
    size_t vec_size = config_.block_q;
    size_t acc_size = config_.block_q * config_.head_dim;
    
    return (block_size + vec_size + vec_size + acc_size) * sizeof(float);
}

void FlashAttentionV2::SetWorkspace(void* workspace, size_t size) {
    workspace_ptr_ = static_cast<float*>(workspace);
    workspace_size_ = size;
}

void FlashAttentionV2::Forward(const float* Q, const float* K, const float* V,
                                float* O, float* softmax_lse) {
    MASM_TELEMETRY_SCOPE(TELEMETRY_ATTENTION_START, TELEMETRY_ATTENTION_END);
    
    const uint32_t batch_size = config_.batch_size;
    const uint32_t num_heads = config_.num_heads;
    const uint32_t seq_len = config_.seq_len;
    const uint32_t head_dim = config_.head_dim;
    const uint32_t block_q = config_.block_q;
    const uint32_t block_kv = config_.block_kv;
    
    const uint32_t num_q_blocks = (seq_len + block_q - 1) / block_q;
    const uint32_t num_kv_blocks = (seq_len + block_kv - 1) / block_kv;
    
    // Allocate workspace partitions
    float* S = workspace_ptr_;
    float* m = S + block_q * block_kv;
    float* l = m + block_q;
    float* acc = l + block_q;
    
    // Process each batch and head
    for (uint32_t b = 0; b < batch_size; ++b) {
        for (uint32_t h = 0; h < num_heads; ++h) {
            // Get pointers for this batch/head
            const float* Q_bh = Q + ((b * num_heads + h) * seq_len * head_dim);
            const float* K_bh = K + ((b * num_heads + h) * seq_len * head_dim);
            const float* V_bh = V + ((b * num_heads + h) * seq_len * head_dim);
            float* O_bh = O + ((b * num_heads + h) * seq_len * head_dim);
            
            // Process query blocks
            for (uint32_t q_block = 0; q_block < num_q_blocks; ++q_block) {
                uint32_t q_start = q_block * block_q;
                uint32_t q_len = std::min(block_q, seq_len - q_start);
                
                // Initialize m, l, acc for this block
                for (uint32_t i = 0; i < q_len; ++i) {
                    m[i] = -std::numeric_limits<float>::infinity();
                    l[i] = 0.0f;
                }
                std::memset(acc, 0, q_len * head_dim * sizeof(float));
                
                // Process key/value blocks
                for (uint32_t kv_block = 0; kv_block < num_kv_blocks; ++kv_block) {
                    uint32_t kv_start = kv_block * block_kv;
                    uint32_t kv_len = std::min(block_kv, seq_len - kv_start);
                    
                    // Compute S = Q * K^T
                    GemmQK(Q_bh + q_start * head_dim,
                           K_bh + kv_start * head_dim,
                           S, q_len, kv_len, head_dim);
                    
                    // Apply softmax scale
                    for (uint32_t i = 0; i < q_len * kv_len; ++i) {
                        S[i] *= config_.softmax_scale;
                    }
                    
                    // Online softmax and accumulate
                    OnlineSoftmaxUpdate(m, l, acc, S, V_bh + kv_start * head_dim,
                                       q_len, kv_len, head_dim);
                }
                
                // Normalize output
                for (uint32_t i = 0; i < q_len; ++i) {
                    for (uint32_t d = 0; d < head_dim; ++d) {
                        O_bh[(q_start + i) * head_dim + d] = acc[i * head_dim + d] / l[i];
                    }
                }
                
                // Store log-sum-exp if requested
                if (softmax_lse) {
                    float* lse_bh = softmax_lse + ((b * num_heads + h) * seq_len);
                    for (uint32_t i = 0; i < q_len; ++i) {
                        lse_bh[q_start + i] = m[i] + std::log(l[i]);
                    }
                }
            }
        }
    }
}

void FlashAttentionV2::ForwardCausal(const float* Q, const float* K, const float* V,
                                     float* O, float* softmax_lse) {
    MASM_TELEMETRY_SCOPE(TELEMETRY_ATTENTION_START, TELEMETRY_ATTENTION_END);
    
    const uint32_t batch_size = config_.batch_size;
    const uint32_t num_heads = config_.num_heads;
    const uint32_t seq_len = config_.seq_len;
    const uint32_t head_dim = config_.head_dim;
    const uint32_t block_q = config_.block_q;
    const uint32_t block_kv = config_.block_kv;
    
    const uint32_t num_q_blocks = (seq_len + block_q - 1) / block_q;
    
    // Allocate workspace partitions
    float* S = workspace_ptr_;
    float* m = S + block_q * block_kv;
    float* l = m + block_q;
    float* acc = l + block_q;
    
    // Process each batch and head
    for (uint32_t b = 0; b < batch_size; ++b) {
        for (uint32_t h = 0; h < num_heads; ++h) {
            const float* Q_bh = Q + ((b * num_heads + h) * seq_len * head_dim);
            const float* K_bh = K + ((b * num_heads + h) * seq_len * head_dim);
            const float* V_bh = V + ((b * num_heads + h) * seq_len * head_dim);
            float* O_bh = O + ((b * num_heads + h) * seq_len * head_dim);
            
            // Process query blocks
            for (uint32_t q_block = 0; q_block < num_q_blocks; ++q_block) {
                uint32_t q_start = q_block * block_q;
                uint32_t q_len = std::min(block_q, seq_len - q_start);
                uint32_t q_end = q_start + q_len;
                
                // Initialize m, l, acc
                for (uint32_t i = 0; i < q_len; ++i) {
                    m[i] = -std::numeric_limits<float>::infinity();
                    l[i] = 0.0f;
                }
                std::memset(acc, 0, q_len * head_dim * sizeof(float));
                
                // Process key/value blocks up to current query position (causal)
                uint32_t max_kv_block = (q_end + block_kv - 1) / block_kv;
                
                for (uint32_t kv_block = 0; kv_block < max_kv_block; ++kv_block) {
                    uint32_t kv_start = kv_block * block_kv;
                    uint32_t kv_len = std::min(block_kv, seq_len - kv_start);
                    uint32_t kv_end = kv_start + kv_len;
                    
                    // Compute S = Q * K^T
                    GemmQK(Q_bh + q_start * head_dim,
                           K_bh + kv_start * head_dim,
                           S, q_len, kv_len, head_dim);
                    
                    // Apply softmax scale
                    for (uint32_t i = 0; i < q_len * kv_len; ++i) {
                        S[i] *= config_.softmax_scale;
                    }
                    
                    // Apply causal mask
                    for (uint32_t i = 0; i < q_len; ++i) {
                        uint32_t global_q = q_start + i;
                        for (uint32_t j = 0; j < kv_len; ++j) {
                            uint32_t global_kv = kv_start + j;
                            if (global_kv > global_q) {
                                S[i * kv_len + j] = -std::numeric_limits<float>::infinity();
                            }
                        }
                    }
                    
                    // Online softmax and accumulate
                    OnlineSoftmaxUpdate(m, l, acc, S, V_bh + kv_start * head_dim,
                                       q_len, kv_len, head_dim);
                }
                
                // Normalize output
                for (uint32_t i = 0; i < q_len; ++i) {
                    for (uint32_t d = 0; d < head_dim; ++d) {
                        O_bh[(q_start + i) * head_dim + d] = acc[i * head_dim + d] / l[i];
                    }
                }
                
                // Store log-sum-exp if requested
                if (softmax_lse) {
                    float* lse_bh = softmax_lse + ((b * num_heads + h) * seq_len);
                    for (uint32_t i = 0; i < q_len; ++i) {
                        lse_bh[q_start + i] = m[i] + std::log(l[i]);
                    }
                }
            }
        }
    }
}

void FlashAttentionV2::OnlineSoftmaxUpdate(float* m, float* l, float* acc,
                                              const float* S, const float* V_block,
                                              uint32_t q_len, uint32_t kv_len, uint32_t head_dim) {
    // Use AVX512-optimized kernel when available
    if (KernelBridge::IsAvailable()) {
        KernelBridge::AttentionSoftmaxV(S, V_block, acc, m, l, q_len, kv_len, head_dim);
        return;
    }
    
    // Fallback to scalar implementation
    for (uint32_t i = 0; i < q_len; ++i) {
        // Find max score for numerical stability
        float m_new = m[i];
        for (uint32_t j = 0; j < kv_len; ++j) {
            m_new = std::max(m_new, S[i * kv_len + j]);
        }
        
        // Compute exp(S - m_new) and sum
        float l_new = 0.0f;
        for (uint32_t j = 0; j < kv_len; ++j) {
            l_new += std::exp(S[i * kv_len + j] - m_new);
        }
        
        // Update running statistics
        float m_old = m[i];
        float l_old = l[i];
        
        if (m_old == -std::numeric_limits<float>::infinity()) {
            // First iteration
            m[i] = m_new;
            l[i] = l_new;
            
            // Compute output: acc = exp(S - m_new) * V
            for (uint32_t d = 0; d < head_dim; ++d) {
                float sum = 0.0f;
                for (uint32_t j = 0; j < kv_len; ++j) {
                    sum += std::exp(S[i * kv_len + j] - m_new) * V_block[j * head_dim + d];
                }
                acc[i * head_dim + d] = sum;
            }
        } else {
            // Update with rescaling
            float scale = std::exp(m_old - m_new);
            m[i] = m_new;
            l[i] = l_old * scale + l_new;
            
            // Rescale accumulator and add new contribution
            for (uint32_t d = 0; d < head_dim; ++d) {
                float sum = acc[i * head_dim + d] * scale;
                for (uint32_t j = 0; j < kv_len; ++j) {
                    sum += std::exp(S[i * kv_len + j] - m_new) * V_block[j * head_dim + d];
                }
                acc[i * head_dim + d] = sum;
            }
        }
    }
}

void FlashAttentionV2::GemmQK(const float* Q, const float* K, float* S,
                                uint32_t m, uint32_t n, uint32_t k) {
    // Use AVX512-optimized kernel when available
    if (KernelBridge::IsAvailable()) {
        KernelBridge::AttentionQK(Q, K, S, m, n, k, 1.0f);
    } else {
        // Fallback to scalar implementation
        for (uint32_t i = 0; i < m; ++i) {
            for (uint32_t j = 0; j < n; ++j) {
                float sum = 0.0f;
                for (uint32_t l = 0; l < k; ++l) {
                    sum += Q[i * k + l] * K[j * k + l];
                }
                S[i * n + j] = sum;
            }
        }
    }
}

FlashAttentionConfig MakeFlashAttentionConfig(
    uint32_t seq_len,
    uint32_t num_heads,
    uint32_t head_dim,
    uint32_t batch_size) {
    
    FlashAttentionConfig config;
    config.seq_len = seq_len;
    config.num_heads = num_heads;
    config.head_dim = head_dim;
    config.batch_size = batch_size;
    config.softmax_scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
    
    ComputeOptimalBlockSizes(head_dim, config.block_q, config.block_kv);
    
    return config;
}

void ComputeOptimalBlockSizes(uint32_t head_dim, uint32_t& block_q, uint32_t& block_kv) {
    // Target L2 cache size (typically 256KB - 1MB)
    // We want Q_block, K_block, V_block, and S to fit in cache
    // Each block is block_size * head_dim floats
    // S is block_q * block_kv floats
    
    // Conservative estimate: use 64KB for blocks
    const size_t target_cache = 64 * 1024;  // 64KB
    const size_t float_size = sizeof(float);
    
    // Try different block sizes
    uint32_t best_block = 64;
    size_t best_waste = target_cache;
    
    for (uint32_t block : {32, 64, 128}) {
        size_t q_size = block * head_dim * float_size;
        size_t kv_size = block * head_dim * float_size;
        size_t s_size = block * block * float_size;
        size_t total = q_size + 2 * kv_size + s_size;
        
        if (total <= target_cache) {
            size_t waste = target_cache - total;
            if (waste < best_waste) {
                best_waste = waste;
                best_block = block;
            }
        }
    }
    
    block_q = best_block;
    block_kv = best_block;
}

} // namespace Runtime
} // namespace RawrXD
