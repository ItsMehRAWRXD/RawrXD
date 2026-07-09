// ============================================================================
// Multi-threaded Transformer Layer Implementation
// ============================================================================

#include "transformer_layer_parallel.hpp"
#include "avx512_kernels.hpp"
#include <cmath>
#include <algorithm>

namespace RawrXD {
namespace Inference {

ParallelTransformerLayer::ParallelTransformerLayer(const TransformerConfig& config)
    : TransformerLayer(config) {
    
    // Auto-detect thread count
    num_threads_ = ThreadPool::HardwareConcurrency();
    if (num_threads_ == 0) {
        num_threads_ = 4;
    }
    
    // Limit threads to number of heads for attention
    num_threads_ = std::min(num_threads_, static_cast<size_t>(config.num_heads));
    
    thread_pool_.Initialize(num_threads_);
    
    // Allocate per-thread buffers
    thread_buffers_.resize(num_threads_);
    for (auto& buf : thread_buffers_) {
        buf.scores.resize(32768);  // Max sequence length
        buf.out_head.resize(config.head_dim);
    }
}

void ParallelTransformerLayer::SetNumThreads(size_t num_threads) {
    if (num_threads == 0) {
        num_threads = ThreadPool::HardwareConcurrency();
    }
    
    num_threads_ = std::min(num_threads, static_cast<size_t>(config_.num_heads));
    thread_pool_.Shutdown();
    thread_pool_.Initialize(num_threads_);
    
    // Reallocate buffers
    thread_buffers_.resize(num_threads_);
    for (auto& buf : thread_buffers_) {
        buf.scores.resize(32768);  // Max sequence length
        buf.out_head.resize(config_.head_dim);
    }
}

void ParallelTransformerLayer::AttentionForwardParallel(
    const float* Q, const float* K, const float* V,
    float* output, KVCache& kv_cache, uint32_t position) {
    
    uint32_t num_heads = config_.num_heads;
    uint32_t num_kv_heads = config_.num_kv_heads;
    uint32_t head_dim = config_.head_dim;
    uint32_t kv_hidden = num_kv_heads * head_dim;
    
    // Store K and V in cache (sequential - must be done before parallel reads)
    for (uint32_t i = 0; i < kv_hidden; i++) {
        kv_cache.k_cache[position * kv_hidden + i] = K[i];
        kv_cache.v_cache[position * kv_hidden + i] = V[i];
    }
    kv_cache.cache_len = position + 1;
    
    // Parallelize over attention heads
    auto process_head = [&](size_t h) {
        uint32_t head = static_cast<uint32_t>(h);
        uint32_t kv_h = head / (num_heads / num_kv_heads);  // GQA mapping
        
        // Get thread-local buffers
        size_t thread_id = std::min(h, num_threads_ - 1);
        auto& buffers = thread_buffers_[thread_id];
        
        // Q for this head
        const float* q_head = Q + head * head_dim;
        float* out_head = output + head * head_dim;
        
        // Compute attention scores for each position in cache
        float* scores = buffers.scores.data();
        for (uint32_t pos = 0; pos < kv_cache.cache_len; pos++) {
            const float* k_head = kv_cache.k_cache.data() + pos * kv_hidden + kv_h * head_dim;
            
            // Q * K^T / sqrt(head_dim)
            float dot = 0.0f;
            for (uint32_t d = 0; d < head_dim; d++) {
                dot += q_head[d] * k_head[d];
            }
            scores[pos] = dot / std::sqrt(static_cast<float>(head_dim));
        }
        
        // Softmax
        float max_val = scores[0];
        for (uint32_t i = 1; i < kv_cache.cache_len; i++) {
            if (scores[i] > max_val) max_val = scores[i];
        }
        
        float sum = 0.0f;
        for (uint32_t i = 0; i < kv_cache.cache_len; i++) {
            scores[i] = std::exp(scores[i] - max_val);
            sum += scores[i];
        }
        
        for (uint32_t i = 0; i < kv_cache.cache_len; i++) {
            scores[i] /= sum;
        }
        
        // Compute weighted sum of V
        for (uint32_t d = 0; d < head_dim; d++) {
            out_head[d] = 0.0f;
        }
        
        for (uint32_t pos = 0; pos < kv_cache.cache_len; pos++) {
            const float* v_head = kv_cache.v_cache.data() + pos * kv_hidden + kv_h * head_dim;
            for (uint32_t d = 0; d < head_dim; d++) {
                out_head[d] += scores[pos] * v_head[d];
            }
        }
    };
    
    // Execute in parallel
    thread_pool_.ParallelFor(0, num_heads, process_head);
}

void ParallelTransformerLayer::FFNForwardParallel(const float* input, float* output) {
    uint32_t hidden = config_.hidden_size;
    uint32_t intermediate = config_.intermediate_size;
    
    // Split FFN computation into chunks along intermediate dimension
    size_t num_chunks = std::min(num_threads_, static_cast<size_t>(4));
    size_t chunk_size = intermediate / num_chunks;
    
    if (chunk_size == 0) {
        // Fall back to sequential for small intermediate size
        SiLU(ffn_gate_.data(), intermediate);
        for (uint32_t i = 0; i < intermediate; i++) {
            ffn_act_[i] = ffn_gate_[i] * ffn_up_[i];
        }
        return;
    }
    
    // Parallel SiLU and element-wise multiply
    auto process_ffn_chunk = [&](size_t chunk) {
        size_t start = chunk * chunk_size;
        size_t end = (chunk == num_chunks - 1) ? intermediate : start + chunk_size;
        
        // SiLU and multiply
        for (size_t i = start; i < end; i++) {
            // SiLU: x * sigmoid(x)
            float x = ffn_gate_[i];
            float sigmoid = 1.0f / (1.0f + std::exp(-x));
            ffn_act_[i] = x * sigmoid * ffn_up_[i];
        }
    };
    
    thread_pool_.ParallelFor(0, num_chunks, process_ffn_chunk);
}

// Parallel matrix multiplication - splits M dimension across threads
void ParallelTransformerLayer::ParallelMatMul(const float* A, const float* B, float* C,
                                               uint32_t M, uint32_t K, uint32_t N) {
    if (num_threads_ <= 1 || M < num_threads_) {
        // Fall back to sequential for small matrices or single thread
        MatMul(A, B, C, M, K, N);
        return;
    }
    
    // Split M dimension across threads
    size_t rows_per_thread = M / num_threads_;
    size_t remainder = M % num_threads_;
    
    // Launch parallel tasks
    std::vector<std::future<void>> futures;
    futures.reserve(num_threads_);
    
    size_t current_row = 0;
    for (size_t t = 0; t < num_threads_; t++) {
        size_t local_rows = rows_per_thread + (t < remainder ? 1 : 0);
        size_t start_row = current_row;
        current_row += local_rows;
        
        futures.push_back(thread_pool_.Submit([this, start_row, local_rows, A, B, C, K, N]() {
            // Use AVX-512 kernel for each thread's portion
            for (size_t m = start_row; m < start_row + local_rows; m++) {
                // Compute row m of output using AVX-512
                SEG::KernelDispatch::MatMulF32(
                    A + m * K, 
                    B, 
                    C + m * N, 
                    1, N, K
                );
            }
        }));
    }
    
    // Wait for completion
    for (auto& f : futures) {
        f.wait();
    }
}

bool ParallelTransformerLayer::ForwardParallel(const float* input, float* output,
                                               KVCache& kv_cache, uint32_t position) {
    uint32_t hidden = config_.hidden_size;
    uint32_t kv_hidden = config_.num_kv_heads * config_.head_dim;
    uint32_t intermediate = config_.intermediate_size;
    
    // === Attention Block ===
    // 1. RMSNorm
    RMSNorm(input, weights_.attn_norm.data(), normed_.data(), hidden);
    
    // 2. QKV projections (PARALLEL over output columns)
    ParallelMatMul(normed_.data(), weights_.q_weight.data(), q_proj_.data(), 1, hidden, hidden);
    ParallelMatMul(normed_.data(), weights_.k_weight.data(), k_proj_.data(), 1, hidden, kv_hidden);
    ParallelMatMul(normed_.data(), weights_.v_weight.data(), v_proj_.data(), 1, hidden, kv_hidden);
    
    // 3. Attention (PARALLEL over heads)
    AttentionForwardParallel(q_proj_.data(), k_proj_.data(), v_proj_.data(),
                               attn_out_.data(), kv_cache, position);
    
    // 4. Output projection (PARALLEL over output columns)
    ParallelMatMul(attn_out_.data(), weights_.o_weight.data(), normed_.data(), 1, hidden, hidden);
    
    // 5. Residual connection
    for (uint32_t i = 0; i < hidden; i++) {
        normed_[i] = input[i] + normed_[i];
    }
    
    // === FFN Block ===
    // 6. RMSNorm
    RMSNorm(normed_.data(), weights_.ffn_norm.data(), ffn_gate_.data(), hidden);
    
    // 7-8. FFN Gate and Up projections (PARALLEL over output columns)
    ParallelMatMul(ffn_gate_.data(), weights_.ffn_gate.data(), ffn_gate_.data(), 1, hidden, intermediate);
    ParallelMatMul(ffn_gate_.data(), weights_.ffn_up.data(), ffn_up_.data(), 1, hidden, intermediate);
    
    // 9. SiLU and element-wise multiply (already parallel in FFNForwardParallel)
    FFNForwardParallel(ffn_gate_.data(), output);
    
    // 10. Down projection (PARALLEL over output columns)
    ParallelMatMul(ffn_act_.data(), weights_.ffn_down.data(), output, 1, intermediate, hidden);
    
    // 11. Residual connection
    for (uint32_t i = 0; i < hidden; i++) {
        output[i] = normed_[i] + output[i];
    }
    
    return true;
}

} // namespace Inference
} // namespace RawrXD
