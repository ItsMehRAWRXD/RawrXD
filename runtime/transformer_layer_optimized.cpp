// ============================================================================
// Optimized Transformer Layer Implementation
// ============================================================================
// Integrates OptimizedKVCache with multi-threaded attention
// ============================================================================

#include "transformer_layer_optimized.hpp"
#include "../kernels/avx2_kernels.hpp"
#include "../kernels/avx512_kernels.hpp"

#include <thread>
#include <vector>
#include <cstring>
#include <cmath>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// OptimizedTransformerLayer Implementation
// ============================================================================

OptimizedTransformerLayer::OptimizedTransformerLayer() = default;
OptimizedTransformerLayer::~OptimizedTransformerLayer() = default;

bool OptimizedTransformerLayer::Initialize(const TransformerConfig& config) {
    config_ = config;
    
    // Initialize KV cache
    OptimizedKVCache::Config kv_config;
    kv_config.num_layers = 1;  // Per layer
    kv_config.num_heads = config.num_heads;
    kv_config.head_dim = config.head_dim;
    kv_config.max_seq_len = config.max_seq_len;
    kv_config.batch_size = config.batch_size;
    
    if (!kv_cache_.Initialize(kv_config)) {
        return false;
    }
    
    // Allocate intermediate buffers with 64-byte alignment
    size_t hidden_size = config.hidden_size;
    size_t intermediate_size = config.intermediate_size;
    
    q_buf_.resize(hidden_size + 16);
    k_buf_.resize(hidden_size + 16);
    v_buf_.resize(hidden_size + 16);
    attn_out_.resize(hidden_size + 16);
    ffn_gate_.resize(intermediate_size + 16);
    ffn_up_.resize(intermediate_size + 16);
    ffn_out_.resize(hidden_size + 16);
    
    // Align pointers
    q_aligned_ = reinterpret_cast<float*>(
        (reinterpret_cast<uintptr_t>(q_buf_.data()) + 63) & ~63ULL);
    k_aligned_ = reinterpret_cast<float*>(
        (reinterpret_cast<uintptr_t>(k_buf_.data()) + 63) & ~63ULL);
    v_aligned_ = reinterpret_cast<float*>(
        (reinterpret_cast<uintptr_t>(v_buf_.data()) + 63) & ~63ULL);
    attn_out_aligned_ = reinterpret_cast<float*>(
        (reinterpret_cast<uintptr_t>(attn_out_.data()) + 63) & ~63ULL);
    ffn_gate_aligned_ = reinterpret_cast<float*>(
        (reinterpret_cast<uintptr_t>(ffn_gate_.data()) + 63) & ~63ULL);
    ffn_up_aligned_ = reinterpret_cast<float*>(
        (reinterpret_cast<uintptr_t>(ffn_up_.data()) + 63) & ~63ULL);
    ffn_out_aligned_ = reinterpret_cast<float*>(
        (reinterpret_cast<uintptr_t>(ffn_out_.data()) + 63) & ~63ULL);
    
    initialized_ = true;
    return true;
}

void OptimizedTransformerLayer::Reset() {
    kv_cache_.Reset();
    current_seq_len_ = 0;
}

bool OptimizedTransformerLayer::Forward(
    const float* input,
    const float* q_weights,
    const float* k_weights,
    const float* v_weights,
    const float* o_weights,
    const float* ffn_gate_weights,
    const float* ffn_up_weights,
    const float* ffn_down_weights,
    float* output,
    uint32_t seq_len) {
    
    if (!initialized_) return false;
    
    using namespace rawrxd::kernels;
    
    const uint32_t hidden_size = config_.hidden_size;
    const uint32_t num_heads = config_.num_heads;
    const uint32_t head_dim = config_.head_dim;
    const uint32_t intermediate_size = config_.intermediate_size;
    
    // =========================================================================
    // Step 1: QKV Projections (can be parallelized)
    // =========================================================================
    
    // For single token generation, we compute Q, K, V for the new token
    // For prompt processing, we'd parallelize across sequence
    
    // Q projection
    KernelDispatch::MatMulF32(input, q_weights, q_aligned_, 
                               seq_len, hidden_size, hidden_size);
    
    // K projection
    KernelDispatch::MatMulF32(input, k_weights, k_aligned_,
                               seq_len, hidden_size, hidden_size);
    
    // V projection
    KernelDispatch::MatMulF32(input, v_weights, v_aligned_,
                               seq_len, hidden_size, hidden_size);
    
    // =========================================================================
    // Step 2: Store K, V in cache (SoA layout)
    // =========================================================================
    
    for (uint32_t s = 0; s < seq_len; ++s) {
        uint32_t cache_pos = current_seq_len_ + s;
        if (cache_pos >= config_.max_seq_len) break;
        
        for (uint32_t h = 0; h < num_heads; ++h) {
            float* k_cache = kv_cache_.GetK(0, h, cache_pos);
            float* v_cache = kv_cache_.GetV(0, h, cache_pos);
            
            // Copy from K/V buffers to cache
            const float* k_src = k_aligned_ + s * hidden_size + h * head_dim;
            const float* v_src = v_aligned_ + s * hidden_size + h * head_dim;
            
            std::memcpy(k_cache, k_src, head_dim * sizeof(float));
            std::memcpy(v_cache, v_src, head_dim * sizeof(float));
        }
    }
    
    // =========================================================================
    // Step 3: Multi-Head Attention (parallelized across heads)
    // =========================================================================
    
    uint32_t total_seq_len = current_seq_len_ + seq_len;
    
    // Parallel attention across heads
    std::vector<std::thread> threads;
    uint32_t num_threads = std::min(
        static_cast<uint32_t>(std::thread::hardware_concurrency()),
        num_heads);
    uint32_t heads_per_thread = num_heads / num_threads;
    
    auto attention_worker = [&](uint32_t head_start, uint32_t head_end) {
        std::vector<float> scores(total_seq_len);
        std::vector<float> attn_weights(total_seq_len);
        
        for (uint32_t h = head_start; h < head_end; ++h) {
            for (uint32_t s = 0; s < seq_len; ++s) {
                uint32_t q_idx = s * hidden_size + h * head_dim;
                
                // Compute attention scores: Q @ K^T
                for (uint32_t pos = 0; pos < total_seq_len; ++pos) {
                    float* k_cache = kv_cache_.GetK(0, h, pos);
                    
                    // Prefetch next K block
                    if (pos + 16 < total_seq_len) {
                        kv_cache_.PrefetchK(0, h, pos + 16, 4);
                    }
                    
                    scores[pos] = KernelDispatch::VecDotF32(
                        q_aligned_ + q_idx, k_cache, head_dim);
                    scores[pos] /= std::sqrt(static_cast<float>(head_dim));
                }
                
                // Apply causal mask for autoregressive generation
                for (uint32_t pos = current_seq_len_ + s + 1; pos < total_seq_len; ++pos) {
                    scores[pos] = -1e9f;  // Mask out future tokens
                }
                
                // Softmax
                KernelDispatch::SoftmaxF32(scores.data(), attn_weights.data(), total_seq_len);
                
                // Compute weighted sum: softmax @ V
                float* out_ptr = attn_out_aligned_ + s * hidden_size + h * head_dim;
                std::memset(out_ptr, 0, head_dim * sizeof(float));
                
                for (uint32_t pos = 0; pos < total_seq_len; ++pos) {
                    float* v_cache = kv_cache_.GetV(0, h, pos);
                    
                    // Prefetch next V block
                    if (pos + 16 < total_seq_len) {
                        kv_cache_.PrefetchV(0, h, pos + 16, 4);
                    }
                    
                    // out += v * weight
                    // Use scale then add
                    std::vector<float> scaled(head_dim);
                    for (uint32_t d = 0; d < head_dim; ++d) {
                        scaled[d] = v_cache[d] * attn_weights[pos];
                    }
                    KernelDispatch::VecAddF32(out_ptr, scaled.data(), out_ptr, head_dim);
                }
            }
        }
    };
    
    // Launch threads
    for (uint32_t t = 0; t < num_threads; ++t) {
        uint32_t head_start = t * heads_per_thread;
        uint32_t head_end = (t == num_threads - 1) ? num_heads : (t + 1) * heads_per_thread;
        threads.emplace_back(attention_worker, head_start, head_end);
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    // =========================================================================
    // Step 4: Output projection
    // =========================================================================
    
    KernelDispatch::MatMulF32(attn_out_aligned_, o_weights, output,
                               seq_len, hidden_size, hidden_size);
    
    // Residual connection
    KernelDispatch::VecAddF32(output, input, output, seq_len * hidden_size);
    
    // =========================================================================
    // Step 5: FFN (parallelized across batch)
    // =========================================================================
    
    // Gate projection
    KernelDispatch::MatMulF32(output, ffn_gate_weights, ffn_gate_aligned_,
                               seq_len, intermediate_size, hidden_size);
    
    // Up projection
    KernelDispatch::MatMulF32(output, ffn_up_weights, ffn_up_aligned_,
                               seq_len, intermediate_size, hidden_size);
    
    // SiLU activation on gate
    KernelDispatch::SiLUF32(ffn_gate_aligned_, ffn_gate_aligned_, 
                             seq_len * intermediate_size);
    
    // Element-wise multiply: gate * up
    KernelDispatch::VecMulF32(ffn_gate_aligned_, ffn_up_aligned_, 
                               ffn_gate_aligned_, seq_len * intermediate_size);
    
    // Down projection
    KernelDispatch::MatMulF32(ffn_gate_aligned_, ffn_down_weights, ffn_out_aligned_,
                               seq_len, hidden_size, intermediate_size);
    
    // Residual connection
    KernelDispatch::VecAddF32(output, ffn_out_aligned_, output, seq_len * hidden_size);
    
    // Update sequence length
    current_seq_len_ = total_seq_len;
    
    return true;
}

// ============================================================================
// OptimizedTransformerModel Implementation
// ============================================================================

OptimizedTransformerModel::OptimizedTransformerModel() = default;
OptimizedTransformerModel::~OptimizedTransformerModel() = default;

bool OptimizedTransformerModel::Initialize(const TransformerConfig& config) {
    config_ = config;
    
    // Initialize all layers
    layers_.resize(config.num_layers);
    for (uint32_t i = 0; i < config.num_layers; ++i) {
        TransformerConfig layer_config = config;
        layer_config.num_layers = 1;  // Each layer manages its own cache
        
        if (!layers_[i].Initialize(layer_config)) {
            return false;
        }
    }
    
    // Allocate embedding/output buffers
    embedding_buf_.resize(config.hidden_size + 16);
    output_buf_.resize(config.hidden_size + 16);
    logits_buf_.resize(config.vocab_size + 16);
    
    embedding_aligned_ = reinterpret_cast<float*>(
        (reinterpret_cast<uintptr_t>(embedding_buf_.data()) + 63) & ~63ULL);
    output_aligned_ = reinterpret_cast<float*>(
        (reinterpret_cast<uintptr_t>(output_buf_.data()) + 63) & ~63ULL);
    logits_aligned_ = reinterpret_cast<float*>(
        (reinterpret_cast<uintptr_t>(logits_buf_.data()) + 63) & ~63ULL);
    
    initialized_ = true;
    return true;
}

void OptimizedTransformerModel::Reset() {
    for (auto& layer : layers_) {
        layer.Reset();
    }
    current_seq_len_ = 0;
}

bool OptimizedTransformerModel::Forward(
    const int32_t* input_tokens,
    const float* embedding_weights,
    const float* output_weights,
    const float* layer_weights,  // Array of layer weights
    float* logits,
    uint32_t seq_len) {
    
    if (!initialized_) return false;
    
    using namespace rawrxd::kernels;
    
    const uint32_t hidden_size = config_.hidden_size;
    
    // Embedding lookup (simplified - just copy weights)
    for (uint32_t s = 0; s < seq_len; ++s) {
        int32_t token_id = input_tokens[s];
        const float* token_emb = embedding_weights + token_id * hidden_size;
        std::memcpy(embedding_aligned_ + s * hidden_size, 
                    token_emb, hidden_size * sizeof(float));
    }
    
    // Forward through all layers
    float* layer_input = embedding_aligned_;
    float* layer_output = output_aligned_;
    
    for (uint32_t l = 0; l < config_.num_layers; ++l) {
        // Get weights for this layer
        const float* q_weights = layer_weights + l * 7 * hidden_size * hidden_size;
        const float* k_weights = q_weights + hidden_size * hidden_size;
        const float* v_weights = k_weights + hidden_size * hidden_size;
        const float* o_weights = v_weights + hidden_size * hidden_size;
        const float* ffn_gate = o_weights + hidden_size * hidden_size;
        const float* ffn_up = ffn_gate + hidden_size * config_.intermediate_size;
        const float* ffn_down = ffn_up + hidden_size * config_.intermediate_size;
        
        if (!layers_[l].Forward(layer_input, q_weights, k_weights, v_weights, o_weights,
                                 ffn_gate, ffn_up, ffn_down, layer_output, seq_len)) {
            return false;
        }
        
        // Swap input/output for next layer
        std::swap(layer_input, layer_output);
    }
    
    // Final output projection to logits
    // Use the last token's hidden state
    KernelDispatch::MatMulF32(layer_input + (seq_len - 1) * hidden_size,
                               output_weights, logits_aligned_,
                               1, config_.vocab_size, hidden_size);
    
    std::memcpy(logits, logits_aligned_, config_.vocab_size * sizeof(float));
    
    current_seq_len_ += seq_len;
    
    return true;
}

} // namespace Runtime
} // namespace RawrXD
