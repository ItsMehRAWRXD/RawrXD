// ============================================================================
// Sovereign_RoPE.h - C++ Interface for Rotary Position Embedding
// ============================================================================
// Production-ready header for RawrXD Transformer
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <stdexcept>
#include <cmath>

#ifdef __cplusplus
extern "C" {
#endif

// ----------------------------------------------------------------------------
// C API
// ----------------------------------------------------------------------------

/**
 * @brief Precompute RoPE frequency cache
 * 
 * @param head_dim Dimension of each attention head (must be even)
 * @param max_seq_len Maximum sequence length to support
 * @param theta Base frequency (typically 10000.0)
 * @param cache Output cache buffer (size = max_seq_len * head_dim * 2)
 * @return 0 on success, -1 on error
 */
int rope_precompute_cache(size_t head_dim, size_t max_seq_len, 
                          float theta, float* cache);

/**
 * @brief Apply RoPE to Q/K tensor
 * 
 * @param tensor Input/output tensor (F32)
 * @param freq_cache Precomputed frequency cache
 * @param seq_len Sequence length
 * @param head_dim Head dimension
 * @param num_heads Number of attention heads
 * @return 0 on success, -1 on error
 */
int rope_apply_f32(float* tensor, float* freq_cache,
                   size_t seq_len, size_t head_dim, size_t num_heads);

/**
 * @brief Apply Llama-style RoPE with position indices
 * 
 * @param q Query tensor
 * @param k Key tensor
 * @param positions Position indices array
 * @param seq_len Sequence length
 * @param head_dim Head dimension
 * @param theta Base frequency
 * @return 0 on success, -1 on error
 */
int rope_apply_llama_f32(float* q, float* k, int* positions,
                         size_t seq_len, size_t head_dim, float theta);

// ----------------------------------------------------------------------------
// C++ Wrapper
// ----------------------------------------------------------------------------

#ifdef __cplusplus

namespace Sovereign {

/**
 * @brief RoPE (Rotary Position Embedding) manager
 */
class RoPE {
public:
    /**
     * @brief Construct RoPE with parameters
     * @param head_dim Dimension of each attention head (must be even)
     * @param max_seq_len Maximum sequence length to support
     * @param theta Base frequency (default: 10000.0)
     */
    RoPE(size_t head_dim, size_t max_seq_len, float theta = 10000.0f)
        : head_dim_(head_dim), max_seq_len_(max_seq_len), theta_(theta) {
        
        if (head_dim % 2 != 0) {
            throw std::invalid_argument("head_dim must be even");
        }
        
        // Allocate cache: [cos, sin] pairs for each position and dimension
        cache_.resize(max_seq_len * head_dim * 2);
        
        // Precompute frequencies
        int result = rope_precompute_cache(head_dim, max_seq_len, theta, cache_.data());
        if (result != 0) {
            throw std::runtime_error("Failed to precompute RoPE cache");
        }
    }
    
    /**
     * @brief Apply RoPE to Q tensor
     * @param q Query tensor [seq_len, num_heads, head_dim]
     * @param seq_len Current sequence length
     * @param num_heads Number of attention heads
     */
    void apply_q(float* q, size_t seq_len, size_t num_heads) {
        int result = rope_apply_f32(q, cache_.data(), seq_len, head_dim_, num_heads);
        if (result != 0) {
            throw std::runtime_error("RoPE application failed");
        }
    }
    
    /**
     * @brief Apply RoPE to K tensor
     * @param k Key tensor [seq_len, num_heads, head_dim]
     * @param seq_len Current sequence length
     * @param num_heads Number of attention heads
     */
    void apply_k(float* k, size_t seq_len, size_t num_heads) {
        int result = rope_apply_f32(k, cache_.data(), seq_len, head_dim_, num_heads);
        if (result != 0) {
            throw std::runtime_error("RoPE application failed");
        }
    }
    
    /**
     * @brief Apply Llama-style RoPE with custom positions
     * @param q Query tensor
     * @param k Key tensor
     * @param positions Position indices [seq_len]
     * @param seq_len Sequence length
     */
    void apply_llama_style(float* q, float* k, const std::vector<int>& positions, 
                          size_t seq_len) {
        if (positions.size() < seq_len) {
            throw std::invalid_argument("positions array too small");
        }
        
        int result = rope_apply_llama_f32(q, k, const_cast<int*>(positions.data()),
                                          seq_len, head_dim_, theta_);
        if (result != 0) {
            throw std::runtime_error("Llama-style RoPE application failed");
        }
    }
    
    size_t head_dim() const { return head_dim_; }
    size_t max_seq_len() const { return max_seq_len_; }
    float theta() const { return theta_; }

private:
    size_t head_dim_;
    size_t max_seq_len_;
    float theta_;
    std::vector<float> cache_;
};

/**
 * @brief Simplified RoPE application for single tensor
 * @tparam T Data type (float)
 * @param tensor Input tensor [seq_len, num_heads, head_dim]
 * @param seq_len Sequence length
 * @param num_heads Number of heads
 * @param head_dim Head dimension
 * @param theta Base frequency
 */
template<typename T>
inline void apply_rope(T* tensor, size_t seq_len, size_t num_heads, 
                       size_t head_dim, float theta = 10000.0f) {
    static_assert(std::is_same_v<T, float>, "Only F32 is currently supported");
    
    // Create temporary cache (inefficient but simple)
    std::vector<float> cache(seq_len * head_dim * 2);
    
    int result = rope_precompute_cache(head_dim, seq_len, theta, cache.data());
    if (result != 0) {
        throw std::runtime_error("RoPE cache precomputation failed");
    }
    
    result = rope_apply_f32(reinterpret_cast<float*>(tensor), cache.data(),
                          seq_len, head_dim, num_heads);
    if (result != 0) {
        throw std::runtime_error("RoPE application failed");
    }
}

} // namespace Sovereign

#endif // __cplusplus

#ifdef __cplusplus
}
#endif
