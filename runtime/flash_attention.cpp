// ============================================================================
// flash_attention.cpp - Optimized Attention Implementation
// ============================================================================

#include "flash_attention.hpp"
#include "kv_cache.hpp"
#include "tensor_view.hpp"
#include <cmath>
#include <cstring>
#include <algorithm>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// CPU Feature Detection
// ============================================================================
CPUFeatures CPUFeatures::Detect() {
    CPUFeatures features;
    
    #if defined(__x86_64__) || defined(_M_X64)
    int cpu_info[4] = {0};
    
    // Check max function ID
    __cpuid(cpu_info, 0);
    int max_id = cpu_info[0];
    
    if (max_id >= 1) {
        __cpuid(cpu_info, 1);
        features.has_avx = (cpu_info[2] & (1 << 28)) != 0;
        features.has_fma = (cpu_info[2] & (1 << 12)) != 0;
    }
    
    if (max_id >= 7) {
        __cpuid(cpu_info, 7);
        features.has_avx2 = (cpu_info[1] & (1 << 5)) != 0;
        features.has_avx512f = (cpu_info[1] & (1 << 16)) != 0;
    }
    #endif
    
    return features;
}

// ============================================================================
// Online Softmax Implementation
// ============================================================================
void OnlineSoftmaxState::Update(float x) {
    if (x > max_val) {
        // New max - rescale sum
        float exp_factor = std::exp(max_val - x);
        sum_exp = sum_exp * exp_factor + 1.0f;
        max_val = x;
    } else {
        // Same max - just add
        sum_exp += std::exp(x - max_val);
    }
}

float OnlineSoftmaxState::Normalize(float x) const {
    return std::exp(x - max_val) / sum_exp;
}

// ============================================================================
// FlashAttention Implementation
// ============================================================================
FlashAttention::FlashAttention() = default;
FlashAttention::~FlashAttention() = default;

bool FlashAttention::Initialize(const FlashAttentionConfig& config) {
    m_config = config;
    
    // Validate configuration
    if (m_config.head_dim == 0 || m_config.num_heads == 0) {
        return false;
    }
    
    // Compute attention scale if not set
    if (m_config.attention_scale == 0.0f) {
        m_config.attention_scale = 1.0f / std::sqrt(static_cast<float>(m_config.head_dim));
    }
    
    m_initialized = true;
    return true;
}

bool FlashAttention::Forward(
    const float* q,
    const KVCache& kv_cache,
    uint32_t seq_len,
    float* output,
    uint64_t* cycles_out
) {
    if (!m_initialized || seq_len == 0) return false;
    
    #ifdef _WIN32
    uint64_t start_cycles = __rdtsc();
    #else
    uint64_t start_cycles = 0;  // Use clock_gettime on Linux
    #endif
    
    // Process each head
    for (uint32_t h = 0; h < m_config.num_heads; ++h) {
        const float* q_head = q + h * m_config.head_dim;
        float* out_head = output + h * m_config.head_dim;
        
        // Get KV head index (for GQA/MQA)
        uint32_t kv_h = GetKVHeadIndex(h);
        
        // Gather K and V for this head from cache
        // For efficiency, we process in tiles
        OnlineSoftmaxState softmax_state;
        alignas(64) float accum[256];  // Accumulator for output
        std::memset(accum, 0, m_config.head_dim * sizeof(float));
        
        // Tile over sequence length
        for (uint32_t tile_start = 0; tile_start < seq_len; tile_start += m_config.tile_size_kv) {
            uint32_t tile_len = std::min(m_config.tile_size_kv, seq_len - tile_start);
            
            // Load K tile from cache
            for (uint32_t t = 0; t < tile_len; ++t) {
                const float* k_cached = kv_cache.GetKey(tile_start + t, kv_h);
                if (k_cached) {
                    std::memcpy(m_tile_k + t * m_config.head_dim, k_cached, 
                               m_config.head_dim * sizeof(float));
                }
            }
            
            // Compute Q @ K^T for this tile
            alignas(64) float scores[256];
            ComputeQKDotProduct(q_head, m_tile_k, scores, 1, tile_len, m_config.head_dim);
            
            // Scale scores
            for (uint32_t i = 0; i < tile_len; ++i) {
                scores[i] *= m_config.attention_scale;
            }
            
            // Online softmax update
            float tile_max = -INFINITY;
            for (uint32_t i = 0; i < tile_len; ++i) {
                if (scores[i] > tile_max) tile_max = scores[i];
            }
            
            // Rescale accumulator if max changed
            if (tile_max > softmax_state.max_val) {
                float scale_factor = std::exp(softmax_state.max_val - tile_max);
                for (uint32_t d = 0; d < m_config.head_dim; ++d) {
                    accum[d] *= scale_factor;
                }
                softmax_state.max_val = tile_max;
            }
            
            // Compute softmax and accumulate weighted values
            float sum_exp = 0.0f;
            for (uint32_t i = 0; i < tile_len; ++i) {
                float exp_score = std::exp(scores[i] - softmax_state.max_val);
                sum_exp += exp_score;
                
                // Load V and accumulate
                const float* v_cached = kv_cache.GetKey(tile_start + i, kv_h);
                if (v_cached) {
                    for (uint32_t d = 0; d < m_config.head_dim; ++d) {
                        accum[d] += exp_score * v_cached[d];
                    }
                }
            }
            
            softmax_state.sum_exp += sum_exp;
        }
        
        // Normalize and write output
        float inv_sum = 1.0f / softmax_state.sum_exp;
        for (uint32_t d = 0; d < m_config.head_dim; ++d) {
            out_head[d] = accum[d] * inv_sum;
        }
    }
    
    #ifdef _WIN32
    if (cycles_out) {
        *cycles_out = __rdtsc() - start_cycles;
    }
    #endif
    
    return true;
}

bool FlashAttention::ForwardSingleHead(
    const float* q_head,
    const float* k_cache_head,
    const float* v_cache_head,
    uint32_t seq_len,
    float* output_head
) {
    if (seq_len == 0) return false;
    
    // Compute attention scores
    alignas(64) float scores[8192];  // Max seq len
    
    // Q @ K^T
    for (uint32_t t = 0; t < seq_len; ++t) {
        const float* k_t = k_cache_head + t * m_config.head_dim;
        float dot = 0.0f;
        
        #ifdef __AVX2__
        __m256 sum_vec = _mm256_setzero_ps();
        for (uint32_t d = 0; d + 8 <= m_config.head_dim; d += 8) {
            __m256 q_vec = _mm256_loadu_ps(q_head + d);
            __m256 k_vec = _mm256_loadu_ps(k_t + d);
            sum_vec = _mm256_fmadd_ps(q_vec, k_vec, sum_vec);
        }
        
        // Horizontal sum
        float temp[8];
        _mm256_storeu_ps(temp, sum_vec);
        for (int i = 0; i < 8; ++i) dot += temp[i];
        
        // Remainder
        for (uint32_t d = (m_config.head_dim / 8) * 8; d < m_config.head_dim; ++d) {
            dot += q_head[d] * k_t[d];
        }
        #else
        for (uint32_t d = 0; d < m_config.head_dim; ++d) {
            dot += q_head[d] * k_t[d];
        }
        #endif
        
        scores[t] = dot * m_config.attention_scale;
    }
    
    // Softmax
    float max_score = scores[0];
    for (uint32_t t = 1; t < seq_len; ++t) {
        if (scores[t] > max_score) max_score = scores[t];
    }
    
    float sum_exp = 0.0f;
    for (uint32_t t = 0; t < seq_len; ++t) {
        scores[t] = std::exp(scores[t] - max_score);
        sum_exp += scores[t];
    }
    
    float inv_sum = 1.0f / sum_exp;
    for (uint32_t t = 0; t < seq_len; ++t) {
        scores[t] *= inv_sum;
    }
    
    // Weighted sum of values
    std::memset(output_head, 0, m_config.head_dim * sizeof(float));
    
    for (uint32_t t = 0; t < seq_len; ++t) {
        const float* v_t = v_cache_head + t * m_config.head_dim;
        float weight = scores[t];
        
        #ifdef __AVX2__
        __m256 w_vec = _mm256_set1_ps(weight);
        for (uint32_t d = 0; d + 8 <= m_config.head_dim; d += 8) {
            __m256 out_vec = _mm256_loadu_ps(output_head + d);
            __m256 v_vec = _mm256_loadu_ps(v_t + d);
            out_vec = _mm256_fmadd_ps(w_vec, v_vec, out_vec);
            _mm256_storeu_ps(output_head + d, out_vec);
        }
        // Remainder handled below
        for (uint32_t d = (m_config.head_dim / 8) * 8; d < m_config.head_dim; ++d) {
            output_head[d] += weight * v_t[d];
        }
        #else
        for (uint32_t d = 0; d < m_config.head_dim; ++d) {
            output_head[d] += weight * v_t[d];
        }
        #endif
    }
    
    return true;
}

void FlashAttention::ComputeQKDotProduct(
    const float* q_tile,
    const float* k_tile,
    float* scores,
    uint32_t q_len,
    uint32_t kv_len,
    uint32_t dim
) {
    #ifdef __AVX512F__
    if (m_config.use_avx512) {
        ComputeQKDotProductAVX512(q_tile, k_tile, scores, q_len, kv_len, dim);
        return;
    }
    #endif
    
    #ifdef __AVX2__
    if (m_config.use_avx2) {
        ComputeQKDotProductAVX2(q_tile, k_tile, scores, q_len, kv_len, dim);
        return;
    }
    #endif
    
    // Scalar fallback
    for (uint32_t i = 0; i < q_len; ++i) {
        for (uint32_t j = 0; j < kv_len; ++j) {
            float dot = 0.0f;
            for (uint32_t d = 0; d < dim; ++d) {
                dot += q_tile[i * dim + d] * k_tile[j * dim + d];
            }
            scores[i * kv_len + j] = dot;
        }
    }
}

void FlashAttention::ComputeQKDotProductAVX2(
    const float* q,
    const float* k,
    float* scores,
    uint32_t q_len,
    uint32_t kv_len,
    uint32_t dim
) {
    for (uint32_t i = 0; i < q_len; ++i) {
        for (uint32_t j = 0; j < kv_len; ++j) {
            __m256 sum_vec = _mm256_setzero_ps();
            
            uint32_t d = 0;
            for (; d + 8 <= dim; d += 8) {
                __m256 q_vec = _mm256_loadu_ps(q + i * dim + d);
                __m256 k_vec = _mm256_loadu_ps(k + j * dim + d);
                sum_vec = _mm256_fmadd_ps(q_vec, k_vec, sum_vec);
            }
            
            // Horizontal sum
            float temp[8];
            _mm256_storeu_ps(temp, sum_vec);
            float dot = temp[0] + temp[1] + temp[2] + temp[3] + 
                       temp[4] + temp[5] + temp[6] + temp[7];
            
            // Remainder
            for (; d < dim; ++d) {
                dot += q[i * dim + d] * k[j * dim + d];
            }
            
            scores[i * kv_len + j] = dot;
        }
    }
}

void FlashAttention::ComputeQKDotProductAVX512(
    const float* q,
    const float* k,
    float* scores,
    uint32_t q_len,
    uint32_t kv_len,
    uint32_t dim
) {
    #ifdef __AVX512F__
    for (uint32_t i = 0; i < q_len; ++i) {
        for (uint32_t j = 0; j < kv_len; ++j) {
            __m512 sum_vec = _mm512_setzero_ps();
            
            uint32_t d = 0;
            for (; d + 16 <= dim; d += 16) {
                __m512 q_vec = _mm512_loadu_ps(q + i * dim + d);
                __m512 k_vec = _mm512_loadu_ps(k + j * dim + d);
                sum_vec = _mm512_fmadd_ps(q_vec, k_vec, sum_vec);
            }
            
            float dot = _mm512_reduce_add_ps(sum_vec);
            
            // Remainder
            for (; d < dim; ++d) {
                dot += q[i * dim + d] * k[j * dim + d];
            }
            
            scores[i * kv_len + j] = dot;
        }
    }
    #endif
}

void FlashAttention::SoftmaxAVX2(float* data, uint32_t len) {
    #ifdef __AVX2__
    // Find max
    __m256 max_vec = _mm256_set1_ps(-INFINITY);
    uint32_t i = 0;
    for (; i + 8 <= len; i += 8) {
        __m256 v = _mm256_loadu_ps(data + i);
        max_vec = _mm256_max_ps(max_vec, v);
    }
    
    float max_vals[8];
    _mm256_storeu_ps(max_vals, max_vec);
    float max_val = max_vals[0];
    for (int j = 1; j < 8; ++j) {
        if (max_vals[j] > max_val) max_val = max_vals[j];
    }
    for (; i < len; ++i) {
        if (data[i] > max_val) max_val = data[i];
    }
    
    // Compute exp(x - max) and sum
    __m256 sum_vec = _mm256_setzero_ps();
    __m256 max_broadcast = _mm256_set1_ps(max_val);
    
    i = 0;
    for (; i + 8 <= len; i += 8) {
        __m256 v = _mm256_loadu_ps(data + i);
        v = _mm256_sub_ps(v, max_broadcast);
        // Approximate exp with polynomial or use scalar
        float temp[8];
        _mm256_storeu_ps(temp, v);
        for (int j = 0; j < 8; ++j) {
            temp[j] = std::exp(temp[j]);
        }
        _mm256_storeu_ps(data + i, _mm256_loadu_ps(temp));
        sum_vec = _mm256_add_ps(sum_vec, _mm256_loadu_ps(temp));
    }
    
    float sum_vals[8];
    _mm256_storeu_ps(sum_vals, sum_vec);
    float sum = sum_vals[0] + sum_vals[1] + sum_vals[2] + sum_vals[3] +
                sum_vals[4] + sum_vals[5] + sum_vals[6] + sum_vals[7];
    
    for (; i < len; ++i) {
        data[i] = std::exp(data[i] - max_val);
        sum += data[i];
    }
    
    // Normalize
    __m256 inv_sum_vec = _mm256_set1_ps(1.0f / sum);
    for (i = 0; i + 8 <= len; i += 8) {
        __m256 v = _mm256_loadu_ps(data + i);
        v = _mm256_mul_ps(v, inv_sum_vec);
        _mm256_storeu_ps(data + i, v);
    }
    for (; i < len; ++i) {
        data[i] /= sum;
    }
    #endif
}

// ============================================================================
// Quantized MatMul Implementation
// ============================================================================
bool QuantizedMatMul::Compute(
    const TensorView& weight,
    const float* input,
    float* output,
    uint32_t in_dim,
    uint32_t out_dim,
    bool use_avx2
) {
    if (!weight.IsValid()) return false;
    
    // For each output dimension (row of weight matrix)
    for (uint32_t o = 0; o < out_dim; ++o) {
        // Dequantize row and compute dot product
        alignas(64) float dequantized[4096];
        size_t dequantized_count = weight.DequantizeRow(o, dequantized, in_dim);
        
        if (dequantized_count != in_dim) {
            output[o] = 0.0f;
            continue;
        }
        
        // Dot product
        float sum = 0.0f;
        
        #ifdef __AVX2__
        if (use_avx2) {
            __m256 sum_vec = _mm256_setzero_ps();
            uint32_t d = 0;
            for (; d + 8 <= in_dim; d += 8) {
                __m256 w_vec = _mm256_loadu_ps(dequantized + d);
                __m256 i_vec = _mm256_loadu_ps(input + d);
                sum_vec = _mm256_fmadd_ps(w_vec, i_vec, sum_vec);
            }
            
            float temp[8];
            _mm256_storeu_ps(temp, sum_vec);
            for (int i = 0; i < 8; ++i) sum += temp[i];
            
            // Remainder
            for (; d < in_dim; ++d) {
                sum += dequantized[d] * input[d];
            }
        } else
        #endif
        {
            for (uint32_t d = 0; d < in_dim; ++d) {
                sum += dequantized[d] * input[d];
            }
        }
        
        output[o] = sum;
    }
    
    return true;
}

bool QuantizedMatMul::ComputeBatch(
    const TensorView& weight,
    const float* input,
    float* output,
    uint32_t batch_size,
    uint32_t in_dim,
    uint32_t out_dim
) {
    for (uint32_t b = 0; b < batch_size; ++b) {
        if (!Compute(weight, input + b * in_dim, output + b * out_dim, in_dim, out_dim)) {
            return false;
        }
    }
    return true;
}

} // namespace Runtime
} // namespace RawrXD
