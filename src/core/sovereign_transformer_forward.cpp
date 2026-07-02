// =============================================================================
// sovereign_transformer_forward.cpp
// Hybrid C++/MASM Transformer Forward Pass Implementation
// =============================================================================

#include "sovereign_transformer_forward.h"
#include "sovereign_q3_k_s_dequant.h"
#include "sovereign_q4_0_dequant.h"
#include "sovereign_q6_k_dequant.h"
#include "sovereign_quantized_matmul.h"
#include "../rawrxd_kernels.h"  // MASM kernel declarations
#include <windows.h>  // VirtualAlloc, VirtualFree
#include <cstring>
#include <cmath>
#include <algorithm>
#include <vector>
#include <random>
#include <unordered_map>

// External debug flag from sovereign_super_node.cpp
extern bool g_debug;

namespace Sovereign {

// =============================================================================
// Quantized Matrix-Vector Multiplication Helper
// =============================================================================
void QuantizedMatVecMul_Q3_K_S(const QuantizedWeightData& q_weights, 
                                const float* input, 
                                float* output,
                                uint32_t output_dim,
                                uint32_t input_dim) {
    // DEBUG: printf("[Q3_K_S] Enter: output_dim=%u, input_dim=%u, weight_size=%zu\n", output_dim, input_dim, q_weights.size);
    // Safety check
    if (!q_weights.data || !input || !output) {
        // DEBUG: printf("[Q3_K_S] ERROR: null pointer - data=%p input=%p output=%p\n", 
        //        (void*)q_weights.data, (void*)input, (void*)output);
        return;
    }
    
    if (q_weights.size == 0) {
        // DEBUG: printf("[Q3_K_S] ERROR: weight size is 0\n");
        return;
    }
    
    // Q3_K_S block structure (from reference implementation):
    // - 256 weights per block
    // - Block size: 98 bytes
    // - Layout: scales[2] + quants[96]
    // - 4 scales per block (packed as 4 nibbles in 2 bytes)
    // - Each scale applies to a group of 64 elements
    // - 3-bit values are packed sequentially (256 * 3 bits = 768 bits = 96 bytes)
    
    const uint32_t block_size = 256;
    const uint32_t bytes_per_block = 98;
    const uint32_t group_size = 64;  // Each scale applies to 64 elements
    
    // Calculate total blocks
    uint32_t total_blocks = static_cast<uint32_t>(q_weights.size / bytes_per_block);
    // DEBUG: printf("[Q3_K_S] total_blocks=%u\n", total_blocks);
    
    // Calculate expected blocks based on matrix dimensions
    uint32_t input_blocks = (input_dim + block_size - 1) / block_size;  // Blocks needed for input
    uint32_t expected_blocks = output_dim * input_blocks;
    
    if (total_blocks < expected_blocks) {
        // Adjust output_dim to what we can actually process
        output_dim = total_blocks / input_blocks;
        if (output_dim == 0) {
            return;
        }
    }
    // Initialize output to zero
    for (uint32_t i = 0; i < output_dim; i++) {
        output[i] = 0.0f;
    }
    
    // Process each output row
    for (uint32_t row = 0; row < output_dim; row++) {
        float sum = 0.0f;
        
        // Process each input block
        for (uint32_t b = 0; b < input_blocks; b++) {
            uint32_t block_idx = row * input_blocks + b;
            if (block_idx >= total_blocks) break;
            
            const uint8_t* block = q_weights.data + block_idx * bytes_per_block;
            uint32_t base_idx = b * block_size;
            
            // Extract 4 scales from first 2 bytes (4 nibbles)
            float scales[4];
            scales[0] = static_cast<float>(block[0] & 0x0F) / 16.0f;
            scales[1] = static_cast<float>((block[0] >> 4) & 0x0F) / 16.0f;
            scales[2] = static_cast<float>(block[1] & 0x0F) / 16.0f;
            scales[3] = static_cast<float>((block[1] >> 4) & 0x0F) / 16.0f;
            
            // Dequantize and multiply with input
            const uint8_t* quants = block + 2;  // Skip scale bytes
            
            for (uint32_t i = 0; i < block_size && (base_idx + i) < input_dim; i++) {
                uint32_t input_idx = base_idx + i;
                
                // Extract 3-bit value (packed sequentially)
                uint32_t bit_pos = i * 3;
                uint32_t byte_idx = bit_pos / 8;
                uint32_t bit_offset = bit_pos % 8;
                
                // Bounds check for quants array (96 bytes)
                if (byte_idx >= 96) {
                    break;
                }
                
                uint8_t qval = 0;
                if (bit_offset <= 5) {
                    // All 3 bits in one byte
                    qval = (quants[byte_idx] >> bit_offset) & 0x07;
                } else {
                    // Split across two bytes - check bounds
                    if (byte_idx + 1 >= 96) {
                        break;
                    }
                    uint8_t low_bits = (quants[byte_idx] >> bit_offset) & ((1 << (8 - bit_offset)) - 1);
                    uint8_t high_bits = (quants[byte_idx + 1] << (8 - bit_offset)) & 0x07;
                    qval = low_bits | high_bits;
                }
                
                // Dequantize: map 0-7 to -3.5 to +3.5, then apply group scale
                float dequant = (static_cast<float>(qval) - 3.5f);
                uint32_t group = i / group_size;
                dequant *= scales[group];
                
                sum += dequant * input[input_idx];
            }
        }
        output[row] = sum;
    }
}

// =============================================================================
// Q4_0 Matrix-Vector Multiplication
// =============================================================================
void QuantizedMatVecMul_Q4_0(const QuantizedWeightData& q_weights,
                                const float* input,
                                float* output,
                                uint32_t output_dim,
                                uint32_t input_dim) {
    // Safety check
    if (!q_weights.data || !input || !output) {
        return;
    }

    if (q_weights.size == 0) {
        return;
    }

    // Q4_0 block structure:
    // - 32 weights per block
    // - Block size: 18 bytes (2 scale + 16 packed weights)
    // - 4-bit values packed 2 per byte

    const uint32_t block_size = 32;
    const uint32_t bytes_per_block = 18;

    // Calculate total blocks
    uint32_t total_blocks = static_cast<uint32_t>(q_weights.size / bytes_per_block);

    // Calculate expected blocks based on matrix dimensions
    uint32_t input_blocks = (input_dim + block_size - 1) / block_size;
    uint32_t expected_blocks = output_dim * input_blocks;

    if (total_blocks < expected_blocks) {
        // Adjust output_dim to what we can actually process
        output_dim = total_blocks / input_blocks;
        if (output_dim == 0) {
            return;
        }
    }

    // Initialize output to zero
    for (uint32_t i = 0; i < output_dim; i++) {
        output[i] = 0.0f;
    }

    // Process each output row
    for (uint32_t row = 0; row < output_dim; row++) {
        float sum = 0.0f;

        // Process each input block
        for (uint32_t b = 0; b < input_blocks; b++) {
            uint32_t block_idx = row * input_blocks + b;
            if (block_idx >= total_blocks) break;

            const uint8_t* block = q_weights.data + block_idx * bytes_per_block;
            uint32_t base_idx = b * block_size;

            // Extract scale (first 2 bytes as FP16)
            // GGML Q4_0 uses little-endian FP16
            uint16_t scale_bits = block[0] | (block[1] << 8);
            float scale = float16_to_float32(scale_bits);
            
            // DEBUG: Check for unreasonable scale values
            if (std::isnan(scale) || std::isinf(scale) || scale > 1000.0f || scale < -1000.0f) {
                fprintf(stderr, "[Q4_0] WARNING: Unreasonable scale at block %u: %f (bits=0x%04x)\n", 
                        block_idx, scale, scale_bits);
                scale = 1.0f;  // Fallback
            }

            // Process 32 weights in this block
            for (uint32_t i = 0; i < block_size && (base_idx + i) < input_dim; i++) {
                uint32_t input_idx = base_idx + i;
                uint32_t byte_idx = 2 + (i / 2);  // Skip scale bytes

                if (byte_idx >= bytes_per_block) break;

                // Extract 4-bit value
                uint8_t packed = block[byte_idx];
                uint8_t qval = (i % 2 == 0) ? (packed & 0x0F) : (packed >> 4);

                // Dequantize: (q - 8) * scale
                float weight = (static_cast<float>(qval) - 8.0f) * scale;
                sum += weight * input[input_idx];
            }
        }
        output[row] = sum;
    }
}

// =============================================================================
// Q6_K Matrix-Vector Multiplication
// =============================================================================
void QuantizedMatVecMul_Q6_K(const QuantizedWeightData& q_weights,
                                const float* input,
                                float* output,
                                uint32_t output_dim,
                                uint32_t input_dim) {
    // Safety check
    if (!q_weights.data || !input || !output) {
        fprintf(stderr, "[Q6_K] ERROR: null pointer\n");
        return;
    }

    if (q_weights.size == 0) {
        fprintf(stderr, "[Q6_K] ERROR: weight size is 0\n");
        return;
    }

    // Calculate total elements
    uint32_t total_elements = output_dim * input_dim;
    
    // Q6_K: 210 bytes per 256 elements
    uint32_t max_elements = static_cast<uint32_t>((q_weights.size / 210) * 256);
    
    if (max_elements < total_elements) {
        fprintf(stderr, "[Q6_K] WARNING: not enough data: have %u elements, need %u\n", 
                max_elements, total_elements);
        // Adjust
        if (max_elements < input_dim) {
            fprintf(stderr, "[Q6_K] ERROR: cannot even process one row\n");
            return;
        }
        output_dim = max_elements / input_dim;
    }
    
    // Allocate buffer for dequantized weights
    float* dequantized = static_cast<float*>(
        VirtualAlloc(nullptr, total_elements * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    );
    
    if (!dequantized) {
        fprintf(stderr, "[Q6_K] ERROR: failed to allocate dequantized buffer\n");
        return;
    }
    
    // Dequantize all weights using the existing function
    Dequantize_Q6_K(q_weights.data, dequantized, total_elements);
    
    // Perform matrix-vector multiplication
    for (uint32_t row = 0; row < output_dim; row++) {
        float sum = 0.0f;
        uint32_t row_offset = row * input_dim;
        for (uint32_t col = 0; col < input_dim; col++) {
            sum += dequantized[row_offset + col] * input[col];
        }
        output[row] = sum;
    }
    
    VirtualFree(dequantized, 0, MEM_RELEASE);
}

// =============================================================================
// KV Cache Implementation
// =============================================================================
bool KVCache::Initialize(uint32_t n_layers, uint32_t max_seq, uint32_t n_kv_heads, uint32_t head_dim) {
    max_seq_len = max_seq;
    current_pos = 0;
    
    size_t cache_size = static_cast<size_t>(n_layers) * max_seq * n_kv_heads * head_dim * sizeof(float);
    
    k_cache = static_cast<float*>(VirtualAlloc(nullptr, cache_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    v_cache = static_cast<float*>(VirtualAlloc(nullptr, cache_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    
    if (!k_cache || !v_cache) {
        Cleanup();
        return false;
    }
    
    // Zero initialize
    memset(k_cache, 0, cache_size);
    memset(v_cache, 0, cache_size);
    
    return true;
}

void KVCache::Reset() {
    current_pos = 0;
    if (k_cache && v_cache && max_seq_len > 0) {
        size_t cache_size = static_cast<size_t>(max_seq_len) * sizeof(float); // Simplified
        memset(k_cache, 0, cache_size);
        memset(v_cache, 0, cache_size);
    }
}

void KVCache::Cleanup() {
    if (k_cache) {
        VirtualFree(k_cache, 0, MEM_RELEASE);
        k_cache = nullptr;
    }
    if (v_cache) {
        VirtualFree(v_cache, 0, MEM_RELEASE);
        v_cache = nullptr;
    }
    max_seq_len = 0;
    current_pos = 0;
}

// =============================================================================
// Transformer Forward Implementation
// =============================================================================
TransformerForward::TransformerForward(const ModelWeights& weights, KVCache& kv_cache)
    : weights_ptr_(&weights), kv_cache_(kv_cache) {
    // Initialize guard cookie for pointer validation
    weights_guard_ = (uint64_t)weights_ptr_ ^ 0xDEADBEEFCAFEBABEULL;
    fflush(stdout);
    AllocateScratchBuffers();
    // Note: KV cache is managed by KVCache struct, not TransformerForward
}

TransformerForward::~TransformerForward() {
    FreeScratchBuffers();
    // Note: KV cache is managed by KVCache struct, not TransformerForward
}

bool TransformerForward::AllocateScratchBuffers() {
    // FIX: Use validated weights() accessor
    const ModelWeights& w = weights();
    
    const uint32_t hd = w.hidden_dim;
    const uint32_t fd = w.ffn_dim;
    const uint32_t nh = w.n_heads;
    const uint32_t nkv = w.n_kv_heads;
    const uint32_t hdim = w.head_dim;
    const uint32_t max_seq = kv_cache_.max_seq_len;
    
    hidden_states_ = static_cast<float*>(VirtualAlloc(nullptr, hd * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    attn_out_ = static_cast<float*>(VirtualAlloc(nullptr, nh * hdim * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    attn_output_ = static_cast<float*>(VirtualAlloc(nullptr, hd * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    // FFN intermediate needs space for both up and gate (2 * fd)
    ffn_intermediate_ = static_cast<float*>(VirtualAlloc(nullptr, 2 * fd * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    q_proj_ = static_cast<float*>(VirtualAlloc(nullptr, nh * hdim * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    k_proj_ = static_cast<float*>(VirtualAlloc(nullptr, nkv * hdim * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    v_proj_ = static_cast<float*>(VirtualAlloc(nullptr, nkv * hdim * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    attn_scores_ = static_cast<float*>(VirtualAlloc(nullptr, nh * max_seq * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    
    return hidden_states_ && attn_out_ && attn_output_ && ffn_intermediate_ && 
           q_proj_ && k_proj_ && v_proj_ && attn_scores_;
}

void TransformerForward::FreeScratchBuffers() {
    auto free_buf = [](float*& buf) {
        if (buf) {
            VirtualFree(buf, 0, MEM_RELEASE);
            buf = nullptr;
        }
    };
    free_buf(hidden_states_);
    free_buf(attn_out_);
    free_buf(attn_output_);
    free_buf(ffn_intermediate_);
    free_buf(q_proj_);
    free_buf(k_proj_);
    free_buf(v_proj_);
    free_buf(attn_scores_);
}

bool TransformerForward::InitializePersistentKVCache() {
    // Initialize persistent KV cache that survives across ForwardToken calls
    const ModelWeights& w = weights();
    
    n_layers_ = w.n_layers;
    n_kv_heads_ = w.n_kv_heads;
    head_dim_ = w.head_dim;
    max_seq_ = kv_cache_.max_seq_len > 0 ? kv_cache_.max_seq_len : 2048;
    
    uint32_t kv_dim = n_kv_heads_ * head_dim_;
    size_t cache_size = (size_t)n_layers_ * max_seq_ * kv_dim * sizeof(float);
    
    if (g_debug) {
        printf("[KV-Cache] Initializing persistent cache: layers=%u, max_seq=%u, kv_dim=%u, size=%zu bytes\n",
               n_layers_, max_seq_, kv_dim, cache_size);
        fflush(stdout);
    }
    fflush(stdout);
    
    k_cache_ = (float*)calloc(cache_size / sizeof(float), sizeof(float));
    v_cache_ = (float*)calloc(cache_size / sizeof(float), sizeof(float));
    
    if (!k_cache_ || !v_cache_) {
        fprintf(stderr, "[KV-Cache] ERROR: Failed to allocate persistent KV cache!\n");
        fflush(stderr);
        return false;
    }
    
    kv_cache_initialized_ = true;
    if (g_debug) {
        printf("[KV-Cache] Persistent cache initialized: k_cache=%p, v_cache=%p\n", 
               (void*)k_cache_, (void*)v_cache_);
        fflush(stdout);
    }
    return true;
}

void TransformerForward::FreePersistentKVCache() {
    if (k_cache_) {
        free(k_cache_);
        k_cache_ = nullptr;
    }
    if (v_cache_) {
        free(v_cache_);
        v_cache_ = nullptr;
    }
    kv_cache_initialized_ = false;
    if (g_debug) {
        printf("[KV-Cache] Persistent cache freed\n");
        fflush(stdout);
    }
}

// =============================================================================
// Core Operations
// =============================================================================
void TransformerForward::EmbeddingLookup(uint32_t token_id, float* output) {
    // Safety check
    if (!output) {
        fprintf(stderr, "[EmbeddingLookup] ERROR: output is null\n");
        return;
    }
    
    // FIX: Use validated weights() accessor
    const ModelWeights& w = weights();
    const uint32_t hidden_dim = w.hidden_dim;
    
    // Calculate actual vocab size from quantized embedding tensor
    // Q4_0: 32 elements per 18 bytes
    uint32_t bytes_per_block = 18;
    uint32_t block_size = 32;
    uint32_t blocks_per_row = (hidden_dim + block_size - 1) / block_size;
    uint64_t row_size = static_cast<uint64_t>(blocks_per_row) * bytes_per_block;
    uint32_t effective_vocab = static_cast<uint32_t>(w.q_token_embeddings.size / row_size);
    
    // Clamp token_id to valid range
    uint32_t safe_token_id = token_id;
    if (safe_token_id >= effective_vocab) {
        // Wrap around to valid range instead of crashing
        safe_token_id = safe_token_id % effective_vocab;
        
        // Only print warning once per unique out-of-bounds token
        static uint32_t last_warned = 0xFFFFFFFF;
        if (token_id != last_warned) {
            fprintf(stderr, "[WARN] token_id %u out of bounds (max=%u), wrapped to %u\n",
                    token_id, effective_vocab - 1, safe_token_id);
            fflush(stderr);
            last_warned = token_id;
        }
    }
    
    // Check if we have quantized embeddings
    if (w.use_quantized && w.q_token_embeddings.data && w.q_token_embeddings.size > 0) {
        // Handle different quantization types
        if (w.q_token_embeddings.quant_type == 3) {  // Q4_0
            // Q4_0 format: 32 weights per block, 18 bytes per block (2 scale + 16 packed weights)
            
            // Calculate offset for this token's row using SAFE token_id
            uint64_t token_offset = static_cast<uint64_t>(safe_token_id) * row_size;
            if (token_offset + row_size > w.q_token_embeddings.size) {
                fprintf(stderr, "[EmbeddingLookup] ERROR: safe_token_id %u still out of bounds (size=%zu)\n", 
                        safe_token_id, w.q_token_embeddings.size);
                memset(output, 0, hidden_dim * sizeof(float));
                return;
            }
            
            // Calculate offset for this token's row
            const uint8_t* row_data = w.q_token_embeddings.data + token_offset;
            
            // Dequantize each block
            for (uint32_t b = 0; b < blocks_per_row; b++) {
                const uint8_t* block = row_data + b * bytes_per_block;
                uint32_t base_idx = b * block_size;
                
                // Check bounds
                if (base_idx >= hidden_dim) break;
                
                // Extract scale (first 2 bytes as FP16)
                uint16_t scale_bits = block[0] | (block[1] << 8);
                float scale = float16_to_float32(scale_bits);
                
                // Dequantize 32 weights (4-bit packed, 2 weights per byte)
                for (uint32_t i = 0; i < block_size && (base_idx + i) < hidden_dim; i++) {
                    uint32_t idx = base_idx + i;
                    uint32_t byte_idx = 2 + (i / 2);  // Skip scale bytes
                    
                    if (byte_idx >= bytes_per_block) break;
                    
                    // Extract 4-bit value
                    uint8_t packed = block[byte_idx];
                    uint8_t qval = (i % 2 == 0) ? (packed & 0x0F) : (packed >> 4);
                    
                    // Dequantize: (q - 8) * scale
                    float val = (static_cast<float>(qval) - 8.0f) * scale;
                    output[idx] = val;
                }
            }
        } else if (w.q_token_embeddings.quant_type == 2) {  // Q6_K
            // Q6_K format: 256 elements per block
            const uint32_t block_size = 256;
            const uint32_t bytes_per_block = 210;  // Q6_K block size
            
            // Calculate blocks per row
            uint32_t blocks_per_row = (hidden_dim + block_size - 1) / block_size;
            
            // Calculate row size in bytes
            uint64_t row_size = static_cast<uint64_t>(blocks_per_row) * bytes_per_block;
            
            // Check if token_id is valid
            uint64_t token_offset = static_cast<uint64_t>(token_id) * row_size;
            if (token_offset + row_size > w.q_token_embeddings.size) {
                fprintf(stderr, "[EmbeddingLookup] ERROR: token_id %u out of bounds (size=%zu)\n", 
                        token_id, w.q_token_embeddings.size);
                memset(output, 0, hidden_dim * sizeof(float));
                return;
            }
            
            // Calculate offset for this token's row
            const uint8_t* row_data = w.q_token_embeddings.data + token_offset;
            
            // Dequantize each block
            for (uint32_t b = 0; b < blocks_per_row; b++) {
                const uint8_t* block = row_data + b * bytes_per_block;
                uint32_t base_idx = b * block_size;
                
                // Check bounds
                if (base_idx >= hidden_dim) break;
                
                // Extract scales (first 2 bytes in Q6_K)
                float scale = static_cast<float>(block[0] & 0x7F) / 64.0f;
                
                // Dequantize 256 elements (simplified Q6_K)
                for (uint32_t i = 0; i < block_size && (base_idx + i) < hidden_dim; i++) {
                    uint32_t idx = base_idx + i;
                    
                    // 6-bit extraction (simplified)
                    uint32_t byte_idx = 2 + i / 4;
                    if (byte_idx >= bytes_per_block) break;
                    
                    uint8_t qval = (block[byte_idx] >> ((i % 4) * 2)) & 0x3F;
                    float val = (static_cast<float>(qval) - 32.0f) / 32.0f;
                    output[idx] = val * scale;
                }
            }
        } else {
            fprintf(stderr, "[EmbeddingLookup] WARNING: Unsupported quant_type %d\n", 
                    w.q_token_embeddings.quant_type);
            memset(output, 0, hidden_dim * sizeof(float));
        }
    } else if (w.token_embeddings) {
        // Standard float embeddings
        const float* embed = w.token_embeddings + token_id * hidden_dim;
        memcpy(output, embed, hidden_dim * sizeof(float));
    } else {
        // Fallback: zero embeddings
        fprintf(stderr, "[EmbeddingLookup] WARNING: No embeddings available, using zeros\n");
        memset(output, 0, hidden_dim * sizeof(float));
    }
}

void TransformerForward::RMSNorm(const float* input, const float* weight, float* output, 
                                  uint32_t size, float eps) {
    // Check inputs
    if (!input || !weight || !output) {
        fprintf(stderr, "[RMSNorm] ERROR: null pointer (input=%p, weight=%p, output=%p)\n", 
                (void*)input, (void*)weight, (void*)output);
        return;
    }
    
    // Compute RMS: sqrt(mean(x^2) + eps)
    float sum_sq = 0.0f;
    for (uint32_t i = 0; i < size; i++) {
        sum_sq += input[i] * input[i];
    }
    
    float rms = std::sqrt(sum_sq / static_cast<float>(size) + eps);
    float scale = 1.0f / rms;
    
    // Normalize and apply weight
    for (uint32_t i = 0; i < size; i++) {
        output[i] = input[i] * scale * weight[i];
    }
}

void TransformerForward::ResidualAdd(float* output, const float* residual) {
    // FIX: Use validated weights() accessor
    const ModelWeights& w = weights();
    for (uint32_t i = 0; i < w.hidden_dim; i++) {
        output[i] += residual[i];
    }
}

// =============================================================================
// RoPE (Rotary Position Embedding) Implementation
// =============================================================================
void ApplyRoPE(float* q, float* k, uint32_t pos, uint32_t head_dim, 
               uint32_t n_heads, uint32_t n_kv_heads) {
    // DEBUG: Check inputs
    bool q_in_nan = false, k_in_nan = false;
    if (g_debug) {
        for (uint32_t i = 0; i < n_heads * head_dim && i < 100; i++) {
            if (std::isnan(q[i])) q_in_nan = true;
        }
        for (uint32_t i = 0; i < n_kv_heads * head_dim && i < 100; i++) {
            if (std::isnan(k[i])) k_in_nan = true;
        }
        printf("[RoPE] Input - Q NaN: %s, K NaN: %s\n", q_in_nan ? "YES" : "NO", k_in_nan ? "YES" : "NO");
    }
    
    // RoPE applies rotation to pairs of dimensions (d, d + head_dim/2)
    // For each position pos, compute rotation angle = pos * theta_i
    // where theta_i = base^(2i/head_dim) for i in [0, head_dim/2)
    
    const float rope_base = 10000.0f;  // Standard Llama base
    const float inv_scale = 2.0f / head_dim;
    
    // DEBUG: Check first few values before rotation
    if (g_debug) {
        printf("[RoPE] First 4 Q values before: %.4f %.4f %.4f %.4f\n", 
               q[0], q[1], q[2], q[3]);
        printf("[RoPE] Parameters: head_dim=%u, inv_scale=%f, rope_base=%f\n",
               head_dim, inv_scale, rope_base);
    }
    
    // Precompute rotation frequencies for this position
    // For each pair i, freq = pos / (rope_base^(2i/head_dim))
    // = pos * rope_base^(-2i/head_dim)
    
    // Apply to Q (n_heads)
    for (uint32_t h = 0; h < n_heads; h++) {
        float* q_head = q + h * head_dim;
        
        for (uint32_t i = 0; i < head_dim / 2; i++) {
            // Compute rotation angle
            // FIX: Cast i to float before negation to avoid integer overflow
            float exponent = -(static_cast<float>(i)) * inv_scale;
            float freq = std::pow(rope_base, exponent);
            float angle = static_cast<float>(pos) * freq;
            
            // DEBUG: Check for first few iterations
            if (g_debug && h == 0 && i < 5) {
                printf("[RoPE] h=%u, i=%u: exponent=%f, freq=%f, angle=%f\n",
                       h, i, exponent, freq, angle);
            }
            
            float cos_a = std::cos(angle);
            float sin_a = std::sin(angle);
            
            // Check for NaN in trig functions
            if (g_debug && (std::isnan(cos_a) || std::isnan(sin_a))) {
                printf("[RoPE] NaN in trig at h=%u, i=%u, angle=%f\n", h, i, angle);
            }
            
            // Get the pair
            float x = q_head[i];
            float y = q_head[i + head_dim / 2];
            
            // Check for NaN in input
            if (g_debug && (std::isnan(x) || std::isnan(y))) {
                printf("[RoPE] NaN in Q input at h=%u, i=%u: x=%f, y=%f\n", h, i, x, y);
            }
            
            // Apply rotation: [x, y] rotated by angle
            // x' = x * cos - y * sin
            // y' = x * sin + y * cos
            q_head[i] = x * cos_a - y * sin_a;
            q_head[i + head_dim / 2] = x * sin_a + y * cos_a;
        }
    }
    
    // DEBUG: Check Q after rotation
    if (g_debug) {
        bool q_out_nan = false;
        for (uint32_t i = 0; i < n_heads * head_dim && i < 100; i++) {
            if (std::isnan(q[i])) q_out_nan = true;
        }
        printf("[RoPE] After Q rotation - NaN: %s\n", q_out_nan ? "YES" : "NO");
        printf("[RoPE] First 4 Q values after: %.4f %.4f %.4f %.4f\n", 
               q[0], q[1], q[2], q[3]);
    }
    
    // Apply to K (n_kv_heads - GQA)
    for (uint32_t h = 0; h < n_kv_heads; h++) {
        float* k_head = k + h * head_dim;
        
        for (uint32_t i = 0; i < head_dim / 2; i++) {
            // FIX: Cast i to float before negation to avoid integer overflow
            float exponent = -(static_cast<float>(i)) * inv_scale;
            float freq = std::pow(rope_base, exponent);
            float angle = static_cast<float>(pos) * freq;
            
            float cos_a = std::cos(angle);
            float sin_a = std::sin(angle);
            
            float x = k_head[i];
            float y = k_head[i + head_dim / 2];
            
            k_head[i] = x * cos_a - y * sin_a;
            k_head[i + head_dim / 2] = x * sin_a + y * cos_a;
        }
    }
}

void TransformerForward::Softmax(float* logits, uint32_t size) {
    // Find max for numerical stability
    float max_val = logits[0];
    for (uint32_t i = 1; i < size; i++) {
        if (logits[i] > max_val) max_val = logits[i];
    }
    
    // Compute exp(x - max) and sum
    float sum = 0.0f;
    for (uint32_t i = 0; i < size; i++) {
        logits[i] = std::exp(logits[i] - max_val);
        sum += logits[i];
    }
    
    // Normalize
    for (uint32_t i = 0; i < size; i++) {
        logits[i] /= sum;
    }
}

// =============================================================================
// Sampling Configuration
// =============================================================================
struct SamplingConfig {
    float temperature = 0.8f;      // Temperature scaling (0.0 = greedy, 1.0 = creative)
    uint32_t top_k = 40;           // Top-K filtering (0 = disabled)
    float top_p = 0.95f;           // Top-P (nucleus) sampling (1.0 = disabled)
    float repeat_penalty = 1.5f;   // Penalty for repeating tokens (increased from 1.3f)
};

// Global sampling config (can be made configurable)
static SamplingConfig g_sampling_config;

// =============================================================================
// Sampling Helper: Repetition Penalty
// =============================================================================
static void ApplyRepetitionPenalty(float* logits, uint32_t vocab_size, 
                                    const std::vector<uint32_t>& generated_tokens,
                                    float penalty) {
    if (penalty <= 1.0f || generated_tokens.empty()) {
        return;  // No penalty needed
    }
    
    // Count occurrences of each token
    std::unordered_map<uint32_t, uint32_t> token_counts;
    for (uint32_t token : generated_tokens) {
        token_counts[token]++;
    }
    
    // Apply penalty: divide logits by penalty for repeated tokens
    // Higher penalty = lower probability for repeated tokens
    for (const auto& [token, count] : token_counts) {
        if (token < vocab_size) {
            // Apply penalty proportional to how many times token was repeated
            float effective_penalty = std::pow(penalty, count);
            if (logits[token] > 0) {
                logits[token] /= effective_penalty;
            } else {
                logits[token] *= effective_penalty;  // For negative logits, multiply makes them more negative
            }
        }
    }
}
static void ApplyTemperature(float* logits, uint32_t vocab_size, float temperature) {
    if (temperature <= 0.0f || temperature == 1.0f) {
        return;  // No temperature scaling needed
    }
    
    for (uint32_t i = 0; i < vocab_size; i++) {
        logits[i] /= temperature;
    }
}

// =============================================================================
// Sampling Helper: Top-K Filtering
// =============================================================================
static void ApplyTopK(float* logits, uint32_t vocab_size, uint32_t k) {
    if (k == 0 || k >= vocab_size) {
        return;  // Top-K disabled
    }
    
    // Find the k-th largest logit using quickselect-like approach
    // For simplicity, we'll use a partial sort
    std::vector<std::pair<float, uint32_t>> logit_indices;
    logit_indices.reserve(vocab_size);
    for (uint32_t i = 0; i < vocab_size; i++) {
        logit_indices.push_back({logits[i], i});
    }
    
    // Partial sort to find top k
    std::nth_element(logit_indices.begin(), 
                     logit_indices.begin() + k, 
                     logit_indices.end(),
                     std::greater<std::pair<float, uint32_t>>());
    
    // Get the k-th largest value as threshold
    float threshold = logit_indices[k].first;
    
    // Set all logits below threshold to -infinity (very negative)
    for (uint32_t i = 0; i < vocab_size; i++) {
        if (logits[i] < threshold) {
            logits[i] = -1e10f;  // Effectively zero probability after softmax
        }
    }
}

// =============================================================================
// Sampling Helper: Top-P (Nucleus) Sampling
// =============================================================================
static void ApplyTopP(float* logits, uint32_t vocab_size, float p) {
    if (p >= 1.0f || p <= 0.0f) {
        return;  // Top-P disabled
    }
    
    // Create pairs of (logit, index)
    std::vector<std::pair<float, uint32_t>> logit_indices;
    logit_indices.reserve(vocab_size);
    for (uint32_t i = 0; i < vocab_size; i++) {
        logit_indices.push_back({logits[i], i});
    }
    
    // Sort by logit descending
    std::sort(logit_indices.begin(), logit_indices.end(),
              std::greater<std::pair<float, uint32_t>>());
    
    // Compute softmax probabilities
    float max_logit = logit_indices[0].first;
    float sum_exp = 0.0f;
    std::vector<float> probs(vocab_size);
    
    for (uint32_t i = 0; i < vocab_size; i++) {
        probs[i] = std::exp(logit_indices[i].first - max_logit);
        sum_exp += probs[i];
    }
    
    // Normalize
    for (uint32_t i = 0; i < vocab_size; i++) {
        probs[i] /= sum_exp;
    }
    
    // Find nucleus cutoff
    float cumsum = 0.0f;
    uint32_t cutoff_idx = vocab_size - 1;
    for (uint32_t i = 0; i < vocab_size; i++) {
        cumsum += probs[i];
        if (cumsum >= p) {
            cutoff_idx = i;
            break;
        }
    }
    
    // Get threshold from cutoff position
    float threshold = logit_indices[cutoff_idx].first;
    
    // Set all logits below threshold to -infinity
    for (uint32_t i = 0; i < vocab_size; i++) {
        if (logits[i] < threshold) {
            logits[i] = -1e10f;
        }
    }
}

// =============================================================================
// Sampling Helper: Random Weighted Selection
// =============================================================================
static uint32_t SampleFromDistribution(const float* probs, uint32_t vocab_size) {
    // Generate random number between 0 and 1
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_real_distribution<float> dis(0.0f, 1.0f);
    
    float r = dis(gen);
    float cumsum = 0.0f;
    
    for (uint32_t i = 0; i < vocab_size; i++) {
        cumsum += probs[i];
        if (r <= cumsum) {
            return i;
        }
    }
    
    return vocab_size - 1;  // Fallback
}

// =============================================================================
// Main Sampling Function
// =============================================================================
uint32_t TransformerForward::SampleToken(const float* logits) {
    // FIX: Use validated weights() accessor
    const ModelWeights& w = weights();
    const uint32_t vocab_size = w.vocab_size;
    
    // DEBUG: Print first few logits
    fprintf(stderr, "[SAMPLE] vocab_size=%u, first 5 logits: ", vocab_size);
    for (uint32_t i = 0; i < std::min(5u, vocab_size); i++) {
        fprintf(stderr, "%.3f ", logits[i]);
    }
    fprintf(stderr, "\n");
    
    // Find max logit
    float max_logit = logits[0];
    uint32_t max_idx = 0;
    for (uint32_t i = 1; i < vocab_size; i++) {
        if (logits[i] > max_logit) {
            max_logit = logits[i];
            max_idx = i;
        }
    }
    fprintf(stderr, "[SAMPLE] max_logit=%.3f at idx=%u\n", max_logit, max_idx);
    
    // Copy logits to mutable buffer
    std::vector<float> mutable_logits(vocab_size);
    std::memcpy(mutable_logits.data(), logits, vocab_size * sizeof(float));
    
    // 1. Apply Temperature
    ApplyTemperature(mutable_logits.data(), vocab_size, g_sampling_config.temperature);
    
    // 2. Apply Top-K filtering
    ApplyTopK(mutable_logits.data(), vocab_size, g_sampling_config.top_k);
    
    // 3. Apply Top-P (Nucleus) filtering
    ApplyTopP(mutable_logits.data(), vocab_size, g_sampling_config.top_p);
    
    // 4. Convert to probabilities (softmax)
    max_logit = mutable_logits[0];
    for (uint32_t i = 1; i < vocab_size; i++) {
        if (mutable_logits[i] > max_logit) {
            max_logit = mutable_logits[i];
        }
    }
    
    float sum_exp = 0.0f;
    for (uint32_t i = 0; i < vocab_size; i++) {
        mutable_logits[i] = std::exp(mutable_logits[i] - max_logit);
        sum_exp += mutable_logits[i];
    }
    
    for (uint32_t i = 0; i < vocab_size; i++) {
        mutable_logits[i] /= sum_exp;
    }
    
    // 5. Sample from the filtered distribution
    uint32_t result = SampleFromDistribution(mutable_logits.data(), vocab_size);
    fprintf(stderr, "[SAMPLE] Sampled token: %u\n", result);
    return result;
}

// =============================================================================
// Sample Token with Repetition Penalty
// =============================================================================
uint32_t TransformerForward::SampleTokenWithHistory(const float* logits, 
                                                   const std::vector<uint32_t>& generated_tokens) {
    // FIX: Use validated weights() accessor
    const ModelWeights& w = weights();
    const uint32_t vocab_size = w.vocab_size;
    
    if (g_debug) {
        fprintf(stderr, "[SAMPLE_HISTORY] vocab_size=%u, history_size=%zu\n", 
                vocab_size, generated_tokens.size());
    }
    
    // Copy logits to mutable buffer
    std::vector<float> mutable_logits(vocab_size);
    std::memcpy(mutable_logits.data(), logits, vocab_size * sizeof(float));
    
    // 1. Apply Repetition Penalty FIRST (before temperature)
    ApplyRepetitionPenalty(mutable_logits.data(), vocab_size, generated_tokens, 
                           g_sampling_config.repeat_penalty);
    
    // 2. Apply Temperature
    ApplyTemperature(mutable_logits.data(), vocab_size, g_sampling_config.temperature);
    
    // 3. Apply Top-K filtering
    ApplyTopK(mutable_logits.data(), vocab_size, g_sampling_config.top_k);
    
    // 4. Apply Top-P (Nucleus) filtering
    ApplyTopP(mutable_logits.data(), vocab_size, g_sampling_config.top_p);
    
    // 5. Convert to probabilities (softmax)
    float max_logit = mutable_logits[0];
    for (uint32_t i = 1; i < vocab_size; i++) {
        if (mutable_logits[i] > max_logit) {
            max_logit = mutable_logits[i];
        }
    }
    
    float sum_exp = 0.0f;
    for (uint32_t i = 0; i < vocab_size; i++) {
        mutable_logits[i] = std::exp(mutable_logits[i] - max_logit);
        sum_exp += mutable_logits[i];
    }
    
    for (uint32_t i = 0; i < vocab_size; i++) {
        mutable_logits[i] /= sum_exp;
    }
    
    // 6. Sample from the filtered distribution
    uint32_t result = SampleFromDistribution(mutable_logits.data(), vocab_size);
    if (g_debug) {
        fprintf(stderr, "[SAMPLE_HISTORY] Sampled token: %u\n", result);
    }
    return result;
}

// =============================================================================
// MASM Kernel Wrappers
// =============================================================================
void TransformerForward::Kernel_MatMul(const float* a, const float* b, float* c,
                                      uint32_t m, uint32_t n, uint32_t k) {
    // Call MASM MatMul_F16_AVX512 if available, else fallback to C++
    // For now: simple C++ matmul (can be replaced with MASM)
    for (uint32_t i = 0; i < m; i++) {
        for (uint32_t j = 0; j < n; j++) {
            float sum = 0.0f;
            for (uint32_t kk = 0; kk < k; kk++) {
                sum += a[i * k + kk] * b[kk * n + j];
            }
            c[i * n + j] = sum;
        }
    }
}

void TransformerForward::Kernel_RMSNorm(float* x, const float* weight, uint32_t size, float eps) {
    // Call MASM RMSNorm_AVX512 if available
    // For now: C++ implementation
    RMSNorm(x, weight, x, size, eps);
}

void TransformerForward::Kernel_Softmax(float* x, uint32_t size) {
    // Call MASM SoftMax_AVX512 if available
    // For now: C++ implementation
    Softmax(x, size);
}

// =============================================================================
// Attention Layer
// =============================================================================
void TransformerForward::AttentionLayer(uint32_t layer_idx, uint32_t pos) {
    // DEBUG: printf("[AttentionLayer] Entered layer %u\n", layer_idx); fflush(stdout);
    
    // FIX: Use validated weights() accessor instead of direct weights_ reference
    const ModelWeights& w = weights();
    
    const uint32_t hd = w.hidden_dim;
    const uint32_t hdim = w.head_dim;
    const uint32_t nh = w.n_heads;
    const uint32_t nkv = w.n_kv_heads;
    
    // DEBUG: printf("[AttentionLayer] dims: hd=%u, hdim=%u, nh=%u, nkv=%u\n", hd, hdim, nh, nkv); fflush(stdout);
    
    // Save residual for later (use a separate buffer to avoid overwrite)
    float* residual_save = static_cast<float*>(
        VirtualAlloc(nullptr, hd * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    );
    if (!residual_save) {
        fprintf(stderr, "[AttentionLayer] ERROR: Failed to allocate residual buffer\n");
        return;
    }
    memcpy(residual_save, hidden_states_, hd * sizeof(float));
    
    // DEBUG: printf("[AttentionLayer] Saved residual\n"); fflush(stdout);
    
    // Pre-attention RMSNorm
    // DEBUG: printf("[AttentionLayer] Checking attn_norm[%u]...\n", layer_idx); fflush(stdout);
    if (!w.attn_norm || !w.attn_norm[layer_idx]) {
        fprintf(stderr, "[AttentionLayer] ERROR: attn_norm[%u] is null!\n", layer_idx);
        return;
    }
    
    // DEBUG: printf("[AttentionLayer] Running RMSNorm with hd=%u...\n", hd); fflush(stdout);
    
    Kernel_RMSNorm(hidden_states_, w.attn_norm[layer_idx], hd, 1e-6f);
    
    // DEBUG: printf("[AttentionLayer] Starting QKV projections...\n"); fflush(stdout);
    
    // DIAGNOSTIC: Test weights pointer access step by step
    if (g_debug) {
        printf("[DBG-A] weights_ptr_=%p, guard=%llx\n", (void*)weights_ptr_, weights_guard_); fflush(stdout);
        printf("[DBG-B] use_quantized=%d\n", w.use_quantized); fflush(stdout);
    }
    
    // Q, K, V projections
    // For quantized mode, we need to dequantize on-the-fly during matmul
    if (g_debug) {
        printf("[AttentionLayer] use_quantized=%d\n", w.use_quantized); fflush(stdout);
    }
    if (w.use_quantized) {
        if (g_debug) {
            printf("[AttentionLayer] Using quantized path\n"); fflush(stdout);
        }
        
        // Check for fused QKV first (models like Phi-3)
        bool have_wqkv = w.q_wqkv && w.q_wqkv[layer_idx].data && w.q_wqkv[layer_idx].size > 0;
        
        // Check if separate quantized weights are available
        bool have_wq = w.q_wq && w.q_wq[layer_idx].data && w.q_wq[layer_idx].size > 0;
        bool have_wk = w.q_wk && w.q_wk[layer_idx].data && w.q_wk[layer_idx].size > 0;
        bool have_wv = w.q_wv && w.q_wv[layer_idx].data && w.q_wv[layer_idx].size > 0;
        
        if (g_debug) {
            printf("[AttentionLayer] have_wqkv=%d, have_wq=%d, have_wk=%d, have_wv=%d\n", have_wqkv, have_wq, have_wk, have_wv);
        }
        
        if (have_wqkv) {
            // FUSED QKV PATH (Phi-3, etc.)
            // One matmul produces combined QKV, then we split
            if (g_debug) {
                printf("[AttentionLayer] Using fused QKV matmul\n");
            }
            
            // Allocate temporary buffer for combined QKV output
            // QKV size = (n_heads + 2*n_kv_heads) * head_dim
            uint32_t total_qkv_dim = (nh + 2 * nkv) * hdim;
            
            // FIX: Validate VirtualAlloc return value
            size_t qkv_bytes = total_qkv_dim * sizeof(float);
            if (g_debug) {
                printf("[DBG-C] Allocating QKV buffer: %zu bytes\n", qkv_bytes); fflush(stdout);
            }
            
            float* qkv_combined = static_cast<float*>(
                VirtualAlloc(nullptr, qkv_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            );
            
            if (g_debug) {
                printf("[DBG-D] qkv_combined=%p\n", (void*)qkv_combined); fflush(stdout);
            }
            
            if (!qkv_combined) {
                fprintf(stderr, "[AttentionLayer] FATAL: VirtualAlloc failed for QKV buffer (size=%zu, err=%lu)\n",
                        qkv_bytes, GetLastError());
                fflush(stderr);
                memset(q_proj_, 0, nh * hdim * sizeof(float));
                memset(k_proj_, 0, nkv * hdim * sizeof(float));
                memset(v_proj_, 0, nkv * hdim * sizeof(float));
            } else {
                if (g_debug) {
                    printf("[DBG-E] wqkv data=%p, size=%llu, type=%d\n",
                           (void*)w.q_wqkv[layer_idx].data, w.q_wqkv[layer_idx].size, w.q_wqkv[layer_idx].quant_type);
                    fflush(stdout);
                    
                    // Single matmul for fused QKV
                    printf("[DBG-F] Calling QuantizedMatVecMul...\n"); fflush(stdout);
                }
                
                if (w.q_wqkv[layer_idx].quant_type == 3) {  // Q4_0
                    QuantizedMatVecMul_Q4_0(w.q_wqkv[layer_idx], hidden_states_, qkv_combined, total_qkv_dim, hd);
                } else if (w.q_wqkv[layer_idx].quant_type == 2) {  // Q6_K
                    printf("[AttentionLayer] WARNING: Q6_K fused QKV not yet implemented, using zeros\n");
                    memset(qkv_combined, 0, total_qkv_dim * sizeof(float));
                } else {  // Q3_K or other
                    QuantizedMatVecMul_Q3_K_S(w.q_wqkv[layer_idx], hidden_states_, qkv_combined, total_qkv_dim, hd);
                }
                
                printf("[DBG-G] MatVecMul returned OK\n"); fflush(stdout);
                
                // Split QKV into separate projections
                // Q = first nh*hdim elements
                memcpy(q_proj_, qkv_combined, nh * hdim * sizeof(float));
                // K = next nkv*hdim elements
                memcpy(k_proj_, qkv_combined + nh * hdim, nkv * hdim * sizeof(float));
                // V = last nkv*hdim elements
                memcpy(v_proj_, qkv_combined + (nh + nkv) * hdim, nkv * hdim * sizeof(float));
                
                VirtualFree(qkv_combined, 0, MEM_RELEASE);
                if (g_debug) {
                    printf("[AttentionLayer] Fused QKV split complete\n");
                }
            }
        } else if (have_wq && have_wk && have_wv) {
            // SEPARATE Q/K/V PATH (Llama, etc.)
            if (g_debug) {
                printf("[AttentionLayer] Running separate Q/K/V matmul, quant_types: wq=%d, wk=%d, wv=%d\n",
                       w.q_wq[layer_idx].quant_type, w.q_wk[layer_idx].quant_type, w.q_wv[layer_idx].quant_type);
            }
            
            // Q projection
            if (g_debug) printf("[AttentionLayer] Q projection...\n");
            if (w.q_wq[layer_idx].quant_type == 3) {  // Q4_0
                QuantizedMatVecMul_Q4_0(w.q_wq[layer_idx], hidden_states_, q_proj_, nh * hdim, hd);
            } else {  // Q3_K or other
                QuantizedMatVecMul_Q3_K_S(w.q_wq[layer_idx], hidden_states_, q_proj_, nh * hdim, hd);
            }
            // Check for NaN in q_proj_
            if (g_debug) {
                bool q_has_nan = false;
                for (uint32_t i = 0; i < nh * hdim && i < 100; i++) {
                    if (std::isnan(q_proj_[i])) { q_has_nan = true; break; }
                }
                printf("[AttentionLayer] Q projection has NaN: %s\n", q_has_nan ? "YES" : "NO");
            }
            
            if (g_debug) printf("[AttentionLayer] K projection...\n");
            // K projection
            if (w.q_wk[layer_idx].quant_type == 3) {  // Q4_0
                QuantizedMatVecMul_Q4_0(w.q_wk[layer_idx], hidden_states_, k_proj_, nkv * hdim, hd);
            } else {  // Q3_K or other
                QuantizedMatVecMul_Q3_K_S(w.q_wk[layer_idx], hidden_states_, k_proj_, nkv * hdim, hd);
            }
            // Check for NaN in k_proj_
            if (g_debug) {
                bool k_has_nan = false;
                for (uint32_t i = 0; i < nkv * hdim && i < 100; i++) {
                    if (std::isnan(k_proj_[i])) { k_has_nan = true; break; }
                }
                printf("[AttentionLayer] K projection has NaN: %s\n", k_has_nan ? "YES" : "NO");
            }
            
            if (g_debug) printf("[AttentionLayer] V projection...\n");
            // V projection
            if (w.q_wv[layer_idx].quant_type == 3) {  // Q4_0
                QuantizedMatVecMul_Q4_0(w.q_wv[layer_idx], hidden_states_, v_proj_, nkv * hdim, hd);
            } else {  // Q3_K or other
                QuantizedMatVecMul_Q3_K_S(w.q_wv[layer_idx], hidden_states_, v_proj_, nkv * hdim, hd);
            }
            // Check for NaN in v_proj_
            if (g_debug) {
                bool v_has_nan = false;
                for (uint32_t i = 0; i < nkv * hdim && i < 100; i++) {
                    if (std::isnan(v_proj_[i])) { v_has_nan = true; break; }
                }
                printf("[AttentionLayer] V projection has NaN: %s\n", v_has_nan ? "YES" : "NO");
            }
            
            if (g_debug) printf("[AttentionLayer] QKV projections complete\n");
        } else {
            printf("[AttentionLayer] WARNING: Missing quantized weights (neither fused nor separate), using zeros\n");
            // Zero outputs as fallback
            memset(q_proj_, 0, nh * hdim * sizeof(float));
            memset(k_proj_, 0, nkv * hdim * sizeof(float));
            memset(v_proj_, 0, nkv * hdim * sizeof(float));
        }
    } else {
        printf("[AttentionLayer] Using float path\n");
        // Standard float matmul path
        // Q: [hidden_dim] @ [hidden_dim, n_heads * head_dim] -> [n_heads, head_dim]
        Kernel_MatMul(hidden_states_, w.wq[layer_idx], q_proj_, 1, nh * hdim, hd);
        
        // K: [hidden_dim] @ [hidden_dim, n_kv_heads * head_dim] -> [n_kv_heads, head_dim]
        Kernel_MatMul(hidden_states_, w.wk[layer_idx], k_proj_, 1, nkv * hdim, hd);
        
        // V: [hidden_dim] @ [hidden_dim, n_kv_heads * head_dim] -> [n_kv_heads, head_dim]
        Kernel_MatMul(hidden_states_, w.wv[layer_idx], v_proj_, 1, nkv * hdim, hd);
    }
    
    // === APPLY RoPE (Rotary Position Embedding) ===
    if (g_debug) {
        printf("[AttentionLayer] Applying RoPE at position %u...\n", pos);
    }
    
    // DEBUG: Check Q/K before RoPE
    if (g_debug) {
        bool q_before_rope = false, k_before_rope = false;
        for (uint32_t i = 0; i < nh * hdim && i < 100; i++) {
            if (std::isnan(q_proj_[i])) q_before_rope = true;
        }
        for (uint32_t i = 0; i < nkv * hdim && i < 100; i++) {
            if (std::isnan(k_proj_[i])) k_before_rope = true;
        }
        printf("[AttentionLayer] Before RoPE - Q NaN: %s, K NaN: %s\n", 
               q_before_rope ? "YES" : "NO", k_before_rope ? "YES" : "NO");
    }
    
    ApplyRoPE(q_proj_, k_proj_, pos, hdim, nh, nkv);
    
    // DEBUG: Check Q/K after RoPE
    if (g_debug) {
        bool q_after_rope = false, k_after_rope = false;
        for (uint32_t i = 0; i < nh * hdim && i < 100; i++) {
            if (std::isnan(q_proj_[i])) q_after_rope = true;
        }
        for (uint32_t i = 0; i < nkv * hdim && i < 100; i++) {
            if (std::isnan(k_proj_[i])) k_after_rope = true;
        }
        printf("[AttentionLayer] After RoPE - Q NaN: %s, K NaN: %s\n", 
               q_after_rope ? "YES" : "NO", k_after_rope ? "YES" : "NO");
        printf("[AttentionLayer] RoPE applied\n");
    }
    
    // === STORE K,V in PERSISTENT KV CACHE ===
    // Use the KVCache struct's buffers (shared across all layers)
    // Layout: kv_cache_.k_cache[layer][pos][head][dim]
    uint32_t kv_dim = nkv * hdim;
    float* k_cache_layer = kv_cache_.k_cache + layer_idx * kv_cache_.max_seq_len * kv_dim;
    float* v_cache_layer = kv_cache_.v_cache + layer_idx * kv_cache_.max_seq_len * kv_dim;
    
    memcpy(k_cache_layer + pos * kv_dim, k_proj_, kv_dim * sizeof(float));
    memcpy(v_cache_layer + pos * kv_dim, v_proj_, kv_dim * sizeof(float));
    
    if (g_debug) {
        printf("[AttentionLayer] Stored K,V in persistent cache at pos=%u, layer=%u\n", pos, layer_idx);
    }
    
    // Attention computation for each head
    const float scale = 1.0f / std::sqrt(static_cast<float>(hdim));
    
    // [ATTN-CHECK] Diagnostic: Verify attention is being computed
    if (g_debug) {
        fprintf(stderr, "[ATTN-CHECK] Computing attention scores for pos=%u, nh=%u, nkv=%u, scale=%.4f, positions=0..%u\n", 
                pos, nh, nkv, scale, pos);
        fflush(stderr);
    }
    
    float max_qk_score = -1e30f;
    float min_qk_score = 1e30f;
    
    for (uint32_t h = 0; h < nh; h++) {
        uint32_t kv_head = h / (nh / nkv);  // GQA: map query head to kv head
        
        // Bounds check
        if (kv_head >= nkv) {
            continue;
        }
        
        // Compute attention scores: Q @ K^T
        for (uint32_t t = 0; t <= pos; t++) {
            float* k_t = k_cache_layer + t * nkv * hdim + kv_head * hdim;
            float* q_h = q_proj_ + h * hdim;
            
            float score = 0.0f;
            for (uint32_t d = 0; d < hdim; d++) {
                score += q_h[d] * k_t[d];
            }
            float scaled_score = score * scale;
            attn_scores_[h * kv_cache_.max_seq_len + t] = scaled_score;
            
            // Track min/max BEFORE softmax
            if (scaled_score > max_qk_score) max_qk_score = scaled_score;
            if (scaled_score < min_qk_score) min_qk_score = scaled_score;
        }
        
        // Softmax over attention scores
        Softmax(attn_scores_ + h * kv_cache_.max_seq_len, pos + 1);
        
        // Compute attention output: scores @ V
        float* out_h = attn_out_ + h * hdim;
        memset(out_h, 0, hdim * sizeof(float));
        
        for (uint32_t t = 0; t <= pos; t++) {
            float* v_t = v_cache_layer + t * nkv * hdim + kv_head * hdim;
            float score = attn_scores_[h * kv_cache_.max_seq_len + t];
            for (uint32_t d = 0; d < hdim; d++) {
                out_h[d] += score * v_t[d];
            }
        }
    }
    
    // [ATTN-CHECK] Report attention statistics (only in debug mode)
    if (g_debug) {
        // Count how many positions we actually attended to
        uint32_t num_positions = pos + 1;
        
        // Check if softmax produced uniform distribution (indicates single position)
        float first_score = attn_scores_[0 * kv_cache_.max_seq_len + 0];
        bool is_uniform = true;
        for (uint32_t t = 1; t < num_positions && t < 10; t++) {
            if (std::abs(attn_scores_[0 * kv_cache_.max_seq_len + t] - first_score) > 0.001f) {
                is_uniform = false;
                break;
            }
        }
        
        fprintf(stderr, "[ATTN-CHECK] pos=%u, attending to %u positions | Q·K^T: min=%.4f, max=%.4f | ", 
                pos, num_positions, min_qk_score, max_qk_score);
        
        if (num_positions == 1) {
            fprintf(stderr, "softmax=1.0 (single position)");
        } else if (is_uniform) {
            fprintf(stderr, "softmax uniform (BUG - only 1 position in cache!)");
        } else {
            fprintf(stderr, "softmax varied (OK - %u positions)", num_positions);
        }
        
        // DEBUG: Print actual scores for head 0
        if (pos >= 1) {
            fprintf(stderr, " | h0_scores=[");
            for (uint32_t t = 0; t <= pos && t < 5; t++) {
                fprintf(stderr, "%.3f ", attn_scores_[0 * kv_cache_.max_seq_len + t]);
            }
            if (pos >= 5) fprintf(stderr, "...");
            fprintf(stderr, "]");
        }
        fprintf(stderr, "\n");
        fflush(stderr);
    }
    
    // Output projection: [n_heads * head_dim] -> [hidden_dim]
    
    // DEBUG: Check for NaN in attn_out_ (input to projection)
    if (g_debug) {
        bool attn_in_has_nan = false;
        for (uint32_t i = 0; i < nh * hdim && i < 100; i++) {
            if (std::isnan(attn_out_[i])) { attn_in_has_nan = true; break; }
        }
        printf("[AttentionLayer] attn_out_ (input to proj) has NaN: %s\n", attn_in_has_nan ? "YES" : "NO");
    }
    
    if (w.use_quantized && w.q_wo[layer_idx].data) {
        if (g_debug) printf("[AttentionLayer] Using q_wo quant_type=%d\n", w.q_wo[layer_idx].quant_type);
        QuantizedMatVecMul_Q3_K_S(w.q_wo[layer_idx], attn_out_, attn_output_, hd, nh * hdim);
    } else {
        if (g_debug) printf("[AttentionLayer] Using float wo\n");
        Kernel_MatMul(attn_out_, w.wo[layer_idx], attn_output_, 1, hd, nh * hdim);
    }
    
    // DEBUG: Check for NaN in attn_output_
    if (g_debug) {
        bool attn_out_has_nan = false;
        for (uint32_t i = 0; i < hd && i < 100; i++) {
            if (std::isnan(attn_output_[i])) { attn_out_has_nan = true; break; }
        }
        printf("[AttentionLayer] attn_output has NaN: %s\n", attn_out_has_nan ? "YES" : "NO");
    }
    
    // DEBUG: Check for NaN in residual_save
    if (g_debug) {
        bool resid_has_nan = false;
        for (uint32_t i = 0; i < hd && i < 100; i++) {
            if (std::isnan(residual_save[i])) { resid_has_nan = true; break; }
        }
        printf("[AttentionLayer] residual_save has NaN: %s\n", resid_has_nan ? "YES" : "NO");
    }
    
    // Residual connection: add attention output to saved residual
    for (uint32_t i = 0; i < hd; i++) {
        hidden_states_[i] = attn_output_[i] + residual_save[i];
    }
    
    // DEBUG: Check for NaN after residual
    if (g_debug) {
        bool hs_has_nan = false;
        for (uint32_t i = 0; i < hd && i < 100; i++) {
            if (std::isnan(hidden_states_[i])) { hs_has_nan = true; break; }
        }
        printf("[AttentionLayer] hidden_states after residual has NaN: %s\n", hs_has_nan ? "YES" : "NO");
    }
    
    // Free the residual save buffer
    VirtualFree(residual_save, 0, MEM_RELEASE);
    
    if (g_debug) printf("[AttentionLayer] Layer %u complete\n", layer_idx);
}

// =============================================================================
// FFN Layer (SwiGLU)
// =============================================================================
void TransformerForward::FFNLayer(uint32_t layer_idx) {
    // FIX: Use validated weights() accessor
    const ModelWeights& w = weights();
    
    const uint32_t hd = w.hidden_dim;
    const uint32_t fd = w.ffn_dim;
    
    // Save residual
    memcpy(ffn_intermediate_, hidden_states_, hd * sizeof(float));
    
    // Pre-FFN RMSNorm
    // Use the configured hidden_dim which should match actual tensor sizes
    Kernel_RMSNorm(hidden_states_, w.ffn_norm[layer_idx], w.hidden_dim, 1e-6f);
    
    // DEBUG: Check for NaN after RMSNorm
    if (g_debug) {
        bool rms_has_nan = false;
        for (uint32_t i = 0; i < hd && i < 100; i++) {
            if (std::isnan(hidden_states_[i])) { rms_has_nan = true; break; }
        }
        printf("[FFNLayer] After RMSNorm has NaN: %s\n", rms_has_nan ? "YES" : "NO");
    }
    
    // SwiGLU: gate = x @ w_gate, up = x @ w_up
    float* gate_buf = ffn_intermediate_ + fd;  // Reuse buffer
    
    // Check what weights are available
    bool have_q_gate = w.use_quantized && w.q_w_gate[layer_idx].data;
    bool have_q_up = w.use_quantized && w.q_w_up[layer_idx].data;
    bool have_f_gate = w.w_gate[layer_idx] != nullptr;
    bool have_f_up = w.w_up[layer_idx] != nullptr;
    
    // Use quantized matmul if available
    if (have_q_gate && have_q_up) {
        QuantizedMatVecMul_Q3_K_S(w.q_w_gate[layer_idx], hidden_states_, gate_buf, fd, hd);
        QuantizedMatVecMul_Q3_K_S(w.q_w_up[layer_idx], hidden_states_, ffn_intermediate_, fd, hd);
    } else if (have_f_gate && have_f_up) {
        Kernel_MatMul(hidden_states_, w.w_gate[layer_idx], gate_buf, 1, fd, hd);
        Kernel_MatMul(hidden_states_, w.w_up[layer_idx], ffn_intermediate_, 1, fd, hd);
    } else {
        // Fallback: No FFN weights available (model may use fused weights or different format)
        // Just pass through the residual (identity FFN)
        printf("[FFNLayer] WARNING: No FFN weights available for layer %u, using identity\n", layer_idx);
        memset(gate_buf, 0, fd * sizeof(float));
        memset(ffn_intermediate_, 0, fd * sizeof(float));
    }
    
    // DEBUG: Check for NaN after gate/up projections
    if (g_debug) {
        bool gate_has_nan = false, up_has_nan = false;
        for (uint32_t i = 0; i < fd && i < 100; i++) {
            if (std::isnan(gate_buf[i])) { gate_has_nan = true; }
            if (std::isnan(ffn_intermediate_[i])) { up_has_nan = true; }
        }
        printf("[FFNLayer] After gate/up projection - gate NaN: %s, up NaN: %s\n", 
               gate_has_nan ? "YES" : "NO", up_has_nan ? "YES" : "NO");
    }
    
    // SiLU activation: x * sigmoid(x)
    for (uint32_t i = 0; i < fd; i++) {
        float x = ffn_intermediate_[i];
        float sigmoid = 1.0f / (1.0f + std::exp(-x));
        ffn_intermediate_[i] = gate_buf[i] * x * sigmoid;  // SwiGLU
    }
    
    // DEBUG: Check for NaN after SiLU
    if (g_debug) {
        bool silu_has_nan = false;
        for (uint32_t i = 0; i < fd && i < 100; i++) {
            if (std::isnan(ffn_intermediate_[i])) { silu_has_nan = true; break; }
        }
        printf("[FFNLayer] After SiLU has NaN: %s\n", silu_has_nan ? "YES" : "NO");
    }
    
    // Down projection
    bool have_q_down = w.use_quantized && w.q_w_down[layer_idx].data;
    bool have_f_down = w.w_down[layer_idx] != nullptr;
    
    if (have_q_down) {
        QuantizedMatVecMul_Q3_K_S(w.q_w_down[layer_idx], ffn_intermediate_, hidden_states_, hd, fd);
    } else if (have_f_down) {
        Kernel_MatMul(ffn_intermediate_, w.w_down[layer_idx], hidden_states_, 1, hd, fd);
    } else {
        // No down projection available, keep hidden_states_ as-is
        printf("[FFNLayer] WARNING: No down projection weights for layer %u\n", layer_idx);
    }
    
    // Residual connection
    ResidualAdd(hidden_states_, attn_output_);  // attn_output_ has the residual from before
}

// =============================================================================
// Main Forward Pass
// =============================================================================
bool TransformerForward::Forward(const uint32_t* input_tokens, uint32_t seq_len, float* output_logits) {
    if (!hidden_states_ || seq_len == 0) return false;
    
    // Process each position in sequence
    for (uint32_t pos = 0; pos < seq_len; pos++) {
        if (!ForwardToken(input_tokens[pos], pos, output_logits)) {
            return false;
        }
    }
    
    return true;
}

bool TransformerForward::ForwardToken(uint32_t token_id, uint32_t pos, float* output_logits) {
    // FIX: Use validated weights() accessor
    const ModelWeights& w = weights();
    
    if (!hidden_states_) {
        fprintf(stderr, "[ForwardToken] ERROR: hidden_states_ is null\n");
        return false;
    }

    if (!output_logits) {
        fprintf(stderr, "[ForwardToken] ERROR: output_logits is null\n");
        return false;
    }

    // Check if weights are mapped (accept either float or quantized embeddings)
    if (!w.token_embeddings && !w.q_token_embeddings.data) {
        fprintf(stderr, "[ForwardToken] ERROR: No embeddings available\n");
        return false;
    }

    if (g_debug) {
        printf("[ForwardToken] Starting embedding lookup for token %u\n", token_id);
    }

    // Embedding lookup
    EmbeddingLookup(token_id, hidden_states_);
    
    // DEBUG: Check for NaN in hidden states after embedding
    if (g_debug) {
        bool has_nan = false;
        for (uint32_t i = 0; i < w.hidden_dim && i < 10; i++) {
            if (std::isnan(hidden_states_[i]) || std::isinf(hidden_states_[i])) {
                has_nan = true;
                fprintf(stderr, "[FWD] NaN/Inf in hidden_states[%u] after embedding: %f\n", i, hidden_states_[i]);
            }
        }
        if (!has_nan) {
            fprintf(stderr, "[FWD] Embedding OK (first 10 values)\n");
        }
    }

    if (g_debug) {
        printf("[ForwardToken] Running %u transformer layers...\n", w.n_layers);
    }

    // Transformer layers
    for (uint32_t layer = 0; layer < w.n_layers; layer++) {
        if (g_debug) {
            printf("[ForwardToken] Layer %u: Attention...\n", layer);
        }
        AttentionLayer(layer, pos);
        if (g_debug) {
            printf("[ForwardToken] Layer %u: FFN...\n", layer);
        }
        FFNLayer(layer);
        
        // DEBUG: Check for NaN after each layer
        if (g_debug) {
            bool layer_has_nan = false;
            for (uint32_t i = 0; i < w.hidden_dim && i < 10; i++) {
                if (std::isnan(hidden_states_[i]) || std::isinf(hidden_states_[i])) {
                    layer_has_nan = true;
                    break;
                }
            }
            if (layer_has_nan) {
                printf("[ForwardToken] Layer %u: WARNING - NaN/Inf detected in hidden_states!\n", layer);
            }
            
            printf("[ForwardToken] Layer %u complete\n", layer);
        }
    }
    
    // Final RMSNorm
    Kernel_RMSNorm(hidden_states_, w.output_norm, w.hidden_dim, 1e-6f);
    
    // DEBUG: Check hidden_states before LM head (only in debug mode)
    if (g_debug) {
        fprintf(stderr, "[LM_HEAD] hidden_states first 5: ");
        for (int i = 0; i < 5 && i < w.hidden_dim; i++) {
            fprintf(stderr, "%.4f ", hidden_states_[i]);
        }
        fprintf(stderr, "\n");
        bool hs_has_nan = false;
        for (uint32_t i = 0; i < w.hidden_dim; i++) {
            if (std::isnan(hidden_states_[i]) || std::isinf(hidden_states_[i])) {
                hs_has_nan = true;
                break;
            }
        }
        fprintf(stderr, "[LM_HEAD] hidden_states has NaN/Inf: %s\n", hs_has_nan ? "YES" : "NO");
    }
    
    // LM head projection
    if (w.use_quantized && w.q_lm_head.data) {
        if (g_debug) fprintf(stderr, "[LM_HEAD] Using quantized LM head, quant_type=%d\n", w.q_lm_head.quant_type);
        // Use quantized LM head based on quant_type
        if (w.q_lm_head.quant_type == 3) {  // Q4_0
            QuantizedMatVecMul_Q4_0(w.q_lm_head, hidden_states_, output_logits, w.vocab_size, w.hidden_dim);
        } else if (w.q_lm_head.quant_type == 2) {  // Q6_K
            QuantizedMatVecMul_Q6_K(w.q_lm_head, hidden_states_, output_logits, w.vocab_size, w.hidden_dim);
        } else if (w.q_lm_head.quant_type == 1) {  // Q3_K
            QuantizedMatVecMul_Q3_K_S(w.q_lm_head, hidden_states_, output_logits, w.vocab_size, w.hidden_dim);
        } else {
            fprintf(stderr, "[ForwardToken] WARNING: Unsupported lm_head quant_type %d\n", w.q_lm_head.quant_type);
            // Fallback: generate placeholder logits
            for (uint32_t i = 0; i < w.vocab_size; i++) {
                output_logits[i] = (float)(rand() % 1000) / 1000.0f - 0.5f;
            }
        }
    } else if (w.lm_head) {
        // Use float LM head
        Kernel_MatMul(hidden_states_, w.lm_head, output_logits, 1, w.vocab_size, w.hidden_dim);
    } else {
        // Fallback: generate placeholder logits (for testing)
        for (uint32_t i = 0; i < w.vocab_size; i++) {
            output_logits[i] = (float)(rand() % 1000) / 1000.0f - 0.5f;
        }
    }
    
    return true;
}

// =============================================================================
// Model Weights Loader
// =============================================================================
bool MapGGUFToModelWeights(void* gguf_handle, ModelWeights& out_weights) {
    // TODO: Implement GGUF tensor mapping
    // This would parse the GGUF file and set up the weight pointers
    // For now: return false to indicate not implemented
    (void)gguf_handle;
    (void)out_weights;
    return false;
}

} // namespace Sovereign
