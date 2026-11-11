/* K2LogitsClimb — Packed kernel logits projection for K2 architecture
 * Computes logits = W * x directly on Q6_K packed weights without FP32 warehouse.
 */
#pragma once

#include <vector>
#include <cstdint>
#include <cstddef>
#include <algorithm>
#include "rawr_gemm_avx512.h"
#include "K2Telemetry.hpp"
#include "K2VNNIKernel.cpp"

namespace rawrxd {
namespace deep2 {

class K2LogitsClimb {
public:
    bool vnni_available = false;
    bool use_vnni = false;

    void init(const void* weights, int vocab_size, int dim) {
        weights_ = static_cast<const rawrxd::gemm::block_q6_K*>(weights);
        vocab_size_ = vocab_size;
        dim_ = dim;
        blocks_per_row_ = (dim + 255) / 256;  // 256 weights per Q6_K block
        
        // Check VNNI availability
        const auto& features = rawrxd::gemm::get_cpu_features();
        vnni_available = features.has_avx512vnni;
        use_vnni = vnni_available;
    }

    std::vector<float> compute(const float* hidden) {
        std::vector<float> logits(vocab_size_, 0.0f);
        
        // For each vocab row, compute dot product with hidden
        for (int v = 0; v < vocab_size_; ++v) {
            float sum = 0.0f;
            const rawrxd::gemm::block_q6_K* row_weights = weights_ + v * blocks_per_row_;
            
            // Process each block in the row
            for (int b = 0; b < blocks_per_row_; ++b) {
                const rawrxd::gemm::block_q6_K* blk = row_weights + b;
                int block_start = b * 256;
                int block_end = std::min(block_start + 256, dim_);
                int block_len = block_end - block_start;
                
                // Increment telemetry for each block processed
                auto& tel = GetK2Telemetry();
                tel.q6k_q8k_dot_entry.fetch_add(1, std::memory_order_relaxed);
                
                if (use_vnni && block_len == 256) {
                    // VNNI path: quantize activations to Q8_K on-the-fly
                    rawrxd::gemm::block_q8_K q8_block;
                    quantize_activations_to_q8k(hidden + block_start, &q8_block, block_len);
                    sum += K2VNNIKernel::dot_q6k_q8k_vnni(blk, &q8_block);
                } else {
                    // Scalar fallback: dequantize Q6_K and compute dot product
                    sum += compute_block_scalar(blk, hidden + block_start, block_len);
                }
            }
            logits[v] = sum;
        }
        return logits;
    }

private:
    const rawrxd::gemm::block_q6_K* weights_ = nullptr;
    int vocab_size_ = 0;
    int dim_ = 0;
    int blocks_per_row_ = 1;

    float compute_block_scalar(const rawrxd::gemm::block_q6_K* blk, const float* hidden, int len) {
        float sum = 0.0f;
        float d = rawrxd::gemm::fp16_to_fp32(blk->d);
        
        for (int i = 0; i < len; ++i) {
            // Lower 4 bits: ql[i/2] nibble
            uint8_t ql = (blk->ql[i / 2] >> (4 * (i & 1))) & 0x0F;
            // Upper 2 bits: qh[i/4] bit pair
            uint8_t qh = (blk->qh[i / 4] >> (2 * (i & 3))) & 0x03;
            int raw6 = (int)(ql | (qh << 4));  // 0..63
            int w = raw6 - 32;                  // -32..31
            int8_t scale = blk->scales[i / 16];  // per-super-block scale
            sum += w * scale * hidden[i];
        }
        return sum * d;
    }

    // Quantize FP32 activations to Q8_K format for VNNI
    void quantize_activations_to_q8k(const float* src, rawrxd::gemm::block_q8_K* dst, int len) {
        // Find max absolute value for scaling
        float max_abs = 0.0f;
        for (int i = 0; i < len; ++i) {
            float abs_val = std::abs(src[i]);
            if (abs_val > max_abs) max_abs = abs_val;
        }
        
        float scale = (max_abs > 0.0f) ? (127.0f / max_abs) : 1.0f;
        
        for (int i = 0; i < len; ++i) {
            int v = (int)std::round(src[i] * scale);
            if (v < -127) v = -127;
            if (v > 127) v = 127;
            dst->qs[i] = static_cast<int8_t>(v);
        }
        
        // Set block sums (simplified: zero)
        for (int i = 0; i < 16; ++i) {
            dst->bsums[i] = 0;
        }
        
        // Set scale
        dst->d = 1.0f / scale;
    }
};

} // namespace deep2
} // namespace rawrxd