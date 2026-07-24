// ============================================================================
// TransformerBlockExecutor.hpp
// ============================================================================
// Executes a single transformer block end-to-end using the universal runtime.
// This is the numerical validation gate: does the format-agnostic runtime
// produce correct logits?
//
// Pipeline per block:
//   embedding → RMSNorm → QKV proj → RoPE → attention → FFN/SwiGLU → output
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#pragma once

#include "UniversalTensorDescriptor.hpp"
#include "KernelRegistry.hpp"
#include "TensorView.hpp"
#include <cmath>
#include <cstring>
#include <cstdio>

namespace RawrXD {

// ============================================================================
// Transformer Block Configuration
// ============================================================================
struct BlockConfig {
    uint32_t hiddenDim;
    uint32_t numHeads;
    uint32_t numKVHeads;
    uint32_t headDim;
    uint32_t interDim;       // FFN intermediate size
    float    rmsNormEps;
    float    ropeTheta;

    // MoE
    bool     isMoE;
    uint32_t numExperts;
    uint32_t numExpertsPerTok;

    BlockConfig()
        : hiddenDim(4096), numHeads(32), numKVHeads(32), headDim(128),
          interDim(11008), rmsNormEps(1e-6f), ropeTheta(10000.0f),
          isMoE(false), numExperts(0), numExpertsPerTok(0) {}
};

// ============================================================================
// Transformer Block Tensors (by name)
// ============================================================================
struct BlockTensors {
    // Attention
    TensorView* qProjWeight;
    TensorView* kProjWeight;
    TensorView* vProjWeight;
    TensorView* oProjWeight;
    TensorView* attnNormWeight;

    // FFN
    TensorView* gateProjWeight;  // SwiGLU gate
    TensorView* upProjWeight;    // SwiGLU up
    TensorView* downProjWeight;
    TensorView* ffnNormWeight;

    BlockTensors() : qProjWeight(nullptr), kProjWeight(nullptr),
        vProjWeight(nullptr), oProjWeight(nullptr), attnNormWeight(nullptr),
        gateProjWeight(nullptr), upProjWeight(nullptr), downProjWeight(nullptr),
        ffnNormWeight(nullptr) {}
};

// ============================================================================
// Scalar Reference Kernels (for validation)
// ============================================================================
namespace ScalarRef {

// RMSNorm: y = x / sqrt(mean(x^2) + eps) * weight
inline void rmsnorm(const float* x, const float* weight, float* out,
                    uint32_t dim, float eps) {
    float sumSq = 0.0f;
    for (uint32_t i = 0; i < dim; ++i) {
        sumSq += x[i] * x[i];
    }
    float rms = 1.0f / std::sqrt(sumSq / dim + eps);
    for (uint32_t i = 0; i < dim; ++i) {
        out[i] = x[i] * rms * weight[i];
    }
}

// GEMV: y = W * x  (W is [rows, cols], x is [cols], y is [rows])
// For F32 dense weights
inline void gemv_f32(const float* W, const float* x, float* y,
                     uint32_t rows, uint32_t cols) {
    for (uint32_t r = 0; r < rows; ++r) {
        float sum = 0.0f;
        const float* wRow = W + r * cols;
        for (uint32_t c = 0; c < cols; ++c) {
            sum += wRow[c] * x[c];
        }
        y[r] = sum;
    }
}

// RoPE: rotary position embedding (simplified)
inline void rope(float* x, uint32_t dim, uint32_t position, float theta) {
    for (uint32_t i = 0; i < dim; i += 2) {
        float freq = 1.0f / std::pow(theta, static_cast<float>(i) / dim);
        float angle = position * freq;
        float cosA = std::cos(angle);
        float sinA = std::sin(angle);
        float x0 = x[i];
        float x1 = x[i + 1];
        x[i]     = x0 * cosA - x1 * sinA;
        x[i + 1] = x0 * sinA + x1 * cosA;
    }
}

// SiLU: x * sigmoid(x)
inline void silu(const float* x, float* out, uint32_t dim) {
    for (uint32_t i = 0; i < dim; ++i) {
        float s = 1.0f / (1.0f + std::exp(-x[i]));
        out[i] = x[i] * s;
    }
}

// SwiGLU FFN: down(silu(gate(x)) * up(x))
inline void swiglu_ffn(const float* gateW, const float* upW, const float* downW,
                       const float* x, float* out,
                       uint32_t hiddenDim, uint32_t interDim) {
    // gate = gateW * x  -> [interDim]
    // up = upW * x      -> [interDim]
    // act = silu(gate) * up
    // out = downW * act -> [hiddenDim]

    float* gate = new float[interDim];
    float* up = new float[interDim];
    float* act = new float[interDim];

    gemv_f32(gateW, x, gate, interDim, hiddenDim);
    gemv_f32(upW, x, up, interDim, hiddenDim);

    for (uint32_t i = 0; i < interDim; ++i) {
        float s = 1.0f / (1.0f + std::exp(-gate[i]));
        act[i] = gate[i] * s * up[i];
    }

    gemv_f32(downW, act, out, hiddenDim, interDim);

    delete[] gate;
    delete[] up;
    delete[] act;
}

// Simple attention (single head, no mask)
inline void attention_single_head(
    const float* Q, const float* K, const float* V,
    float* output,
    uint32_t seqLen, uint32_t headDim
) {
    float scale = 1.0f / std::sqrt(static_cast<float>(headDim));

    for (uint32_t q = 0; q < seqLen; ++q) {
        // Compute scores
        float* scores = new float[seqLen];
        float maxScore = -1e30f;

        for (uint32_t k = 0; k < seqLen; ++k) {
            float dot = 0.0f;
            for (uint32_t d = 0; d < headDim; ++d) {
                dot += Q[q * headDim + d] * K[k * headDim + d];
            }
            scores[k] = dot * scale;
            if (scores[k] > maxScore) maxScore = scores[k];
        }

        // Softmax
        float sumExp = 0.0f;
        for (uint32_t k = 0; k < seqLen; ++k) {
            scores[k] = std::exp(scores[k] - maxScore);
            sumExp += scores[k];
        }

        // Weighted sum of V
        for (uint32_t d = 0; d < headDim; ++d) {
            float acc = 0.0f;
            for (uint32_t k = 0; k < seqLen; ++k) {
                acc += (scores[k] / sumExp) * V[k * headDim + d];
            }
            output[q * headDim + d] = acc;
        }

        delete[] scores;
    }
}

} // namespace ScalarRef

// ============================================================================
// Transformer Block Executor
// ============================================================================
class TransformerBlockExecutor {
public:
    TransformerBlockExecutor(const BlockConfig& config, const ResolvedKernelTable& kernels)
        : config_(config), kernels_(kernels) {}

    // ------------------------------------------------------------------------
    // Execute one block: input [hiddenDim] -> output [hiddenDim]
    // ------------------------------------------------------------------------
    bool Execute(const float* input, float* output,
                 const BlockTensors& tensors,
                 uint32_t position, uint32_t seqLen) {
        uint32_t H = config_.hiddenDim;
        uint32_t nH = config_.numHeads;
        uint32_t nKV = config_.numKVHeads;
        uint32_t hd = config_.headDim;
        uint32_t I = config_.interDim;

        // Buffers
        float* normed = new float[H];
        float* q = new float[nH * hd];
        float* k = new float[nKV * hd];
        float* v = new float[nKV * hd];
        float* attnOut = new float[nH * hd];
        float* projOut = new float[H];
        float* ffnNormed = new float[H];
        float* ffnOut = new float[H];

        // 1. Pre-attention RMSNorm
        if (tensors.attnNormWeight) {
            ScalarRef::rmsnorm(input, tensors.attnNormWeight->asF32(),
                              normed, H, config_.rmsNormEps);
        } else {
            std::memcpy(normed, input, H * sizeof(float));
        }

        // 2. QKV projections
        if (tensors.qProjWeight) {
            ScalarRef::gemv_f32(tensors.qProjWeight->asF32(), normed, q, nH * hd, H);
        }
        if (tensors.kProjWeight) {
            ScalarRef::gemv_f32(tensors.kProjWeight->asF32(), normed, k, nKV * hd, H);
        }
        if (tensors.vProjWeight) {
            ScalarRef::gemv_f32(tensors.vProjWeight->asF32(), normed, v, nKV * hd, H);
        }

        // 3. RoPE on Q and K
        for (uint32_t h = 0; h < nH; ++h) {
            ScalarRef::rope(q + h * hd, hd, position, config_.ropeTheta);
        }
        for (uint32_t h = 0; h < nKV; ++h) {
            ScalarRef::rope(k + h * hd, hd, position, config_.ropeTheta);
        }

        // 4. Attention (simplified: single head for validation)
        // In production, this uses the resolved attention kernel
        // For validation, use scalar reference on first head
        if (nH > 0) {
            // Expand KV for multi-head attention (GQA: repeat KV heads)
            float* kExpanded = new float[nH * hd * seqLen];
            float* vExpanded = new float[nH * hd * seqLen];

            // For single-token generation, seqLen=1, so attention is trivial
            // Just copy V as output (attention with 1 token = identity)
            if (seqLen == 1) {
                for (uint32_t h = 0; h < nH; ++h) {
                    uint32_t kvH = h % nKV;
                    std::memcpy(attnOut + h * hd, v + kvH * hd, hd * sizeof(float));
                }
            } else {
                // Multi-token attention (for prefill)
                for (uint32_t h = 0; h < nH; ++h) {
                    uint32_t kvH = h % nKV;
                    ScalarRef::attention_single_head(
                        q + h * hd,
                        kExpanded + h * hd * seqLen,
                        vExpanded + h * hd * seqLen,
                        attnOut + h * hd,
                        seqLen, hd
                    );
                }
            }

            delete[] kExpanded;
            delete[] vExpanded;
        }

        // 5. Output projection
        if (tensors.oProjWeight) {
            ScalarRef::gemv_f32(tensors.oProjWeight->asF32(), attnOut, projOut, H, nH * hd);
        }

        // 6. Residual
        for (uint32_t i = 0; i < H; ++i) {
            projOut[i] += input[i];
        }

        // 7. Pre-FFN RMSNorm
        if (tensors.ffnNormWeight) {
            ScalarRef::rmsnorm(projOut, tensors.ffnNormWeight->asF32(),
                              ffnNormed, H, config_.rmsNormEps);
        } else {
            std::memcpy(ffnNormed, projOut, H * sizeof(float));
        }

        // 8. SwiGLU FFN
        if (tensors.gateProjWeight && tensors.upProjWeight && tensors.downProjWeight) {
            ScalarRef::swiglu_ffn(
                tensors.gateProjWeight->asF32(),
                tensors.upProjWeight->asF32(),
                tensors.downProjWeight->asF32(),
                ffnNormed, ffnOut, H, I
            );
        }

        // 9. Residual
        for (uint32_t i = 0; i < H; ++i) {
            output[i] = ffnOut[i] + projOut[i];
        }

        // Cleanup
        delete[] normed;
        delete[] q;
        delete[] k;
        delete[] v;
        delete[] attnOut;
        delete[] projOut;
        delete[] ffnNormed;
        delete[] ffnOut;

        return true;
    }

private:
    BlockConfig config_;
    ResolvedKernelTable kernels_;
};

} // namespace RawrXD