#pragma once

#include "../../core/common.hpp"

namespace rawrxd::inference::kernels {

// Quantized GEMM configuration
struct QuantizedGEMMConfig {
    enum class Type {
        INT8,       // 8-bit integer
        INT4,       // 4-bit integer
        FP8_E4M3,   // FP8 E4M3 format
        FP8_E5M2,   // FP8 E5M2 format
        NF4         // Normal Float 4 (QLoRA)
    };

    Type type = Type::INT8;
    bool symmetric = true;      // Symmetric quantization
    bool per_channel = false;   // Per-channel vs per-tensor
    int group_size = 128;       // Group size for grouping
};

// Quantized GEMM kernel
class QuantizedGEMM {
public:
    explicit QuantizedGEMM(const QuantizedGEMMConfig& config);

    // C = A @ B^T + bias
    // A: [M, K] float
    // B: [N, K] quantized
    // C: [M, N] float
    Tensor forward(const Tensor& A,
                   const Tensor& B_quantized,
                   const Tensor& scales,
                   const std::optional<Tensor>& bias = std::nullopt);

    // With zero points (asymmetric quantization)
    Tensor forwardAsymmetric(const Tensor& A,
                              const Tensor& B_quantized,
                              const Tensor& scales,
                              const Tensor& zero_points);

    // Batch GEMM
    Tensor batchForward(const std::vector<Tensor>& A_batch,
                        const Tensor& B_quantized,
                        const Tensor& scales);

    // Dequantize B for inspection
    Tensor dequantize(const Tensor& B_quantized,
                      const Tensor& scales,
                      const std::optional<Tensor>& zero_points = std::nullopt);

private:
    QuantizedGEMMConfig config_;

    // Kernel implementations
    void gemm_int8(const float* A, const int8_t* B, float* C,
                   int M, int N, int K,
                   const float* scales);

    void gemm_int4(const float* A, const uint8_t* B, float* C,
                   int M, int N, int K,
                   const float* scales);

    void gemm_fp8(const float* A, const uint8_t* B, float* C,
                  int M, int N, int K,
                  const float* scales);

    // Tiling for cache efficiency
    void tiledGEMM(const float* A, const void* B, float* C,
                   int M, int N, int K,
                   const float* scales);
};

// Weight-only quantization (for LLM inference)
class WeightOnlyQuantizedGEMM : public QuantizedGEMM {
public:
    explicit WeightOnlyQuantizedGEMM(const QuantizedGEMMConfig& config);

    // Optimized for weight-only quantization (activations in FP16)
    Tensor forwardActivationsFP16(const Tensor& A_fp16,
                                   const Tensor& B_quantized,
                                   const Tensor& scales);

    // Dequantize on-the-fly during GEMM
    Tensor forwardOnTheFlyDequant(const Tensor& A,
                                   const Tensor& B_quantized,
                                   const Tensor& scales);

    // Mixed-precision GEMM
    Tensor forwardMixedPrecision(const Tensor& A,
                                  const Tensor& B_quantized,
                                  const Tensor& scales,
                                  bool use_fp16_accum);
};

// GPTQ-style quantization (group-wise)
class GPTQGEMM : public QuantizedGEMM {
public:
    GPTQGEMM(int group_size = 128, bool use_act_order = false);

    // GPTQ uses group-wise quantization with activation reordering
    Tensor forwardGPTQ(const Tensor& A,
                        const Tensor& B_quantized,
                        const Tensor& scales,
                        const Tensor& g_idx,      // Group indices
                        const std::optional<Tensor>& bias = std::nullopt);

    // With fused dequantization
    Tensor forwardFused(const Tensor& A,
                        const Tensor& B_quantized,
                        const Tensor& scales,
                        const Tensor& g_idx);

private:
    int group_size_;
    bool use_act_order_;
};

// AWQ-style quantization (activation-aware)
class AWQGEMM : public QuantizedGEMM {
public:
    AWQGEMM(int group_size = 128);

    // AWQ applies per-channel scaling based on activation distribution
    Tensor forwardAWQ(const Tensor& A,
                       const Tensor& B_quantized,
                       const Tensor& scales,
                       const Tensor& awq_scales);  // Additional AWQ scales

private:
    int group_size_;
};

// Marlin kernel (optimized 4-bit inference)
class MarlinGEMM {
public:
    // Marlin uses specialized 4-bit packing and kernel
    static Tensor forward(const Tensor& A,
                          const Tensor& B_marlin_packed,
                          const Tensor& scales);

    // Convert to Marlin format
    static Tensor packToMarlin(const Tensor& B_quantized);

    // Check if Marlin is available
    static bool isAvailable();
};

// Quantization utilities
namespace quant_utils {

// Quantize float to int8
std::pair<Tensor, Tensor> quantizeInt8(const Tensor& weights, bool per_channel = false);

// Quantize float to int4 (packed)
std::pair<Tensor, Tensor> quantizeInt4(const Tensor& weights, int group_size = 128);

// Quantize to FP8
std::pair<Tensor, Tensor> quantizeFP8(const Tensor& weights,
                                       QuantizedGEMMConfig::Type fp8_type);

// Dequantize
Tensor dequantize(const Tensor& quantized,
                  const Tensor& scales,
                  const std::optional<Tensor>& zero_points = std::nullopt);

// Pack int4 (2 values per byte)
Tensor packInt4(const Tensor& weights_int4);

// Unpack int4
Tensor unpackInt4(const Tensor& packed_weights, int num_elements);

} // namespace quant_utils

} // namespace rawrxd::inference::kernels
