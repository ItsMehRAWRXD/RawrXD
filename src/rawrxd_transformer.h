#pragma once
#include <vector>
#ifdef RAWR_ENABLE_VULKAN
#include <vulkan/vulkan.h>
#else
// Standard Win32/CPU build - Vulkan handles not needed
#ifndef VK_NULL_HANDLE
#define VK_NULL_HANDLE 0
#endif
#endif
#include "rawrxd_model_loader.h"

class RawrXDTransformer {
public:
    struct Config {
        int dim;
        int hidden_dim;
        int n_layers;
        int n_heads;
        int n_kv_heads;
        int vocab_size;
        int n_ctx;      // Context length
        int seq_len;
        float rope_theta;
        float rms_norm_eps;
    };

    void Initialize(VkDevice device, VkPhysicalDevice physDevice, Config cfg, RawrXDModelLoader* loader);
    std::vector<float> Forward(const std::vector<uint32_t>& tokens, int start_pos);
    std::vector<float> ForwardBatch(const std::vector<uint32_t>& tokens, int start_pos);
    void InvalidateDecodeCarry();

    // -----------------------------------------------------------------------
    // Layer matmul primitives.
    //
    // Both functions resolve `weightName` through the model loader ONCE, then
    // compute. ExecuteLayerMatMul is the single-row form; ExecuteLayerMatMulBatch
    // is the T-row form and delegates to it so there is exactly one arithmetic
    // path (a bug in one is a bug in the other, never a divergence).
    //
    // Weight layout: the loader returns dequantised weights in (outDim, inDim)
    // row-major, i.e. W[j * inDim + k], matching MatrixMultiply_AVX512's B
    // operand. Output: out[j] = sum_{k < inDim} in[k] * W[j * inDim + k].
    //
    // Returns false (and leaves `out` untouched apart from what it wrote) when
    // the tensor is missing or a dimension is non-positive. Callers must treat
    // false as a hard failure, not a soft one.
    // -----------------------------------------------------------------------
    bool ExecuteLayerMatMul(const std::string& weightName, const float* in, float* out,
                            int inDim, int outDim, uint32_t layer);

    bool ExecuteLayerMatMulBatch(const std::string& weightName, const float* in, float* out,
                                 int inDim, int outDim, int T, uint32_t layer);

private:
    Config config;
    VkDevice device;
    RawrXDModelLoader* loader;
    
    // KV Cache
    std::vector<float> kv_cache_k;
    std::vector<float> kv_cache_v;
    
    // B015 decode carry state
    bool m_b015DecodeBypass = false;
    bool m_b015CarryWarm = false;
};

