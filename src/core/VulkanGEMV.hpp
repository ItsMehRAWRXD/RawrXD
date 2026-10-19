#pragma once
#include <vulkan/vulkan.h>
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>

namespace Deep2Rom::Compute {

    class VulkanComputeEngine;

    // GEMV operation: y = W @ x
    // Supports FP32 and Q2_K quantized weights on GPU
    class VulkanGEMV {
    public:
        enum class WeightType {
            F32,       // Full precision float32 weights
            Q2_K,      // 2-bit quantized weights (GGUF format)
        };

        VulkanGEMV(VulkanComputeEngine& engine);
        ~VulkanGEMV();

        // Initialize pipelines for the given shader paths
        bool init(const std::string& gemv_f32_spirv, const std::string& gemv_q2k_spirv);

        // Upload weight matrix to GPU
        // For F32: weights is row-major float array of size rows*cols
        // For Q2_K: weights is packed Q2_K data
        bool uploadWeights(WeightType type, uint32_t rows, uint32_t cols, const void* weightData);

        // Upload input vector to GPU
        bool uploadInput(uint32_t cols, const float* inputData);

        // Run GEMV: y = W @ x
        // output must have space for 'rows' floats
        bool run(WeightType type, uint32_t rows, uint32_t cols, float* output);

        // Get GPU buffer handles (for integration with existing buffers)
        VkBuffer weightBuffer() const { return m_weightBuf.buffer; }
        VkBuffer inputBuffer() const { return m_inputBuf.buffer; }
        VkBuffer outputBuffer() const { return m_outputBuf.buffer; }

    private:
        VulkanComputeEngine* m_engine;

        // Weight type and dimensions
        WeightType m_weightType{ WeightType::F32 };
        uint32_t m_rows{ 0 };
        uint32_t m_cols{ 0 };

        // GPU buffers
        VulkanBuffer m_weightBuf;
        VulkanBuffer m_inputBuf;
        VulkanBuffer m_outputBuf;

        // Descriptor sets for each pipeline
        VkDescriptorSet m_descSetF32{ VK_NULL_HANDLE };
        VkDescriptorSet m_descSetQ2K{ VK_NULL_HANDLE };

        bool createDescriptorSet(ComputePipeline* pipeline, VkDescriptorSet& descSet,
                                 VkBuffer weightBuf, VkBuffer inputBuf, VkBuffer outputBuf);
        bool updateDescriptorSet(VkDescriptorSet descSet,
                                 VkBuffer weightBuf, VkBuffer inputBuf, VkBuffer outputBuf);
    };

} // namespace Deep2Rom::Compute
