#pragma once
#include <vulkan/vulkan.h>
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>

#include "VulkanComputeEngine.hpp"

// ggml_type and the validated row-stride trait.
#include "QuantBlockTraits.hpp"

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

        // Upload a row range of a weight matrix to the GPU.
        //
        // The device buffer receives `rowCount` rows beginning at `rowOffset`
        // in the source tensor. Rows are laid out with the engine's per-row
        // stride, ceil(cols / elementsPerBlock) * blockBytes, which is what
        // the GEMV shader and the CPU reference kernels address rows by. The
        // previous size calculation used ceil(rows*cols/256) * 84, which
        // under-allocates whenever the column count is not a multiple of 256
        // and disagrees with the kernel's row addressing.
        //
        // `weightData` points at the first byte of row `rowOffset`. Its rows
        // are packed `sourceRowStride` bytes apart; pass 0 when the source
        // already uses the device stride, which is the single contiguous copy
        // case. A different source stride is repacked row by row.
        //
        // Only the types this class has a shader pipeline for are accepted:
        // F32 and Q2_K.
        bool uploadWeights(ggml_type type,
                           uint32_t totalRows,
                           uint32_t cols,
                           uint32_t rowOffset,
                           uint32_t rowCount,
                           const uint8_t* weightData,
                           uint64_t sourceRowStride = 0);

        // Upload input vector to GPU
        bool uploadInput(uint32_t cols, const float* inputData);

        // Run GEMV: y = W @ x
        // output must have space for 'rows' floats
        bool run(WeightType type, uint32_t rows, uint32_t cols, float* output);

        // Rows currently resident in the weight buffer, and the first source
        // row they came from.
        uint32_t uploadedRows() const { return m_rowCount; }
        uint32_t uploadedRowOffset() const { return m_rowOffset; }

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

        // Row range currently resident in m_weightBuf.
        uint32_t m_rowOffset{ 0 };
        uint32_t m_rowCount{ 0 };


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
