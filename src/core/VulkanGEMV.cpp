#include "VulkanGEMV.hpp"
#include "VulkanComputeEngine.hpp"
#include <iostream>
#include <cstring>

namespace Deep2Rom::Compute {

    VulkanGEMV::VulkanGEMV(VulkanComputeEngine& engine)
        : m_engine(&engine) {}

    VulkanGEMV::~VulkanGEMV() {
        if (m_engine->device() != VK_NULL_HANDLE) {
            if (m_weightBuf.buffer != VK_NULL_HANDLE) {
                vkDestroyBuffer(m_engine->device(), m_weightBuf.buffer, nullptr);
                vkFreeMemory(m_engine->device(), m_weightBuf.memory, nullptr);
            }
            if (m_inputBuf.buffer != VK_NULL_HANDLE) {
                vkDestroyBuffer(m_engine->device(), m_inputBuf.buffer, nullptr);
                vkFreeMemory(m_engine->device(), m_inputBuf.memory, nullptr);
            }
            if (m_outputBuf.buffer != VK_NULL_HANDLE) {
                vkDestroyBuffer(m_engine->device(), m_outputBuf.buffer, nullptr);
                vkFreeMemory(m_engine->device(), m_outputBuf.memory, nullptr);
            }
            // vkFreeDescriptorSets takes a descriptor pool, not a device.
            // The previous code passed the device here, and passed the
            // command pool where the descriptor pool belongs.
            if (m_descSetF32 != VK_NULL_HANDLE && m_engine->descriptorPool() != VK_NULL_HANDLE) {
                vkFreeDescriptorSets(m_engine->device(), m_engine->descriptorPool(), 1, &m_descSetF32);
            }
            if (m_descSetQ2K != VK_NULL_HANDLE && m_engine->descriptorPool() != VK_NULL_HANDLE) {
                vkFreeDescriptorSets(m_engine->device(), m_engine->descriptorPool(), 1, &m_descSetQ2K);
            }
        }
    }

    bool VulkanGEMV::init(const std::string& gemv_f32_spirv, const std::string& gemv_q2k_spirv) {
        if (!m_engine->createComputePipeline("gemv_f32", gemv_f32_spirv, 8, 3)) {
            std::cerr << "[VulkanGEMV] Failed to create FP32 pipeline\n";
            return false;
        }
        // Q2_K pipeline is optional - we can dequantize on CPU instead
        if (!m_engine->createComputePipeline("gemv_q2k", gemv_q2k_spirv, 16, 3)) {
            std::cerr << "[VulkanGEMV] Q2_K pipeline not available, will dequantize Q2_K on CPU\n";
        }
        return true;
    }

    bool VulkanGEMV::uploadWeights(ggml_type type,
                                   uint32_t totalRows,
                                   uint32_t cols,
                                   uint32_t rowOffset,
                                   uint32_t rowCount,
                                   const uint8_t* weightData,
                                   uint64_t sourceRowStride) {
        // Only F32 and Q2_K have a shader pipeline in this class.
        WeightType weightType;
        switch (type) {
            case GGML_TYPE_F32: weightType = WeightType::F32; break;
            case GGML_TYPE_Q2_K: weightType = WeightType::Q2_K; break;
            default:
                std::cerr << "[VulkanGEMV] Unsupported weight type id " << static_cast<int>(type)
                          << "; this class only has F32 and Q2_K pipelines\n";
                return false;
        }

        if (!weightData || rowCount == 0 || totalRows == 0 ||
            rowOffset > totalRows || rowCount > totalRows - rowOffset) {
            std::cerr << "[VulkanGEMV] Invalid upload row range: offset=" << rowOffset
                      << " count=" << rowCount << " totalRows=" << totalRows << "\n";
            return false;
        }

        // Task 1: the size comes from the validated trait. The old expression
        // ceil(rows*cols/256)*84 disagrees with the kernel's row addressing
        // (weights + r * ceil(cols/256) * blockBytes) whenever the column
        // count is not a multiple of 256, and it under-allocates the buffer.
        const uint64_t stride = deep2::Quant::RowStride(type, cols);
        if (stride == 0) {
            std::cerr << "[VulkanGEMV] No block layout for type id " << static_cast<int>(type) << "\n";
            return false;
        }
        const VkDeviceSize uploadSizeBytes = static_cast<VkDeviceSize>(rowCount) * stride;

        m_weightType = weightType;
        m_rows = rowCount;
        m_cols = cols;
        m_rowOffset = rowOffset;
        m_rowCount = rowCount;

        // Task 2: point at the first byte of the requested row.
        // sourceRowStride == 0 means the source already uses the device
        // stride, so the range is one contiguous block and a single copy
        // region suffices. A different source stride means the rows are
        // packed differently and have to be repacked one by one.
        const uint64_t srcStride = (sourceRowStride == 0) ? stride : sourceRowStride;
        const uint8_t* segmentedSourcePtr = weightData + (static_cast<uint64_t>(rowOffset) * srcStride);
        const bool contiguous = (srcStride == stride);

        if (!m_engine->createBuffer(m_weightBuf, uploadSizeBytes,
                                    VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                                    false)) {
            std::cerr << "[VulkanGEMV] Failed to create weight buffer\n";
            return false;
        }

        VulkanBuffer stagingBuf;
        if (!m_engine->createBuffer(stagingBuf, uploadSizeBytes,
                                    VK_BUFFER_USAGE_TRANSFER_SRC_BIT, true)) {
            std::cerr << "[VulkanGEMV] Failed to create staging buffer\n";
            return false;
        }

        if (contiguous) {
            if (!m_engine->uploadBuffer(stagingBuf, segmentedSourcePtr, uploadSizeBytes)) {
                std::cerr << "[VulkanGEMV] Failed to upload weight data\n";
                return false;
            }
        } else {
            // Repack the rows into the staging buffer so the device sees the
            // per-row stride the kernels expect.
            std::vector<uint8_t> packed(static_cast<size_t>(uploadSizeBytes));
            for (uint32_t r = 0; r < rowCount; ++r) {
                const uint8_t* src = segmentedSourcePtr + (static_cast<uint64_t>(r) * srcStride);
                std::memcpy(packed.data() + (static_cast<size_t>(r) * stride), src,
                            static_cast<size_t>(stride));
            }
            if (!m_engine->uploadBuffer(stagingBuf, packed.data(), uploadSizeBytes)) {
                std::cerr << "[VulkanGEMV] Failed to upload repacked weight data\n";
                return false;
            }
        }

        VkCommandBuffer cmd;
        if (!m_engine->beginCommandBuffer(cmd)) {
            std::cerr << "[VulkanGEMV] Failed to begin command buffer\n";
            return false;
        }

        VkBufferCopy region{ 0, 0, uploadSizeBytes };
        vkCmdCopyBuffer(cmd, stagingBuf.buffer, m_weightBuf.buffer, 1, &region);

        VkBufferMemoryBarrier barrier{ VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER };
        barrier.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        barrier.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
        barrier.buffer = m_weightBuf.buffer;
        barrier.size = uploadSizeBytes;
        vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                             0, 0, nullptr, 1, &barrier, 0, nullptr);

        if (!m_engine->submitAndWait(cmd)) {
            std::cerr << "[VulkanGEMV] Failed to submit weight upload\n";
            return false;
        }

        if (stagingBuf.buffer != VK_NULL_HANDLE) {
            vkDestroyBuffer(m_engine->device(), stagingBuf.buffer, nullptr);
            vkFreeMemory(m_engine->device(), stagingBuf.memory, nullptr);
        }

        return true;
    }

    bool VulkanGEMV::uploadInput(uint32_t cols, const float* inputData) {
        m_cols = cols;
        VkDeviceSize inputSize = static_cast<VkDeviceSize>(cols) * sizeof(float);

        if (!m_engine->createBuffer(m_inputBuf, inputSize,
                                    VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                                    false)) {
            std::cerr << "[VulkanGEMV] Failed to create input buffer\n";
            return false;
        }

        VulkanBuffer stagingBuf;
        if (!m_engine->createBuffer(stagingBuf, inputSize,
                                    VK_BUFFER_USAGE_TRANSFER_SRC_BIT, true)) {
            std::cerr << "[VulkanGEMV] Failed to create input staging buffer\n";
            return false;
        }

        if (!m_engine->uploadBuffer(stagingBuf, inputData, inputSize)) {
            std::cerr << "[VulkanGEMV] Failed to upload input data\n";
            return false;
        }

        VkCommandBuffer cmd;
        if (!m_engine->beginCommandBuffer(cmd)) {
            std::cerr << "[VulkanGEMV] Failed to begin command buffer\n";
            return false;
        }

        VkBufferCopy region{ 0, 0, inputSize };
        vkCmdCopyBuffer(cmd, stagingBuf.buffer, m_inputBuf.buffer, 1, &region);

        VkBufferMemoryBarrier barrier{ VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER };
        barrier.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        barrier.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
        barrier.buffer = m_inputBuf.buffer;
        barrier.size = inputSize;
        vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                             0, 0, nullptr, 1, &barrier, 0, nullptr);

        if (!m_engine->submitAndWait(cmd)) {
            std::cerr << "[VulkanGEMV] Failed to submit input upload\n";
            return false;
        }

        if (stagingBuf.buffer != VK_NULL_HANDLE) {
            vkDestroyBuffer(m_engine->device(), stagingBuf.buffer, nullptr);
            vkFreeMemory(m_engine->device(), stagingBuf.memory, nullptr);
        }

        return true;
    }

    bool VulkanGEMV::run(WeightType type, uint32_t rows, uint32_t cols, float* output) {
        m_weightType = type;

        // The weight buffer holds only the row range that was uploaded, so the
        // dispatch and the output buffer are sized for that range. A caller
        // that uploaded a split of a larger tensor gets the split's result.
        const uint32_t residentRows = (m_rowCount != 0) ? m_rowCount : rows;
        if (cols == 0) cols = m_cols;
        m_rows = residentRows;
        m_cols = cols;

        VkDeviceSize outputSize = static_cast<VkDeviceSize>(residentRows) * sizeof(float);

        if (!m_engine->createBuffer(m_outputBuf, outputSize,
                                    VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                                    true)) {
            std::cerr << "[VulkanGEMV] Failed to create output buffer\n";
            return false;
        }

        ComputePipeline* pipeline = nullptr;
        VkDescriptorSet& descSet = (type == WeightType::F32) ? m_descSetF32 : m_descSetQ2K;
        if (type == WeightType::F32) {
            pipeline = m_engine->getPipeline("gemv_f32");
        } else {
            pipeline = m_engine->getPipeline("gemv_q2k");
        }

        if (!pipeline || !pipeline->pipeline) {
            std::cerr << "[VulkanGEMV] Pipeline not found for type "
                      << (type == WeightType::F32 ? "F32" : "Q2_K") << "\n";
            return false;
        }

        // Create/update descriptor set
        if (descSet == VK_NULL_HANDLE) {
            if (!m_engine->createDescriptorSet(pipeline, descSet, m_weightBuf.buffer, m_inputBuf.buffer, m_outputBuf.buffer)) {
                std::cerr << "[VulkanGEMV] Failed to create descriptor set\n";
                return false;
            }
        } else {
            m_engine->updateDescriptorSet(descSet, m_weightBuf.buffer, m_inputBuf.buffer, m_outputBuf.buffer);
        }

        VkCommandBuffer cmd;
        if (!m_engine->beginCommandBuffer(cmd)) {
            std::cerr << "[VulkanGEMV] Failed to begin command buffer\n";
            return false;
        }

        vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline->pipeline);
        vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline->layout, 0, 1, &descSet, 0, nullptr);

        // Push constants
        if (type == WeightType::F32) {
            uint32_t pc[2] = { residentRows, cols };
            vkCmdPushConstants(cmd, pipeline->layout, VK_SHADER_STAGE_COMPUTE_BIT, 0, 8, pc);
        } else {
            uint32_t pc[4] = { residentRows, cols, 256, 0 };
            vkCmdPushConstants(cmd, pipeline->layout, VK_SHADER_STAGE_COMPUTE_BIT, 0, 16, pc);
        }

        uint32_t groupCount = (residentRows + pipeline->localSizeX - 1) / pipeline->localSizeX;
        vkCmdDispatch(cmd, groupCount, 1, 1);

        // Read back output
        VkBufferMemoryBarrier barrier{ VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER };
        barrier.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
        barrier.dstAccessMask = VK_ACCESS_HOST_READ_BIT;
        barrier.buffer = m_outputBuf.buffer;
        barrier.size = outputSize;
        vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_HOST_BIT,
                             0, 0, nullptr, 1, &barrier, 0, nullptr);

        if (!m_engine->submitAndWait(cmd)) {
            std::cerr << "[VulkanGEMV] Failed to submit GEMV dispatch\n";
            return false;
        }

        // Map output buffer and read results
        void* mapped;
        if (vkMapMemory(m_engine->device(), m_outputBuf.memory, 0, outputSize, 0, &mapped) != VK_SUCCESS) {
            std::cerr << "[VulkanGEMV] Failed to map output buffer\n";
            return false;
        }
        std::memcpy(output, mapped, static_cast<size_t>(outputSize));
        vkUnmapMemory(m_engine->device(), m_outputBuf.memory);

        return true;
    }

} // namespace Deep2Rom::Compute
