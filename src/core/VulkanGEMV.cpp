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
            if (m_descSetF32 != VK_NULL_HANDLE) {
                vkFreeDescriptorSets(m_engine->device(), m_engine->commandPool() ? m_engine->device() : VK_NULL_HANDLE, 1, &m_descSetF32);
            }
            if (m_descSetQ2K != VK_NULL_HANDLE) {
                vkFreeDescriptorSets(m_engine->device(), m_engine->device() ? m_engine->device() : VK_NULL_HANDLE, 1, &m_descSetQ2K);
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

    bool VulkanGEMV::uploadWeights(WeightType type, uint32_t rows, uint32_t cols, const void* weightData) {
        m_weightType = type;
        m_rows = rows;
        m_cols = cols;

        VkDeviceSize weightSize;
        if (type == WeightType::F32) {
            weightSize = static_cast<VkDeviceSize>(rows) * static_cast<VkDeviceSize>(cols) * sizeof(float);
        } else {
            uint32_t numBlocks = (rows * cols + 255) / 256;
            weightSize = static_cast<VkDeviceSize>(numBlocks) * 84;
        }

        if (!m_engine->createBuffer(m_weightBuf, weightSize,
                                    VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                                    false)) {
            std::cerr << "[VulkanGEMV] Failed to create weight buffer\n";
            return false;
        }

        VulkanBuffer stagingBuf;
        if (!m_engine->createBuffer(stagingBuf, weightSize,
                                    VK_BUFFER_USAGE_TRANSFER_SRC_BIT, true)) {
            std::cerr << "[VulkanGEMV] Failed to create staging buffer\n";
            return false;
        }

        if (!m_engine->uploadBuffer(stagingBuf, weightData, weightSize)) {
            std::cerr << "[VulkanGEMV] Failed to upload weight data\n";
            return false;
        }

        VkCommandBuffer cmd;
        if (!m_engine->beginCommandBuffer(cmd)) {
            std::cerr << "[VulkanGEMV] Failed to begin command buffer\n";
            return false;
        }

        VkBufferCopy region{ 0, 0, weightSize };
        vkCmdCopyBuffer(cmd, stagingBuf.buffer, m_weightBuf.buffer, 1, &region);

        VkBufferMemoryBarrier barrier{ VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER };
        barrier.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        barrier.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
        barrier.buffer = m_weightBuf.buffer;
        barrier.size = weightSize;
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
        m_rows = rows;
        m_cols = cols;

        VkDeviceSize outputSize = static_cast<VkDeviceSize>(rows) * sizeof(float);

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
            uint32_t pc[2] = { rows, cols };
            vkCmdPushConstants(cmd, pipeline->layout, VK_SHADER_STAGE_COMPUTE_BIT, 0, 8, pc);
        } else {
            uint32_t pc[4] = { rows, cols, 256, 0 };
            vkCmdPushConstants(cmd, pipeline->layout, VK_SHADER_STAGE_COMPUTE_BIT, 0, 16, pc);
        }

        uint32_t groupCount = (rows + pipeline->localSizeX - 1) / pipeline->localSizeX;
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
