#include "VulkanComputeEngine.hpp"
#include <iostream>
#include <fstream>
#include <cstring>
#include <algorithm>

namespace Deep2Rom::Compute {

    VulkanComputeEngine::VulkanComputeEngine() = default;

    VulkanComputeEngine::~VulkanComputeEngine() {
        if (m_device != VK_NULL_HANDLE) {
            vkDeviceWaitIdle(m_device);
            for (auto& [name, pipe] : m_pipelines) {
                if (pipe.pipeline != VK_NULL_HANDLE)
                    vkDestroyPipeline(m_device, pipe.pipeline, nullptr);
                if (pipe.layout != VK_NULL_HANDLE)
                    vkDestroyPipelineLayout(m_device, pipe.layout, nullptr);
                if (pipe.dslayout != VK_NULL_HANDLE)
                    vkDestroyDescriptorSetLayout(m_device, pipe.dslayout, nullptr);
                if (pipe.shaderModule != VK_NULL_HANDLE)
                    vkDestroyShaderModule(m_device, pipe.shaderModule, nullptr);
            }
            if (m_descriptorPool != VK_NULL_HANDLE)
                vkDestroyDescriptorPool(m_device, m_descriptorPool, nullptr);
            if (m_pipelineCache != VK_NULL_HANDLE)
                vkDestroyPipelineCache(m_device, m_pipelineCache, nullptr);
            if (m_commandPool != VK_NULL_HANDLE)
                vkDestroyCommandPool(m_device, m_commandPool, nullptr);
        }
        if (m_secondaryDevice != VK_NULL_HANDLE) {
            vkDeviceWaitIdle(m_secondaryDevice);
            if (m_secondaryCommandPool != VK_NULL_HANDLE)
                vkDestroyCommandPool(m_secondaryDevice, m_secondaryCommandPool, nullptr);
        }
    }

    bool VulkanComputeEngine::init(VkDevice device, VkPhysicalDevice physicalDevice,
                                   uint32_t graphicsQueueFamilyIndex, uint32_t computeQueueFamilyIndex) {
        (void)graphicsQueueFamilyIndex;  // Unused - using compute queue for everything
        m_device = device;
        m_physicalDevice = physicalDevice;

        // Get compute queue
        vkGetDeviceQueue(m_device, computeQueueFamilyIndex, 0, &m_computeQueue);

        // Create command pool for compute
        VkCommandPoolCreateInfo cpInfo{ VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO };
        cpInfo.queueFamilyIndex = computeQueueFamilyIndex;
        cpInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
        if (vkCreateCommandPool(m_device, &cpInfo, nullptr, &m_commandPool) != VK_SUCCESS) {
            std::cerr << "[VulkanCompute] Failed to create command pool\n";
            return false;
        }

        // Create descriptor pool
        if (!createDescriptorPool()) {
            std::cerr << "[VulkanCompute] Failed to create descriptor pool\n";
            return false;
        }

        // Create pipeline cache
        VkPipelineCacheCreateInfo pcInfo{ VK_STRUCTURE_TYPE_PIPELINE_CACHE_CREATE_INFO };
        vkCreatePipelineCache(m_device, &pcInfo, nullptr, &m_pipelineCache);

        std::cout << "[VulkanCompute] Engine initialized on primary device\n";
        return true;
    }

    bool VulkanComputeEngine::createDescriptorPool() {
        VkDescriptorPoolSize poolSizes[] = {
            { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 100 },
            { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC, 100 },
        };
        VkDescriptorPoolCreateInfo dpInfo{ VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO };
        dpInfo.maxSets = 100;
        dpInfo.poolSizeCount = 2;
        dpInfo.pPoolSizes = poolSizes;
        return vkCreateDescriptorPool(m_device, &dpInfo, nullptr, &m_descriptorPool) == VK_SUCCESS;
    }

    bool VulkanComputeEngine::createShaderModule(const std::vector<uint32_t>& code, VkShaderModule& outModule) {
        VkShaderModuleCreateInfo smInfo{ VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO };
        smInfo.codeSize = code.size() * sizeof(uint32_t);
        smInfo.pCode = code.data();
        return vkCreateShaderModule(m_device, &smInfo, nullptr, &outModule) == VK_SUCCESS;
    }

    bool VulkanComputeEngine::createComputePipeline(const std::string& name, const std::string& spirvPath,
                                                     uint32_t pushConstantBytes,
                                                     uint32_t descriptorSetCount) {
        // Read SPIR-V file
        std::ifstream file(spirvPath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            std::cerr << "[VulkanCompute] Cannot open SPIR-V: " << spirvPath << "\n";
            return false;
        }
        size_t fileSize = static_cast<size_t>(file.tellg());
        file.seekg(0, std::ios::beg);
        std::vector<uint32_t> code(fileSize / sizeof(uint32_t));
        file.read(reinterpret_cast<char*>(code.data()), fileSize);

        VkShaderModule shaderModule;
        if (!createShaderModule(code, shaderModule)) {
            std::cerr << "[VulkanCompute] Failed to create shader module: " << spirvPath << "\n";
            return false;
        }

        // Get local workgroup size from SPIR-V (OpDecorate BuiltIn GlobalInvocationId)
        // For now assume 256, 1, 1 (matches gemv_f32.comp)
        uint32_t localSizeX = 256, localSizeY = 1, localSizeZ = 1;

        // Create descriptor set layout with storage buffer bindings
        std::vector<VkDescriptorSetLayoutBinding> bindings(descriptorSetCount);
        for (uint32_t i = 0; i < descriptorSetCount; ++i) {
            bindings[i].binding = i;
            bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
            bindings[i].descriptorCount = 1;
            bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
            bindings[i].pImmutableSamplers = nullptr;
        }

        VkDescriptorSetLayoutCreateInfo dslInfo{ VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO };
        dslInfo.bindingCount = static_cast<uint32_t>(bindings.size());
        dslInfo.pBindings = bindings.data();

        VkDescriptorSetLayout dslayout;
        if (vkCreateDescriptorSetLayout(m_device, &dslInfo, nullptr, &dslayout) != VK_SUCCESS) {
            std::cerr << "[VulkanCompute] Failed to create descriptor set layout\n";
            vkDestroyShaderModule(m_device, shaderModule, nullptr);
            return false;
        }

        // Push constant ranges
        VkPushConstantRange pcRange{ VK_SHADER_STAGE_COMPUTE_BIT, 0, pushConstantBytes };

        VkPipelineLayoutCreateInfo plInfo{ VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO };
        plInfo.setLayoutCount = 1;
        plInfo.pSetLayouts = &dslayout;
        plInfo.pushConstantRangeCount = pushConstantBytes > 0 ? 1 : 0;
        plInfo.pPushConstantRanges = pushConstantBytes > 0 ? &pcRange : nullptr;

        VkPipelineLayout layout;
        if (vkCreatePipelineLayout(m_device, &plInfo, nullptr, &layout) != VK_SUCCESS) {
            std::cerr << "[VulkanCompute] Failed to create pipeline layout\n";
            vkDestroyDescriptorSetLayout(m_device, dslayout, nullptr);
            vkDestroyShaderModule(m_device, shaderModule, nullptr);
            return false;
        }

        VkComputePipelineCreateInfo cpInfo{ VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO };
        cpInfo.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
        cpInfo.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
        cpInfo.stage.module = shaderModule;
        cpInfo.stage.pName = "main";
        cpInfo.layout = layout;

        VkPipeline pipeline;
        if (vkCreateComputePipelines(m_device, m_pipelineCache, 1, &cpInfo, nullptr, &pipeline) != VK_SUCCESS) {
            std::cerr << "[VulkanCompute] Failed to create compute pipeline: " << name << "\n";
            vkDestroyPipelineLayout(m_device, layout, nullptr);
            vkDestroyDescriptorSetLayout(m_device, dslayout, nullptr);
            vkDestroyShaderModule(m_device, shaderModule, nullptr);
            return false;
        }

        ComputePipeline& np = m_pipelines[name];
        np.pipeline = pipeline;
        np.layout = layout;
        np.dslayout = dslayout;
        np.shaderModule = shaderModule;
        np.name = name;
        np.localSizeX = localSizeX;
        np.localSizeY = localSizeY;
        np.localSizeZ = localSizeZ;

        std::cout << "[VulkanCompute] Pipeline created: " << name << " (" << spirvPath << ")\n";
        return true;
    }

    ComputePipeline* VulkanComputeEngine::getPipeline(const std::string& name) {
        auto it = m_pipelines.find(name);
        if (it == m_pipelines.end()) return nullptr;
        return &it->second;
    }

    bool VulkanComputeEngine::createBuffer(VulkanBuffer& buf, VkDeviceSize size, VkBufferUsageFlags usage,
                                            bool hostVisible) {
        VkBufferCreateInfo bi{ VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
        bi.size = size;
        bi.usage = usage;
        bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

        if (vkCreateBuffer(m_device, &bi, nullptr, &buf.buffer) != VK_SUCCESS) return false;

        VkMemoryRequirements mr;
        vkGetBufferMemoryRequirements(m_device, buf.buffer, &mr);

        VkPhysicalDeviceMemoryProperties mp;
        vkGetPhysicalDeviceMemoryProperties(m_physicalDevice, &mp);

        uint32_t typeIndex = 0xFFFFFFFF;
        VkMemoryPropertyFlags requiredFlags = hostVisible ?
            (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) :
            VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT;

        for (uint32_t i = 0; i < mp.memoryTypeCount; ++i) {
            if ((mr.memoryTypeBits & (1 << i)) &&
                (mp.memoryTypes[i].propertyFlags & requiredFlags) == requiredFlags) {
                typeIndex = i;
                break;
            }
        }
        if (typeIndex == 0xFFFFFFFF) {
            vkDestroyBuffer(m_device, buf.buffer, nullptr);
            return false;
        }

        VkMemoryAllocateInfo ai{ VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
        ai.allocationSize = mr.size;
        ai.memoryTypeIndex = typeIndex;

        VkDeviceMemory memory;
        if (vkAllocateMemory(m_device, &ai, nullptr, &memory) != VK_SUCCESS) {
            vkDestroyBuffer(m_device, buf.buffer, nullptr);
            return false;
        }

        if (vkBindBufferMemory(m_device, buf.buffer, memory, 0) != VK_SUCCESS) {
            vkDestroyBuffer(m_device, buf.buffer, nullptr);
            vkFreeMemory(m_device, memory, nullptr);
            return false;
        }

        void* mapped = nullptr;
        if (hostVisible) {
            if (vkMapMemory(m_device, memory, 0, size, 0, &mapped) != VK_SUCCESS) {
                vkDestroyBuffer(m_device, buf.buffer, nullptr);
                vkFreeMemory(m_device, memory, nullptr);
                return false;
            }
        }

        buf.buffer = buf.buffer;
        buf.memory = memory;
        buf.size = mr.size;
        buf.hostVisible = hostVisible;
        buf.mapped = mapped;
        return true;
    }

    bool VulkanComputeEngine::uploadBuffer(VulkanBuffer& buf, const void* data, VkDeviceSize size) {
        if (!buf.hostVisible || !buf.mapped) return false;
        std::memcpy(buf.mapped, data, static_cast<size_t>(size));
        return true;
    }

    bool VulkanComputeEngine::beginCommandBuffer(VkCommandBuffer& cmd) {
        VkCommandBufferAllocateInfo ai{ VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
        ai.commandPool = m_commandPool;
        ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        ai.commandBufferCount = 1;

        if (vkAllocateCommandBuffers(m_device, &ai, &cmd) != VK_SUCCESS) return false;

        VkCommandBufferBeginInfo bi{ VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
        bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        return vkBeginCommandBuffer(cmd, &bi) == VK_SUCCESS;
    }

    bool VulkanComputeEngine::createDescriptorSet(ComputePipeline* pipeline, VkDescriptorSet& descSet,
                                                   VkBuffer weightBuf, VkBuffer inputBuf, VkBuffer outputBuf) {
        VkDescriptorSetAllocateInfo ai{ VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO };
        ai.descriptorPool = m_descriptorPool;
        ai.descriptorSetCount = 1;
        ai.pSetLayouts = &pipeline->dslayout;

        if (vkAllocateDescriptorSets(m_device, &ai, &descSet) != VK_SUCCESS) {
            std::cerr << "[VulkanCompute] Failed to allocate descriptor set\n";
            return false;
        }

        std::vector<VkDescriptorBufferInfo> binfos(3);
        binfos[0].buffer = weightBuf;
        binfos[0].offset = 0;
        binfos[0].range = VK_WHOLE_SIZE;
        binfos[1].buffer = inputBuf;
        binfos[1].offset = 0;
        binfos[1].range = VK_WHOLE_SIZE;
        binfos[2].buffer = outputBuf;
        binfos[2].offset = 0;
        binfos[2].range = VK_WHOLE_SIZE;

        std::vector<VkWriteDescriptorSet> writes(3);
        writes[0].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[0].dstSet = descSet;
        writes[0].dstBinding = 0;
        writes[0].descriptorCount = 1;
        writes[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[0].pBufferInfo = &binfos[0];

        writes[1].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[1].dstSet = descSet;
        writes[1].dstBinding = 1;
        writes[1].descriptorCount = 1;
        writes[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[1].pBufferInfo = &binfos[1];

        writes[2].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[2].dstSet = descSet;
        writes[2].dstBinding = 2;
        writes[2].descriptorCount = 1;
        writes[2].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[2].pBufferInfo = &binfos[2];

        vkUpdateDescriptorSets(m_device, 3, writes.data(), 0, nullptr);
        return true;
    }

    bool VulkanComputeEngine::updateDescriptorSet(VkDescriptorSet descSet,
                                                   VkBuffer weightBuf, VkBuffer inputBuf, VkBuffer outputBuf) {
        std::vector<VkDescriptorBufferInfo> binfos(3);
        binfos[0].buffer = weightBuf;
        binfos[0].offset = 0;
        binfos[0].range = VK_WHOLE_SIZE;
        binfos[1].buffer = inputBuf;
        binfos[1].offset = 0;
        binfos[1].range = VK_WHOLE_SIZE;
        binfos[2].buffer = outputBuf;
        binfos[2].offset = 0;
        binfos[2].range = VK_WHOLE_SIZE;

        std::vector<VkWriteDescriptorSet> writes(3);
        writes[0].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[0].dstSet = descSet;
        writes[0].dstBinding = 0;
        writes[0].descriptorCount = 1;
        writes[0].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[0].pBufferInfo = &binfos[0];

        writes[1].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[1].dstSet = descSet;
        writes[1].dstBinding = 1;
        writes[1].descriptorCount = 1;
        writes[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[1].pBufferInfo = &binfos[1];

        writes[2].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[2].dstSet = descSet;
        writes[2].dstBinding = 2;
        writes[2].descriptorCount = 1;
        writes[2].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[2].pBufferInfo = &binfos[2];

        vkUpdateDescriptorSets(m_device, 3, writes.data(), 0, nullptr);
        return true;
    }

    bool VulkanComputeEngine::submitAndWait(VkCommandBuffer cmd) {
        if (vkEndCommandBuffer(cmd) != VK_SUCCESS) return false;

        VkSubmitInfo si{ VK_STRUCTURE_TYPE_SUBMIT_INFO };
        si.commandBufferCount = 1;
        si.pCommandBuffers = &cmd;

        if (vkQueueSubmit(m_computeQueue, 1, &si, VK_NULL_HANDLE) != VK_SUCCESS) return false;
        if (vkQueueWaitIdle(m_computeQueue) != VK_SUCCESS) return false;

        vkFreeCommandBuffers(m_device, m_commandPool, 1, &cmd);
        return true;
    }

    void VulkanComputeEngine::setPrimaryDevice(VkDevice device, VkPhysicalDevice physicalDevice) {
        m_device = device;
        m_physicalDevice = physicalDevice;
    }

} // namespace Deep2Rom::Compute
