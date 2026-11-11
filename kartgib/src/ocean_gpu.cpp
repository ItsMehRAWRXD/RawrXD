#include "ocean_field.hpp"
#include "shader_file.hpp"
#include "vulkan_renderer.hpp"
#include <cstring>
#include <iostream>
#include <vector>

float oceanGpuReadback(VulkanRenderer& renderer, VkPipeline pipeline, VkPipelineLayout layout, VkDescriptorSet sets[2], VkDeviceMemory memory, int n, const std::vector<Cx>& cpu);

bool runOceanGpuParity(VulkanRenderer& renderer, float& maxError) {
    maxError = -1.0f;
    const int n = 32;
    OceanParams params; params.cascades = 1;
    std::vector<Cx> spectrum;
    fillSpectrum(params, spectrum);
    std::vector<Cx> cpu = spectrum;
    ifft2d(cpu, n);
    VkDevice device = renderer.getDevice();
    VkBuffer buffers[2] = {};
    VkDeviceMemory memory[2] = {};
    VkShaderModule shader = VK_NULL_HANDLE;
    VkPipeline pipeline = VK_NULL_HANDLE;
    VkPipelineLayout layout = VK_NULL_HANDLE;
    VkDescriptorSetLayout setLayout = VK_NULL_HANDLE;
    VkDescriptorPool pool = VK_NULL_HANDLE;
    VkDescriptorSet sets[2] = {};
    auto cleanup = [&]() {
        if (pipeline) vkDestroyPipeline(device, pipeline, nullptr);
        if (layout) vkDestroyPipelineLayout(device, layout, nullptr);
        if (pool) { vkFreeDescriptorSets(device, pool, 2, sets); vkDestroyDescriptorPool(device, pool, nullptr); }
        if (setLayout) vkDestroyDescriptorSetLayout(device, setLayout, nullptr);
        if (shader) vkDestroyShaderModule(device, shader, nullptr);
        for (int i = 0; i < 2; ++i) {
            if (buffers[i]) vkDestroyBuffer(device, buffers[i], nullptr);
            if (memory[i]) vkFreeMemory(device, memory[i], nullptr);
        }
    };
    try {
        VkDeviceSize bytes = sizeof(Cx) * static_cast<size_t>(n * n);
        for (int i = 0; i < 2; ++i) renderer.createBuffer(bytes,
            VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, buffers[i], memory[i]);
        void* mapped = nullptr;
        vkMapMemory(device, memory[0], 0, bytes, 0, &mapped);
        std::memcpy(mapped, spectrum.data(), bytes);
        vkUnmapMemory(device, memory[0]);
        auto code = readShaderFile("ocean_fft.comp.spv");
        if (code.empty()) { cleanup(); return false; }
        VkShaderModuleCreateInfo moduleInfo{VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
        moduleInfo.codeSize = code.size();
        moduleInfo.pCode = reinterpret_cast<const uint32_t*>(code.data());
        if (vkCreateShaderModule(device, &moduleInfo, nullptr, &shader) != VK_SUCCESS) { cleanup(); return false; }
        VkDescriptorSetLayoutBinding bindings[2]{};
        bindings[0].binding = 0; bindings[1].binding = 1;
        bindings[0].descriptorType = bindings[1].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[0].descriptorCount = bindings[1].descriptorCount = 1;
        bindings[0].stageFlags = bindings[1].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
        VkDescriptorSetLayoutCreateInfo layoutInfo{VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO};
        layoutInfo.bindingCount = 2; layoutInfo.pBindings = bindings;
        vkCreateDescriptorSetLayout(device, &layoutInfo, nullptr, &setLayout);
        VkPushConstantRange range{VK_SHADER_STAGE_COMPUTE_BIT, 0, 8};
        VkPipelineLayoutCreateInfo pipeLayout{VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO};
        pipeLayout.setLayoutCount = 1; pipeLayout.pSetLayouts = &setLayout; pipeLayout.pushConstantRangeCount = 1; pipeLayout.pPushConstantRanges = &range;
        vkCreatePipelineLayout(device, &pipeLayout, nullptr, &layout);
        VkComputePipelineCreateInfo pipe{VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO};
        pipe.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
        pipe.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT; pipe.stage.module = shader; pipe.stage.pName = "main"; pipe.layout = layout;
        if (vkCreateComputePipelines(device, VK_NULL_HANDLE, 1, &pipe, nullptr, &pipeline) != VK_SUCCESS) { cleanup(); return false; }
        VkDescriptorPoolSize size{VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 4};
        VkDescriptorPoolCreateInfo poolInfo{VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO};
        poolInfo.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
        poolInfo.maxSets = 2; poolInfo.poolSizeCount = 1; poolInfo.pPoolSizes = &size;
        vkCreateDescriptorPool(device, &poolInfo, nullptr, &pool);
        VkDescriptorSetLayout layouts[2] = {setLayout, setLayout};
        VkDescriptorSetAllocateInfo alloc{VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO};
        alloc.descriptorPool = pool; alloc.descriptorSetCount = 2; alloc.pSetLayouts = layouts;
        vkAllocateDescriptorSets(device, &alloc, sets);
        for (int s = 0; s < 2; ++s) {
            VkDescriptorBufferInfo info[2]{{buffers[s], 0, bytes}, {buffers[1 - s], 0, bytes}};
            VkWriteDescriptorSet write{VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET};
            write.dstSet = sets[s]; write.descriptorCount = 2; write.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; write.pBufferInfo = info;
            vkUpdateDescriptorSets(device, 1, &write, 0, nullptr);
        }
        maxError = oceanGpuReadback(renderer, pipeline, layout, sets, memory[0], n, cpu);
        cleanup();
        std::cout << "[OCEAN] gpu_error=" << maxError << std::endl;
        return maxError < 2.0e-2f;
    } catch (const std::exception& ex) {
        std::cout << "[OCEAN] gpu_exception=" << ex.what() << std::endl;
        cleanup();
        return false;
    }
}
