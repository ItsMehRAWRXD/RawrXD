#include "VulkanDevice.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <set>

namespace deep2 {

static VkResult check(VkResult r) { return r; }

VulkanDevice::VulkanDevice() = default;
VulkanDevice::~VulkanDevice() { shutdown(); }

bool VulkanDevice::init() {
    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "Deep2 Emulator";
    appInfo.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.pEngineName = "deep2";
    appInfo.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.apiVersion = VK_API_VERSION_1_2;

    VkInstanceCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo = &appInfo;

    if (vkCreateInstance(&ci, nullptr, &m_instance) != VK_SUCCESS) {
        fprintf(stderr, "[VULKAN] vkCreateInstance failed\n");
        return false;
    }

    uint32_t gpuCount = 0;
    if (vkEnumeratePhysicalDevices(m_instance, &gpuCount, nullptr) != VK_SUCCESS || gpuCount == 0) {
        fprintf(stderr, "[VULKAN] no physical devices\n");
        return false;
    }
    std::vector<VkPhysicalDevice> pds(gpuCount);
    vkEnumeratePhysicalDevices(m_instance, &gpuCount, pds.data());

    struct Scored { VkPhysicalDevice pd; uint64_t vram; int rank; };
    std::vector<Scored> scored;
    for (auto pd : pds) {
        VkPhysicalDeviceProperties props{};
        vkGetPhysicalDeviceProperties(pd, &props);
        if (props.deviceType != VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) continue;
        if (props.vendorID != 0x1002u) continue; // AMD only in this milestone
        VkPhysicalDeviceMemoryProperties mem{};
        vkGetPhysicalDeviceMemoryProperties(pd, &mem);
        uint64_t localHeap = 0;
        for (uint32_t i = 0; i < mem.memoryHeapCount; ++i) {
            if (mem.memoryHeaps[i].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT)
                localHeap += mem.memoryHeaps[i].size;
        }
        scored.push_back({pd, localHeap, 0});
        fprintf(stderr, "[VULKAN] found GPU: %s (vendor 0x%04X, device-local heaps %llu MB)\n",
                props.deviceName, props.vendorID,
                (unsigned long long)(localHeap / (1024ull * 1024ull)));
    }
    if (scored.empty()) {
        fprintf(stderr, "[VULKAN] no AMD discrete GPUs found\n");
        return false;
    }
    std::sort(scored.begin(), scored.end(),
              [](const Scored& a, const Scored& b) { return b.vram < a.vram; });

    for (auto& s : scored) {
        VkPhysicalDevice pd = s.pd;
        VkPhysicalDeviceProperties props{};
        vkGetPhysicalDeviceProperties(pd, &props);
        VkPhysicalDeviceMemoryProperties mem{};
        vkGetPhysicalDeviceMemoryProperties(pd, &mem);

        // Compute queue family.
        uint32_t qfCount = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(pd, &qfCount, nullptr);
        std::vector<VkQueueFamilyProperties> qfs(qfCount);
        vkGetPhysicalDeviceQueueFamilyProperties(pd, &qfCount, qfs.data());
        uint32_t qf = UINT32_MAX;
        for (uint32_t i = 0; i < qfCount; ++i) {
            if (qfs[i].queueFlags & VK_QUEUE_COMPUTE_BIT) { qf = i; break; }
        }
        if (qf == UINT32_MAX) continue;

        float qPriority = 1.0f;
        VkDeviceQueueCreateInfo qci{};
        qci.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
        qci.queueFamilyIndex = qf;
        qci.queueCount = 1;
        qci.pQueuePriorities = &qPriority;

        VkDeviceCreateInfo di{};
        di.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
        di.queueCreateInfoCount = 1;
        di.pQueueCreateInfos = &qci;

        VkDevice device = VK_NULL_HANDLE;
        if (vkCreateDevice(pd, &di, nullptr, &device) != VK_SUCCESS) continue;

        VkQueue queue = VK_NULL_HANDLE;
        vkGetDeviceQueue(device, qf, 0, &queue);

        VkCommandPoolCreateInfo cpci{};
        cpci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
        cpci.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
        cpci.queueFamilyIndex = qf;
        VkCommandPool pool = VK_NULL_HANDLE;
        if (vkCreateCommandPool(device, &cpci, nullptr, &pool) != VK_SUCCESS) {
            vkDestroyDevice(device, nullptr);
            continue;
        }

        Gpu g;
        g.pd = pd; g.device = device; g.queue = queue; g.pool = pool;
        g.queueFamily = qf; g.props = props; g.memProps = mem;
        g.name = props.deviceName;
        g.vramBytes = s.vram;
        g.instance = m_instance;
        m_gpus.push_back(std::move(g));
        fprintf(stderr, "[VULKAN] initialized device: %s\n", g.name.c_str());
    }

    return !m_gpus.empty();
}

void VulkanDevice::shutdown() {
    for (auto& g : m_gpus) {
        vkDeviceWaitIdle(g.device);
        vkDestroyCommandPool(g.device, g.pool, nullptr);
        vkDestroyDevice(g.device, nullptr);
    }
    m_gpus.clear();
    if (m_instance) {
        vkDestroyInstance(m_instance, nullptr);
        m_instance = VK_NULL_HANDLE;
    }
}

bool VulkanDevice::pickMemoryType(const Gpu& gpu, uint32_t typeBits,
                                  VkMemoryPropertyFlags props, uint32_t& index) const {
    for (uint32_t i = 0; i < gpu.memProps.memoryTypeCount; ++i) {
        if ((typeBits & (1u << i)) &&
            (gpu.memProps.memoryTypes[i].propertyFlags & props) == props) {
            index = i;
            return true;
        }
    }
    return false;
}

bool VulkanDevice::createBuffer(const Gpu& gpu, VkDeviceSize size, VkBufferUsageFlags usage,
                                VkMemoryPropertyFlags memProps, VkBuffer& buf,
                                VkDeviceMemory& mem, void** mapped) {
    buf = VK_NULL_HANDLE; mem = VK_NULL_HANDLE;
    if (size == 0) return true;

    VkBufferCreateInfo bci{};
    bci.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bci.size = size;
    bci.usage = usage;
    bci.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (vkCreateBuffer(gpu.device, &bci, nullptr, &buf) != VK_SUCCESS) return false;

    VkMemoryRequirements mr{};
    vkGetBufferMemoryRequirements(gpu.device, buf, &mr);

    uint32_t mt = 0;
    if (!pickMemoryType(gpu, mr.memoryTypeBits, memProps, mt)) {
        vkDestroyBuffer(gpu.device, buf, nullptr);
        return false;
    }

    VkMemoryAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    ai.allocationSize = mr.size;
    ai.memoryTypeIndex = mt;
    if (vkAllocateMemory(gpu.device, &ai, nullptr, &mem) != VK_SUCCESS) {
        vkDestroyBuffer(gpu.device, buf, nullptr);
        return false;
    }
    vkBindBufferMemory(gpu.device, buf, mem, 0);

    if (mapped && (memProps & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)) {
        vkMapMemory(gpu.device, mem, 0, mr.size, 0, mapped);
    }
    return true;
}

void VulkanDevice::destroyBuffer(const Gpu& gpu, VkBuffer buf, VkDeviceMemory mem) {
    if (buf != VK_NULL_HANDLE) vkDestroyBuffer(gpu.device, buf, nullptr);
    if (mem != VK_NULL_HANDLE) vkFreeMemory(gpu.device, mem, nullptr);
}

bool VulkanDevice::uploadToBuffer(const Gpu& gpu, VkBuffer dst, VkDeviceSize dstOffset,
                                  const void* data, VkDeviceSize size) {
    if (size == 0) return true;
    VkBuffer staging = VK_NULL_HANDLE;
    VkDeviceMemory smem = VK_NULL_HANDLE;
    void* mapped = nullptr;
    if (!createBuffer(gpu, size, VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                      staging, smem, &mapped)) {
        return false;
    }
    std::memcpy(mapped, data, static_cast<size_t>(size));
    vkUnmapMemory(gpu.device, smem);

    VkCommandBufferAllocateInfo cbai{};
    cbai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cbai.commandPool = gpu.pool;
    cbai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cbai.commandBufferCount = 1;
    VkCommandBuffer cmd = VK_NULL_HANDLE;
    vkAllocateCommandBuffers(gpu.device, &cbai, &cmd);

    VkCommandBufferBeginInfo cbi{};
    cbi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    cbi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &cbi);

    VkBufferCopy region{};
    region.srcOffset = 0; region.dstOffset = dstOffset; region.size = size;
    vkCmdCopyBuffer(cmd, staging, dst, 1, &region);

    vkEndCommandBuffer(cmd);
    VkFence fence = VK_NULL_HANDLE;
    VkFenceCreateInfo fci{}; fci.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    vkCreateFence(gpu.device, &fci, nullptr, &fence);
    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmd;
    vkQueueSubmit(gpu.queue, 1, &si, fence);
    vkWaitForFences(gpu.device, 1, &fence, VK_TRUE, UINT64_MAX);
    vkDestroyFence(gpu.device, fence, nullptr);
    vkFreeCommandBuffers(gpu.device, gpu.pool, 1, &cmd);
    destroyBuffer(gpu, staging, smem);
    return true;
}

bool VulkanDevice::writeMapped(const Gpu& gpu, VkDeviceMemory mem, VkDeviceSize offset,
                               const void* data, VkDeviceSize size) {
    void* mapped = nullptr;
    if (vkMapMemory(gpu.device, mem, offset, size, 0, &mapped) != VK_SUCCESS) return false;
    std::memcpy(mapped, data, static_cast<size_t>(size));
    vkUnmapMemory(gpu.device, mem);
    return true;
}

// ---------------- VulkanProgram ----------------

VulkanProgram::VulkanProgram() = default;
VulkanProgram::~VulkanProgram() { /* caller must call destroy before device teardown */ }

static std::vector<uint8_t> readFileSpv(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return {};
    std::streamsize sz = f.tellg(); f.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(sz);
    if (!f.read(reinterpret_cast<char*>(buf.data()), sz)) return {};
    return buf;
}

bool VulkanProgram::init(VkDevice device, const std::string& spvPath) {
    m_device = device;
    auto spv = readFileSpv(spvPath);
    if (spv.empty()) {
        fprintf(stderr, "[VULKAN] could not read SPIR-V: %s\n", spvPath.c_str());
        return false;
    }

    VkShaderModuleCreateInfo smci{};
    smci.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    smci.codeSize = spv.size();
    smci.pCode = reinterpret_cast<const uint32_t*>(spv.data());
    if (vkCreateShaderModule(device, &smci, nullptr, &m_shader) != VK_SUCCESS) {
        fprintf(stderr, "[VULKAN] vkCreateShaderModule failed\n");
        return false;
    }

    VkPipelineShaderStageCreateInfo ssi{};
    ssi.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    ssi.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    ssi.module = m_shader;
    ssi.pName = "main";

    // Descriptor set layout: 0 = W, 1 = x, 2 = y (storage buffers).
    VkDescriptorSetLayoutBinding bindings[3] = {};
    for (int i = 0; i < 3; ++i) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo dslci{};
    dslci.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    dslci.bindingCount = 3;
    dslci.pBindings = bindings;
    if (vkCreateDescriptorSetLayout(device, &dslci, nullptr, &m_dsl) != VK_SUCCESS) return false;

    VkPushConstantRange pcr{};
    pcr.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pcr.offset = 0;
    pcr.size = 8; // uint rows, uint cols

    VkPipelineLayoutCreateInfo plci{};
    plci.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    plci.setLayoutCount = 1;
    plci.pSetLayouts = &m_dsl;
    plci.pushConstantRangeCount = 1;
    plci.pPushConstantRanges = &pcr;
    if (vkCreatePipelineLayout(device, &plci, nullptr, &m_layout) != VK_SUCCESS) return false;

    VkComputePipelineCreateInfo cpci{};
    cpci.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    cpci.stage = ssi;
    cpci.layout = m_layout;
    if (vkCreateComputePipelines(device, VK_NULL_HANDLE, 1, &cpci, nullptr, &m_pipeline) != VK_SUCCESS) {
        fprintf(stderr, "[VULKAN] vkCreateComputePipelines failed\n");
        return false;
    }

    VkDescriptorPoolSize poolSizes[1] = {};
    poolSizes[0].type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSizes[0].descriptorCount = 8;
    VkDescriptorPoolCreateInfo dpci{};
    dpci.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    dpci.maxSets = 4;
    dpci.poolSizeCount = 1;
    dpci.pPoolSizes = poolSizes;
    if (vkCreateDescriptorPool(device, &dpci, nullptr, &m_pool) != VK_SUCCESS) return false;

    VkDescriptorSetAllocateInfo dsai{};
    dsai.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    dsai.descriptorPool = m_pool;
    dsai.descriptorSetCount = 1;
    dsai.pSetLayouts = &m_dsl;
    if (vkAllocateDescriptorSets(device, &dsai, &m_set) != VK_SUCCESS) return false;

    VkFenceCreateInfo fci{}; fci.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    vkCreateFence(device, &fci, nullptr, &m_fence);
    return true;
}

void VulkanProgram::destroy(VkDevice device) {
    if (m_fence) vkDestroyFence(device, m_fence, nullptr);
    if (m_pool) vkDestroyDescriptorPool(device, m_pool, nullptr);
    if (m_dsl) vkDestroyDescriptorSetLayout(device, m_dsl, nullptr);
    if (m_pipeline) vkDestroyPipeline(device, m_pipeline, nullptr);
    if (m_layout) vkDestroyPipelineLayout(device, m_layout, nullptr);
    if (m_shader) vkDestroyShaderModule(device, m_shader, nullptr);
}

bool VulkanProgram::dispatch(const VulkanDevice::Gpu& gpu, VkBuffer W, VkBuffer x, VkBuffer y,
                             uint32_t rows, uint32_t cols) {
    if (m_device == VK_NULL_HANDLE) return false;
    m_queue = gpu.queue;

    VkDescriptorBufferInfo binfos[3] = {};
    binfos[0].buffer = W; binfos[0].range = VK_WHOLE_SIZE;
    binfos[1].buffer = x; binfos[1].range = VK_WHOLE_SIZE;
    binfos[2].buffer = y; binfos[2].range = VK_WHOLE_SIZE;
    VkWriteDescriptorSet writes[3] = {};
    for (int i = 0; i < 3; ++i) {
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = m_set;
        writes[i].dstBinding = i;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[i].pBufferInfo = &binfos[i];
    }
    vkUpdateDescriptorSets(m_device, 3, writes, 0, nullptr);

    VkCommandBufferAllocateInfo cbai{};
    cbai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cbai.commandPool = gpu.pool;
    cbai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cbai.commandBufferCount = 1;
    VkCommandBuffer cmd = VK_NULL_HANDLE;
    if (vkAllocateCommandBuffers(m_device, &cbai, &cmd) != VK_SUCCESS) return false;

    VkCommandBufferBeginInfo cbi{};
    cbi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    cbi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &cbi);

    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, m_pipeline);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, m_layout, 0, 1, &m_set, 0, nullptr);
    uint32_t pc[2] = {rows, cols};
    vkCmdPushConstants(cmd, m_layout, VK_SHADER_STAGE_COMPUTE_BIT, 0, 8, pc);
    uint32_t groups = (rows + 255) / 256;
    vkCmdDispatch(cmd, groups, 1, 1);

    vkEndCommandBuffer(cmd);

    vkResetFences(m_device, 1, &m_fence);
    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmd;
    vkQueueSubmit(gpu.queue, 1, &si, m_fence);
    vkWaitForFences(m_device, 1, &m_fence, VK_TRUE, UINT64_MAX);
    vkFreeCommandBuffers(m_device, gpu.pool, 1, &cmd);
    return true;
}

} // namespace deep2
