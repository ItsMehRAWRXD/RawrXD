#include "VulkanDevice.hpp"

#include <cstdio>
#include <windows.h>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <set>

namespace deep2 {

static VkResult check(VkResult r) { return r; }

namespace {

// The deployed shaders sit next to the executable, in a shaders directory.
//
// The path is resolved from the running image rather than the working
// directory, so the engine finds its shaders however it is launched.
std::string ShaderPath(const char* fileName) {
    char path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, path, sizeof(path));
    std::string s(path);
    const size_t slash = s.find_last_of("\\/");
    if (slash != std::string::npos) s = s.substr(0, slash + 1);
    else s = "./";
    return s + "shaders\\" + fileName;
}

std::string F32ShaderName() { return ShaderPath("gemv_f32.spv"); }
std::string Q2KShaderName() { return ShaderPath("gemv_q2k.spv"); }

} // namespace

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
          // Skip the D3D12 interop proxies. Mesa's "Dozen" exposes the same
          // physical GPU as the native AMD device, so a two-device split that
          // picked one of these would put both halves of a matrix on a single
          // card while reporting two devices. The interop devices announce
          // themselves as "Microsoft Direct3D12 (<card>)".
          if (std::strncmp(props.deviceName, "Microsoft Direct3D12", 19) == 0) {
              fprintf(stderr, "[VULKAN] skipping D3D12 interop proxy: %s\n", props.deviceName);
              continue;
          }
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
    // The cached programs own objects created on the devices, so they have to
    // be destroyed while those devices are still alive.
    destroyPrograms();
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

bool VulkanDevice::ensureProgram(const Gpu& gpu, const std::string& spvPath,
                                  uint32_t pushConstantBytes) {
    std::lock_guard<std::mutex> lock(m_programMutex);
    const auto key = std::make_pair(gpu.device, spvPath);
    if (m_programs.find(key) != m_programs.end()) return true;

    auto program = std::make_unique<VulkanProgram>();
    if (!program->init(gpu.device, spvPath, pushConstantBytes)) return false;
    fprintf(stderr, "[VULKAN] compute program created for device %p (%s)\n",
            (void*)gpu.device, spvPath.c_str());
    m_programs.emplace(key, std::move(program));
    return true;
}

bool VulkanDevice::dispatchProgram(const Gpu& gpu, VkBuffer W, VkBuffer x, VkBuffer y,
                                   uint32_t rows, uint32_t cols) {
    VulkanProgram* program = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_programMutex);
        auto it = m_programs.find(std::make_pair(gpu.device, F32ShaderName()));
        if (it == m_programs.end()) return false;
        program = it->second.get();
    }
    const uint32_t push[2] = { rows, cols };
    return program->dispatch(gpu, W, x, y, push, 2);
}

bool VulkanDevice::dispatchProgramQ2K(const Gpu& gpu, VkBuffer Wpacked, VkBuffer x, VkBuffer y,
                                      uint32_t rows, uint32_t cols, uint32_t blockSize) {
    VulkanProgram* program = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_programMutex);
        auto it = m_programs.find(std::make_pair(gpu.device, Q2KShaderName()));
        if (it == m_programs.end()) return false;
        program = it->second.get();
    }
    const uint32_t push[4] = { rows, cols, blockSize, 0 };
    return program->dispatch(gpu, Wpacked, x, y, push, 4);
}

bool VulkanDevice::beginDispatchProgram(const Gpu& gpu, VkBuffer W, VkBuffer x, VkBuffer y,
                                        uint32_t rows, uint32_t cols, VulkanDispatch& out) {
    VulkanProgram* program = nullptr;
    {
        // The lock is only held for the lookup. The dispatch itself takes
        // the program's own dispatch lock, so two devices can be dispatched
        // at the same time.
        std::lock_guard<std::mutex> lock(m_programMutex);
        auto it = m_programs.find(std::make_pair(gpu.device, F32ShaderName()));
        if (it == m_programs.end()) return false;
        program = it->second.get();
    }
    const uint32_t push[2] = { rows, cols };
    return program->beginDispatch(gpu, W, x, y, push, 2, out);
}

bool VulkanDevice::beginDispatchProgramQ2K(const Gpu& gpu, VkBuffer Wpacked, VkBuffer x, VkBuffer y,
                                           uint32_t rows, uint32_t cols, uint32_t blockSize,
                                           VulkanDispatch& out) {
    VulkanProgram* program = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_programMutex);
        auto it = m_programs.find(std::make_pair(gpu.device, Q2KShaderName()));
        if (it == m_programs.end()) return false;
        program = it->second.get();
    }
    const uint32_t push[4] = { rows, cols, blockSize, 0 };
    return program->beginDispatch(gpu, Wpacked, x, y, push, 4, out);
}

void VulkanDevice::destroyPrograms() {
    std::lock_guard<std::mutex> lock(m_programMutex);
    for (auto& entry : m_programs) {
        // The map key holds the device the program was created on.
        entry.second->destroy(entry.first.first);
    }
    m_programs.clear();
}

bool VulkanDevice::createKvCache(const Gpu& gpu, uint32_t layers, uint32_t window,
                                 uint32_t hiddenDim, uint32_t bytesPerElement,
                                 VkDeviceSize budgetBytes, KvCache& out) {
    destroyKvCache(gpu, out);
    if (layers == 0 || window == 0 || hiddenDim == 0) return false;
    if (bytesPerElement != deep2::kKvBytesFp16 && bytesPerElement != deep2::kKvBytesFp32) {
        fprintf(stderr, "[VULKAN] KV cache element size must be 2 (fp16) or 4 (fp32)\n");
        return false;
    }

    const VkDeviceSize required = KvCacheBytes(layers, window, hiddenDim, bytesPerElement);
    const VkDeviceSize budget = budgetBytes ? budgetBytes : gpu.vramBytes;
    if (required > budget) {
        fprintf(stderr, "[VULKAN] KV cache of %llu bytes does not fit in %llu bytes on %s\n",
                (unsigned long long)required, (unsigned long long)budget, gpu.name.c_str());
        return false;
    }

    const VkDeviceSize perBuffer = required / 2;
    // The cache buffers are filled with vkCmdCopyBuffer, so they need the
    // transfer-destination usage as well as the storage usage.
    const VkBufferUsageFlags cacheUsage =
        VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    if (!createBuffer(gpu, perBuffer, cacheUsage,
                      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, out.keyBuffer, out.keyMemory) ||
        !createBuffer(gpu, perBuffer, cacheUsage,
                      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, out.valueBuffer, out.valueMemory)) {
        destroyKvCache(gpu, out);
        return false;
    }
    out.layers = layers;
    out.window = window;
    out.hiddenDim = hiddenDim;
    out.bytesPerElement = bytesPerElement;
    return true;
}

void VulkanDevice::destroyKvCache(const Gpu& gpu, KvCache& cache) {
    if (cache.keyBuffer != VK_NULL_HANDLE) destroyBuffer(gpu, cache.keyBuffer, cache.keyMemory);
    if (cache.valueBuffer != VK_NULL_HANDLE) destroyBuffer(gpu, cache.valueBuffer, cache.valueMemory);
    cache.keyBuffer = VK_NULL_HANDLE;
    cache.valueBuffer = VK_NULL_HANDLE;
    cache.keyMemory = VK_NULL_HANDLE;
    cache.valueMemory = VK_NULL_HANDLE;
    cache.layers = 0;
    cache.window = 0;
    cache.hiddenDim = 0;
    cache.bytesPerElement = 0;
}

bool VulkanDevice::appendKvPosition(const Gpu& gpu, KvCache& cache, uint32_t layer,
                                     uint32_t logicalPos, const float* keys, const float* values) {
    if (cache.keyBuffer == VK_NULL_HANDLE || !keys || !values) return false;
    if (layer >= cache.layers || cache.window == 0) return false;

    // The cache is a ring: the logical position lives in the slot
    // logicalPos % window, so writing past the window overwrites the oldest
    // token. The key keeps its absolute RoPE position, because the rotation
    // is applied here and never to the position the key was computed for.
    const uint32_t physical = deep2::KvPhysicalIndex(logicalPos, cache.window);

    const VkDeviceSize rowBytes =
        static_cast<VkDeviceSize>(cache.hiddenDim) * cache.bytesPerElement;
    const VkDeviceSize layerStride = static_cast<VkDeviceSize>(cache.window) * rowBytes;
    const VkDeviceSize offset = (static_cast<VkDeviceSize>(layer) * layerStride) +
                                (static_cast<VkDeviceSize>(physical) * rowBytes);

    if (cache.bytesPerElement == deep2::kKvBytesFp16) {
        // The cache is stored in half precision, so the row is converted
        // before it goes up.
        std::vector<uint16_t> halves(cache.hiddenDim);
        for (uint32_t i = 0; i < cache.hiddenDim; ++i) {
            halves[i] = deep2::KvFloatToHalf(keys[i]);
        }
        if (!uploadToBuffer(gpu, cache.keyBuffer, offset, halves.data(), rowBytes)) return false;
        for (uint32_t i = 0; i < cache.hiddenDim; ++i) {
            halves[i] = deep2::KvFloatToHalf(values[i]);
        }
        if (!uploadToBuffer(gpu, cache.valueBuffer, offset, halves.data(), rowBytes)) return false;
        return true;
    }

    if (!uploadToBuffer(gpu, cache.keyBuffer, offset, keys, rowBytes)) return false;
    if (!uploadToBuffer(gpu, cache.valueBuffer, offset, values, rowBytes)) return false;
    return true;
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

bool VulkanProgram::init(VkDevice device, const std::string& spvPath, uint32_t pushConstantBytes) {
    m_device = device;
    m_pushConstantBytes = pushConstantBytes;
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
    // The size is a property of the shader. The f32 GEMV passes two words,
    // the packed Q2_K GEMV passes four.
    pcr.size = pushConstantBytes;

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
    if (m_fence) { vkDestroyFence(device, m_fence, nullptr); m_fence = VK_NULL_HANDLE; }
    if (m_pool) { vkDestroyDescriptorPool(device, m_pool, nullptr); m_pool = VK_NULL_HANDLE; }
    if (m_dsl) { vkDestroyDescriptorSetLayout(device, m_dsl, nullptr); m_dsl = VK_NULL_HANDLE; }
    if (m_pipeline) { vkDestroyPipeline(device, m_pipeline, nullptr); m_pipeline = VK_NULL_HANDLE; }
    if (m_layout) { vkDestroyPipelineLayout(device, m_layout, nullptr); m_layout = VK_NULL_HANDLE; }
    if (m_shader) { vkDestroyShaderModule(device, m_shader, nullptr); m_shader = VK_NULL_HANDLE; }
    m_set = VK_NULL_HANDLE;
    m_device = VK_NULL_HANDLE;
}

bool VulkanProgram::dispatch(const VulkanDevice::Gpu& gpu, VkBuffer W, VkBuffer x, VkBuffer y,
                             const uint32_t* pushConstants, uint32_t pushWordCount) {
    Dispatch d;
    if (!beginDispatch(gpu, W, x, y, pushConstants, pushWordCount, d)) return false;
    return d.wait();
}

bool VulkanProgram::beginDispatch(const VulkanDevice::Gpu& gpu, VkBuffer W, VkBuffer x, VkBuffer y,
                                  const uint32_t* pushConstants, uint32_t pushWordCount,
                                  Dispatch& out) {
    if (m_device == VK_NULL_HANDLE) return false;

    // Take the program's dispatch lock for the whole lifetime of the
    // dispatch. The descriptor set and the fence belong to this program, so
    // a second dispatch on the same device has to wait for the first one:
    // it would otherwise rewrite the descriptor set the first dispatch is
    // still using and reset the fence it is still waiting on.
    out.m_lock = std::unique_lock<std::mutex>(m_dispatchMutex);
    if (!out.m_lock.owns_lock()) return false;

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
    if (vkAllocateCommandBuffers(m_device, &cbai, &cmd) != VK_SUCCESS) {
        out.m_lock.unlock();
        return false;
    }

    VkCommandBufferBeginInfo cbi{};
    cbi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    cbi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &cbi);

    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, m_pipeline);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, m_layout, 0, 1, &m_set, 0, nullptr);
    // The shader decides what the words mean; the program only knows how
    // many there are.
    vkCmdPushConstants(cmd, m_layout, VK_SHADER_STAGE_COMPUTE_BIT, 0,
                       pushWordCount * 4, pushConstants);
    uint32_t groups = (pushConstants[0] + 255) / 256;
    vkCmdDispatch(cmd, groups, 1, 1);

    vkEndCommandBuffer(cmd);

    vkResetFences(m_device, 1, &m_fence);
    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmd;
    if (vkQueueSubmit(gpu.queue, 1, &si, m_fence) != VK_SUCCESS) {
        vkFreeCommandBuffers(m_device, gpu.pool, 1, &cmd);
        out.m_lock.unlock();
        fprintf(stderr, "[VULKAN] vkQueueSubmit failed\n");
        return false;
    }

    // The work is in flight. The handle owns the command buffer until the
    // fence signals, and holds the dispatch lock until then.
    out.m_program = this;
    out.m_device = m_device;
    out.m_pool = gpu.pool;
    out.m_cmd = cmd;
    out.m_fence = m_fence;
    return true;
}

// ---------------- VulkanDispatch ----------------

VulkanDispatch::~VulkanDispatch() {
    // A dispatch that is dropped without being waited on still has a
    // command buffer in flight. Wait for it so the buffer is not freed
    // while the device is still reading it.
    wait();
}

VulkanDispatch::VulkanDispatch(VulkanDispatch&& other) noexcept
    : m_program(other.m_program)
    , m_device(other.m_device)
    , m_pool(other.m_pool)
    , m_cmd(other.m_cmd)
    , m_fence(other.m_fence)
    , m_lock(std::move(other.m_lock)) {
    other.m_program = nullptr;
    other.m_device = VK_NULL_HANDLE;
    other.m_pool = VK_NULL_HANDLE;
    other.m_cmd = VK_NULL_HANDLE;
    other.m_fence = VK_NULL_HANDLE;
}

VulkanDispatch& VulkanDispatch::operator=(VulkanDispatch&& other) noexcept {
    if (this != &other) {
        wait();
        m_program = other.m_program;
        m_device = other.m_device;
        m_pool = other.m_pool;
        m_cmd = other.m_cmd;
        m_fence = other.m_fence;
        m_lock = std::move(other.m_lock);
        other.m_program = nullptr;
        other.m_device = VK_NULL_HANDLE;
        other.m_pool = VK_NULL_HANDLE;
        other.m_cmd = VK_NULL_HANDLE;
        other.m_fence = VK_NULL_HANDLE;
    }
    return *this;
}

bool VulkanDispatch::wait() {
    if (!m_program) return true;

    const VkResult r = vkWaitForFences(m_device, 1, &m_fence, VK_TRUE, UINT64_MAX);

    // The device is done with the command buffer now, so it can go back to
    // the pool.
    if (m_cmd != VK_NULL_HANDLE) {
        vkFreeCommandBuffers(m_device, m_pool, 1, &m_cmd);
        m_cmd = VK_NULL_HANDLE;
    }

    m_program = nullptr;
    m_fence = VK_NULL_HANDLE;
    m_device = VK_NULL_HANDLE;
    m_pool = VK_NULL_HANDLE;

    // Release the program's dispatch lock, so a later dispatch on this
    // device can proceed.
    if (m_lock.owns_lock()) m_lock.unlock();

    return r == VK_SUCCESS;
}

} // namespace deep2
