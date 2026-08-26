// ============================================================================
// Minimal Vulkan GEMV Standalone Test
// Directly tests CPUInference::VulkanCompute::DispatchGEMV() without
// the full inference pipeline. Links only against vulkan-1.lib.
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <vector>
#include <string>
#include <windows.h>

// Minimal Vulkan header subset (we only need a few functions)
#include <vulkan/vulkan.h>

// Forward-declare the VulkanCompute class from the project
namespace CPUInference {
class VulkanCompute;
}

// Instead of including the full header (which has dummy types issues),
// we'll directly use Vulkan API here to test the shader.

static bool g_verbose = true;

// Reference CPU GEMV for verification
static void cpuGemv(const float* weights, const float* input, float* output,
                    uint32_t rows, uint32_t cols) {
    for (uint32_t r = 0; r < rows; ++r) {
        float sum = 0.0f;
        for (uint32_t c = 0; c < cols; ++c) {
            sum += weights[r * cols + c] * input[c];
        }
        output[r] = sum;
    }
}

static bool nearlyEqual(float a, float b, float tol) {
    return std::fabs(a - b) <= tol * std::max(std::fabs(a), std::fabs(b));
}

// ============================================================================
// Minimal Vulkan GEMV test (inline, no project dependencies)
// ============================================================================
class MinimalVulkanGEMV {
public:
    VkInstance instance_ = VK_NULL_HANDLE;
    VkPhysicalDevice physicalDevice_ = VK_NULL_HANDLE;
    VkDevice device_ = VK_NULL_HANDLE;
    VkQueue queue_ = VK_NULL_HANDLE;
    VkCommandPool cmdPool_ = VK_NULL_HANDLE;
    VkPipeline pipeline_ = VK_NULL_HANDLE;
    VkPipelineLayout pipelineLayout_ = VK_NULL_HANDLE;
    VkDescriptorSetLayout dsLayout_ = VK_NULL_HANDLE;
    VkDescriptorPool descPool_ = VK_NULL_HANDLE;
    bool initialized_ = false;

    bool Initialize(const std::string& spirvPath);
    void Shutdown();
    bool Dispatch(const float* weights, const float* input, float* output,
                    uint32_t rows, uint32_t cols);

private:
    bool LoadSpirv(const std::string& path, std::vector<uint32_t>& code);
    bool CreatePipeline(const std::vector<uint32_t>& code);
    uint32_t FindMemoryType(uint32_t typeBits, VkMemoryPropertyFlags props);
};

bool MinimalVulkanGEMV::LoadSpirv(const std::string& path, std::vector<uint32_t>& code) {
    FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "rb");
    if (!f) {
        printf("[VulkanGEMV] Failed to open SPIR-V: %s\n", path.c_str());
        return false;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    code.resize(size / sizeof(uint32_t));
    fread(code.data(), 1, size, f);
    fclose(f);
    printf("[VulkanGEMV] Loaded SPIR-V: %s (%ld bytes)\n", path.c_str(), size);
    return true;
}

uint32_t MinimalVulkanGEMV::FindMemoryType(uint32_t typeBits, VkMemoryPropertyFlags props) {
    VkPhysicalDeviceMemoryProperties memProps;
    vkGetPhysicalDeviceMemoryProperties(physicalDevice_, &memProps);
    for (uint32_t i = 0; i < memProps.memoryTypeCount; ++i) {
        if ((typeBits & (1u << i)) && (memProps.memoryTypes[i].propertyFlags & props) == props) {
            return i;
        }
    }
    return 0xFFFFFFFF;
}

bool MinimalVulkanGEMV::CreatePipeline(const std::vector<uint32_t>& code) {
    VkShaderModuleCreateInfo shaderInfo{};
    shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    shaderInfo.codeSize = code.size() * sizeof(uint32_t);
    shaderInfo.pCode = code.data();
    VkShaderModule shaderModule = VK_NULL_HANDLE;
    if (vkCreateShaderModule(device_, &shaderInfo, nullptr, &shaderModule) != VK_SUCCESS) {
        printf("[VulkanGEMV] vkCreateShaderModule failed\n");
        return false;
    }

    VkDescriptorSetLayoutBinding bindings[3] = {};
    for (int i = 0; i < 3; ++i) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo dslInfo{};
    dslInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    dslInfo.bindingCount = 3;
    dslInfo.pBindings = bindings;
    if (vkCreateDescriptorSetLayout(device_, &dslInfo, nullptr, &dsLayout_) != VK_SUCCESS) {
        printf("[VulkanGEMV] vkCreateDescriptorSetLayout failed\n");
        vkDestroyShaderModule(device_, shaderModule, nullptr);
        return false;
    }

    VkPushConstantRange pcRange{};
    pcRange.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pcRange.offset = 0;
    pcRange.size = sizeof(uint32_t) * 2;

    VkPipelineLayoutCreateInfo plInfo{};
    plInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    plInfo.setLayoutCount = 1;
    plInfo.pSetLayouts = &dsLayout_;
    plInfo.pushConstantRangeCount = 1;
    plInfo.pPushConstantRanges = &pcRange;
    if (vkCreatePipelineLayout(device_, &plInfo, nullptr, &pipelineLayout_) != VK_SUCCESS) {
        printf("[VulkanGEMV] vkCreatePipelineLayout failed\n");
        vkDestroyDescriptorSetLayout(device_, dsLayout_, nullptr);
        dsLayout_ = VK_NULL_HANDLE;
        vkDestroyShaderModule(device_, shaderModule, nullptr);
        return false;
    }

    VkPipelineShaderStageCreateInfo stageInfo{};
    stageInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stageInfo.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stageInfo.module = shaderModule;
    stageInfo.pName = "main";

    VkComputePipelineCreateInfo pipelineInfo{};
    pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipelineInfo.layout = pipelineLayout_;
    pipelineInfo.stage = stageInfo;

    VkResult result = vkCreateComputePipelines(device_, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &pipeline_);
    vkDestroyShaderModule(device_, shaderModule, nullptr);
    if (result != VK_SUCCESS) {
        printf("[VulkanGEMV] vkCreateComputePipelines failed (VkResult=%d)\n", static_cast<int>(result));
        vkDestroyPipelineLayout(device_, pipelineLayout_, nullptr);
        pipelineLayout_ = VK_NULL_HANDLE;
        vkDestroyDescriptorSetLayout(device_, dsLayout_, nullptr);
        dsLayout_ = VK_NULL_HANDLE;
        return false;
    }

    VkDescriptorPoolSize poolSize{};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 3;
    VkDescriptorPoolCreateInfo dpInfo{};
    dpInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    dpInfo.maxSets = 1;
    dpInfo.poolSizeCount = 1;
    dpInfo.pPoolSizes = &poolSize;
    if (vkCreateDescriptorPool(device_, &dpInfo, nullptr, &descPool_) != VK_SUCCESS) {
        printf("[VulkanGEMV] vkCreateDescriptorPool failed\n");
        vkDestroyPipeline(device_, pipeline_, nullptr);
        pipeline_ = VK_NULL_HANDLE;
        vkDestroyPipelineLayout(device_, pipelineLayout_, nullptr);
        pipelineLayout_ = VK_NULL_HANDLE;
        vkDestroyDescriptorSetLayout(device_, dsLayout_, nullptr);
        dsLayout_ = VK_NULL_HANDLE;
        return false;
    }
    printf("[VulkanGEMV] Pipeline created successfully\n");
    return true;
}

bool MinimalVulkanGEMV::Initialize(const std::string& spirvPath) {
    // 1. Create instance
    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "RawrXD GEMV Test";
    appInfo.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.apiVersion = VK_API_VERSION_1_3;

    VkInstanceCreateInfo createInfo{};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &appInfo;
    createInfo.enabledLayerCount = 0;
    createInfo.enabledExtensionCount = 0;

    if (vkCreateInstance(&createInfo, nullptr, &instance_) != VK_SUCCESS) {
        printf("[VulkanGEMV] vkCreateInstance failed\n");
        return false;
    }

    // 2. Select physical device
    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance_, &deviceCount, nullptr);
    if (deviceCount == 0) {
        printf("[VulkanGEMV] No Vulkan devices found\n");
        vkDestroyInstance(instance_, nullptr);
        instance_ = VK_NULL_HANDLE;
        return false;
    }
    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(instance_, &deviceCount, devices.data());
    physicalDevice_ = devices[0];
    VkPhysicalDeviceProperties props;
    vkGetPhysicalDeviceProperties(physicalDevice_, &props);
    printf("[VulkanGEMV] Selected GPU: %s\n", props.deviceName);

    // 3. Create device
    float queuePriority = 1.0f;
    VkDeviceQueueCreateInfo queueCreateInfo{};
    queueCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueCreateInfo.queueFamilyIndex = 0;
    queueCreateInfo.queueCount = 1;
    queueCreateInfo.pQueuePriorities = &queuePriority;

    VkDeviceCreateInfo deviceCreateInfo{};
    deviceCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    deviceCreateInfo.queueCreateInfoCount = 1;
    deviceCreateInfo.pQueueCreateInfos = &queueCreateInfo;
    deviceCreateInfo.enabledExtensionCount = 0;

    if (vkCreateDevice(physicalDevice_, &deviceCreateInfo, nullptr, &device_) != VK_SUCCESS) {
        printf("[VulkanGEMV] vkCreateDevice failed\n");
        vkDestroyInstance(instance_, nullptr);
        instance_ = VK_NULL_HANDLE;
        return false;
    }
    vkGetDeviceQueue(device_, 0, 0, &queue_);

    // 4. Create command pool
    VkCommandPoolCreateInfo poolInfo{};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    poolInfo.queueFamilyIndex = 0;
    if (vkCreateCommandPool(device_, &poolInfo, nullptr, &cmdPool_) != VK_SUCCESS) {
        printf("[VulkanGEMV] vkCreateCommandPool failed\n");
        vkDestroyDevice(device_, nullptr);
        vkDestroyInstance(instance_, nullptr);
        device_ = VK_NULL_HANDLE;
        instance_ = VK_NULL_HANDLE;
        return false;
    }

    // 5. Load SPIR-V and create pipeline
    std::vector<uint32_t> spirvCode;
    if (!LoadSpirv(spirvPath, spirvCode)) {
        Shutdown();
        return false;
    }
    if (!CreatePipeline(spirvCode)) {
        Shutdown();
        return false;
    }

    initialized_ = true;
    printf("[VulkanGEMV] Initialized successfully\n");
    return true;
}

void MinimalVulkanGEMV::Shutdown() {
    if (descPool_) vkDestroyDescriptorPool(device_, descPool_, nullptr);
    if (pipeline_) vkDestroyPipeline(device_, pipeline_, nullptr);
    if (pipelineLayout_) vkDestroyPipelineLayout(device_, pipelineLayout_, nullptr);
    if (dsLayout_) vkDestroyDescriptorSetLayout(device_, dsLayout_, nullptr);
    if (cmdPool_) vkDestroyCommandPool(device_, cmdPool_, nullptr);
    if (device_) vkDestroyDevice(device_, nullptr);
    if (instance_) vkDestroyInstance(instance_, nullptr);
    descPool_ = VK_NULL_HANDLE;
    pipeline_ = VK_NULL_HANDLE;
    pipelineLayout_ = VK_NULL_HANDLE;
    dsLayout_ = VK_NULL_HANDLE;
    cmdPool_ = VK_NULL_HANDLE;
    queue_ = VK_NULL_HANDLE;
    device_ = VK_NULL_HANDLE;
    physicalDevice_ = VK_NULL_HANDLE;
    instance_ = VK_NULL_HANDLE;
    initialized_ = false;
}

bool MinimalVulkanGEMV::Dispatch(const float* weights, const float* input, float* output,
                                   uint32_t rows, uint32_t cols) {
    if (!initialized_) return false;

    size_t weightBytes = (size_t)rows * cols * sizeof(float);
    size_t inputBytes  = (size_t)cols * sizeof(float);
    size_t outputBytes = (size_t)rows * sizeof(float);

    // Helper: create device-local buffer
    auto createBuf = [&](size_t size, VkBufferUsageFlags usage) -> std::pair<VkBuffer, VkDeviceMemory> {
        VkBufferCreateInfo info{};
        info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        info.size = size;
        info.usage = usage | VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
        info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        VkBuffer buf = VK_NULL_HANDLE;
        vkCreateBuffer(device_, &info, nullptr, &buf);
        VkMemoryRequirements req;
        vkGetBufferMemoryRequirements(device_, buf, &req);
        VkMemoryAllocateInfo alloc{};
        alloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        alloc.allocationSize = req.size;
        alloc.memoryTypeIndex = FindMemoryType(req.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
        VkDeviceMemory mem = VK_NULL_HANDLE;
        vkAllocateMemory(device_, &alloc, nullptr, &mem);
        vkBindBufferMemory(device_, buf, mem, 0);
        return {buf, mem};
    };

    auto [wBuf, wMem] = createBuf(weightBytes, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT);
    auto [iBuf, iMem] = createBuf(inputBytes, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT);
    auto [oBuf, oMem] = createBuf(outputBytes, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT);

    // Upload via staging
    auto upload = [&](const void* data, size_t size, VkBuffer dst) {
        VkBufferCreateInfo sinfo{};
        sinfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        sinfo.size = size;
        sinfo.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
        sinfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        VkBuffer sbuf = VK_NULL_HANDLE;
        vkCreateBuffer(device_, &sinfo, nullptr, &sbuf);
        VkMemoryRequirements sreq;
        vkGetBufferMemoryRequirements(device_, sbuf, &sreq);
        VkMemoryAllocateInfo salloc{};
        salloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        salloc.allocationSize = sreq.size;
        salloc.memoryTypeIndex = FindMemoryType(sreq.memoryTypeBits, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
        VkDeviceMemory smem = VK_NULL_HANDLE;
        vkAllocateMemory(device_, &salloc, nullptr, &smem);
        vkBindBufferMemory(device_, sbuf, smem, 0);
        void* mapped = nullptr;
        vkMapMemory(device_, smem, 0, size, 0, &mapped);
        memcpy(mapped, data, size);
        vkUnmapMemory(device_, smem);

        VkCommandBufferAllocateInfo allocInfo{};
        allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        allocInfo.commandPool = cmdPool_;
        allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        allocInfo.commandBufferCount = 1;
        VkCommandBuffer cmd = VK_NULL_HANDLE;
        vkAllocateCommandBuffers(device_, &allocInfo, &cmd);
        VkCommandBufferBeginInfo begin{};
        begin.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        vkBeginCommandBuffer(cmd, &begin);
        VkBufferCopy region{};
        region.size = size;
        vkCmdCopyBuffer(cmd, sbuf, dst, 1, &region);
        vkEndCommandBuffer(cmd);
        VkSubmitInfo submit{};
        submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        submit.commandBufferCount = 1;
        submit.pCommandBuffers = &cmd;
        vkQueueSubmit(queue_, 1, &submit, VK_NULL_HANDLE);
        vkQueueWaitIdle(queue_);
        vkFreeCommandBuffers(device_, cmdPool_, 1, &cmd);
        vkDestroyBuffer(device_, sbuf, nullptr);
        vkFreeMemory(device_, smem, nullptr);
    };

    upload(weights, weightBytes, wBuf);
    upload(input, inputBytes, iBuf);

    // Dispatch compute
    VkCommandBufferAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = cmdPool_;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;
    VkCommandBuffer cmd = VK_NULL_HANDLE;
    vkAllocateCommandBuffers(device_, &allocInfo, &cmd);

    VkDescriptorSetAllocateInfo dsAlloc{};
    dsAlloc.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    dsAlloc.descriptorPool = descPool_;
    dsAlloc.descriptorSetCount = 1;
    dsAlloc.pSetLayouts = &dsLayout_;
    VkDescriptorSet ds = VK_NULL_HANDLE;
    vkAllocateDescriptorSets(device_, &dsAlloc, &ds);

    VkDescriptorBufferInfo dbiW{wBuf, 0, weightBytes};
    VkDescriptorBufferInfo dbiI{iBuf, 0, inputBytes};
    VkDescriptorBufferInfo dbiO{oBuf, 0, outputBytes};
    VkWriteDescriptorSet writes[3] = {};
    for (int i = 0; i < 3; ++i) {
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = ds;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    }
    writes[0].dstBinding = 0; writes[0].pBufferInfo = &dbiW;
    writes[1].dstBinding = 1; writes[1].pBufferInfo = &dbiI;
    writes[2].dstBinding = 2; writes[2].pBufferInfo = &dbiO;
    vkUpdateDescriptorSets(device_, 3, writes, 0, nullptr);

    VkCommandBufferBeginInfo begin{};
    begin.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &begin);
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline_);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipelineLayout_, 0, 1, &ds, 0, nullptr);
    uint32_t push[2] = {rows, cols};
    vkCmdPushConstants(cmd, pipelineLayout_, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(push), push);
    vkCmdDispatch(cmd, (rows + 255) / 256, 1, 1);
    vkEndCommandBuffer(cmd);

    VkFence fence = VK_NULL_HANDLE;
    VkFenceCreateInfo fenceInfo{};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    vkCreateFence(device_, &fenceInfo, nullptr, &fence);
    VkSubmitInfo submit{};
    submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit.commandBufferCount = 1;
    submit.pCommandBuffers = &cmd;
    VkResult result = vkQueueSubmit(queue_, 1, &submit, fence);
    if (result != VK_SUCCESS) {
        printf("[VulkanGEMV] vkQueueSubmit failed (VkResult=%d)\n", static_cast<int>(result));
        vkDestroyFence(device_, fence, nullptr);
        vkFreeCommandBuffers(device_, cmdPool_, 1, &cmd);
        vkDestroyBuffer(device_, wBuf, nullptr); vkFreeMemory(device_, wMem, nullptr);
        vkDestroyBuffer(device_, iBuf, nullptr); vkFreeMemory(device_, iMem, nullptr);
        vkDestroyBuffer(device_, oBuf, nullptr); vkFreeMemory(device_, oMem, nullptr);
        return false;
    }
    vkWaitForFences(device_, 1, &fence, VK_TRUE, 10000000000ULL);

    // Download result
    VkBufferCreateInfo rinfo{};
    rinfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    rinfo.size = outputBytes;
    rinfo.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    rinfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    VkBuffer rbuf = VK_NULL_HANDLE;
    vkCreateBuffer(device_, &rinfo, nullptr, &rbuf);
    VkMemoryRequirements rreq;
    vkGetBufferMemoryRequirements(device_, rbuf, &rreq);
    VkMemoryAllocateInfo ralloc{};
    ralloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    ralloc.allocationSize = rreq.size;
    ralloc.memoryTypeIndex = FindMemoryType(rreq.memoryTypeBits, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    VkDeviceMemory rmem = VK_NULL_HANDLE;
    vkAllocateMemory(device_, &ralloc, nullptr, &rmem);
    vkBindBufferMemory(device_, rbuf, rmem, 0);

    VkCommandBuffer dlCmd = VK_NULL_HANDLE;
    vkAllocateCommandBuffers(device_, &allocInfo, &dlCmd);
    VkCommandBufferBeginInfo dlBegin{};
    dlBegin.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    dlBegin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(dlCmd, &dlBegin);
    VkBufferCopy dlCopy{};
    dlCopy.size = outputBytes;
    vkCmdCopyBuffer(dlCmd, oBuf, rbuf, 1, &dlCopy);
    vkEndCommandBuffer(dlCmd);
    VkSubmitInfo dlSubmit{};
    dlSubmit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    dlSubmit.commandBufferCount = 1;
    dlSubmit.pCommandBuffers = &dlCmd;
    vkQueueSubmit(queue_, 1, &dlSubmit, VK_NULL_HANDLE);
    vkQueueWaitIdle(queue_);
    void* mappedOut = nullptr;
    vkMapMemory(device_, rmem, 0, outputBytes, 0, &mappedOut);
    memcpy(output, mappedOut, outputBytes);
    vkUnmapMemory(device_, rmem);

    // Cleanup
    vkFreeCommandBuffers(device_, cmdPool_, 1, &cmd);
    vkFreeCommandBuffers(device_, cmdPool_, 1, &dlCmd);
    vkDestroyFence(device_, fence, nullptr);
    vkDestroyBuffer(device_, rbuf, nullptr);
    vkFreeMemory(device_, rmem, nullptr);
    vkDestroyBuffer(device_, wBuf, nullptr); vkFreeMemory(device_, wMem, nullptr);
    vkDestroyBuffer(device_, iBuf, nullptr); vkFreeMemory(device_, iMem, nullptr);
    vkDestroyBuffer(device_, oBuf, nullptr); vkFreeMemory(device_, oMem, nullptr);

    return true;
}

// ============================================================================
// Main test harness
// ============================================================================
int main(int argc, char** argv) {
    printf("============================================================\n");
    printf("  RawrXD Vulkan GEMV Standalone Test\n");
    printf("============================================================\n\n");

    std::string spirvPath = "D:/rawrxd/src/backend/gemv.spv";
    if (argc > 1) spirvPath = argv[1];

    MinimalVulkanGEMV vulkan;
    if (!vulkan.Initialize(spirvPath)) {
        printf("[TEST] Vulkan initialization FAILED\n");
        return 1;
    }

    // Test 1: Small GEMV (4x8)
    {
        uint32_t rows = 4, cols = 8;
        std::vector<float> weights(rows * cols);
        std::vector<float> input(cols);
        std::vector<float> output(rows);
        std::vector<float> expected(rows);

        for (uint32_t i = 0; i < rows * cols; ++i) weights[i] = (float)(i % 7) - 3.0f;
        for (uint32_t i = 0; i < cols; ++i) input[i] = (float)(i % 5) - 2.0f;

        cpuGemv(weights.data(), input.data(), expected.data(), rows, cols);
        bool ok = vulkan.Dispatch(weights.data(), input.data(), output.data(), rows, cols);
        if (!ok) {
            printf("[TEST 1] Dispatch FAILED\n");
            vulkan.Shutdown();
            return 1;
        }

        bool match = true;
        float maxErr = 0.0f;
        for (uint32_t i = 0; i < rows; ++i) {
            float err = std::fabs(output[i] - expected[i]);
            if (err > maxErr) maxErr = err;
            if (!nearlyEqual(output[i], expected[i], 1e-4f)) {
                match = false;
                printf("[TEST 1] Mismatch at %u: GPU=%.6f CPU=%.6f\n", i, output[i], expected[i]);
            }
        }
        if (match) {
            printf("[TEST 1] PASS  (4x8 GEMV, maxErr=%.6e)\n", maxErr);
        } else {
            printf("[TEST 1] FAIL  (4x8 GEMV)\n");
            vulkan.Shutdown();
            return 1;
        }
    }

    // Test 2: Medium GEMV (256x512) — representative of transformer hidden dim
    {
        uint32_t rows = 256, cols = 512;
        std::vector<float> weights(rows * cols);
        std::vector<float> input(cols);
        std::vector<float> output(rows);
        std::vector<float> expected(rows);

        for (uint32_t i = 0; i < rows * cols; ++i) weights[i] = (float)(rand() % 100) / 100.0f - 0.5f;
        for (uint32_t i = 0; i < cols; ++i) input[i] = (float)(rand() % 100) / 100.0f - 0.5f;

        cpuGemv(weights.data(), input.data(), expected.data(), rows, cols);
        bool ok = vulkan.Dispatch(weights.data(), input.data(), output.data(), rows, cols);
        if (!ok) {
            printf("[TEST 2] Dispatch FAILED\n");
            vulkan.Shutdown();
            return 1;
        }

        bool match = true;
        float maxErr = 0.0f;
        for (uint32_t i = 0; i < rows; ++i) {
            float err = std::fabs(output[i] - expected[i]);
            if (err > maxErr) maxErr = err;
            if (!nearlyEqual(output[i], expected[i], 1e-3f)) {
                match = false;
                if (i < 5) {
                    printf("[TEST 2] Mismatch at %u: GPU=%.6f CPU=%.6f\n", i, output[i], expected[i]);
                }
            }
        }
        if (match) {
            printf("[TEST 2] PASS  (256x512 GEMV, maxErr=%.6e)\n", maxErr);
        } else {
            printf("[TEST 2] FAIL  (256x512 GEMV, maxErr=%.6e)\n", maxErr);
            vulkan.Shutdown();
            return 1;
        }
    }

    // Test 3: Large GEMV (4096x4096) — LM head size
    {
        uint32_t rows = 4096, cols = 4096;
        std::vector<float> weights(rows * cols);
        std::vector<float> input(cols);
        std::vector<float> output(rows);
        std::vector<float> expected(rows);

        for (uint32_t i = 0; i < rows * cols; ++i) weights[i] = (float)(rand() % 100) / 100.0f - 0.5f;
        for (uint32_t i = 0; i < cols; ++i) input[i] = (float)(rand() % 100) / 100.0f - 0.5f;

        cpuGemv(weights.data(), input.data(), expected.data(), rows, cols);
        bool ok = vulkan.Dispatch(weights.data(), input.data(), output.data(), rows, cols);
        if (!ok) {
            printf("[TEST 3] Dispatch FAILED\n");
            vulkan.Shutdown();
            return 1;
        }

        bool match = true;
        float maxErr = 0.0f;
        for (uint32_t i = 0; i < rows; ++i) {
            float err = std::fabs(output[i] - expected[i]);
            if (err > maxErr) maxErr = err;
            if (!nearlyEqual(output[i], expected[i], 1e-3f)) {
                match = false;
                if (i < 5) {
                    printf("[TEST 3] Mismatch at %u: GPU=%.6f CPU=%.6f\n", i, output[i], expected[i]);
                }
            }
        }
        if (match) {
            printf("[TEST 3] PASS  (4096x4096 GEMV, maxErr=%.6e)\n", maxErr);
        } else {
            printf("[TEST 3] FAIL  (4096x4096 GEMV, maxErr=%.6e)\n", maxErr);
            vulkan.Shutdown();
            return 1;
        }
    }

    vulkan.Shutdown();
    printf("\n============================================================\n");
    printf("  ALL TESTS PASSED\n");
    printf("============================================================\n");
    return 0;
}
