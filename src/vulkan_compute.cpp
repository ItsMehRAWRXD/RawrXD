// Path-qualified for the same reason quant_dot_dispatch.cpp qualifies its
// include: a bare "vulkan_compute.h" resolves to the THIS file's directory
// first and then to whatever comes first on the include path, and
// src/deep2/vulkan_compute.h defines a DIFFERENT class (Deep2::VulkanCompute)
// that silently shadows the device-level ::VulkanCompute implemented here.
// Qualifying the path pins the header to include/vulkan_compute.h.
#include "include/vulkan_compute.h"
#include <vulkan/vulkan.h>
#include <iostream>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <cmath>
#include <cstring>

VulkanCompute::VulkanCompute()
    : instance_(nullptr), physical_device_(nullptr), device_(nullptr),
      command_pool_(nullptr), compute_queue_(nullptr) {
    std::memset(&device_info_, 0, sizeof(VulkanDeviceInfo));
}

VulkanCompute::~VulkanCompute() {
    Cleanup();
}

bool VulkanCompute::Initialize() {
    if (!CreateInstance()) {
        std::cerr << "Failed to create Vulkan instance" << std::endl;
        return false;
    }
    
    if (!SelectPhysicalDevice()) {
        std::cerr << "Failed to select physical device" << std::endl;
        return false;
    }
    
    if (!CreateLogicalDevice()) {
        std::cerr << "Failed to create logical device" << std::endl;
        return false;
    }
    
    if (!CreateCommandPool()) {
        std::cerr << "Failed to create command pool" << std::endl;
        return false;
    }
    
    // Initialize async command buffer pool
    InitializeCommandBufferPool(4);  // Start with 4 reusable command buffers
    
    std::cout << "Vulkan initialized successfully on device: " << device_info_.device_name << std::endl;
    std::cout << "AMD Device: " << (IsAMDDevice() ? "Yes" : "No") << std::endl;
    std::cout << "Compute Queue Family: " << device_info_.compute_queue_family << std::endl;
    
    return true;
}

void VulkanCompute::InitializeCommandBufferPool(uint32_t pool_size) {
    command_buffer_pool_.resize(pool_size);
    
    VkCommandBufferAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    alloc_info.commandPool = command_pool_;
    alloc_info.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    alloc_info.commandBufferCount = pool_size;
    
    std::vector<VkCommandBuffer> buffers(pool_size);
    if (vkAllocateCommandBuffers(device_, &alloc_info, buffers.data()) != VK_SUCCESS) {
        std::cerr << "Failed to allocate command buffers for pool" << std::endl;
        return;
    }
    
    // Create fences and populate pool
    for (uint32_t i = 0; i < pool_size; ++i) {
        VkFenceCreateInfo fence_info{};
        fence_info.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        fence_info.flags = VK_FENCE_CREATE_SIGNALED_BIT;  // Start signaled (available)
        
        if (vkCreateFence(device_, &fence_info, nullptr, &command_buffer_pool_[i].fence) != VK_SUCCESS) {
            std::cerr << "Failed to create fence for command buffer pool" << std::endl;
            return;
        }
        
        command_buffer_pool_[i].buffer = buffers[i];
        command_buffer_pool_[i].is_available = true;
        available_buffer_indices_.push(i);
    }
    
    std::cout << "Initialized command buffer pool with " << pool_size << " buffers" << std::endl;
}

void VulkanCompute::CleanupCommandBufferPool() {
    for (auto& cmd_buf : command_buffer_pool_) {
        if (cmd_buf.fence) {
            vkDestroyFence(device_, cmd_buf.fence, nullptr);
        }
    }
    command_buffer_pool_.clear();
    while (!available_buffer_indices_.empty()) {
        available_buffer_indices_.pop();
    }
}

VkCommandBuffer VulkanCompute::AcquireAsyncCommandBuffer() {
    // Try to find available command buffer
    while (!available_buffer_indices_.empty()) {
        size_t idx = available_buffer_indices_.front();
        available_buffer_indices_.pop();
        
        // Check if fence is complete (non-blocking)
        VkResult result = vkGetFenceStatus(device_, command_buffer_pool_[idx].fence);
        if (result == VK_SUCCESS) {
            // Fence is signaled, buffer is available
            command_buffer_pool_[idx].is_available = false;
            
            // Reset fence for next submission
            vkResetFences(device_, 1, &command_buffer_pool_[idx].fence);
            
            // Reset command buffer for reuse
            vkResetCommandBuffer(command_buffer_pool_[idx].buffer, VK_COMMAND_BUFFER_RESET_RELEASE_RESOURCES_BIT);
            
            return command_buffer_pool_[idx].buffer;
        } else if (result == VK_NOT_READY) {
            // Buffer still in use, put it back and try next
            available_buffer_indices_.push(idx);
        }
    }
    
    // No buffers available - need to wait (shouldn't happen with adequate pool size)
    std::cerr << "WARNING: All command buffers in use, this may cause stalls. Increase pool size." << std::endl;
    return nullptr;
}

bool VulkanCompute::SubmitAsyncCommandBuffer(VkCommandBuffer cmd_buffer) {
    // Find which pool entry this is
    int pool_idx = -1;
    for (size_t i = 0; i < command_buffer_pool_.size(); ++i) {
        if (command_buffer_pool_[i].buffer == cmd_buffer) {
            pool_idx = i;
            break;
        }
    }
    
    if (pool_idx < 0) {
        std::cerr << "Command buffer not from pool" << std::endl;
        return false;
    }
    
    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &cmd_buffer;
    
    if (vkQueueSubmit(compute_queue_, 1, &submit_info, command_buffer_pool_[pool_idx].fence) != VK_SUCCESS) {
        std::cerr << "Failed to submit command buffer" << std::endl;
        return false;
    }
    
    return true;
}

bool VulkanCompute::FlushAsyncCommands() {
    // Wait for all command buffers to complete
    std::vector<VkFence> all_fences;
    for (auto& cmd_buf : command_buffer_pool_) {
        if (!cmd_buf.is_available) {
            all_fences.push_back(cmd_buf.fence);
        }
    }
    
    if (all_fences.empty()) {
        return true;  // Nothing to wait for
    }
    
    if (vkWaitForFences(device_, (uint32_t)all_fences.size(), all_fences.data(), VK_TRUE, UINT64_MAX) != VK_SUCCESS) {
        std::cerr << "Failed to wait for async command buffers" << std::endl;
        return false;
    }
    
    // Reset all fences after successful wait
    vkResetFences(device_, (uint32_t)all_fences.size(), all_fences.data());
    
    // Clear and repopulate available indices (simplified management)
    while (!available_buffer_indices_.empty()) {
        available_buffer_indices_.pop();
    }
    
    // Mark all as available and rebuild queue
    for (size_t i = 0; i < command_buffer_pool_.size(); ++i) {
        command_buffer_pool_[i].is_available = true;
        available_buffer_indices_.push(i);
    }
    
    return true;
}

bool VulkanCompute::CheckAsyncCompletion(VkCommandBuffer cmd_buffer) {
    // Find which pool entry this is
    int pool_idx = -1;
    for (size_t i = 0; i < command_buffer_pool_.size(); ++i) {
        if (command_buffer_pool_[i].buffer == cmd_buffer) {
            pool_idx = i;
            break;
        }
    }
    
    if (pool_idx < 0) {
        return false;
    }
    
    return vkGetFenceStatus(device_, command_buffer_pool_[pool_idx].fence) == VK_SUCCESS;
}

bool VulkanCompute::ExecuteSingleTimeCommands(std::function<void(VkCommandBuffer)> record_func) {
    // Allocate a one-time command buffer
    VkCommandBufferAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    alloc_info.commandPool = command_pool_;
    alloc_info.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    alloc_info.commandBufferCount = 1;

    VkCommandBuffer command_buffer;
    if (vkAllocateCommandBuffers(device_, &alloc_info, &command_buffer) != VK_SUCCESS) {
        std::cerr << "Failed to allocate command buffer" << std::endl;
        return false;
    }

    // Begin recording
    VkCommandBufferBeginInfo begin_info{};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;

    if (vkBeginCommandBuffer(command_buffer, &begin_info) != VK_SUCCESS) {
        std::cerr << "Failed to begin command buffer recording" << std::endl;
        vkFreeCommandBuffers(device_, command_pool_, 1, &command_buffer);
        return false;
    }

    // Execute the recording function
    record_func(command_buffer);

    // End recording
    if (vkEndCommandBuffer(command_buffer) != VK_SUCCESS) {
        std::cerr << "Failed to end command buffer recording" << std::endl;
        vkFreeCommandBuffers(device_, command_pool_, 1, &command_buffer);
        return false;
    }

    // Submit and wait for completion
    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &command_buffer;

    VkFenceCreateInfo fence_info{};
    fence_info.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;

    VkFence fence;
    if (vkCreateFence(device_, &fence_info, nullptr, &fence) != VK_SUCCESS) {
        std::cerr << "Failed to create fence" << std::endl;
        vkFreeCommandBuffers(device_, command_pool_, 1, &command_buffer);
        return false;
    }

    if (vkQueueSubmit(compute_queue_, 1, &submit_info, fence) != VK_SUCCESS) {
        std::cerr << "Failed to submit command buffer" << std::endl;
        vkDestroyFence(device_, fence, nullptr);
        vkFreeCommandBuffers(device_, command_pool_, 1, &command_buffer);
        return false;
    }
    ++gpu_counters_.submits;

    // Wait for fence
    const auto wait_begin = std::chrono::steady_clock::now();
    if (vkWaitForFences(device_, 1, &fence, VK_TRUE, UINT64_MAX) != VK_SUCCESS) {
        std::cerr << "Failed to wait for fence" << std::endl;
        vkDestroyFence(device_, fence, nullptr);
        vkFreeCommandBuffers(device_, command_pool_, 1, &command_buffer);
        return false;
    }
    const auto wait_end = std::chrono::steady_clock::now();
    ++gpu_counters_.waits;
    gpu_counters_.wait_ms += std::chrono::duration<double, std::milli>(wait_end - wait_begin).count();
    // The queue-side execution of this submission is the interval between the
    // submit and the fence signalling; the wait duration is its host-visible
    // component.
    gpu_counters_.kernel_ms += std::chrono::duration<double, std::milli>(wait_end - wait_begin).count();

    // Cleanup
    vkDestroyFence(device_, fence, nullptr);
    vkFreeCommandBuffers(device_, command_pool_, 1, &command_buffer);

    return true;
}

bool VulkanCompute::ExecuteCommandBuffer(VkCommandBuffer cmd_buffer) {
    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &cmd_buffer;

    VkFenceCreateInfo fence_info{};
    fence_info.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;

    VkFence fence;
    if (vkCreateFence(device_, &fence_info, nullptr, &fence) != VK_SUCCESS) {
        std::cerr << "Failed to create fence" << std::endl;
        return false;
    }

    if (vkQueueSubmit(compute_queue_, 1, &submit_info, fence) != VK_SUCCESS) {
        std::cerr << "Failed to submit command buffer" << std::endl;
        vkDestroyFence(device_, fence, nullptr);
        return false;
    }

    // Wait for fence with timeout of 5 seconds
    VkResult wait_result = vkWaitForFences(device_, 1, &fence, VK_TRUE, 5000000000ULL);
    if (wait_result != VK_SUCCESS) {
        std::cerr << "Command buffer execution timeout or failed" << std::endl;
        vkDestroyFence(device_, fence, nullptr);
        return false;
    }

    vkDestroyFence(device_, fence, nullptr);
    return true;
}

bool VulkanCompute::CreateInstance() {
    VkApplicationInfo app_info{};
    app_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app_info.pApplicationName = "RawrXD-ModelLoader";
    app_info.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.pEngineName = "RawrXD";
    app_info.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.apiVersion = VK_API_VERSION_1_3;

    VkInstanceCreateInfo create_info{};
    create_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    create_info.pApplicationInfo = &app_info;

    if (vkCreateInstance(&create_info, nullptr, &instance_) != VK_SUCCESS) {
        std::cerr << "Failed to create Vulkan instance" << std::endl;
        return false;
    }

    return true;
}

std::vector<VulkanCompute::EnumeratedDevice> VulkanCompute::EnumerateDevices() {
    std::vector<EnumeratedDevice> out;

    VkApplicationInfo app{};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = "RawrXD-Enumerate";
    app.apiVersion = VK_API_VERSION_1_1;

    VkInstanceCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo = &app;

    VkInstance inst = VK_NULL_HANDLE;
    if (vkCreateInstance(&ci, nullptr, &inst) != VK_SUCCESS) return out;

    uint32_t n = 0;
    vkEnumeratePhysicalDevices(inst, &n, nullptr);
    if (n == 0) { vkDestroyInstance(inst, nullptr); return out; }

    std::vector<VkPhysicalDevice> devs(n);
    vkEnumeratePhysicalDevices(inst, &n, devs.data());

    out.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        VkPhysicalDeviceProperties p{};
        vkGetPhysicalDeviceProperties(devs[i], &p);
        EnumeratedDevice e;
        e.index = (int32_t)i;
        e.name = p.deviceName;
        e.vendor_id = p.vendorID;
        e.device_id = p.deviceID;
        e.device_type = p.deviceType;
        out.push_back(e);
    }

    vkDestroyInstance(inst, nullptr);
    return out;
}

bool VulkanCompute::SelectPhysicalDevice() {
    uint32_t device_count = 0;
    vkEnumeratePhysicalDevices(instance_, &device_count, nullptr);
    
    if (device_count == 0) {
        std::cerr << "No Vulkan devices found" << std::endl;
        return false;
    }

    std::vector<VkPhysicalDevice> devices(device_count);
    vkEnumeratePhysicalDevices(instance_, &device_count, devices.data());

    // Prefer AMD devices, then other discrete GPUs
    int best_device_idx = -1;
    int best_device_score = -1;

    for (uint32_t i = 0; i < device_count; ++i) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(devices[i], &props);

        uint32_t vendor_id = props.vendorID;
        int score = 0;

        // AMD RDNA3 (7800XT is vendor 0x1002)
        if (vendor_id == 0x1002) {
            score = 100;  // Highest priority
        } else if (vendor_id == 0x10DE) {
            score = 80;   // Nvidia
        } else if (vendor_id == 0x8086) {
            score = 60;   // Intel
        } else if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) {
            score = 50;
        } else if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU) {
            score = 30;
        }

        if (score > best_device_score) {
            best_device_score = score;
            best_device_idx = i;
        }

        std::cout << "Found device " << i << ": " << props.deviceName
                  << " (Vendor: 0x" << std::hex << vendor_id << std::dec
                  << ", Score: " << score << ")" << std::endl;
    }

    // Multi-GPU: honour an explicit device index when one was requested.
    // This lets a single process drive more than one GPU.
    if (preferred_device_index_ >= 0 &&
        (uint32_t)preferred_device_index_ < device_count) {
        best_device_idx = preferred_device_index_;
        std::cout << "Pinning to requested device index " << best_device_idx << std::endl;
    }

    if (best_device_idx < 0) {
        std::cerr << "No suitable device found" << std::endl;
        return false;
    }

    physical_device_ = devices[best_device_idx];
    active_device_index_ = best_device_idx;
    vkGetPhysicalDeviceProperties(physical_device_, &device_info_.properties);
    vkGetPhysicalDeviceMemoryProperties(physical_device_, &device_info_.memory_props);
    
    device_info_.device_name = device_info_.properties.deviceName;
    device_info_.vendor_id = device_info_.properties.vendorID;
    device_info_.device_id = device_info_.properties.deviceID;

    std::cout << "Selected device: " << device_info_.device_name << std::endl;

    return true;
}

bool VulkanCompute::CreateLogicalDevice() {
    // Find compute queue family
    uint32_t queue_family_count = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(physical_device_, &queue_family_count, nullptr);

    std::vector<VkQueueFamilyProperties> queue_families(queue_family_count);
    vkGetPhysicalDeviceQueueFamilyProperties(physical_device_, &queue_family_count, queue_families.data());

    int compute_queue_family = -1;
    for (uint32_t i = 0; i < queue_family_count; ++i) {
        if (queue_families[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            compute_queue_family = i;
            break;
        }
    }

    if (compute_queue_family < 0) {
        std::cerr << "No compute queue family found" << std::endl;
        return false;
    }

    device_info_.compute_queue_family = compute_queue_family;
    device_info_.supports_compute = true;

    float queue_priority = 1.0f;
    VkDeviceQueueCreateInfo queue_create_info{};
    queue_create_info.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queue_create_info.queueFamilyIndex = compute_queue_family;
    queue_create_info.queueCount = 1;
    queue_create_info.pQueuePriorities = &queue_priority;

    VkDeviceCreateInfo device_create_info{};
    device_create_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    device_create_info.queueCreateInfoCount = 1;
    device_create_info.pQueueCreateInfos = &queue_create_info;

    if (vkCreateDevice(physical_device_, &device_create_info, nullptr, &device_) != VK_SUCCESS) {
        std::cerr << "Failed to create logical device" << std::endl;
        return false;
    }

    vkGetDeviceQueue(device_, compute_queue_family, 0, &compute_queue_);

    return true;
}

bool VulkanCompute::CreateCommandPool() {
    VkCommandPoolCreateInfo pool_info{};
    pool_info.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_info.queueFamilyIndex = device_info_.compute_queue_family;
    pool_info.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;

    if (vkCreateCommandPool(device_, &pool_info, nullptr, &command_pool_) != VK_SUCCESS) {
        std::cerr << "Failed to create command pool" << std::endl;
        return false;
    }

    return true;
}

bool VulkanCompute::LoadShader(const std::string& name, const std::string& spirv_path) {
    std::vector<uint32_t> spirv_code;
    if (!LoadSPIRVCode(spirv_path, spirv_code)) {
        std::cerr << "Failed to load SPIR-V code: " << spirv_path << std::endl;
        return false;
    }

    VkShaderModuleCreateInfo create_info{};
    create_info.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    create_info.codeSize = spirv_code.size() * sizeof(uint32_t);
    create_info.pCode = spirv_code.data();

    ComputeShader shader;
    shader.name = name;
    shader.spirv_code = spirv_code;

    if (vkCreateShaderModule(device_, &create_info, nullptr, &shader.module) != VK_SUCCESS) {
        std::cerr << "Failed to create shader module: " << name << std::endl;
        return false;
    }

    shaders_[name] = std::move(shader);
    std::cout << "Loaded shader: " << name << std::endl;

    return true;
}

bool VulkanCompute::CreateComputePipeline(const std::string& shader_name) {
    auto it = shaders_.find(shader_name);
    if (it == shaders_.end()) {
        std::cerr << "Shader not found: " << shader_name << std::endl;
        return false;
    }

    VkPipelineLayoutCreateInfo pipeline_layout_info{};
    pipeline_layout_info.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;

    if (vkCreatePipelineLayout(device_, &pipeline_layout_info, nullptr, &it->second.layout) != VK_SUCCESS) {
        std::cerr << "Failed to create pipeline layout: " << shader_name << std::endl;
        return false;
    }

    VkPipelineShaderStageCreateInfo stage_info{};
    stage_info.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stage_info.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stage_info.module = it->second.module;
    stage_info.pName = "main";

    VkComputePipelineCreateInfo compute_pipeline_info{};
    compute_pipeline_info.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    compute_pipeline_info.layout = it->second.layout;
    compute_pipeline_info.stage = stage_info;

    if (vkCreateComputePipelines(device_, nullptr, 1, &compute_pipeline_info, nullptr, &it->second.pipeline) != VK_SUCCESS) {
        std::cerr << "Failed to create compute pipeline: " << shader_name << std::endl;
        return false;
    }

    std::cout << "Created compute pipeline: " << shader_name << std::endl;
    return true;
}

bool VulkanCompute::AllocateBuffer(size_t size, VkBuffer& buffer, VkDeviceMemory& memory) {
    VkBufferCreateInfo buffer_info{};
    buffer_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    buffer_info.size = size;
    buffer_info.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;

    if (vkCreateBuffer(device_, &buffer_info, nullptr, &buffer) != VK_SUCCESS) {
        std::cerr << "Failed to create buffer" << std::endl;
        return false;
    }

    VkMemoryRequirements mem_requirements;
    vkGetBufferMemoryRequirements(device_, buffer, &mem_requirements);

    VkMemoryAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc_info.allocationSize = mem_requirements.size;
    alloc_info.memoryTypeIndex = FindMemoryType(mem_requirements.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);

    if (vkAllocateMemory(device_, &alloc_info, nullptr, &memory) != VK_SUCCESS) {
        std::cerr << "Failed to allocate memory" << std::endl;
        vkDestroyBuffer(device_, buffer, nullptr);
        return false;
    }

    vkBindBufferMemory(device_, buffer, memory, 0);
    return true;
}

// ==================== STAGING BUFFER HELPER ====================
bool VulkanCompute::CreateStagingBuffer(size_t size, VkBuffer& buffer, VkDeviceMemory& memory) {
    // Create staging buffer with host-accessible memory
    VkBufferCreateInfo buffer_info{};
    buffer_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    buffer_info.size = size;
    buffer_info.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;

    if (vkCreateBuffer(device_, &buffer_info, nullptr, &buffer) != VK_SUCCESS) {
        std::cerr << "Failed to create staging buffer" << std::endl;
        return false;
    }

    VkMemoryRequirements mem_requirements;
    vkGetBufferMemoryRequirements(device_, buffer, &mem_requirements);

    VkMemoryAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc_info.allocationSize = mem_requirements.size;
    alloc_info.memoryTypeIndex = FindMemoryType(mem_requirements.memoryTypeBits,
                                              VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);

    if (vkAllocateMemory(device_, &alloc_info, nullptr, &memory) != VK_SUCCESS) {
        std::cerr << "Failed to allocate staging memory" << std::endl;
        vkDestroyBuffer(device_, buffer, nullptr);
        return false;
    }

    vkBindBufferMemory(device_, buffer, memory, 0);
    return true;
}
// ==================== END STAGING BUFFER HELPER ====================

bool VulkanCompute::AllocateBuffer(size_t size, uint32_t& buffer_idx, size_t& memory_size) {
    VkBuffer buffer;
    VkDeviceMemory memory;

    if (!AllocateBuffer(size, buffer, memory)) {
        return false;
    }

    buffer_idx = static_cast<uint32_t>(allocated_buffers_.size());
    allocated_buffers_.push_back(std::make_pair(buffer, memory));
    memory_size = size;

    // RAWRXD_DEEP2_TPS_AND_CERTIFICATION_RECOVERY: every allocation is
    // accounted so residency and churn are measurable. The quant-dot fast path
    // must not land here on the steady-state decode path.
    ++gpu_counters_.buffer_allocations;
    gpu_counters_.device_bytes_live += size;
    if (gpu_counters_.device_bytes_live > gpu_counters_.device_bytes_peak)
        gpu_counters_.device_bytes_peak = gpu_counters_.device_bytes_live;
    if (std::getenv("RR_VULKAN_VERBOSE"))
        std::cout << "Allocated buffer " << buffer_idx << " with " << size << " bytes" << std::endl;
    return true;
}

bool VulkanCompute::CopyBufferToHost(VkBuffer device_buffer, void* host_data, size_t size) {
    // Create staging buffer using helper
    VkBuffer staging_buffer;
    VkDeviceMemory staging_memory;

    if (!CreateStagingBuffer(size, staging_buffer, staging_memory)) {
        return false;
    }
    gpu_counters_.download_bytes += size;

    // Record copy command from device buffer to staging buffer
    if (!ExecuteSingleTimeCommands([&](VkCommandBuffer cmd_buffer) {
        VkBufferCopy copy_region{};
        copy_region.srcOffset = 0;
        copy_region.dstOffset = 0;
        copy_region.size = size;
        vkCmdCopyBuffer(cmd_buffer, device_buffer, staging_buffer, 1, &copy_region);
    })) {
        std::cerr << "Failed to copy buffer from device to host" << std::endl;
        vkDestroyBuffer(device_, staging_buffer, nullptr);
        vkFreeMemory(device_, staging_memory, nullptr);
        return false;
    }

    // Map and read staging buffer
    void* mapped_data;
    if (vkMapMemory(device_, staging_memory, 0, size, 0, &mapped_data) != VK_SUCCESS) {
        std::cerr << "Failed to map staging memory" << std::endl;
        vkDestroyBuffer(device_, staging_buffer, nullptr);
        vkFreeMemory(device_, staging_memory, nullptr);
        return false;
    }

    std::memcpy(host_data, mapped_data, size);
    vkUnmapMemory(device_, staging_memory);

    // Cleanup staging buffer
    vkDestroyBuffer(device_, staging_buffer, nullptr);
    vkFreeMemory(device_, staging_memory, nullptr);

    return true;
}

bool VulkanCompute::CopyBufferToHost(uint32_t buffer_idx, void* host_data, size_t size) {
    if (buffer_idx >= allocated_buffers_.size()) {
        std::cerr << "Invalid buffer index: " << buffer_idx << std::endl;
        return false;
    }
    
    return CopyBufferToHost(allocated_buffers_[buffer_idx].first, host_data, size);
}

bool VulkanCompute::CopyHostToBuffer(void* host_data, VkBuffer device_buffer, size_t size) {
    // Create staging buffer using helper
    VkBuffer staging_buffer;
    VkDeviceMemory staging_memory;

    if (!CreateStagingBuffer(size, staging_buffer, staging_memory)) {
        return false;
    }
    gpu_counters_.upload_bytes += size;

    // Map and copy host data to staging buffer
    void* mapped_data;
    if (vkMapMemory(device_, staging_memory, 0, size, 0, &mapped_data) != VK_SUCCESS) {
        std::cerr << "Failed to map staging memory" << std::endl;
        vkDestroyBuffer(device_, staging_buffer, nullptr);
        vkFreeMemory(device_, staging_memory, nullptr);
        return false;
    }

    std::memcpy(mapped_data, host_data, size);
    vkUnmapMemory(device_, staging_memory);

    // Record copy command from staging buffer to device buffer
    if (!ExecuteSingleTimeCommands([&](VkCommandBuffer cmd_buffer) {
        VkBufferCopy copy_region{};
        copy_region.srcOffset = 0;
        copy_region.dstOffset = 0;
        copy_region.size = size;
        vkCmdCopyBuffer(cmd_buffer, staging_buffer, device_buffer, 1, &copy_region);
    })) {
        std::cerr << "Failed to copy buffer from host to device" << std::endl;
        vkDestroyBuffer(device_, staging_buffer, nullptr);
        vkFreeMemory(device_, staging_memory, nullptr);
        return false;
    }

    // Cleanup staging buffer
    vkDestroyBuffer(device_, staging_buffer, nullptr);
    vkFreeMemory(device_, staging_memory, nullptr);

    return true;
}

bool VulkanCompute::CopyHostToBuffer(void* host_data, uint32_t buffer_idx, size_t size) {
    if (buffer_idx >= allocated_buffers_.size()) {
        std::cerr << "Invalid buffer index: " << buffer_idx << std::endl;
        return false;
    }
    
    return CopyHostToBuffer(host_data, allocated_buffers_[buffer_idx].first, size);
}

VulkanTensor VulkanCompute::TransferGGUFTensor(const std::string& tensor_name,
                                               const void* data_ptr,
                                               size_t size_bytes,
                                               uint32_t usage) {
    VulkanTensor tensor;
    tensor.name = tensor_name;
    tensor.size_bytes = size_bytes;
    
    // Copy data to host memory
    tensor.host_data.resize(size_bytes / sizeof(float));
    std::memcpy(tensor.host_data.data(), data_ptr, size_bytes);
    
    // Allocate device buffer
    if (!AllocateBuffer(size_bytes, tensor.device_buffer, tensor.device_memory)) {
        std::cerr << "Failed to allocate device buffer for tensor: " << tensor_name << std::endl;
        return tensor;
    }
    
    // Copy host data to device
    if (!CopyHostToBuffer(tensor.host_data.data(), tensor.device_buffer, size_bytes)) {
        std::cerr << "Failed to transfer tensor to device: " << tensor_name << std::endl;
        return tensor;
    }
    
    uploaded_tensors_.push_back(tensor);
    std::cout << "Transferred tensor '" << tensor_name << "' (" << size_bytes << " bytes) to device" << std::endl;
    
    return tensor;
}

void VulkanCompute::ReleaseTensors() {
    for (auto& tensor : uploaded_tensors_) {
        if (tensor.device_buffer) {
            vkDestroyBuffer(device_, tensor.device_buffer, nullptr);
        }
        if (tensor.device_memory) {
            vkFreeMemory(device_, tensor.device_memory, nullptr);
        }
    }
    uploaded_tensors_.clear();
    std::cout << "Released all tensors" << std::endl;
}

bool VulkanCompute::EnsureMatMulPipeline(const std::string& spirv_path) {
    // Check if matmul pipeline already exists
    auto it = shaders_.find("matmul");
    if (it != shaders_.end() && it->second.pipeline && matmul_descriptor_set_layout_ && matmul_descriptor_pool_) {
        return true;  // Already fully initialized
    }
    
    // 1. Load Shader
    if (!LoadShader("matmul", spirv_path)) {
        std::cerr << "Failed to load matmul shader from: " << spirv_path << std::endl;
        return false;
    }
    
    // Get the shader iterator again after loading
    it = shaders_.find("matmul");
    if (it == shaders_.end()) {
        std::cerr << "Shader not found after loading" << std::endl;
        return false;
    }
    
    // --- 2. Create PERMANENT Descriptor Set Layout (Bindings 0, 1, 2 for A, B, Output) ---
    std::vector<VkDescriptorSetLayoutBinding> bindings(3);
    for (uint32_t i = 0; i < 3; ++i) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
        bindings[i].pImmutableSamplers = nullptr;
    }
    
    VkDescriptorSetLayoutCreateInfo layout_info{};
    layout_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layout_info.bindingCount = 3;
    layout_info.pBindings = bindings.data();

    if (vkCreateDescriptorSetLayout(device_, &layout_info, nullptr, &matmul_descriptor_set_layout_) != VK_SUCCESS) {
        std::cerr << "Failed to create MatMul descriptor set layout!" << std::endl;
        return false;
    }
    std::cout << "Created permanent MatMul descriptor set layout" << std::endl;

    // --- 3. Create PERMANENT Descriptor Pool ---
    VkDescriptorPoolSize pool_size{};
    pool_size.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    pool_size.descriptorCount = 30;  // Max 10 simultaneous MatMul sets (3 buffers each)
    
    VkDescriptorPoolCreateInfo pool_info{};
    pool_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    pool_info.poolSizeCount = 1;
    pool_info.pPoolSizes = &pool_size;
    pool_info.maxSets = 10;  // Max 10 descriptor sets
    
    if (vkCreateDescriptorPool(device_, &pool_info, nullptr, &matmul_descriptor_pool_) != VK_SUCCESS) {
        std::cerr << "Failed to create MatMul descriptor pool!" << std::endl;
        vkDestroyDescriptorSetLayout(device_, matmul_descriptor_set_layout_, nullptr);
        matmul_descriptor_set_layout_ = nullptr;
        return false;
    }
    std::cout << "Created permanent MatMul descriptor pool" << std::endl;
    
    // --- 4. Create Pipeline Layout (using the permanent layout with Push Constants) ---
    VkPushConstantRange push_constant{};
    push_constant.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    push_constant.offset = 0;
    push_constant.size = sizeof(uint32_t) * 3;  // For M, K, N
    
    VkPipelineLayoutCreateInfo pipeline_layout_info{};
    pipeline_layout_info.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pipeline_layout_info.setLayoutCount = 1;
    pipeline_layout_info.pSetLayouts = &matmul_descriptor_set_layout_;
    pipeline_layout_info.pushConstantRangeCount = 1;
    pipeline_layout_info.pPushConstantRanges = &push_constant;

    if (vkCreatePipelineLayout(device_, &pipeline_layout_info, nullptr, &it->second.layout) != VK_SUCCESS) {
        std::cerr << "Failed to create MatMul pipeline layout" << std::endl;
        vkDestroyDescriptorSetLayout(device_, matmul_descriptor_set_layout_, nullptr);
        vkDestroyDescriptorPool(device_, matmul_descriptor_pool_, nullptr);
        matmul_descriptor_set_layout_ = nullptr;
        matmul_descriptor_pool_ = nullptr;
        return false;
    }
    std::cout << "Created MatMul pipeline layout with push constants" << std::endl;
    
    // --- 5. Create Compute Pipeline ---
    VkPipelineShaderStageCreateInfo stage_info{};
    stage_info.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stage_info.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stage_info.module = it->second.module;
    stage_info.pName = "main";

    VkComputePipelineCreateInfo compute_pipeline_info{};
    compute_pipeline_info.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    compute_pipeline_info.layout = it->second.layout;
    compute_pipeline_info.stage = stage_info;

    if (vkCreateComputePipelines(device_, nullptr, 1, &compute_pipeline_info, nullptr, &it->second.pipeline) != VK_SUCCESS) {
        std::cerr << "Failed to create MatMul compute pipeline" << std::endl;
        return false;
    }

    std::cout << "MatMul pipeline and permanent descriptor system initialized successfully" << std::endl;
    return true;
}

bool VulkanCompute::EnsureRoPEPipeline(const std::string& spirv_path) {
    if (shaders_.count("rope") &&
        shaders_["rope"].pipeline &&
        rope_descriptor_set_layout_ &&
        rope_descriptor_pool_) {
        return true;   // already initialised
    }

    // Load SPIR-V.
    std::vector<uint32_t> code;
    if (!LoadSPIRVCode(spirv_path, code) || code.empty()) {
        std::cerr << "Failed to load RoPE SPIR-V: " << spirv_path << std::endl;
        return false;
    }

    VkShaderModuleCreateInfo sm{};
    sm.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    sm.codeSize = code.size() * sizeof(uint32_t);
    sm.pCode = code.data();

    ComputeShader cs;
    cs.name = "rope";
    cs.spirv_code = code;
    if (vkCreateShaderModule(device_, &sm, nullptr, &cs.module) != VK_SUCCESS) {
        std::cerr << "Failed to create RoPE shader module" << std::endl;
        return false;
    }

    // Two storage buffers: input (0) and output (1).
    VkDescriptorSetLayoutBinding binds[2] = {};
    for (uint32_t i = 0; i < 2; ++i) {
        binds[i].binding = i;
        binds[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        binds[i].descriptorCount = 1;
        binds[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }

    VkDescriptorSetLayoutCreateInfo dsl{};
    dsl.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    dsl.bindingCount = 2;
    dsl.pBindings = binds;
    if (vkCreateDescriptorSetLayout(device_, &dsl, nullptr, &rope_descriptor_set_layout_) != VK_SUCCESS) {
        std::cerr << "Failed to create RoPE descriptor set layout" << std::endl;
        return false;
    }

    VkDescriptorPoolSize pool_size{};
    pool_size.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    pool_size.descriptorCount = 2 * 64;   // headroom for many dispatches

    VkDescriptorPoolCreateInfo dp{};
    dp.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    dp.maxSets = 64;
    dp.poolSizeCount = 1;
    dp.pPoolSizes = &pool_size;
    if (vkCreateDescriptorPool(device_, &dp, nullptr, &rope_descriptor_pool_) != VK_SUCCESS) {
        std::cerr << "Failed to create RoPE descriptor pool" << std::endl;
        return false;
    }

    VkPushConstantRange pc{};
    pc.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pc.offset = 0;
    pc.size = sizeof(uint32_t) * 8;   // pos, n_rot, dim + 5 float bit patterns

    VkPipelineLayoutCreateInfo pl{};
    pl.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pl.setLayoutCount = 1;
    pl.pSetLayouts = &rope_descriptor_set_layout_;
    pl.pushConstantRangeCount = 1;
    pl.pPushConstantRanges = &pc;
    if (vkCreatePipelineLayout(device_, &pl, nullptr, &cs.layout) != VK_SUCCESS) {
        std::cerr << "Failed to create RoPE pipeline layout" << std::endl;
        return false;
    }

    VkPipelineShaderStageCreateInfo stage{};
    stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stage.module = cs.module;
    stage.pName = "main";

    VkComputePipelineCreateInfo cp{};
    cp.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    cp.stage = stage;
    cp.layout = cs.layout;
    if (vkCreateComputePipelines(device_, nullptr, 1, &cp, nullptr, &cs.pipeline) != VK_SUCCESS) {
        std::cerr << "Failed to create RoPE compute pipeline" << std::endl;
        return false;
    }

    shaders_["rope"] = cs;
    std::cout << "RoPE pipeline and permanent descriptor system initialized successfully" << std::endl;
    return true;
}

bool VulkanCompute::EnsureQuantDotPipeline(const std::string& spirv_path) {
    if (shaders_.count("quantdot") &&
        shaders_["quantdot"].pipeline &&
        quant_descriptor_set_layout_ &&
        quant_descriptor_pool_) {
        return true;
    }

    std::vector<uint32_t> code;
    if (!LoadSPIRVCode(spirv_path, code) || code.empty()) {
        std::cerr << "Failed to load quant-dot SPIR-V: " << spirv_path << std::endl;
        return false;
    }

    VkShaderModuleCreateInfo sm{};
    sm.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    sm.codeSize = code.size() * sizeof(uint32_t);
    sm.pCode = code.data();

    ComputeShader cs;
    cs.name = "quantdot";
    cs.spirv_code = code;
    if (vkCreateShaderModule(device_, &sm, nullptr, &cs.module) != VK_SUCCESS) {
        std::cerr << "Failed to create quant-dot shader module" << std::endl;
        return false;
    }

    // Three storage buffers: packed weights (0), Q8 activations (1), output (2).
    VkDescriptorSetLayoutBinding binds[3] = {};
    for (uint32_t i = 0; i < 3; ++i) {
        binds[i].binding = i;
        binds[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        binds[i].descriptorCount = 1;
        binds[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }

    VkDescriptorSetLayoutCreateInfo dsl{};
    dsl.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    dsl.bindingCount = 3;
    dsl.pBindings = binds;
    if (vkCreateDescriptorSetLayout(device_, &dsl, nullptr, &quant_descriptor_set_layout_) != VK_SUCCESS) {
        std::cerr << "Failed to create quant-dot descriptor set layout" << std::endl;
        return false;
    }

    // Pool capacity is derived from the shader's descriptor-set layout: 3
    // storage-buffer bindings per set. 256 sets is ample for the recycled ring
    // plus any future callers; an exhausted pool must surface as a counted
    // failure, never a silent CPU fallback.
    VkDescriptorPoolSize pool_size{};
    pool_size.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    pool_size.descriptorCount = 3u * kQuantPoolSets;

    VkDescriptorPoolCreateInfo dp{};
    dp.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    // ExecuteQuantDot allocates one set per dispatch and recycles it with
    // vkFreeDescriptorSets once the GPU work has completed. Without
    // VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT that free is invalid
    // and returns an error, so no set was ever reclaimed and the fixed-size
    // pool was exhausted after ~64 dispatches. Every subsequent quant-dot then
    // failed with "Quant-dot descriptor allocation failed", which silently
    // pushed the model onto CPU and broke the GPU-only certificate. The flag
    // makes the recycle path actually reclaim sets.
    dp.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
    dp.maxSets = kQuantPoolSets;
    quant_pool_max_sets_ = dp.maxSets;
    dp.poolSizeCount = 1;
    dp.pPoolSizes = &pool_size;
    if (vkCreateDescriptorPool(device_, &dp, nullptr, &quant_descriptor_pool_) != VK_SUCCESS) {
        ++gpu_counters_.descriptor_alloc_failures;
        std::cerr << "Failed to create quant-dot descriptor pool" << std::endl;
        return false;
    }
    ++gpu_counters_.descriptor_pool_creates;

    // pos, n_rot-style scalars: n_out, n_in, n_blocks, kind.
    VkPushConstantRange pc{};
    pc.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pc.offset = 0;
    pc.size = sizeof(uint32_t) * 4;

    VkPipelineLayoutCreateInfo pl{};
    pl.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pl.setLayoutCount = 1;
    pl.pSetLayouts = &quant_descriptor_set_layout_;
    pl.pushConstantRangeCount = 1;
    pl.pPushConstantRanges = &pc;
    if (vkCreatePipelineLayout(device_, &pl, nullptr, &cs.layout) != VK_SUCCESS) {
        std::cerr << "Failed to create quant-dot pipeline layout" << std::endl;
        return false;
    }

    VkPipelineShaderStageCreateInfo stage{};
    stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stage.module = cs.module;
    stage.pName = "main";

    VkComputePipelineCreateInfo cp{};
    cp.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    cp.stage = stage;
    cp.layout = cs.layout;
    if (vkCreateComputePipelines(device_, nullptr, 1, &cp, nullptr, &cs.pipeline) != VK_SUCCESS) {
        std::cerr << "Failed to create quant-dot compute pipeline" << std::endl;
        return false;
    }

    shaders_["quantdot"] = cs;
    std::cout << "Quant-dot pipeline and permanent descriptor system initialized successfully" << std::endl;
    return true;
}

// RAWRXD_DEEP2_TPS_AND_CERTIFICATION_RECOVERY
//
// One command buffer per dispatch: activation upload -> pipeline barrier ->
// quant-dot dispatch -> barrier -> readback copy, all ending in a single
// vkQueueSubmit + vkWaitForFences. Immutable weights are uploaded once and
// stay device resident (cached by host pointer, fingerprint-checked); the
// activation and output use pooled device buffers; descriptor sets come from a
// small recycled ring. The host still waits for the fence before reading the
// output, so every reuse is race-free, and every failure is reported to the
// caller (never a silent CPU pass-off).
bool VulkanCompute::ExecuteQuantDot(const void* packed, size_t packed_bytes,
                                     const void* q8_interleaved, size_t q8_bytes,
                                     void* out, size_t out_bytes,
                                     size_t n_out, size_t n_in, size_t n_blocks, int kind)
{
    // Validate everything up front. No silent CPU fallback: a failure is
    // reported to the caller so it can decide what to do.
    if (!packed || !q8_interleaved || !out) return false;
    if (kind < 0 || kind > 4) return false;
    if (n_out == 0 || n_in == 0 || n_blocks == 0) return false;

    // Kinds 0/1 are the k-quants (one 256-value super-block per block); kinds
    // 2/3/4 are legacy types (32 values per block, eight per super-block). For
    // the legacy kinds the LAST activation super-block may be PARTIAL:
    // n_in need not divide 256 (e.g. 2688 = 10*256 + 128), so the activation
    // carries ceil(n_in/256) super-blocks and the shader decodes only the
    // legacy blocks whose elements exist.
    const bool legacy = (kind >= 2);
    size_t block_bytes = 0, need_packed = 0, need_q8 = 0;
    if (legacy) {
        if ((n_in % 32u) != 0) return false;
        block_bytes = (kind == 2) ? 22u : ((kind == 3) ? 34u : 18u);  // Q5_0 / Q8_0 / Q4_0
        const size_t n_sb = (n_in + 255u) / 256u;
        need_packed = n_out * ((n_in + 31u) / 32u) * block_bytes;
        need_q8 = n_sb * 273u * sizeof(float);
    } else {
        if ((n_in % 256u) != 0) return false;
        if (n_blocks != n_in / 256u) return false;
        block_bytes = (kind == 0) ? 144u : 210u;
        need_packed = n_out * n_blocks * block_bytes;
        need_q8 = n_blocks * 273u * sizeof(float);
    }
    const size_t need_out = n_out * sizeof(float);
    if (packed_bytes < need_packed || q8_bytes < need_q8 || out_bytes < need_out) return false;

    if (!EnsureQuantDotPipeline(kQuantDotShaderPath)) return false;
    auto it = shaders_.find("quantdot");
    if (it == shaders_.end() || !it->second.pipeline) return false;
    if (!EnsureQuantFastPath()) return false;

    // ---- 1. device-resident weight: upload once, reuse every decode step ----
    QuantWeight* w = EnsureQuantWeight(packed, packed_bytes, kind);
    if (!w) return false;

    // ---- 2. pooled device buffers for the activation and the output --------
    QuantScratch* q8buf = AcquireQuantScratch(q8_bytes);
    if (!q8buf) {
        std::cerr << "Quant-dot activation buffer acquire failed" << std::endl;
        return false;
    }
    QuantScratch* obuf = AcquireQuantScratch(out_bytes);
    if (!obuf) {
        std::cerr << "Quant-dot output buffer acquire failed" << std::endl;
        ReleaseQuantScratch(q8buf);
        return false;
    }

    // ---- 3. persistent host-visible staging for the activation upload ------
    if (!EnsureHostVisible(q8_bytes, upload_staging_, upload_staging_mem_,
                           upload_staging_size_, upload_staging_mapped_)) {
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(q8buf);
        return false;
    }
    std::memcpy(upload_staging_mapped_, q8_interleaved, q8_bytes);
    gpu_counters_.upload_bytes += q8_bytes;

    // ---- 4. persistent host-visible readback for the output ----------------
    if (!EnsureHostVisible(out_bytes, readback_buffer_, readback_memory_,
                           readback_size_, readback_mapped_)) {
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(q8buf);
        return false;
    }

    // ---- 5. recycle a descriptor set from the ring --------------------------
    // The ring advances only after the previous fence has been waited on (the
    // dispatch below is synchronous), so the set being updated is never in
    // flight. Four entries is belt-and-braces, not a correctness requirement.
    // The in-flight guard makes the ownership rule auditable: a slot counts as
    // in flight from acquisition until this function returns, which only
    // happens after the GPU work referencing it has completed or failed.
    VkDescriptorSet ds = quant_ds_ring_[quant_ds_ring_next_];
    quant_ds_ring_next_ = (quant_ds_ring_next_ + 1) % quant_ds_ring_.size();
    ++gpu_counters_.descriptor_reuses;
    ++gpu_counters_.descriptor_sets_in_flight;
    if (gpu_counters_.descriptor_sets_in_flight > gpu_counters_.descriptor_sets_peak)
        gpu_counters_.descriptor_sets_peak = gpu_counters_.descriptor_sets_in_flight;
    struct InFlightGuard {
        GpuCounters& c;
        ~InFlightGuard() { if (c.descriptor_sets_in_flight > 0) --c.descriptor_sets_in_flight; }
    } in_flight_guard{gpu_counters_};

    VkDescriptorBufferInfo infos[3];
    VkWriteDescriptorSet writes[3];
    const VkBuffer bufs[3] = { w->buffer, q8buf->buffer, obuf->buffer };
    const size_t sizes[3] = { packed_bytes, q8_bytes, out_bytes };
    for (int i = 0; i < 3; ++i) {
        infos[i] = {};
        infos[i].buffer = bufs[i];
        infos[i].offset = 0;
        infos[i].range = sizes[i];
        writes[i] = {};
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = ds;
        writes[i].dstBinding = i;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[i].pBufferInfo = &infos[i];
    }
    vkUpdateDescriptorSets(device_, 3, writes, 0, nullptr);

    // ---- 6. one command buffer: upload, dispatch, readback ------------------
    if (vkResetFences(device_, 1, &quant_fence_) != VK_SUCCESS) {
        std::cerr << "Quant-dot fence reset failed" << std::endl;
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(q8buf);
        return false;
    }
    if (vkResetCommandBuffer(quant_cmd_, 0) != VK_SUCCESS) {
        std::cerr << "Quant-dot command buffer reset failed" << std::endl;
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(q8buf);
        return false;
    }

    VkCommandBufferBeginInfo begin_info{};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    if (vkBeginCommandBuffer(quant_cmd_, &begin_info) != VK_SUCCESS) {
        std::cerr << "Quant-dot command buffer begin failed" << std::endl;
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(q8buf);
        return false;
    }

    // Activation upload (staging -> device).
    VkBufferCopy up_region{};
    up_region.size = q8_bytes;
    vkCmdCopyBuffer(quant_cmd_, upload_staging_, q8buf->buffer, 1, &up_region);

    // transfer write -> shader read for the activation.
    VkBufferMemoryBarrier up_barrier{};
    up_barrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    up_barrier.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    up_barrier.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
    up_barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    up_barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    up_barrier.buffer = q8buf->buffer;
    up_barrier.offset = 0;
    up_barrier.size = q8_bytes;
    vkCmdPipelineBarrier(quant_cmd_, VK_PIPELINE_STAGE_TRANSFER_BIT,
                         VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0,
                         0, nullptr, 1, &up_barrier, 0, nullptr);

    uint32_t pc[4] = { (uint32_t)n_out, (uint32_t)n_in,
                       (uint32_t)n_blocks, (uint32_t)kind };
    vkCmdPushConstants(quant_cmd_, it->second.layout, VK_SHADER_STAGE_COMPUTE_BIT,
                       0, sizeof(pc), pc);
    vkCmdBindPipeline(quant_cmd_, VK_PIPELINE_BIND_POINT_COMPUTE, it->second.pipeline);
    vkCmdBindDescriptorSets(quant_cmd_, VK_PIPELINE_BIND_POINT_COMPUTE,
                            it->second.layout, 0, 1, &ds, 0, nullptr);
    // One invocation per output row.
    uint32_t groups = (uint32_t)(n_out / 1u);
    if (groups == 0u) groups = 1u;
    vkCmdDispatch(quant_cmd_, groups, 1, 1);

    // shader write -> transfer read for the output.
    VkBufferMemoryBarrier down_barrier{};
    down_barrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    down_barrier.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
    down_barrier.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
    down_barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    down_barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    down_barrier.buffer = obuf->buffer;
    down_barrier.offset = 0;
    down_barrier.size = out_bytes;
    vkCmdPipelineBarrier(quant_cmd_, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                         VK_PIPELINE_STAGE_TRANSFER_BIT, 0,
                         0, nullptr, 1, &down_barrier, 0, nullptr);

    VkBufferCopy down_region{};
    down_region.size = out_bytes;
    vkCmdCopyBuffer(quant_cmd_, obuf->buffer, readback_buffer_, 1, &down_region);

    if (vkEndCommandBuffer(quant_cmd_) != VK_SUCCESS) {
        std::cerr << "Quant-dot command buffer end failed" << std::endl;
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(q8buf);
        return false;
    }

    const auto submit_begin = std::chrono::steady_clock::now();
    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &quant_cmd_;
    if (vkQueueSubmit(compute_queue_, 1, &submit_info, quant_fence_) != VK_SUCCESS) {
        std::cerr << "Quant-dot queue submit failed" << std::endl;
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(q8buf);
        return false;
    }
    ++gpu_counters_.submits;
    const auto submit_end = std::chrono::steady_clock::now();
    gpu_counters_.submit_ms +=
        std::chrono::duration<double, std::milli>(submit_end - submit_begin).count();

    if (vkWaitForFences(device_, 1, &quant_fence_, VK_TRUE, UINT64_MAX) != VK_SUCCESS) {
        std::cerr << "Quant-dot fence wait failed" << std::endl;
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(q8buf);
        return false;
    }
    const auto wait_end = std::chrono::steady_clock::now();
    ++gpu_counters_.waits;
    const double waited_ms =
        std::chrono::duration<double, std::milli>(wait_end - submit_end).count();
    gpu_counters_.wait_ms += waited_ms;
    // The fence signals only after the whole submission (upload, dispatch,
    // copy) drains, so this is the measured queue-side cost of the call.
    gpu_counters_.kernel_ms += waited_ms;
    gpu_counters_.download_bytes += out_bytes;

    // The readback buffer is HOST_COHERENT, so once the fence has signalled the
    // writes are visible to the host without an explicit invalidate.
    std::memcpy(out, readback_mapped_, out_bytes);

    ReleaseQuantScratch(obuf);
    ReleaseQuantScratch(q8buf);
    return true;
}

// ---------------------------------------------------------------------------
// Batched quant-dot (RAWRXD_DEEP2_LEGACY_QUANT_GPU_001).
//
// The single-call path pays a command-buffer record + submit + fence wait for
// EVERY dot. A MoE block performs 2*selected dots whose results are consumed
// together (all up-dots, then all down-dots), so the batch records them into
// ONE command buffer behind ONE fence. Caller contract:
//   Begin -> Queue* -> End
// Queue only dots whose output is untouched until after End; the batch is not
// a dependency resolver. Any failure returns false and the batch must be
// discarded (no partial state), with the caller falling back to single calls.
//
// Geometry accounting mirrors ExecuteQuantDot exactly (kinds 0..3, partial
// 256-value activation super-block for the legacy kinds).
// ---------------------------------------------------------------------------
bool VulkanCompute::BeginQuantDotBatch() {
    if (quant_batch_active_) return false;   // batches do not nest
    if (!EnsureQuantDotPipeline(kQuantDotShaderPath)) return false;
    auto it = shaders_.find("quantdot");
    if (it == shaders_.end() || !it->second.pipeline) return false;
    if (!EnsureQuantFastPath()) return false;

    quant_batch_entries_.clear();
    quant_batch_q8_host_used_ = 0;
    quant_batch_out_host_used_ = 0;
    // Descriptor sets: one distinct set per queued dot (updating a set that an
    // earlier dispatch in the SAME command buffer also uses is not safe, so
    // the batch never recycles within itself). Allocated once, reused across
    // batches: End waits on the fence before returning, so no batch outlives
    // its submissions.
    if (quant_batch_sets_.empty()) {
        quant_batch_sets_.assign(kQuantBatchMaxSets, VK_NULL_HANDLE);
        VkDescriptorSetLayout layouts[kQuantBatchMaxSets];
        for (uint32_t i = 0; i < kQuantBatchMaxSets; ++i)
            layouts[i] = quant_descriptor_set_layout_;
        VkDescriptorSetAllocateInfo alloc{};
        alloc.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
        alloc.descriptorPool = quant_descriptor_pool_;
        alloc.descriptorSetCount = kQuantBatchMaxSets;
        alloc.pSetLayouts = layouts;
        ++gpu_counters_.descriptor_alloc_attempts;
        const VkResult r = vkAllocateDescriptorSets(device_, &alloc, quant_batch_sets_.data());
        if (r != VK_SUCCESS) {
            ++gpu_counters_.descriptor_alloc_failures;
            std::cerr << "[QUANT_DOT] batch descriptor set allocation failed: VkResult="
                      << static_cast<int>(r) << std::endl;
            quant_batch_sets_.clear();
            return false;
        }
        gpu_counters_.descriptor_allocations += kQuantBatchMaxSets;
    }
    quant_batch_active_ = true;
    return true;
}

namespace {
// Geometry shared by the single-call and batch paths: returns block bytes and
// fills need_packed / need_q8 / n_sb, or false for unsupported geometry.
bool QuantDotGeometry(int kind, size_t n_in, size_t n_out, size_t n_blocks,
                      size_t& block_bytes, size_t& need_packed, size_t& need_q8,
                      size_t& n_sb) {
    if (kind < 0 || kind > 4) return false;
    if (n_out == 0 || n_in == 0) return false;
    if (kind >= 2) {
        if ((n_in % 32u) != 0) return false;
        block_bytes = (kind == 2) ? 22u : ((kind == 3) ? 34u : 18u);  // Q5_0 / Q8_0 / Q4_0
        n_sb = (n_in + 255u) / 256u;
        need_packed = n_out * ((n_in + 31u) / 32u) * block_bytes;
        need_q8 = n_sb * 273u * sizeof(float);
    } else {
        if (n_blocks == 0 || (n_in % 256u) != 0 || n_blocks != n_in / 256u) return false;
        block_bytes = (kind == 0) ? 144u : 210u;  // Q4_K / Q6_K
        n_sb = n_blocks;
        need_packed = n_out * n_blocks * block_bytes;
        need_q8 = n_blocks * 273u * sizeof(float);
    }
    return true;
}
}  // namespace

bool VulkanCompute::QueueQuantDot(const void* packed, size_t packed_bytes,
                                  const void* q8_interleaved, size_t q8_bytes,
                                  void* out, size_t out_bytes,
                                  size_t n_out, size_t n_in, int kind) {
    if (!quant_batch_active_) return false;
    if (quant_batch_entries_.size() >= kQuantBatchMaxSets) return false;
    if (!packed || !q8_interleaved || !out) return false;
    const size_t n_blocks = n_in / 256u;
    size_t block_bytes = 0, need_packed = 0, need_q8 = 0, n_sb = 0;
    if (!QuantDotGeometry(kind, n_in, n_out, n_blocks, block_bytes, need_packed, need_q8, n_sb))
        return false;
    if (packed_bytes < need_packed || q8_bytes < need_q8 || out_bytes < n_out * sizeof(float))
        return false;

    // Device-resident weight (uploads on its own submission + wait on a miss;
    // a cache hit costs nothing).
    QuantWeight* w = EnsureQuantWeight(packed, packed_bytes, kind);
    if (!w) return false;

    // Region at the END of the current batch usage. The host buffers GROW
    // CONTENT-PRESERVING: EnsureHostVisible would destroy and recreate them and
    // silently drop every earlier queued activation in this batch (a growth on
    // the 2nd of 6 queued dots left the first five reading zeros).
    const size_t q8_off = quant_batch_q8_host_used_;
    const size_t out_off = quant_batch_out_host_used_;
    if (q8_off + q8_bytes < q8_off || out_off + out_bytes < out_off) return false;
    auto grow_preserving = [&](VkBuffer& buf, VkDeviceMemory& mem, size_t& size, void*& mapped,
                               size_t need) -> bool {
        if (buf && mapped && size >= need) return true;
        // Create the new buffer beside the old one, copy, then swap. No in-flight
        // command buffer references the host buffer until End records.
        VkBuffer nb = nullptr;
        VkDeviceMemory nm = nullptr;
        size_t nsz = 0;
        void* nmapped = nullptr;
        const size_t alloc_bytes = need > (size * 2) ? need : (size * 2);
        if (!EnsureHostVisible(alloc_bytes, nb, nm, nsz, nmapped)) return false;
        if (buf && mapped && size > 0)
            std::memcpy(nmapped, mapped, size);
        if (mapped) vkUnmapMemory(device_, mem);
        if (buf) vkDestroyBuffer(device_, buf, nullptr);
        if (mem) vkFreeMemory(device_, mem, nullptr);
        buf = nb; mem = nm; size = nsz; mapped = nmapped;
        return true;
    };
    if (!grow_preserving(quant_batch_q8_host_, quant_batch_q8_host_mem_,
                         quant_batch_q8_host_size_, quant_batch_q8_host_mapped_,
                         q8_off + q8_bytes) ||
        !grow_preserving(quant_batch_out_host_, quant_batch_out_host_mem_,
                         quant_batch_out_host_size_, quant_batch_out_host_mapped_,
                         out_off + out_bytes)) {
        return false;
    }
    std::memcpy(static_cast<char*>(quant_batch_q8_host_mapped_) + q8_off, q8_interleaved, q8_bytes);
    quant_batch_q8_host_used_ += q8_bytes;
    quant_batch_out_host_used_ += out_bytes;
    gpu_counters_.upload_bytes += q8_bytes;
    gpu_counters_.download_bytes += out_bytes;

    QuantBatchEntry e;
    e.weight = w->buffer;
    // The device batch buffers are (re)created in End from the summed spans, so
    // the entry must NOT capture the pointers now: on a first-ever batch they
    // are null, and after a grow the old pointers dangle. End resolves both.
    e.q8 = nullptr;
    e.out = nullptr;
    e.q8_bytes = q8_bytes;
    e.out_bytes = out_bytes;
    e.out_host = out;
    e.ds = quant_batch_sets_[quant_batch_entries_.size()];
    e.n_out = (uint32_t)n_out;
    e.n_in = (uint32_t)n_in;
    e.n_blocks = (uint32_t)n_sb;   // the shader's super-block count (legacy-aware)
    e.kind = (uint32_t)kind;
    quant_batch_entries_.push_back(e);
    return true;
}

bool VulkanCompute::EndQuantDotBatch() {
    if (!quant_batch_active_) return false;
    quant_batch_active_ = false;
    const size_t n = quant_batch_entries_.size();
    if (n == 0) return true;

    // Sum the spans, create/grow the device batch buffers, and only then bind
    // the (possibly recreated) device buffers into the entries.
    size_t q8_total = 0, out_total = 0;
    for (const auto& e : quant_batch_entries_) q8_total += e.q8_bytes;
    for (const auto& e : quant_batch_entries_) out_total += e.out_bytes;

    // Device-side batch buffers (storage + transfer). Grown as needed.
    auto ensure_dev = [&](VkBuffer& buf, VkDeviceMemory& mem, size_t& cap, size_t need,
                          VkBufferUsageFlags extra) -> bool {
        if (buf && cap >= need) return true;
        if (buf) {
            vkDestroyBuffer(device_, buf, nullptr);
            vkFreeMemory(device_, mem, nullptr);
            buf = nullptr; mem = nullptr; cap = 0;
        }
        VkBufferCreateInfo bi{};
        bi.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        bi.size = need;
        bi.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | extra;
        bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        if (vkCreateBuffer(device_, &bi, nullptr, &buf) != VK_SUCCESS) return false;
        VkMemoryRequirements mr{};
        vkGetBufferMemoryRequirements(device_, buf, &mr);
        VkMemoryAllocateInfo ai{};
        ai.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        ai.allocationSize = mr.size;
        uint32_t type_bits = mr.memoryTypeBits;
        ai.memoryTypeIndex = UINT32_MAX;
        for (uint32_t i = 0; i < device_info_.memory_props.memoryTypeCount; ++i) {
            const VkMemoryType& mt = device_info_.memory_props.memoryTypes[i];
            if ((type_bits & (1u << i)) &&
                (mt.propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)) {
                ai.memoryTypeIndex = i;
                break;
            }
        }
        if (ai.memoryTypeIndex == UINT32_MAX) return false;
        if (vkAllocateMemory(device_, &ai, nullptr, &mem) != VK_SUCCESS) return false;
        if (vkBindBufferMemory(device_, buf, mem, 0) != VK_SUCCESS) return false;
        cap = need;
        ++gpu_counters_.buffer_allocations;
        if (gpu_counters_.device_bytes_live > gpu_counters_.device_bytes_peak)
            gpu_counters_.device_bytes_peak = gpu_counters_.device_bytes_live;
        return true;
    };
    if (!ensure_dev(quant_batch_q8_dev_, quant_batch_q8_mem_, quant_batch_q8_cap_,
                    q8_total ? q8_total : 1u, VK_BUFFER_USAGE_TRANSFER_DST_BIT)) {
        std::cerr << "[QUANT_DOT] batch activation buffer failed" << std::endl;
        return false;
    }
    if (!ensure_dev(quant_batch_out_dev_, quant_batch_out_mem_, quant_batch_out_cap_,
                    out_total ? out_total : 1u, VK_BUFFER_USAGE_TRANSFER_SRC_BIT)) {
        std::cerr << "[QUANT_DOT] batch output buffer failed" << std::endl;
        return false;
    }
    // The device buffers are final now: bind them into the entries.
    for (auto& e : quant_batch_entries_) {
        e.q8 = quant_batch_q8_dev_;
        e.out = quant_batch_out_dev_;
    }

    if (vkResetFences(device_, 1, &quant_fence_) != VK_SUCCESS || vkResetCommandBuffer(quant_cmd_, 0) != VK_SUCCESS) {
        std::cerr << "[QUANT_DOT] batch reset failed" << std::endl;
        return false;
    }
    VkCommandBufferBeginInfo begin_info{};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    if (vkBeginCommandBuffer(quant_cmd_, &begin_info) != VK_SUCCESS) {
        std::cerr << "[QUANT_DOT] batch command buffer begin failed" << std::endl;
        return false;
    }

    // ---- upload all activations ------------------------------------------------
    size_t q8_up_cursor = 0;
    for (auto& e : quant_batch_entries_) {
        VkBufferCopy region{};
        region.srcOffset = q8_up_cursor;
        region.dstOffset = q8_up_cursor;
        region.size = e.q8_bytes;
        vkCmdCopyBuffer(quant_cmd_, quant_batch_q8_host_, quant_batch_q8_dev_, 1, &region);
        q8_up_cursor += e.q8_bytes;
    }
    if (q8_total) {
        VkBufferMemoryBarrier barrier{};
        barrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
        barrier.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        barrier.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
        barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        barrier.buffer = quant_batch_q8_dev_;
        barrier.offset = 0;
        barrier.size = q8_total;
        vkCmdPipelineBarrier(quant_cmd_, VK_PIPELINE_STAGE_TRANSFER_BIT,
                             VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0,
                             0, nullptr, 1, &barrier, 0, nullptr);
    }

    // ---- dispatch every dot ----------------------------------------------------
    auto sh = shaders_.find("quantdot");
    if (sh == shaders_.end() || !sh->second.pipeline) {
        std::cerr << "[QUANT_DOT] batch pipeline missing" << std::endl;
        return false;
    }
    vkCmdBindPipeline(quant_cmd_, VK_PIPELINE_BIND_POINT_COMPUTE, sh->second.pipeline);
    size_t out_cursor = 0;
    size_t q8_cursor = 0;
    for (auto& e : quant_batch_entries_) {
        // Per-entry descriptor set: weight / q8 region / out region. A distinct
        // set per dispatch avoids updating a set an earlier dispatch in this
        // same command buffer also binds.
        VkDescriptorBufferInfo infos[3];
        VkWriteDescriptorSet writes[3];
        const VkBuffer bufs[3] = { e.weight, quant_batch_q8_dev_, quant_batch_out_dev_ };
        const size_t offs[3] = { 0, q8_cursor, out_cursor };
        const size_t sizes[3] = { VK_WHOLE_SIZE, e.q8_bytes, e.out_bytes };
        for (int i = 0; i < 3; ++i) {
            infos[i] = {};
            infos[i].buffer = bufs[i];
            infos[i].offset = offs[i];
            infos[i].range = sizes[i];
            writes[i] = {};
            writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
            writes[i].dstSet = e.ds;
            writes[i].dstBinding = i;
            writes[i].descriptorCount = 1;
            writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
            writes[i].pBufferInfo = &infos[i];
        }
        vkUpdateDescriptorSets(device_, 3, writes, 0, nullptr);
        ++gpu_counters_.descriptor_reuses;
        // Push constants: n_out, n_in, super-block count, kind.
        vkCmdPushConstants(quant_cmd_, sh->second.layout, VK_SHADER_STAGE_COMPUTE_BIT,
                           0, sizeof(uint32_t) * 4, &e.n_out);
        vkCmdBindDescriptorSets(quant_cmd_, VK_PIPELINE_BIND_POINT_COMPUTE,
                                sh->second.layout, 0, 1, &e.ds, 0, nullptr);
        uint32_t groups = e.n_out;
        if (groups == 0u) groups = 1u;
        vkCmdDispatch(quant_cmd_, groups, 1, 1);
        out_cursor += e.out_bytes;
        q8_cursor += e.q8_bytes;
    }

    // ---- read back every output ------------------------------------------------
    if (out_total) {
        VkBufferMemoryBarrier barrier{};
        barrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
        barrier.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
        barrier.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
        barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        barrier.buffer = quant_batch_out_dev_;
        barrier.offset = 0;
        barrier.size = out_total;
        vkCmdPipelineBarrier(quant_cmd_, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                             VK_PIPELINE_STAGE_TRANSFER_BIT, 0,
                             0, nullptr, 1, &barrier, 0, nullptr);
        size_t cursor = 0;
        for (const auto& e : quant_batch_entries_) {
            VkBufferCopy region{};
            region.srcOffset = cursor;
            region.dstOffset = cursor;
            region.size = e.out_bytes;
            vkCmdCopyBuffer(quant_cmd_, quant_batch_out_dev_, quant_batch_out_host_, 1, &region);
            cursor += e.out_bytes;
        }
    }

    if (vkEndCommandBuffer(quant_cmd_) != VK_SUCCESS) {
        std::cerr << "[QUANT_DOT] batch command buffer end failed" << std::endl;
        return false;
    }

    const auto submit_begin = std::chrono::steady_clock::now();
    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &quant_cmd_;
    if (vkQueueSubmit(compute_queue_, 1, &submit_info, quant_fence_) != VK_SUCCESS) {
        std::cerr << "[QUANT_DOT] batch queue submit failed" << std::endl;
        return false;
    }
    ++gpu_counters_.submits;
    const auto submit_end = std::chrono::steady_clock::now();
    gpu_counters_.submit_ms +=
        std::chrono::duration<double, std::milli>(submit_end - submit_begin).count();
    if (vkWaitForFences(device_, 1, &quant_fence_, VK_TRUE, UINT64_MAX) != VK_SUCCESS) {
        std::cerr << "[QUANT_DOT] batch fence wait failed" << std::endl;
        return false;
    }
    const auto wait_end = std::chrono::steady_clock::now();
    ++gpu_counters_.waits;
    gpu_counters_.wait_ms +=
        std::chrono::duration<double, std::milli>(wait_end - submit_end).count();
    gpu_counters_.kernel_ms +=
        std::chrono::duration<double, std::milli>(wait_end - submit_end).count();

    // The readback is host-coherent; the fence guarantees visibility.
    size_t cursor = 0;
    for (const auto& e : quant_batch_entries_) {
        if (e.out_host)
            std::memcpy(e.out_host, static_cast<char*>(quant_batch_out_host_mapped_) + cursor,
                        e.out_bytes);
        cursor += e.out_bytes;
    }
    quant_batch_entries_.clear();
    return true;
}

namespace {
const char* kF16DotShaderPath = "tools/shaders/fp16_gemv.spv";
}  // namespace

bool VulkanCompute::EnsureF16DotPipeline() {
    if (shaders_.count("fp16gemv") && shaders_["fp16gemv"].pipeline &&
        shaders_["fp16gemv"].layout) {
        return true;
    }
    std::vector<uint32_t> code;
    if (!LoadSPIRVCode(kF16DotShaderPath, code) || code.empty()) {
        std::cerr << "Failed to load fp16-gemv SPIR-V: " << kF16DotShaderPath << std::endl;
        return false;
    }
    VkShaderModuleCreateInfo sm{};
    sm.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    sm.codeSize = code.size() * sizeof(uint32_t);
    sm.pCode = code.data();

    ComputeShader cs;
    cs.name = "fp16gemv";
    cs.spirv_code = code;
    if (vkCreateShaderModule(device_, &sm, nullptr, &cs.module) != VK_SUCCESS) {
        std::cerr << "Failed to create fp16-gemv shader module" << std::endl;
        return false;
    }
    // Reuses the quant-dot descriptor set layout: both are three storage
    // buffers (input, weights, output). A separate pipeline layout carries the
    // same 16-byte push-constant range.
    if (!quant_descriptor_set_layout_) {
        std::cerr << "fp16-gemv needs the quant-dot descriptor layout" << std::endl;
        return false;
    }
    VkPushConstantRange pc{};
    pc.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pc.offset = 0;
    pc.size = sizeof(uint32_t) * 4;
    VkPipelineLayoutCreateInfo pl{};
    pl.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pl.setLayoutCount = 1;
    pl.pSetLayouts = &quant_descriptor_set_layout_;
    pl.pushConstantRangeCount = 1;
    pl.pPushConstantRanges = &pc;
    if (vkCreatePipelineLayout(device_, &pl, nullptr, &cs.layout) != VK_SUCCESS) {
        std::cerr << "Failed to create fp16-gemv pipeline layout" << std::endl;
        return false;
    }
    VkPipelineShaderStageCreateInfo stage{};
    stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stage.module = cs.module;
    stage.pName = "main";
    VkComputePipelineCreateInfo cp{};
    cp.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    cp.stage = stage;
    cp.layout = cs.layout;
    if (vkCreateComputePipelines(device_, nullptr, 1, &cp, nullptr, &cs.pipeline) != VK_SUCCESS) {
        std::cerr << "Failed to create fp16-gemv pipeline" << std::endl;
        return false;
    }
    shaders_["fp16gemv"] = cs;
    return true;
}

bool VulkanCompute::ExecuteF16Dot(const void* packed, size_t packed_bytes,
                                  const float* x, size_t n_in,
                                  void* out, size_t out_bytes,
                                  size_t n_out) {
    const bool trace = (std::getenv("RR_F16_TRACE") != nullptr);
#define F16_FAIL(msg) do { if (trace) { std::cerr << "[f16-trace] " << msg << std::endl; } return false; } while (0)
    if (!packed || !x || !out) F16_FAIL("null argument");
    if (n_out == 0 || n_in == 0 || (n_in % 2u) != 0) F16_FAIL("n_in odd/zero");
    if (reinterpret_cast<uintptr_t>(packed) % 4u != 0) F16_FAIL("weight misaligned");
    const size_t need_packed = n_out * n_in * sizeof(uint16_t);
    const size_t need_x = n_in * sizeof(float);
    if (packed_bytes < need_packed || out_bytes < n_out * sizeof(float)) F16_FAIL("sizes short");
    if (!EnsureQuantDotPipeline(kQuantDotShaderPath)) F16_FAIL("quant pipeline");
    if (!EnsureF16DotPipeline()) F16_FAIL("fp16 pipeline");
    if (!EnsureQuantFastPath()) F16_FAIL("fast path");
#undef F16_FAIL

    // Weight bytes are uploaded once and cached (kind -2 marks the F16 cache
    // entry; the fingerprint still guards the pointer/bytes/size identity).
    QuantWeight* w = EnsureQuantWeight(packed, packed_bytes, /*kind=*/-2);
    if (!w) return false;

    // Device-side activation (scratch) and output (scratch).
    QuantScratch* xbuf = AcquireQuantScratch(need_x);
    if (!xbuf) {
        std::cerr << "fp16 dot activation buffer acquire failed" << std::endl;
        return false;
    }
    QuantScratch* obuf = AcquireQuantScratch(n_out * sizeof(float));
    if (!obuf) {
        std::cerr << "fp16 dot output buffer acquire failed" << std::endl;
        ReleaseQuantScratch(xbuf);
        return false;
    }

    if (!EnsureHostVisible(need_x, upload_staging_, upload_staging_mem_,
                           upload_staging_size_, upload_staging_mapped_)) {
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(xbuf);
        return false;
    }
    std::memcpy(upload_staging_mapped_, x, need_x);
    gpu_counters_.upload_bytes += need_x;
    if (!EnsureHostVisible(n_out * sizeof(float), readback_buffer_, readback_memory_,
                           readback_size_, readback_mapped_)) {
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(xbuf);
        return false;
    }

    VkDescriptorSet ds = quant_ds_ring_[quant_ds_ring_next_];
    quant_ds_ring_next_ = (quant_ds_ring_next_ + 1) % quant_ds_ring_.size();
    ++gpu_counters_.descriptor_reuses;
    ++gpu_counters_.descriptor_sets_in_flight;
    if (gpu_counters_.descriptor_sets_in_flight > gpu_counters_.descriptor_sets_peak)
        gpu_counters_.descriptor_sets_peak = gpu_counters_.descriptor_sets_in_flight;
    struct InFlightGuard {
        GpuCounters& c;
        ~InFlightGuard() { if (c.descriptor_sets_in_flight > 0) --c.descriptor_sets_in_flight; }
    } in_flight_guard{gpu_counters_};

    VkDescriptorBufferInfo infos[3];
    VkWriteDescriptorSet writes[3];
    const VkBuffer bufs[3] = { xbuf->buffer, w->buffer, obuf->buffer };
    const size_t sizes[3] = { need_x, packed_bytes, n_out * sizeof(float) };
    for (int i = 0; i < 3; ++i) {
        infos[i] = {};
        infos[i].buffer = bufs[i];
        infos[i].range = sizes[i];
        writes[i] = {};
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = ds;
        writes[i].dstBinding = i;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[i].pBufferInfo = &infos[i];
    }
    vkUpdateDescriptorSets(device_, 3, writes, 0, nullptr);

    if (vkResetFences(device_, 1, &quant_fence_) != VK_SUCCESS || vkResetCommandBuffer(quant_cmd_, 0) != VK_SUCCESS) {
        std::cerr << "fp16 dot reset failed" << std::endl;
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(xbuf);
        return false;
    }
    VkCommandBufferBeginInfo begin_info{};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    if (vkBeginCommandBuffer(quant_cmd_, &begin_info) != VK_SUCCESS) {
        std::cerr << "fp16 dot command buffer begin failed" << std::endl;
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(xbuf);
        return false;
    }

    VkBufferCopy up_region{};
    up_region.size = need_x;
    vkCmdCopyBuffer(quant_cmd_, upload_staging_, xbuf->buffer, 1, &up_region);
    VkBufferMemoryBarrier up_barrier{};
    up_barrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    up_barrier.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    up_barrier.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
    up_barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    up_barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    up_barrier.buffer = xbuf->buffer;
    up_barrier.size = need_x;
    vkCmdPipelineBarrier(quant_cmd_, VK_PIPELINE_STAGE_TRANSFER_BIT,
                         VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0,
                         0, nullptr, 1, &up_barrier, 0, nullptr);

    auto it = shaders_.find("fp16gemv");
    if (it == shaders_.end() || !it->second.pipeline) {
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(xbuf);
        return false;
    }
    uint32_t pc[4] = { (uint32_t)n_out, (uint32_t)n_in, 0u, 0u };
    vkCmdPushConstants(quant_cmd_, it->second.layout, VK_SHADER_STAGE_COMPUTE_BIT,
                       0, sizeof(pc), pc);
    vkCmdBindPipeline(quant_cmd_, VK_PIPELINE_BIND_POINT_COMPUTE, it->second.pipeline);
    vkCmdBindDescriptorSets(quant_cmd_, VK_PIPELINE_BIND_POINT_COMPUTE,
                            it->second.layout, 0, 1, &ds, 0, nullptr);
    uint32_t groups = (uint32_t)n_out;
    if (groups == 0u) groups = 1u;
    vkCmdDispatch(quant_cmd_, groups, 1, 1);

    VkBufferMemoryBarrier down_barrier{};
    down_barrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    down_barrier.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
    down_barrier.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
    down_barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    down_barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    down_barrier.buffer = obuf->buffer;
    down_barrier.size = n_out * sizeof(float);
    vkCmdPipelineBarrier(quant_cmd_, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                         VK_PIPELINE_STAGE_TRANSFER_BIT, 0,
                         0, nullptr, 1, &down_barrier, 0, nullptr);
    VkBufferCopy down_region{};
    down_region.size = n_out * sizeof(float);
    vkCmdCopyBuffer(quant_cmd_, obuf->buffer, readback_buffer_, 1, &down_region);

    if (vkEndCommandBuffer(quant_cmd_) != VK_SUCCESS) {
        std::cerr << "fp16 dot command buffer end failed" << std::endl;
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(xbuf);
        return false;
    }
    VkSubmitInfo submit_info{};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &quant_cmd_;
    if (vkQueueSubmit(compute_queue_, 1, &submit_info, quant_fence_) != VK_SUCCESS) {
        std::cerr << "fp16 dot queue submit failed" << std::endl;
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(xbuf);
        return false;
    }
    ++gpu_counters_.submits;
    if (vkWaitForFences(device_, 1, &quant_fence_, VK_TRUE, UINT64_MAX) != VK_SUCCESS) {
        std::cerr << "fp16 dot fence wait failed" << std::endl;
        ReleaseQuantScratch(obuf);
        ReleaseQuantScratch(xbuf);
        return false;
    }
    ++gpu_counters_.waits;
    gpu_counters_.download_bytes += n_out * sizeof(float);
    std::memcpy(out, readback_mapped_, n_out * sizeof(float));
    ReleaseQuantScratch(obuf);
    ReleaseQuantScratch(xbuf);
    return true;
}

// ---------------------------------------------------------------------------
// Quant-dot fast path helpers.
// ---------------------------------------------------------------------------

// Grow-or-create a persistent host-visible, host-coherent buffer that stays
// mapped. Grow is only ever attempted between submissions, so no in-flight
// command buffer can reference the old object.
bool VulkanCompute::EnsureHostVisible(size_t bytes, VkBuffer& buf,
                                      VkDeviceMemory& mem, size_t& size,
                                      void*& mapped) {
    if (buf && mapped && size >= bytes) return true;
    if (buf) {
        if (mapped) { vkUnmapMemory(device_, mem); mapped = nullptr; }
        vkDestroyBuffer(device_, buf, nullptr);
        vkFreeMemory(device_, mem, nullptr);
        buf = nullptr; mem = nullptr; size = 0;
    }
    VkBufferCreateInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bi.size = bytes;
    bi.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (vkCreateBuffer(device_, &bi, nullptr, &buf) != VK_SUCCESS) return false;

    VkMemoryRequirements req{};
    vkGetBufferMemoryRequirements(device_, buf, &req);
    VkMemoryAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    ai.allocationSize = req.size;
    ai.memoryTypeIndex = FindMemoryType(req.memoryTypeBits,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    if (vkAllocateMemory(device_, &ai, nullptr, &mem) != VK_SUCCESS) {
        vkDestroyBuffer(device_, buf, nullptr);
        buf = nullptr;
        return false;
    }
    if (vkBindBufferMemory(device_, buf, mem, 0) != VK_SUCCESS ||
        vkMapMemory(device_, mem, 0, req.size, 0, &mapped) != VK_SUCCESS) {
        vkFreeMemory(device_, mem, nullptr);
        vkDestroyBuffer(device_, buf, nullptr);
        buf = nullptr; mem = nullptr;
        return false;
    }
    size = bytes;
    return true;
}

VulkanCompute::QuantWeight* VulkanCompute::EnsureQuantWeight(const void* packed, size_t bytes,
                                              int kind) {
    uint64_t fp = 0;
    std::memcpy(&fp, packed, sizeof(fp) < bytes ? sizeof(fp) : bytes);

    auto it = quant_weight_cache_.find(packed);
    if (it != quant_weight_cache_.end()) {
        QuantWeight& e = it->second;
        if (e.bytes == bytes && e.kind == kind && e.fingerprint == fp) {
            e.last_used = ++quant_lru_seq_;
            ++gpu_counters_.weight_cache_hits;
            return &e;
        }
        // Stale entry (pointer reuse): destroy and re-upload below.
        if (e.buffer) vkDestroyBuffer(device_, e.buffer, nullptr);
        if (e.memory) vkFreeMemory(device_, e.memory, nullptr);
        gpu_counters_.device_bytes_live -= e.bytes;
        quant_weight_cache_.erase(it);
    }

    // Residency budget: weights are immutable, but the model can exceed VRAM,
    // so the cache is budgeted and evicts least-recently-used entries rather
    // than assuming infinite device memory.
    while (!quant_weight_cache_.empty() &&
           gpu_counters_.device_bytes_live + bytes > quant_weight_budget_bytes_) {
        auto victim = quant_weight_cache_.begin();
        for (auto cit = quant_weight_cache_.begin(); cit != quant_weight_cache_.end(); ++cit) {
            if (cit->second.last_used < victim->second.last_used) victim = cit;
        }
        if (victim->second.buffer) vkDestroyBuffer(device_, victim->second.buffer, nullptr);
        if (victim->second.memory) vkFreeMemory(device_, victim->second.memory, nullptr);
        gpu_counters_.device_bytes_live -= victim->second.bytes;
        quant_weight_cache_.erase(victim);
    }

    QuantWeight e;
    e.bytes = bytes;
    e.kind = kind;
    e.fingerprint = fp;
    e.last_used = ++quant_lru_seq_;
    // The upload is a one-time staging copy on its own submission; it completes
    // before this function returns, so later dispatches need no barrier for it.
    //
    // The cache OWNS this buffer exclusively: it uses the raw AllocateBuffer
    // overload, which does NOT register the buffer in allocated_buffers_,
    // because Cleanup() destroys allocated_buffers_ AND ReleaseQuantFastPath()
    // destroys the cache - registering in both is a double free that corrupts
    // the heap at shutdown. The accounting counters are updated here instead
    // so the instrumentation stays complete.
    if (!AllocateBuffer(bytes, e.buffer, e.memory)) {
        std::cerr << "Quant-dot weight buffer allocation failed" << std::endl;
        return nullptr;
    }
    ++gpu_counters_.buffer_allocations;
    gpu_counters_.device_bytes_live += bytes;
    if (gpu_counters_.device_bytes_live > gpu_counters_.device_bytes_peak)
        gpu_counters_.device_bytes_peak = gpu_counters_.device_bytes_live;
    if (!CopyHostToBuffer(const_cast<void*>(packed), e.buffer, bytes)) {
        std::cerr << "Quant-dot weight upload failed" << std::endl;
        vkDestroyBuffer(device_, e.buffer, nullptr);
        vkFreeMemory(device_, e.memory, nullptr);
        gpu_counters_.device_bytes_live -= bytes;
        return nullptr;
    }
    ++gpu_counters_.weight_cache_misses;
    auto res = quant_weight_cache_.emplace(packed, e);
    return &res.first->second;
}

// Pooled device buffers. Acquire returns a free entry with capacity >= bytes,
// or creates one; release makes it available again. Storage is a vector of
// unique_ptr so entries keep STABLE addresses: acquiring a second entry must
// never invalidate a pointer the caller already holds. All reuse happens
// after the caller's fence wait, so a released buffer is never in flight.
VulkanCompute::QuantScratch* VulkanCompute::AcquireQuantScratch(size_t bytes) {
    for (auto& up : quant_scratch_pool_) {
        QuantScratch* s = up.get();
        if (!s->in_use && s->capacity >= bytes) {
            s->in_use = true;
            return s;
        }
    }
    auto up = std::make_unique<QuantScratch>();
    if (!AllocateBuffer(bytes, up->buffer, up->memory)) return nullptr;
    up->capacity = bytes;
    up->in_use = true;
    ++gpu_counters_.buffer_allocations;
    gpu_counters_.device_bytes_live += bytes;
    if (gpu_counters_.device_bytes_live > gpu_counters_.device_bytes_peak)
        gpu_counters_.device_bytes_peak = gpu_counters_.device_bytes_live;
    quant_scratch_pool_.push_back(std::move(up));
    return quant_scratch_pool_.back().get();
}

void VulkanCompute::ReleaseQuantScratch(QuantScratch* s) {
    if (s) s->in_use = false;
}

bool VulkanCompute::EnsureQuantFastPath() {
    if (quant_fast_ready_) return true;
    if (!device_ || quant_descriptor_set_layout_ == nullptr) return false;

    // Residency budget for cached weights: weights are immutable, but the
    // model can exceed VRAM, so the cache is budgeted and evicts LRU entries
    // rather than assuming infinite device memory. The budget defaults to the
    // largest device-local heap MINUS a small reserve for the scratch/upload
    // buffers, not three quarters of it: a MoE expert bank set is tens of GB,
    // and a 3/4 budget makes a model that WOULD fit thrash instead - every
    // expert dot then re-uploads its weights, which is a bandwidth cliff, not
    // a correctness bug (an evicted entry is simply re-uploaded).
    // RR_WEIGHT_CACHE_MAX_BYTES still pins the budget explicitly.
    if (quant_weight_budget_bytes_ == 0) {
        VkDeviceSize largest = 0;
        for (uint32_t i = 0; i < device_info_.memory_props.memoryHeapCount; ++i) {
            const auto& h = device_info_.memory_props.memoryHeaps[i];
            if ((h.flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) && h.size > largest)
                largest = h.size;
        }
        quant_weight_budget_bytes_ = (largest > 0) ? (uint64_t)(largest / 100u * 90u)
                                                   : (uint64_t)1 << 30;
        const char* env = std::getenv("RR_WEIGHT_CACHE_MAX_BYTES");
        if (env && *env) {
            const unsigned long long v = std::strtoull(env, nullptr, 10);
            if (v > 0) quant_weight_budget_bytes_ = (uint64_t)v;
        }
    }

    // Descriptor ring: a handful of sets recycled for the life of the device.
    if (quant_ds_ring_.empty()) {
        quant_ds_ring_.assign(kQuantRingSets, VK_NULL_HANDLE);
        // pSetLayouts is an ARRAY of descriptorSetCount layouts. Passing the
        // address of the single layout member makes the driver read
        // descriptorSetCount handles starting there, i.e. past the member into
        // unrelated class members: the AMD driver answers that malformed
        // request with VK_ERROR_OUT_OF_POOL_MEMORY (-1000069000), which then
        // silently pushed every quant-dot onto the CPU. All ring slots share
        // one layout, so the array is that layout repeated.
        VkDescriptorSetLayout layouts[kQuantRingSets];
        for (uint32_t i = 0; i < kQuantRingSets; ++i) layouts[i] = quant_descriptor_set_layout_;
        VkDescriptorSetAllocateInfo alloc{};
        alloc.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
        alloc.descriptorPool = quant_descriptor_pool_;
        alloc.descriptorSetCount = static_cast<uint32_t>(quant_ds_ring_.size());
        alloc.pSetLayouts = layouts;
        ++gpu_counters_.descriptor_alloc_attempts;
        const VkResult r = vkAllocateDescriptorSets(device_, &alloc, quant_ds_ring_.data());
        if (r != VK_SUCCESS) {
            ++gpu_counters_.descriptor_alloc_failures;
            std::cerr << "[QUANT_DOT] descriptor ring allocation failed: VkResult="
                      << static_cast<int>(r)
                      << " (-1000069000=VK_ERROR_OUT_OF_POOL_MEMORY)"
                         " pool_maxSets=" << quant_pool_max_sets_
                      << " ring_sets=" << quant_ds_ring_.size() << std::endl;
            quant_ds_ring_.clear();
            return false;
        }
        gpu_counters_.descriptor_allocations += quant_ds_ring_.size();
        quant_ds_ring_next_ = 0;
    }

    // Persistent command buffer and fence for the per-call submission.
    if (!quant_cmd_) {
        VkCommandBufferAllocateInfo ai{};
        ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        ai.commandPool = command_pool_;
        ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        ai.commandBufferCount = 1;
        if (vkAllocateCommandBuffers(device_, &ai, &quant_cmd_) != VK_SUCCESS) {
            std::cerr << "Quant-dot command buffer allocation failed" << std::endl;
            return false;
        }
    }
    if (!quant_fence_) {
        VkFenceCreateInfo fi{};
        fi.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        if (vkCreateFence(device_, &fi, nullptr, &quant_fence_) != VK_SUCCESS) {
            std::cerr << "Quant-dot fence creation failed" << std::endl;
            return false;
        }
    }

    quant_fast_ready_ = true;
    return true;
}

void VulkanCompute::ReleaseQuantFastPath() {
    for (auto& kv : quant_weight_cache_) {
        if (kv.second.buffer) vkDestroyBuffer(device_, kv.second.buffer, nullptr);
        if (kv.second.memory) vkFreeMemory(device_, kv.second.memory, nullptr);
    }
    quant_weight_cache_.clear();
    // Batch buffers (host and device) and the batch descriptor sets.
    if (quant_batch_q8_host_) {
        if (quant_batch_q8_host_mapped_) { vkUnmapMemory(device_, quant_batch_q8_host_mem_); }
        vkDestroyBuffer(device_, quant_batch_q8_host_, nullptr);
        vkFreeMemory(device_, quant_batch_q8_host_mem_, nullptr);
        quant_batch_q8_host_ = nullptr; quant_batch_q8_host_mem_ = nullptr;
        quant_batch_q8_host_mapped_ = nullptr; quant_batch_q8_host_size_ = 0;
    }
    if (quant_batch_out_host_) {
        if (quant_batch_out_host_mapped_) { vkUnmapMemory(device_, quant_batch_out_host_mem_); }
        vkDestroyBuffer(device_, quant_batch_out_host_, nullptr);
        vkFreeMemory(device_, quant_batch_out_host_mem_, nullptr);
        quant_batch_out_host_ = nullptr; quant_batch_out_host_mem_ = nullptr;
        quant_batch_out_host_mapped_ = nullptr; quant_batch_out_host_size_ = 0;
    }
    if (quant_batch_q8_dev_) {
        vkDestroyBuffer(device_, quant_batch_q8_dev_, nullptr);
        vkFreeMemory(device_, quant_batch_q8_mem_, nullptr);
        quant_batch_q8_dev_ = nullptr; quant_batch_q8_mem_ = nullptr; quant_batch_q8_cap_ = 0;
    }
    if (quant_batch_out_dev_) {
        vkDestroyBuffer(device_, quant_batch_out_dev_, nullptr);
        vkFreeMemory(device_, quant_batch_out_mem_, nullptr);
        quant_batch_out_dev_ = nullptr; quant_batch_out_mem_ = nullptr; quant_batch_out_cap_ = 0;
    }
    quant_batch_sets_.clear();
    quant_batch_entries_.clear();
    quant_batch_active_ = false;
    for (auto& up : quant_scratch_pool_) {
        if (up->buffer) vkDestroyBuffer(device_, up->buffer, nullptr);
        if (up->memory) vkFreeMemory(device_, up->memory, nullptr);
    }
    quant_scratch_pool_.clear();
    if (upload_staging_mapped_) { vkUnmapMemory(device_, upload_staging_mem_); upload_staging_mapped_ = nullptr; }
    if (upload_staging_) { vkDestroyBuffer(device_, upload_staging_, nullptr); upload_staging_ = nullptr; }
    if (upload_staging_mem_) { vkFreeMemory(device_, upload_staging_mem_, nullptr); upload_staging_mem_ = nullptr; }
    upload_staging_size_ = 0;
    if (readback_mapped_) { vkUnmapMemory(device_, readback_memory_); readback_mapped_ = nullptr; }
    if (readback_buffer_) { vkDestroyBuffer(device_, readback_buffer_, nullptr); readback_buffer_ = nullptr; }
    if (readback_memory_) { vkFreeMemory(device_, readback_memory_, nullptr); readback_memory_ = nullptr; }
    readback_size_ = 0;
    if (quant_cmd_) { vkFreeCommandBuffers(device_, command_pool_, 1, &quant_cmd_); quant_cmd_ = nullptr; }
    if (quant_fence_) { vkDestroyFence(device_, quant_fence_, nullptr); quant_fence_ = nullptr; }
    quant_ds_ring_.clear();
    quant_fast_ready_ = false;
    gpu_counters_.device_bytes_live = 0;
    quant_lru_seq_ = 0;
}


bool VulkanCompute::CreateDescriptorSetLayout(uint32_t binding_count, VkDescriptorSetLayout& layout) {
    // This function is deprecated - descriptor layouts are now created in EnsureMatMulPipeline
    // Kept for backward compatibility but should not be used
    std::cerr << "WARNING: CreateDescriptorSetLayout is deprecated. Use EnsureMatMulPipeline instead." << std::endl;
    return false;
}

bool VulkanCompute::AllocateDescriptorSet(VkDescriptorSetLayout layout, VkDescriptorSet& descriptor_set) {
    // This function is deprecated - descriptor set allocation is now handled in DispatchMatMul
    // Kept for backward compatibility but should not be used
    std::cerr << "WARNING: AllocateDescriptorSet is deprecated. Use DispatchMatMul instead." << std::endl;
    return false;
}

bool VulkanCompute::UpdateDescriptorSet(VkDescriptorSet descriptor_set, uint32_t binding, 
                                        VkBuffer buffer, size_t buffer_size) {
    // This function is deprecated - descriptor set updates are now handled in DispatchMatMul
    // Kept for backward compatibility but should not be used
    std::cerr << "WARNING: UpdateDescriptorSet is deprecated. Use DispatchMatMul instead." << std::endl;
    return false;
}

bool VulkanCompute::DispatchMatMul(uint32_t input_a_idx,
                                   uint32_t input_b_idx,
                                   uint32_t output_idx,
                                   uint32_t M,
                                   uint32_t K,
                                   uint32_t N) {
    
    // Validate buffer indices
    if (input_a_idx >= allocated_buffers_.size() || 
        input_b_idx >= allocated_buffers_.size() ||
        output_idx >= allocated_buffers_.size()) {
        std::cerr << "Invalid buffer indices for MatMul dispatch" << std::endl;
        return false;
    }
    
    // Check if matmul pipeline and descriptor system are initialized
    auto it = shaders_.find("matmul");
    if (it == shaders_.end() || !it->second.pipeline || !matmul_descriptor_set_layout_ || !matmul_descriptor_pool_) {
        std::cerr << "MatMul pipeline or descriptor system not initialized. Call EnsureMatMulPipeline first." << std::endl;
        return false;
    }
    
    // Get buffer handles
    VkBuffer buffers[3] = {
        allocated_buffers_[input_a_idx].first,
        allocated_buffers_[input_b_idx].first,
        allocated_buffers_[output_idx].first
    };
    
    // Calculate buffer sizes
    size_t sizes[3] = {
        (size_t)M * K * sizeof(float),
        (size_t)K * N * sizeof(float),
        (size_t)M * N * sizeof(float)
    };

    // --- 1. Allocate Descriptor Set from the PERMANENT Pool ---
    VkDescriptorSetAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    alloc_info.descriptorPool = matmul_descriptor_pool_;
    alloc_info.descriptorSetCount = 1;
    alloc_info.pSetLayouts = &matmul_descriptor_set_layout_;

    VkDescriptorSet descriptor_set = nullptr;
    if (vkAllocateDescriptorSets(device_, &alloc_info, &descriptor_set) != VK_SUCCESS) {
        std::cerr << "Failed to allocate descriptor set for MatMul" << std::endl;
        return false;
    }

    // --- 2. Update Descriptor Set (Bind Buffers to Bindings 0, 1, 2) ---
    std::vector<VkDescriptorBufferInfo> buffer_infos(3);
    std::vector<VkWriteDescriptorSet> writes(3);

    for (int i = 0; i < 3; ++i) {
        buffer_infos[i].buffer = buffers[i];
        buffer_infos[i].offset = 0;
        buffer_infos[i].range = sizes[i];

        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].pNext = nullptr;
        writes[i].dstSet = descriptor_set;
        writes[i].dstBinding = i;
        writes[i].dstArrayElement = 0;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[i].pImageInfo = nullptr;
        writes[i].pBufferInfo = &buffer_infos[i];
        writes[i].pTexelBufferView = nullptr;
    }

    vkUpdateDescriptorSets(device_, (uint32_t)writes.size(), writes.data(), 0, nullptr);
    std::cout << "Updated descriptor set with 3 storage buffers (A, B, Output)" << std::endl;

    // --- 3. Execute Command Buffer (Dispatch) ---
    bool success = ExecuteSingleTimeCommands([&](VkCommandBuffer cmd_buffer) {
        
        // Push Constants. NOTE: the shader declares its push-constant block as
        // { m, n, k }, so the values MUST be written in that order. This was
        // previously { M, K, N }, which silently swapped n and k and made the
        // GPU compute a differently-shaped matmul than the CPU reference.
        uint32_t push_data[3] = {M, N, K};
        vkCmdPushConstants(cmd_buffer, 
                           it->second.layout, 
                           VK_SHADER_STAGE_COMPUTE_BIT, 
                           0, 
                           sizeof(push_data), 
                           push_data);

        // Bind Compute Pipeline
        vkCmdBindPipeline(cmd_buffer, VK_PIPELINE_BIND_POINT_COMPUTE, it->second.pipeline);

        // Bind Descriptor Set
        vkCmdBindDescriptorSets(cmd_buffer, 
                                VK_PIPELINE_BIND_POINT_COMPUTE, 
                                it->second.layout, 
                                0, 1, &descriptor_set, 0, nullptr);

        // Dispatch Command (Assuming 16x16 tile workgroup size in shader)
        const uint32_t TILE_SIZE = 16;
        uint32_t group_count_x = (N + TILE_SIZE - 1) / TILE_SIZE;
        uint32_t group_count_y = (M + TILE_SIZE - 1) / TILE_SIZE;
        
        std::cout << "Dispatching: " << group_count_x << "x" << group_count_y << "x1 workgroups" << std::endl;
        vkCmdDispatch(cmd_buffer, group_count_x, group_count_y, 1);
    });
    
    // --- 4. Clean up Descriptor Set ---
    if (descriptor_set) {
        // Free the set back to the pool for reuse
        vkFreeDescriptorSets(device_, matmul_descriptor_pool_, 1, &descriptor_set);
    }
    
    if (success) {
        std::cout << "MatMul dispatch completed successfully (" << M << "x" << K << " * " << K << "x" << N << " -> " << M << "x" << N << ")" << std::endl;
    } else {
        std::cerr << "MatMul GPU dispatch failed." << std::endl;
    }
    
    return success;
}

bool VulkanCompute::ExecuteMatMul(const float* input_a, const float* input_b,
                                  float* output, uint32_t m, uint32_t k, uint32_t n) {
    // Naive CPU fallback (O(m*k*n)) for benchmarking correctness.
    // If a Vulkan shader/pipeline is loaded named "matmul" we would dispatch it instead.
    // Clear output
    std::fill(output, output + (size_t)m * n, 0.0f);
    for (uint32_t row = 0; row < m; ++row) {
        const float* arow = input_a + (size_t)row * k;
        for (uint32_t col = 0; col < n; ++col) {
            float sum = 0.0f;
            for (uint32_t inner = 0; inner < k; ++inner) {
                sum += arow[inner] * input_b[(size_t)inner * n + col];
            }
            output[(size_t)row * n + col] = sum;
        }
    }
    return true;
}

bool VulkanCompute::DispatchMatMulAsync(uint32_t input_a_idx,
                                        uint32_t input_b_idx,
                                        uint32_t output_idx,
                                        uint32_t M,
                                        uint32_t K,
                                        uint32_t N) {
    
    // Validate buffer indices
    if (input_a_idx >= allocated_buffers_.size() || 
        input_b_idx >= allocated_buffers_.size() ||
        output_idx >= allocated_buffers_.size()) {
        std::cerr << "Invalid buffer indices for MatMul async dispatch" << std::endl;
        return false;
    }
    
    // Check if matmul pipeline and descriptor system are initialized
    auto it = shaders_.find("matmul");
    if (it == shaders_.end() || !it->second.pipeline || !matmul_descriptor_set_layout_ || !matmul_descriptor_pool_) {
        std::cerr << "MatMul pipeline not initialized. Call EnsureMatMulPipeline first." << std::endl;
        return false;
    }
    
    // Get buffer handles
    VkBuffer buffers[3] = {
        allocated_buffers_[input_a_idx].first,
        allocated_buffers_[input_b_idx].first,
        allocated_buffers_[output_idx].first
    };
    
    // Calculate buffer sizes
    size_t sizes[3] = {
        (size_t)M * K * sizeof(float),
        (size_t)K * N * sizeof(float),
        (size_t)M * N * sizeof(float)
    };

    // --- 1. Allocate Descriptor Set from PERMANENT Pool ---
    VkDescriptorSetAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    alloc_info.descriptorPool = matmul_descriptor_pool_;
    alloc_info.descriptorSetCount = 1;
    alloc_info.pSetLayouts = &matmul_descriptor_set_layout_;

    VkDescriptorSet descriptor_set = nullptr;
    if (vkAllocateDescriptorSets(device_, &alloc_info, &descriptor_set) != VK_SUCCESS) {
        std::cerr << "Failed to allocate descriptor set for async MatMul" << std::endl;
        return false;
    }

    // --- 2. Update Descriptor Set (Bind Buffers A, B, Output) ---
    std::vector<VkDescriptorBufferInfo> buffer_infos(3);
    std::vector<VkWriteDescriptorSet> writes(3);

    for (int i = 0; i < 3; ++i) {
        buffer_infos[i].buffer = buffers[i];
        buffer_infos[i].offset = 0;
        buffer_infos[i].range = sizes[i];

        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].pNext = nullptr;
        writes[i].dstSet = descriptor_set;
        writes[i].dstBinding = i;
        writes[i].dstArrayElement = 0;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[i].pImageInfo = nullptr;
        writes[i].pBufferInfo = &buffer_infos[i];
        writes[i].pTexelBufferView = nullptr;
    }

    vkUpdateDescriptorSets(device_, (uint32_t)writes.size(), writes.data(), 0, nullptr);

    // --- 3. Acquire Command Buffer from Async Pool (NON-BLOCKING) ---
    VkCommandBuffer cmd_buffer = AcquireAsyncCommandBuffer();
    if (!cmd_buffer) {
        std::cerr << "No available command buffers in pool. Consider FlushAsyncCommands()." << std::endl;
        vkFreeDescriptorSets(device_, matmul_descriptor_pool_, 1, &descriptor_set);
        return false;
    }

    // --- 4. Record Commands (Non-blocking recording) ---
    VkCommandBufferBeginInfo begin_info{};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;

    if (vkBeginCommandBuffer(cmd_buffer, &begin_info) != VK_SUCCESS) {
        std::cerr << "Failed to begin command buffer for async MatMul" << std::endl;
        vkFreeDescriptorSets(device_, matmul_descriptor_pool_, 1, &descriptor_set);
        return false;
    }

    // Push Constants. The shader declares its push-constant block as
    // { m, n, k }, so the values MUST be written in that order.
    uint32_t push_data[3] = {M, N, K};
    vkCmdPushConstants(cmd_buffer, 
                       it->second.layout, 
                       VK_SHADER_STAGE_COMPUTE_BIT, 
                       0, 
                       sizeof(push_data), 
                       push_data);

    // Bind Compute Pipeline
    vkCmdBindPipeline(cmd_buffer, VK_PIPELINE_BIND_POINT_COMPUTE, it->second.pipeline);

    // Bind Descriptor Set
    vkCmdBindDescriptorSets(cmd_buffer, 
                            VK_PIPELINE_BIND_POINT_COMPUTE, 
                            it->second.layout, 
                            0, 1, &descriptor_set, 0, nullptr);

    // Dispatch with calculated workgroups
    const uint32_t TILE_SIZE = 16;  // Matches shader compile-time constant
    uint32_t group_count_x = (N + TILE_SIZE - 1) / TILE_SIZE;
    uint32_t group_count_y = (M + TILE_SIZE - 1) / TILE_SIZE;
    
    vkCmdDispatch(cmd_buffer, group_count_x, group_count_y, 1);

    if (vkEndCommandBuffer(cmd_buffer) != VK_SUCCESS) {
        std::cerr << "Failed to end command buffer for async MatMul" << std::endl;
        vkFreeDescriptorSets(device_, matmul_descriptor_pool_, 1, &descriptor_set);
        return false;
    }

    // --- 5. Submit Async (FIRE AND FORGET) ---
    if (!SubmitAsyncCommandBuffer(cmd_buffer)) {
        std::cerr << "Failed to submit async MatMul command buffer" << std::endl;
        vkFreeDescriptorSets(device_, matmul_descriptor_pool_, 1, &descriptor_set);
        return false;
    }

    std::cout << "Async MatMul queued: " << M << "x" << K << " * " << K << "x" << N 
              << " (" << group_count_x << "x" << group_count_y << " workgroups)" << std::endl;
    
    // Note: Descriptor set will be freed after GPU execution completes
    // In a production system, track descriptor sets with command buffers for deferred cleanup
    
    return true;
}

bool VulkanCompute::ExecuteAttention(const float* queries, const float* keys, const float* values,
                                     float* output, uint32_t seq_len, uint32_t head_dim) {
    // CPU scaled dot-product attention (single head)
    // Q: [seq_len, head_dim], K: [seq_len, head_dim], V: [seq_len, head_dim]
    // output = softmax(Q*K^T / sqrt(head_dim)) * V => [seq_len, head_dim]
    if (!queries || !keys || !values || !output || seq_len == 0 || head_dim == 0) return false;
    std::vector<float> scores((size_t)seq_len * seq_len);
    const float scale = 1.0f / std::sqrt((float)head_dim);
    // Compute QK^T
    for (uint32_t i = 0; i < seq_len; ++i) {
        const float* Qi = queries + (size_t)i * head_dim;
        for (uint32_t j = 0; j < seq_len; ++j) {
            const float* Kj = keys + (size_t)j * head_dim;
            float dot = 0.0f;
            for (uint32_t d = 0; d < head_dim; ++d) dot += Qi[d] * Kj[d];
            scores[(size_t)i * seq_len + j] = dot * scale;
        }
    }
    // Softmax per row
    for (uint32_t i = 0; i < seq_len; ++i) {
        float* row = scores.data() + (size_t)i * seq_len;
        float maxv = row[0];
        for (uint32_t j = 1; j < seq_len; ++j) maxv = std::max(maxv, row[j]);
        double sum = 0.0;
        for (uint32_t j = 0; j < seq_len; ++j) { row[j] = std::exp(row[j] - maxv); sum += row[j]; }
        double inv = sum == 0.0 ? 0.0 : 1.0 / sum;
        for (uint32_t j = 0; j < seq_len; ++j) row[j] = (float)(row[j] * inv);
    }
    // Multiply by V: output[i] = Σ_j scores[i,j] * V[j]
    for (uint32_t i = 0; i < seq_len; ++i) {
        float* Outi = output + (size_t)i * head_dim;
        std::fill(Outi, Outi + head_dim, 0.0f);
        float* attRow = scores.data() + (size_t)i * seq_len;
        for (uint32_t j = 0; j < seq_len; ++j) {
            const float* Vj = values + (size_t)j * head_dim;
            float w = attRow[j];
            for (uint32_t d = 0; d < head_dim; ++d) {
                Outi[d] += w * Vj[d];
            }
        }
    }
    return true;
}

bool VulkanCompute::ExecuteRoPE(float* embeddings, uint32_t dim, uint32_t seq_pos, uint32_t rotation_dim) {
    // Real GPU RoPE with YaRN interpolation, matching MGRope::Alpha() in
    // ModelGenieExecutor.cpp. Replaces a placeholder that performed no work.
    //
    // Parameters default to the DeepSeek-V2-Lite Chat configuration so the
    // kernel reproduces the certified CPU path without extra host plumbing.
    if (!embeddings || dim == 0) return false;

    // Deep2 rope.scaling values (see MGRope in ModelGenieExecutor.cpp).
    const float kFreqBase  = 10000.0f;   // rope.scaling.freq_base
    const float kFreqScale = 0.025f;     // rope.scaling.factor
    const float kNCtxOrig  = 4096.0f;    // rope.scaling.original_context_length
    const float kBetaFast  = 32.0f;      // yarn.beta_fast
    const float kBetaSlow  = 1.0f;       // yarn.beta_slow
    // yarn_log_multiplier is not needed: in this configuration
    // attn_factor_org == rope_attn_factor == 1, so mscale == 1 and the
    // cos/sin pair requires no magnitude scaling.

    // Rotation dim must be even; fall back to CPU semantics if it is not.
    uint32_t n_rot = (rotation_dim ? rotation_dim : dim) & ~1u;
    if (n_rot > dim) n_rot = dim & ~1u;

    // Ensure the RoPE pipeline exists.
    if (!EnsureRoPEPipeline(kRoPEShaderPath)) {
        std::cerr << "RoPE pipeline unavailable at " << kRoPEShaderPath << std::endl;
        return false;
    }
    auto it = shaders_.find("rope");
    if (it == shaders_.end() || !it->second.pipeline || !rope_descriptor_pool_) return false;

    const size_t bytes = (size_t)dim * sizeof(float);

    // Device buffers. Upload the vector, dispatch, read it back in place.
    // This is a host round-trip; a future integration can keep the vector
    // resident and avoid it.
    uint32_t in_idx = 0, out_idx = 0;
    size_t in_bytes = 0, out_bytes = 0;
    if (!AllocateBuffer(bytes, in_idx, in_bytes) ||
        !AllocateBuffer(bytes, out_idx, out_bytes)) {
        std::cerr << "RoPE buffer allocation failed" << std::endl;
        return false;
    }

    if (!CopyHostToBuffer(embeddings, in_idx, bytes)) {
        std::cerr << "RoPE upload failed" << std::endl;
        return false;
    }

    // Descriptor set for this dispatch.
    VkDescriptorSetAllocateInfo alloc{};
    alloc.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    alloc.descriptorPool = rope_descriptor_pool_;
    alloc.descriptorSetCount = 1;
    alloc.pSetLayouts = &rope_descriptor_set_layout_;

    VkDescriptorSet ds = VK_NULL_HANDLE;
    if (vkAllocateDescriptorSets(device_, &alloc, &ds) != VK_SUCCESS) {
        std::cerr << "RoPE descriptor allocation failed" << std::endl;
        return false;
    }

    VkBuffer bufs[2] = { allocated_buffers_[in_idx].first, allocated_buffers_[out_idx].first };
    VkDescriptorBufferInfo infos[2];
    VkWriteDescriptorSet writes[2];
    for (int i = 0; i < 2; ++i) {
        infos[i] = {};
        infos[i].buffer = bufs[i];
        infos[i].offset = 0;
        infos[i].range = bytes;
        writes[i] = {};
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = ds;
        writes[i].dstBinding = i;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[i].pBufferInfo = &infos[i];
    }
    vkUpdateDescriptorSets(device_, 2, writes, 0, nullptr);

    auto fb = [](float f) { uint32_t u; std::memcpy(&u, &f, 4); return u; };

    // Push constants. Floats cross the boundary as their bit patterns because
    // push-constant ranges are only guaranteed to be 4-byte aligned scalars.
    struct {
        uint32_t pos, n_rot, dim;
        uint32_t u_freq_base, u_freq_scale, u_n_ctx_orig;
        uint32_t u_beta_fast, u_beta_slow;
    } pc;
    pc.pos = seq_pos;
    pc.n_rot = n_rot;
    pc.dim = dim;
    pc.u_freq_base = fb(kFreqBase);
    pc.u_freq_scale = fb(kFreqScale);
    pc.u_n_ctx_orig = fb(kNCtxOrig);
    pc.u_beta_fast = fb(kBetaFast);
    pc.u_beta_slow = fb(kBetaSlow);

    bool ok = ExecuteSingleTimeCommands([&](VkCommandBuffer cmd) {
        vkCmdPushConstants(cmd, it->second.layout, VK_SHADER_STAGE_COMPUTE_BIT,
                           0, sizeof(pc), &pc);
        vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, it->second.pipeline);
        vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE,
                                it->second.layout, 0, 1, &ds, 0, nullptr);
        // One invocation per pair; the shader also handles the odd tail.
        uint32_t pairs = (dim + 1u) / 2u;
        uint32_t groups = (pairs + 15u) / 16u;
        vkCmdDispatch(cmd, groups, 1, 1);
    });

    if (ok) {
        if (!CopyBufferToHost(out_idx, embeddings, bytes)) {
            std::cerr << "RoPE readback failed" << std::endl;
            ok = false;
        }
    }

    vkFreeDescriptorSets(device_, rope_descriptor_pool_, 1, &ds);
    return ok;
}

bool VulkanCompute::ExecuteRMSNorm(float* data, uint32_t size, float epsilon) {
    // CPU RMSNorm: y = x / sqrt(mean(x^2) + eps)
    double accum = 0.0;
    for (uint32_t i = 0; i < size; ++i) {
        accum += (double)data[i] * (double)data[i];
    }
    double mean_sq = accum / std::max<uint32_t>(size,1);
    double denom = std::sqrt(mean_sq + (double)epsilon);
    if (denom == 0.0) denom = 1.0; // safety
    float inv = (float)(1.0 / denom);
    for (uint32_t i = 0; i < size; ++i) {
        data[i] = data[i] * inv;
    }
    return true;
}

bool VulkanCompute::ExecuteSiLU(float* data, uint32_t size) {
    // CPU SiLU: x * sigmoid(x)
    for (uint32_t i = 0; i < size; ++i) {
        float x = data[i];
        float s = 1.0f / (1.0f + std::exp(-x));
        data[i] = x * s;
    }
    return true;
}

bool VulkanCompute::ExecuteSoftmax(float* data, uint32_t size) {
    // CPU Softmax (in-place)
    if (size == 0) return true;
    float maxv = data[0];
    for (uint32_t i = 1; i < size; ++i) maxv = std::max(maxv, data[i]);
    double sum = 0.0;
    for (uint32_t i = 0; i < size; ++i) {
        data[i] = std::exp(data[i] - maxv);
        sum += data[i];
    }
    if (sum == 0.0) return true;
    double inv = 1.0 / sum;
    for (uint32_t i = 0; i < size; ++i) data[i] = (float)(data[i] * inv);
    return true;
}

bool VulkanCompute::ExecuteDequantize(const uint8_t* quantized, float* output,
                                      uint32_t elements, const std::string& quant_type) {
    if (!quantized || !output) return false;
    if (elements == 0) return true;
    // Basic branching for common quantization types.
    if (quant_type == "F32") {
        // Assume raw bytes represent floats (size must be elements*sizeof(float)) - copy reinterpret.
        const float* src = reinterpret_cast<const float*>(quantized);
        for (uint32_t i = 0; i < elements; ++i) output[i] = src[i];
        return true;
    } else if (quant_type == "Q2_K") {
        // Very rough: 2-bit values packed in bytes (4 values per byte). Scale to [-1,1].
        uint32_t outIndex = 0;
        for (uint32_t b = 0; outIndex < elements; ++b) {
            uint8_t packed = quantized[b];
            for (int nib = 0; nib < 4 && outIndex < elements; ++nib) {
                uint8_t v = (packed >> (nib * 2)) & 0x3;
                float f = (v / 3.0f) * 2.0f - 1.0f; // map 0..3 -> -1..1
                output[outIndex++] = f;
            }
        }
        return true;
    } else if (quant_type == "Q4_K") {
        // 4-bit values packed (2 per byte). Map 0..15 -> -1..1
        uint32_t outIndex = 0;
        for (uint32_t b = 0; outIndex < elements; ++b) {
            uint8_t packed = quantized[b];
            uint8_t hi = (packed >> 4) & 0xF;
            uint8_t lo = packed & 0xF;
            float fhi = (hi / 15.0f) * 2.0f - 1.0f;
            float flo = (lo / 15.0f) * 2.0f - 1.0f;
            output[outIndex++] = flo;
            if (outIndex < elements) output[outIndex++] = fhi;
        }
        return true;
    } else {
        // Fallback byte->[0,1]
        const float scale = 1.0f / 255.0f;
        for (uint32_t i = 0; i < elements; ++i) output[i] = quantized[i] * scale;
        return true;
    }
}

bool VulkanCompute::LoadSPIRVCode(const std::string& path, std::vector<uint32_t>& code) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open SPIR-V file: " << path << std::endl;
        return false;
    }

    size_t file_size = file.tellg();
    if (file_size % sizeof(uint32_t) != 0) {
        std::cerr << "Invalid SPIR-V file size: " << path << std::endl;
        return false;
    }

    file.seekg(0);
    code.resize(file_size / sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(code.data()), file_size);

    return true;
}

// ==================== KV CACHE INFRASTRUCTURE ====================

bool VulkanCompute::AllocateKVCache(uint32_t num_layers, uint32_t max_seq_len, uint32_t head_dim) {
    if (kv_cache_allocated_) {
        std::cerr << "KV cache already allocated. Call ClearKVCache() first." << std::endl;
        return false;
    }
    
    kv_cache_num_layers_ = num_layers;
    kv_cache_max_seq_len_ = max_seq_len;
    kv_cache_head_dim_ = head_dim;
    
    // Allocate 2 buffers per layer (K and V)
    kv_cache_buffers_.resize(num_layers * 2);
    
    size_t cache_size = static_cast<size_t>(max_seq_len) * head_dim * sizeof(float);
    
    std::cout << "Allocating KV cache: " << num_layers << " layers, "
              << max_seq_len << " max tokens, " << head_dim << " head_dim, "
              << (cache_size / 1024 / 1024) << " MB per buffer" << std::endl;
    
    for (uint32_t layer = 0; layer < num_layers; ++layer) {
        // Allocate K cache buffer
        VkBuffer k_buffer;
        VkDeviceMemory k_memory;
        if (!AllocateBuffer(cache_size, k_buffer, k_memory)) {
            std::cerr << "Failed to allocate K cache for layer " << layer << std::endl;
            ClearKVCache();
            return false;
        }
        kv_cache_buffers_[layer * 2] = {k_buffer, k_memory};
        
        // Zero-initialize K cache
        std::vector<float> zeros(max_seq_len * head_dim, 0.0f);
        if (!CopyHostToBuffer(zeros.data(), k_buffer, cache_size)) {
            std::cerr << "Failed to zero-init K cache for layer " << layer << std::endl;
            ClearKVCache();
            return false;
        }
        
        // Allocate V cache buffer
        VkBuffer v_buffer;
        VkDeviceMemory v_memory;
        if (!AllocateBuffer(cache_size, v_buffer, v_memory)) {
            std::cerr << "Failed to allocate V cache for layer " << layer << std::endl;
            ClearKVCache();
            return false;
        }
        kv_cache_buffers_[layer * 2 + 1] = {v_buffer, v_memory};
        
        // Zero-initialize V cache
        if (!CopyHostToBuffer(zeros.data(), v_buffer, cache_size)) {
            std::cerr << "Failed to zero-init V cache for layer " << layer << std::endl;
            ClearKVCache();
            return false;
        }
    }
    
    kv_cache_allocated_ = true;
    
    std::cout << "KV cache allocated successfully: "
              << (num_layers * 2 * cache_size / 1024 / 1024) << " MB total" << std::endl;
    
    return true;
}

bool VulkanCompute::AppendToKVCache(uint32_t layer_idx, const float* k_new, 
                                    const float* v_new, uint32_t token_pos) {
    if (!kv_cache_allocated_) {
        std::cerr << "KV cache not allocated. Call AllocateKVCache() first." << std::endl;
        return false;
    }
    
    if (layer_idx >= kv_cache_num_layers_) {
        std::cerr << "Invalid layer index: " << layer_idx << " >= " << kv_cache_num_layers_ << std::endl;
        return false;
    }
    
    if (token_pos >= kv_cache_max_seq_len_) {
        std::cerr << "Token position " << token_pos << " exceeds max_seq_len " << kv_cache_max_seq_len_ << std::endl;
        return false;
    }
    
    // Calculate offset and size for this token's K/V vectors
    size_t offset = static_cast<size_t>(token_pos) * kv_cache_head_dim_ * sizeof(float);
    size_t size = kv_cache_head_dim_ * sizeof(float);
    
    // Get K/V cache buffers for this layer
    VkBuffer k_buffer = kv_cache_buffers_[layer_idx * 2].first;
    VkBuffer v_buffer = kv_cache_buffers_[layer_idx * 2 + 1].first;
    
    // Update K cache at token_pos
    if (!CopyHostToBufferOffset(k_new, k_buffer, offset, size)) {
        std::cerr << "Failed to update K cache at layer " << layer_idx << ", pos " << token_pos << std::endl;
        return false;
    }
    
    // Update V cache at token_pos
    if (!CopyHostToBufferOffset(v_new, v_buffer, offset, size)) {
        std::cerr << "Failed to update V cache at layer " << layer_idx << ", pos " << token_pos << std::endl;
        return false;
    }
    
    return true;
}

bool VulkanCompute::GetKVCacheSlice(uint32_t layer_idx, uint32_t start_pos, 
                                    uint32_t end_pos, float* k_out, float* v_out) {
    if (!kv_cache_allocated_) {
        std::cerr << "KV cache not allocated" << std::endl;
        return false;
    }
    
    if (layer_idx >= kv_cache_num_layers_) {
        std::cerr << "Invalid layer index: " << layer_idx << std::endl;
        return false;
    }
    
    if (end_pos > kv_cache_max_seq_len_ || start_pos >= end_pos) {
        std::cerr << "Invalid slice range: [" << start_pos << ", " << end_pos << ")" << std::endl;
        return false;
    }
    
    // Calculate offset and size
    size_t offset = static_cast<size_t>(start_pos) * kv_cache_head_dim_ * sizeof(float);
    size_t size = static_cast<size_t>(end_pos - start_pos) * kv_cache_head_dim_ * sizeof(float);
    
    // Get K/V cache buffers
    VkBuffer k_buffer = kv_cache_buffers_[layer_idx * 2].first;
    VkBuffer v_buffer = kv_cache_buffers_[layer_idx * 2 + 1].first;
    
    // Read K cache slice
    if (!CopyBufferToHostOffset(k_buffer, offset, k_out, size)) {
        std::cerr << "Failed to read K cache slice" << std::endl;
        return false;
    }
    
    // Read V cache slice
    if (!CopyBufferToHostOffset(v_buffer, offset, v_out, size)) {
        std::cerr << "Failed to read V cache slice" << std::endl;
        return false;
    }
    
    return true;
}

void VulkanCompute::ClearKVCache() {
    if (!kv_cache_allocated_) {
        return;
    }
    
    // Clean up all KV cache buffers
    for (auto& [buffer, memory] : kv_cache_buffers_) {
        if (buffer) {
            vkDestroyBuffer(device_, buffer, nullptr);
        }
        if (memory) {
            vkFreeMemory(device_, memory, nullptr);
        }
    }
    
    kv_cache_buffers_.clear();
    kv_cache_num_layers_ = 0;
    kv_cache_max_seq_len_ = 0;
    kv_cache_head_dim_ = 0;
    kv_cache_allocated_ = false;
    
    std::cout << "KV cache cleared" << std::endl;
}

// Helper: Copy host data to buffer at specific offset
bool VulkanCompute::CopyHostToBufferOffset(const void* host_data, VkBuffer device_buffer, 
                                           size_t offset, size_t size) {
    // Create staging buffer
    VkBuffer staging_buffer;
    VkDeviceMemory staging_memory;
    
    VkBufferCreateInfo buffer_info{};
    buffer_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    buffer_info.size = size;
    buffer_info.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    
    if (vkCreateBuffer(device_, &buffer_info, nullptr, &staging_buffer) != VK_SUCCESS) {
        std::cerr << "Failed to create staging buffer for offset copy" << std::endl;
        return false;
    }
    
    VkMemoryRequirements mem_requirements;
    vkGetBufferMemoryRequirements(device_, staging_buffer, &mem_requirements);
    
    VkMemoryAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc_info.allocationSize = mem_requirements.size;
    alloc_info.memoryTypeIndex = FindMemoryType(mem_requirements.memoryTypeBits,
                                              VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | 
                                              VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    
    if (vkAllocateMemory(device_, &alloc_info, nullptr, &staging_memory) != VK_SUCCESS) {
        vkDestroyBuffer(device_, staging_buffer, nullptr);
        return false;
    }
    
    vkBindBufferMemory(device_, staging_buffer, staging_memory, 0);
    
    // Map and copy
    void* mapped;
    if (vkMapMemory(device_, staging_memory, 0, size, 0, &mapped) != VK_SUCCESS) {
        vkDestroyBuffer(device_, staging_buffer, nullptr);
        vkFreeMemory(device_, staging_memory, nullptr);
        return false;
    }
    
    std::memcpy(mapped, host_data, size);
    vkUnmapMemory(device_, staging_memory);
    
    // Copy from staging to device buffer at offset
    bool success = ExecuteSingleTimeCommands([&](VkCommandBuffer cmd_buffer) {
        VkBufferCopy copy_region{};
        copy_region.srcOffset = 0;
        copy_region.dstOffset = offset;
        copy_region.size = size;
        vkCmdCopyBuffer(cmd_buffer, staging_buffer, device_buffer, 1, &copy_region);
    });
    
    // Cleanup
    vkDestroyBuffer(device_, staging_buffer, nullptr);
    vkFreeMemory(device_, staging_memory, nullptr);
    
    return success;
}

// Helper: Copy buffer data at offset to host
bool VulkanCompute::CopyBufferToHostOffset(VkBuffer device_buffer, size_t offset, 
                                           void* host_data, size_t size) {
    // Create staging buffer
    VkBuffer staging_buffer;
    VkDeviceMemory staging_memory;
    
    VkBufferCreateInfo buffer_info{};
    buffer_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    buffer_info.size = size;
    buffer_info.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    
    if (vkCreateBuffer(device_, &buffer_info, nullptr, &staging_buffer) != VK_SUCCESS) {
        return false;
    }
    
    VkMemoryRequirements mem_requirements;
    vkGetBufferMemoryRequirements(device_, staging_buffer, &mem_requirements);
    
    VkMemoryAllocateInfo alloc_info{};
    alloc_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    alloc_info.allocationSize = mem_requirements.size;
    alloc_info.memoryTypeIndex = FindMemoryType(mem_requirements.memoryTypeBits,
                                              VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | 
                                              VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    
    if (vkAllocateMemory(device_, &alloc_info, nullptr, &staging_memory) != VK_SUCCESS) {
        vkDestroyBuffer(device_, staging_buffer, nullptr);
        return false;
    }
    
    vkBindBufferMemory(device_, staging_buffer, staging_memory, 0);
    
    // Copy from device buffer at offset to staging
    bool success = ExecuteSingleTimeCommands([&](VkCommandBuffer cmd_buffer) {
        VkBufferCopy copy_region{};
        copy_region.srcOffset = offset;
        copy_region.dstOffset = 0;
        copy_region.size = size;
        vkCmdCopyBuffer(cmd_buffer, device_buffer, staging_buffer, 1, &copy_region);
    });
    
    if (!success) {
        vkDestroyBuffer(device_, staging_buffer, nullptr);
        vkFreeMemory(device_, staging_memory, nullptr);
        return false;
    }
    
    // Map and read
    void* mapped;
    if (vkMapMemory(device_, staging_memory, 0, size, 0, &mapped) != VK_SUCCESS) {
        vkDestroyBuffer(device_, staging_buffer, nullptr);
        vkFreeMemory(device_, staging_memory, nullptr);
        return false;
    }
    
    std::memcpy(host_data, mapped, size);
    vkUnmapMemory(device_, staging_memory);
    
    // Cleanup
    vkDestroyBuffer(device_, staging_buffer, nullptr);
    vkFreeMemory(device_, staging_memory, nullptr);
    
    return true;
}

// ==================== END KV CACHE INFRASTRUCTURE ====================

uint32_t VulkanCompute::FindMemoryType(uint32_t type_filter, VkMemoryPropertyFlags properties) {
    for (uint32_t i = 0; i < device_info_.memory_props.memoryTypeCount; ++i) {
        if ((type_filter & (1 << i)) && 
            (device_info_.memory_props.memoryTypes[i].propertyFlags & properties) == properties) {
            return i;
        }
    }
    return 0;
}

void VulkanCompute::Cleanup() {
    if (device_) {
        vkDeviceWaitIdle(device_);
        
        // Clean up KV cache
        ClearKVCache();
        
        // Clean up async command buffer pool
        CleanupCommandBufferPool();

        // RAWRXD_DEEP2_TPS_AND_CERTIFICATION_RECOVERY: cached weights, pooled
        // scratch, persistent staging/readback, command buffer and fence.
        ReleaseQuantFastPath();

        // Quant-dot and RoPE permanent descriptor systems
        if (quant_descriptor_pool_) {
            vkDestroyDescriptorPool(device_, quant_descriptor_pool_, nullptr);
            quant_descriptor_pool_ = nullptr;
        }
        if (quant_descriptor_set_layout_) {
            vkDestroyDescriptorSetLayout(device_, quant_descriptor_set_layout_, nullptr);
            quant_descriptor_set_layout_ = nullptr;
        }
        if (rope_descriptor_pool_) {
            vkDestroyDescriptorPool(device_, rope_descriptor_pool_, nullptr);
            rope_descriptor_pool_ = nullptr;
        }
        if (rope_descriptor_set_layout_) {
            vkDestroyDescriptorSetLayout(device_, rope_descriptor_set_layout_, nullptr);
            rope_descriptor_set_layout_ = nullptr;
        }
        
        // Clean up shaders and pipelines
        for (auto& shader : shaders_) {
            if (shader.second.pipeline) {
                vkDestroyPipeline(device_, shader.second.pipeline, nullptr);
            }
            if (shader.second.layout) {
                vkDestroyPipelineLayout(device_, shader.second.layout, nullptr);
            }
            if (shader.second.module) {
                vkDestroyShaderModule(device_, shader.second.module, nullptr);
            }
        }
        shaders_.clear();
        
        // Clean up permanent MatMul descriptor system
        if (matmul_descriptor_pool_) {
            vkDestroyDescriptorPool(device_, matmul_descriptor_pool_, nullptr);
            matmul_descriptor_pool_ = nullptr;
        }
        if (matmul_descriptor_set_layout_) {
            vkDestroyDescriptorSetLayout(device_, matmul_descriptor_set_layout_, nullptr);
            matmul_descriptor_set_layout_ = nullptr;
        }
        
        // Clean up persistent staging buffer (for optimized transfers)
        if (staging_buffer_) {
            vkDestroyBuffer(device_, staging_buffer_, nullptr);
            staging_buffer_ = nullptr;
        }
        if (staging_memory_) {
            vkFreeMemory(device_, staging_memory_, nullptr);
            staging_memory_ = nullptr;
        }
        
        // Clean up general descriptor pool (if used)
        if (descriptor_pool_) {
            vkDestroyDescriptorPool(device_, descriptor_pool_, nullptr);
            descriptor_pool_ = nullptr;
        }
        
        // Clean up command pool
        if (command_pool_) {
            vkDestroyCommandPool(device_, command_pool_, nullptr);
            command_pool_ = nullptr;
        }
        
        // Clean up allocated buffers
        for (auto& [buffer, memory] : allocated_buffers_) {
            if (buffer) {
                vkDestroyBuffer(device_, buffer, nullptr);
            }
            if (memory) {
                vkFreeMemory(device_, memory, nullptr);
            }
        }
        allocated_buffers_.clear();
        
        // Clean up uploaded tensors
        ReleaseTensors();
        
        vkDestroyDevice(device_, nullptr);
        device_ = nullptr;
    }
    
    if (instance_) {
        vkDestroyInstance(instance_, nullptr);
        instance_ = nullptr;
    }
    
    std::cout << "Vulkan resources cleaned up successfully" << std::endl;
}
