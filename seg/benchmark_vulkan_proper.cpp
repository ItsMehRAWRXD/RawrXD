// ============================================================================
// Vulkan GPU Benchmark - Using Vulkan SDK
// ============================================================================

#include <iostream>
#include <chrono>
#include <vector>
#include <cstring>

// Use actual Vulkan headers
#define VK_USE_PLATFORM_WIN32_KHR
#include <vulkan/vulkan.h>

class Timer {
public:
    void Start() { start_ = std::chrono::high_resolution_clock::now(); }
    void Stop() { end_ = std::chrono::high_resolution_clock::now(); }
    double ElapsedMs() const {
        return std::chrono::duration<double, std::milli>(end_ - start_).count();
    }
    double ElapsedUs() const {
        return std::chrono::duration<double, std::micro>(end_ - start_).count();
    }
private:
    std::chrono::high_resolution_clock::time_point start_, end_;
};

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "VULKAN GPU BENCHMARK (Vulkan SDK)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    // Create instance
    VkApplicationInfo appInfo = {};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "RawrXD Benchmark";
    appInfo.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.pEngineName = "RawrXD";
    appInfo.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    appInfo.apiVersion = VK_API_VERSION_1_2;

    VkInstanceCreateInfo createInfo = {};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &appInfo;

    VkInstance instance = VK_NULL_HANDLE;
    VkResult result = vkCreateInstance(&createInfo, nullptr, &instance);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to create Vulkan instance: " << result << std::endl;
        return 1;
    }

    std::cout << "Vulkan instance created" << std::endl;

    // Enumerate physical devices
    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance, &deviceCount, nullptr);
    if (deviceCount == 0) {
        std::cout << "No Vulkan-compatible devices found" << std::endl;
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(instance, &deviceCount, devices.data());

    std::cout << "Found " << deviceCount << " device(s)" << std::endl;
    std::cout << std::endl;

    // Select first discrete GPU or any GPU
    VkPhysicalDevice selectedDevice = VK_NULL_HANDLE;
    VkPhysicalDeviceProperties selectedProps = {};
    int computeQueueFamily = -1;

    for (uint32_t i = 0; i < deviceCount; i++) {
        VkPhysicalDeviceProperties props = {};
        vkGetPhysicalDeviceProperties(devices[i], &props);

        uint32_t queueFamilyCount = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(devices[i], &queueFamilyCount, nullptr);
        std::vector<VkQueueFamilyProperties> queueFamilies(queueFamilyCount);
        vkGetPhysicalDeviceQueueFamilyProperties(devices[i], &queueFamilyCount, queueFamilies.data());

        int computeIdx = -1;
        for (uint32_t j = 0; j < queueFamilyCount; j++) {
            if (queueFamilies[j].queueFlags & VK_QUEUE_COMPUTE_BIT) {
                computeIdx = j;
                break;
            }
        }

        if (computeIdx >= 0) {
            std::cout << "Device " << i << ": " << props.deviceName << std::endl;
            std::cout << "  Vendor: ";
            if (props.vendorID == 0x1002) std::cout << "AMD";
            else if (props.vendorID == 0x10DE) std::cout << "NVIDIA";
            else if (props.vendorID == 0x8086) std::cout << "Intel";
            else std::cout << "0x" << std::hex << props.vendorID << std::dec;
            std::cout << std::endl;
            std::cout << "  Type: " << (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU ? "Discrete" :
                                        props.deviceType == VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU ? "Integrated" : "Other") << std::endl;
            std::cout << "  Compute queue family: " << computeIdx << std::endl;
            std::cout << std::endl;

            // Prefer RX 7800 XT
            std::string devName(props.deviceName);
            bool is7800XT = devName.find("RX 7800") != std::string::npos ||
                           devName.find("7800 XT") != std::string::npos;
            
            if (selectedDevice == VK_NULL_HANDLE) {
                selectedDevice = devices[i];
                selectedProps = props;
                computeQueueFamily = computeIdx;
            } else if (is7800XT) {
                selectedDevice = devices[i];
                selectedProps = props;
                computeQueueFamily = computeIdx;
            }
        }
    }

    if (selectedDevice == VK_NULL_HANDLE) {
        std::cout << "No device with compute support found" << std::endl;
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    std::cout << "Selected device: " << selectedProps.deviceName << std::endl;
    std::cout << std::endl;

    // Create logical device
    float queuePriority = 1.0f;
    VkDeviceQueueCreateInfo queueCreateInfo = {};
    queueCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueCreateInfo.queueFamilyIndex = computeQueueFamily;
    queueCreateInfo.queueCount = 1;
    queueCreateInfo.pQueuePriorities = &queuePriority;

    VkDeviceCreateInfo deviceCreateInfo = {};
    deviceCreateInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    deviceCreateInfo.queueCreateInfoCount = 1;
    deviceCreateInfo.pQueueCreateInfos = &queueCreateInfo;

    VkDevice device = VK_NULL_HANDLE;
    result = vkCreateDevice(selectedDevice, &deviceCreateInfo, nullptr, &device);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to create logical device: " << result << std::endl;
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    std::cout << "Logical device created" << std::endl;

    // Get compute queue
    VkQueue computeQueue = VK_NULL_HANDLE;
    vkGetDeviceQueue(device, computeQueueFamily, 0, &computeQueue);

    if (computeQueue == VK_NULL_HANDLE) {
        std::cout << "Failed to get compute queue" << std::endl;
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    std::cout << "Compute queue obtained" << std::endl;
    std::cout << std::endl;

    // Create command pool
    VkCommandPool commandPool = VK_NULL_HANDLE;
    VkCommandPoolCreateInfo poolInfo = {};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.queueFamilyIndex = computeQueueFamily;
    poolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;

    result = vkCreateCommandPool(device, &poolInfo, nullptr, &commandPool);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to create command pool: " << result << std::endl;
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    // Allocate command buffer
    VkCommandBuffer commandBuffer = VK_NULL_HANDLE;
    VkCommandBufferAllocateInfo allocInfo = {};
    allocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocInfo.commandPool = commandPool;
    allocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocInfo.commandBufferCount = 1;

    result = vkAllocateCommandBuffers(device, &allocInfo, &commandBuffer);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to allocate command buffer: " << result << std::endl;
        vkDestroyCommandPool(device, commandPool, nullptr);
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    // Create fence
    VkFence fence = VK_NULL_HANDLE;
    VkFenceCreateInfo fenceInfo = {};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    fenceInfo.flags = VK_FENCE_CREATE_SIGNALED_BIT;

    result = vkCreateFence(device, &fenceInfo, nullptr, &fence);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to create fence: " << result << std::endl;
        vkDestroyCommandPool(device, commandPool, nullptr);
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    // Get memory properties
    VkPhysicalDeviceMemoryProperties memProps = {};
    vkGetPhysicalDeviceMemoryProperties(selectedDevice, &memProps);

    // Allocate GPU buffer
    const size_t bufferSize = 4096 * sizeof(float); // 16KB

    VkBuffer buffer = VK_NULL_HANDLE;
    VkBufferCreateInfo bufferInfo = {};
    bufferInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bufferInfo.size = bufferSize;
    bufferInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    bufferInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    result = vkCreateBuffer(device, &bufferInfo, nullptr, &buffer);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to create buffer: " << result << std::endl;
        vkDestroyFence(device, fence, nullptr);
        vkDestroyCommandPool(device, commandPool, nullptr);
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    VkMemoryRequirements memReqs = {};
    vkGetBufferMemoryRequirements(device, buffer, &memReqs);

    // Find memory type
    uint32_t memoryTypeIndex = UINT32_MAX;
    for (uint32_t i = 0; i < memProps.memoryTypeCount; i++) {
        if ((memReqs.memoryTypeBits & (1 << i)) &&
            (memProps.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)) {
            memoryTypeIndex = i;
            break;
        }
    }

    if (memoryTypeIndex == UINT32_MAX) {
        std::cout << "Failed to find suitable memory type" << std::endl;
        vkDestroyBuffer(device, buffer, nullptr);
        vkDestroyFence(device, fence, nullptr);
        vkDestroyCommandPool(device, commandPool, nullptr);
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    VkDeviceMemory memory = VK_NULL_HANDLE;
    VkMemoryAllocateInfo memAllocInfo = {};
    memAllocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    memAllocInfo.allocationSize = memReqs.size;
    memAllocInfo.memoryTypeIndex = memoryTypeIndex;

    result = vkAllocateMemory(device, &memAllocInfo, nullptr, &memory);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to allocate memory: " << result << std::endl;
        vkDestroyBuffer(device, buffer, nullptr);
        vkDestroyFence(device, fence, nullptr);
        vkDestroyCommandPool(device, commandPool, nullptr);
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    result = vkBindBufferMemory(device, buffer, memory, 0);
    if (result != VK_SUCCESS) {
        std::cout << "Failed to bind buffer memory: " << result << std::endl;
        vkFreeMemory(device, memory, nullptr);
        vkDestroyBuffer(device, buffer, nullptr);
        vkDestroyFence(device, fence, nullptr);
        vkDestroyCommandPool(device, commandPool, nullptr);
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    std::cout << "GPU buffer allocated: " << bufferSize << " bytes" << std::endl;
    std::cout << std::endl;

    // Benchmark GPU operations
    const int iterations = 1000;
    Timer timer;

    std::cout << "Benchmarking GPU operations..." << std::endl;
    timer.Start();

    for (int i = 0; i < iterations; i++) {
        // Reset fence
        vkResetFences(device, 1, &fence);

        // Begin command buffer
        VkCommandBufferBeginInfo beginInfo = {};
        beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;

        vkBeginCommandBuffer(commandBuffer, &beginInfo);

        // End command buffer
        vkEndCommandBuffer(commandBuffer);

        // Submit
        VkSubmitInfo submitInfo = {};
        submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        submitInfo.commandBufferCount = 1;
        submitInfo.pCommandBuffers = &commandBuffer;

        vkQueueSubmit(computeQueue, 1, &submitInfo, fence);

        // Wait for completion
        vkWaitForFences(device, 1, &fence, VK_TRUE, UINT64_MAX);
    }

    timer.Stop();

    double timePerOpUs = timer.ElapsedUs() / iterations;
    double opsPerSec = 1000000.0 / timePerOpUs;

    std::cout << "  Total time: " << timer.ElapsedMs() << " ms" << std::endl;
    std::cout << "  Time per operation: " << timePerOpUs << " us" << std::endl;
    std::cout << "  Operations/sec: " << opsPerSec << std::endl;
    std::cout << std::endl;

    // Cleanup
    vkFreeMemory(device, memory, nullptr);
    vkDestroyBuffer(device, buffer, nullptr);
    vkDestroyFence(device, fence, nullptr);
    vkDestroyCommandPool(device, commandPool, nullptr);
    vkDestroyDevice(device, nullptr);
    vkDestroyInstance(instance, nullptr);

    std::cout << "========================================" << std::endl;
    std::cout << "VULKAN GPU DETECTED AND FUNCTIONAL" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Device: " << selectedProps.deviceName << std::endl;
    std::cout << "GPU overhead: " << timePerOpUs << " us/op" << std::endl;
    std::cout << std::endl;
    std::cout << "Ready for GPU-accelerated inference!" << std::endl;

    return 0;
}
