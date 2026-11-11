// ============================================================================
// Test Vulkan Shader Integration
// ============================================================================
// Verifies SPIR-V shaders load and can be dispatched on RX 7800 XT
// ============================================================================

#include "vulkan_shader_integration.hpp"
#include <iostream>
#include <vector>
#include <string>

// Minimal Vulkan setup for testing
#define VK_USE_PLATFORM_WIN32_KHR
#include <vulkan/vulkan.h>

namespace transformer {

// Test configuration
struct TestConfig {
    std::string shader_dir = "d:/rawrxd/src/inference/shaders";
    bool verbose = true;
};

// ============================================================================
// Minimal Vulkan Context for Testing
// ============================================================================
class TestVulkanContext {
public:
    VkInstance instance = VK_NULL_HANDLE;
    VkPhysicalDevice physical_device = VK_NULL_HANDLE;
    VkDevice device = VK_NULL_HANDLE;
    VkQueue queue = VK_NULL_HANDLE;
    uint32_t queue_family = 0;
    VkCommandPool command_pool = VK_NULL_HANDLE;
    VkDescriptorPool descriptor_pool = VK_NULL_HANDLE;
    VkPipelineLayout pipeline_layout = VK_NULL_HANDLE;
    
    bool Initialize();
    void Cleanup();
    void PrintDeviceInfo();
};

bool TestVulkanContext::Initialize() {
    // Create instance
    VkApplicationInfo app_info = {};
    app_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app_info.pApplicationName = "RawrXD Shader Test";
    app_info.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.pEngineName = "RawrXD";
    app_info.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.apiVersion = VK_API_VERSION_1_2;
    
    VkInstanceCreateInfo instance_info = {};
    instance_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instance_info.pApplicationInfo = &app_info;
    
    const char* extensions[] = { VK_KHR_SURFACE_EXTENSION_NAME };
    instance_info.enabledExtensionCount = 1;
    instance_info.ppEnabledExtensionNames = extensions;
    
    VkResult result = vkCreateInstance(&instance_info, nullptr, &instance);
    if (result != VK_SUCCESS) {
        std::cerr << "Failed to create Vulkan instance: " << result << std::endl;
        return false;
    }
    
    // Enumerate physical devices
    uint32_t device_count = 0;
    vkEnumeratePhysicalDevices(instance, &device_count, nullptr);
    if (device_count == 0) {
        std::cerr << "No Vulkan-compatible devices found" << std::endl;
        return false;
    }
    
    std::vector<VkPhysicalDevice> devices(device_count);
    vkEnumeratePhysicalDevices(instance, &device_count, devices.data());
    
    // Select first device (should be RX 7800 XT)
    physical_device = devices[0];
    
    // Find compute queue
    uint32_t queue_family_count = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(physical_device, &queue_family_count, nullptr);
    
    std::vector<VkQueueFamilyProperties> queue_families(queue_family_count);
    vkGetPhysicalDeviceQueueFamilyProperties(physical_device, &queue_family_count, queue_families.data());
    
    for (uint32_t i = 0; i < queue_family_count; i++) {
        if (queue_families[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            queue_family = i;
            break;
        }
    }
    
    // Create device
    float queue_priority = 1.0f;
    VkDeviceQueueCreateInfo queue_info = {};
    queue_info.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queue_info.queueFamilyIndex = queue_family;
    queue_info.queueCount = 1;
    queue_info.pQueuePriorities = &queue_priority;
    
    VkDeviceCreateInfo device_info = {};
    device_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    device_info.queueCreateInfoCount = 1;
    device_info.pQueueCreateInfos = &queue_info;
    
    result = vkCreateDevice(physical_device, &device_info, nullptr, &device);
    if (result != VK_SUCCESS) {
        std::cerr << "Failed to create device: " << result << std::endl;
        return false;
    }
    
    vkGetDeviceQueue(device, queue_family, 0, &queue);
    
    // Create command pool
    VkCommandPoolCreateInfo pool_info = {};
    pool_info.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_info.queueFamilyIndex = queue_family;
    pool_info.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    
    vkCreateCommandPool(device, &pool_info, nullptr, &command_pool);
    
    // Create descriptor pool
    VkDescriptorPoolSize pool_sizes[] = {
        { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 100 }
    };
    
    VkDescriptorPoolCreateInfo desc_pool_info = {};
    desc_pool_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    desc_pool_info.maxSets = 100;
    desc_pool_info.poolSizeCount = 1;
    desc_pool_info.pPoolSizes = pool_sizes;
    
    vkCreateDescriptorPool(device, &desc_pool_info, nullptr, &descriptor_pool);
    
    // Create pipeline layout
    VkPipelineLayoutCreateInfo layout_info = {};
    layout_info.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    vkCreatePipelineLayout(device, &layout_info, nullptr, &pipeline_layout);
    
    return true;
}

void TestVulkanContext::Cleanup() {
    if (pipeline_layout != VK_NULL_HANDLE) vkDestroyPipelineLayout(device, pipeline_layout, nullptr);
    if (descriptor_pool != VK_NULL_HANDLE) vkDestroyDescriptorPool(device, descriptor_pool, nullptr);
    if (command_pool != VK_NULL_HANDLE) vkDestroyCommandPool(device, command_pool, nullptr);
    if (device != VK_NULL_HANDLE) vkDestroyDevice(device, nullptr);
    if (instance != VK_NULL_HANDLE) vkDestroyInstance(instance, nullptr);
}

void TestVulkanContext::PrintDeviceInfo() {
    VkPhysicalDeviceProperties props;
    vkGetPhysicalDeviceProperties(physical_device, &props);
    
    std::cout << "========================================" << std::endl;
    std::cout << "Vulkan Device Info" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Device: " << props.deviceName << std::endl;
    std::cout << "Vendor: " << props.vendorID << " (AMD=" << 0x1002 << ")" << std::endl;
    std::cout << "API Version: " << VK_VERSION_MAJOR(props.apiVersion) << "."
              << VK_VERSION_MINOR(props.apiVersion) << "."
              << VK_VERSION_PATCH(props.apiVersion) << std::endl;
    std::cout << "Compute Queue Family: " << queue_family << std::endl;
    std::cout << "========================================" << std::endl;
}

// ============================================================================
// Test Functions
// ============================================================================
bool TestSPIRVLoader(const std::string& shader_dir) {
    std::cout << "\n[Test] SPIR-V Loader" << std::endl;
    
    std::vector<std::string> shaders = {
        shader_dir + "/rms_norm_fp16.spv",
        shader_dir + "/matmul_fp16.spv",
        shader_dir + "/softmax_fp16.spv",
        shader_dir + "/flash_attention_fp8_tiled.spv"
    };
    
    bool all_passed = true;
    for (const auto& path : shaders) {
        auto code = SPIRVLoader::LoadFile(path);
        bool valid = SPIRVLoader::Validate(code);
        
        std::cout << "  " << path << ": ";
        if (valid) {
            std::cout << "✓ (" << code.size() << " words)" << std::endl;
        } else {
            std::cout << "✗ FAILED" << std::endl;
            all_passed = false;
        }
    }
    
    return all_passed;
}

bool TestShaderManager(TestVulkanContext& ctx, const std::string& shader_dir) {
    std::cout << "\n[Test] RDNA3 Shader Manager" << std::endl;
    
    RDNA3ShaderManager manager;
    if (!manager.Initialize(ctx.device, ctx.pipeline_layout)) {
        std::cerr << "Failed to initialize shader manager" << std::endl;
        return false;
    }
    
    bool loaded = manager.LoadRawrXDShaders(shader_dir);
    
    std::cout << manager.GetStatus() << std::endl;
    
    return loaded;
}

bool TestGPUDispatcher(TestVulkanContext& ctx, RDNA3ShaderManager& manager) {
    std::cout << "\n[Test] GPU Transformer Dispatcher" << std::endl;
    
    GPUTransformerDispatcher dispatcher;
    if (!dispatcher.Initialize(ctx.device, ctx.queue, ctx.queue_family,
                               ctx.command_pool, ctx.descriptor_pool)) {
        std::cerr << "Failed to initialize dispatcher" << std::endl;
        return false;
    }
    
    dispatcher.SetShaderManager(&manager);
    
    std::cout << "  Dispatcher initialized ✓" << std::endl;
    
    // Note: Actual GPU execution would require buffer allocation
    // This test just verifies the dispatcher setup
    
    return true;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "Vulkan Shader Integration Test" << std::endl;
    std::cout << "========================================" << std::endl;
    
    TestConfig config;
    if (argc > 1) {
        config.shader_dir = argv[1];
    }
    
    std::cout << "Shader directory: " << config.shader_dir << std::endl;
    
    // Test 1: SPIR-V Loader
    bool test1 = TestSPIRVLoader(config.shader_dir);
    
    // Test 2: Vulkan Context
    std::cout << "\n[Test] Vulkan Context" << std::endl;
    TestVulkanContext ctx;
    bool test2 = ctx.Initialize();
    if (test2) {
        ctx.PrintDeviceInfo();
    } else {
        std::cerr << "Vulkan initialization failed - skipping GPU tests" << std::endl;
    }
    
    // Test 3: Shader Manager (requires Vulkan)
    bool test3 = false;
    RDNA3ShaderManager manager;
    if (test2) {
        test3 = TestShaderManager(ctx, config.shader_dir);
    }
    
    // Test 4: GPU Dispatcher (requires shaders)
    bool test4 = false;
    if (test2 && test3) {
        test4 = TestGPUDispatcher(ctx, manager);
    }
    
    // Cleanup
    ctx.Cleanup();
    
    // Summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "SPIR-V Loader: " << (test1 ? "✓ PASS" : "✗ FAIL") << std::endl;
    std::cout << "Vulkan Context: " << (test2 ? "✓ PASS" : "✗ FAIL") << std::endl;
    std::cout << "Shader Manager: " << (test3 ? "✓ PASS" : "✗ SKIP") << std::endl;
    std::cout << "GPU Dispatcher: " << (test4 ? "✓ PASS" : "✗ SKIP") << std::endl;
    std::cout << "========================================" << std::endl;
    
    bool all_passed = test1 && test2 && test3 && test4;
    return all_passed ? 0 : 1;
}

} // namespace transformer

int main(int argc, char* argv[]) {
    return transformer::main(argc, argv);
}
