// Minimal SPIR-V Shader Test
// Tests vkCreateShaderModule and vkCreateComputePipelines step by step

#include <vulkan/vulkan.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>

// Minimal compute shader SPIR-V (does nothing)
// Compiled from: #version 450; layout(local_size_x = 1) in; void main() {}
const uint32_t minimal_spv[] = {
    0x07230203, 0x00010000, 0x00080001, 0x00000013,  // Header
    0x00000000, 0x00020011, 0x00000001, 0x0006000b,  // Capability, MemoryModel
    0x00000001, 0x0004000b, 0x00000004, 0x00000011,  // Entry point
    0x00000001, 0x0002000b, 0x00000007, 0x00030005,    // Execution mode
    0x00000008, 0x00000007, 0x00050048, 0x00000009,    // Source
    0x00000000, 0x0000000b, 0x00000000, 0x00030047,    // Decorations
    0x00000009, 0x0000000b, 0x00040047, 0x0000000c,    // Decorations
    0x0000000b, 0x0000001c, 0x00020013, 0x00000002,    // Type void
    0x00030021, 0x00000003, 0x00000002, 0x00040032,    // Type function
    0x00000006, 0x00000007, 0x00000001, 0x00040032,    // Type function
    0x00000006, 0x00000008, 0x00000001, 0x00040017,    // Type function
    0x00000009, 0x00000006, 0x00000004, 0x00040020,    // Type struct
    0x0000000a, 0x00000009, 0x00000006, 0x0004003b,    // Type pointer
    0x0000000a, 0x0000000b, 0x00000007, 0x000200f8,    // Variable
    0x00000005, 0x0004003d, 0x00000009, 0x0000000c,    // Label
    0x0000000b, 0x0004003d, 0x00000006, 0x0000000d,    // Load
    0x0000000c, 0x0007000c, 0x00000006, 0x0000000e,    // Load
    0x00000001, 0x00000001, 0x0000000d, 0x0000000d,    // Composite construct
    0x0005000e, 0x00000009, 0x0000000f, 0x0000000c,    // Store
    0x0000000e, 0x000100fd, 0x00010038                 // Return
};

bool TestMinimalShader(VkDevice device) {
    std::cout << "\n=== Test: Minimal Shader ===" << std::endl;
    
    // Step 1: Create shader module
    std::cout << "Creating shader module..." << std::endl;
    VkShaderModuleCreateInfo module_info = {};
    module_info.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    module_info.codeSize = sizeof(minimal_spv);
    module_info.pCode = minimal_spv;
    
    VkShaderModule module = VK_NULL_HANDLE;
    VkResult result = vkCreateShaderModule(device, &module_info, nullptr, &module);
    if (result != VK_SUCCESS) {
        std::cerr << "Failed to create shader module: " << result << std::endl;
        return false;
    }
    std::cout << "✅ Shader module created" << std::endl;
    
    // Step 2: Create pipeline layout (empty)
    std::cout << "Creating pipeline layout..." << std::endl;
    VkPipelineLayoutCreateInfo layout_info = {};
    layout_info.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    
    VkPipelineLayout layout = VK_NULL_HANDLE;
    result = vkCreatePipelineLayout(device, &layout_info, nullptr, &layout);
    if (result != VK_SUCCESS) {
        std::cerr << "Failed to create pipeline layout: " << result << std::endl;
        vkDestroyShaderModule(device, module, nullptr);
        return false;
    }
    std::cout << "✅ Pipeline layout created" << std::endl;
    
    // Step 3: Create compute pipeline
    std::cout << "Creating compute pipeline (may hang)..." << std::endl;
    
    VkPipelineShaderStageCreateInfo stage_info = {};
    stage_info.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stage_info.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stage_info.module = module;
    stage_info.pName = "main";
    
    VkComputePipelineCreateInfo pipeline_info = {};
    pipeline_info.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipeline_info.stage = stage_info;
    pipeline_info.layout = layout;
    
    VkPipeline pipeline = VK_NULL_HANDLE;
    result = vkCreateComputePipelines(device, VK_NULL_HANDLE, 1, &pipeline_info, nullptr, &pipeline);
    
    if (result != VK_SUCCESS) {
        std::cerr << "Failed to create compute pipeline: " << result << std::endl;
        vkDestroyPipelineLayout(device, layout, nullptr);
        vkDestroyShaderModule(device, module, nullptr);
        return false;
    }
    std::cout << "✅ Compute pipeline created" << std::endl;
    
    // Cleanup
    vkDestroyPipeline(device, pipeline, nullptr);
    vkDestroyPipelineLayout(device, layout, nullptr);
    vkDestroyShaderModule(device, module, nullptr);
    
    return true;
}

bool TestFileShader(VkDevice device, const std::string& path) {
    std::cout << "\n=== Test: File Shader (" << path << ") ===" << std::endl;
    
    // Load SPIR-V file
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open: " << path << std::endl;
        return false;
    }
    
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint32_t> code(size / sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(code.data()), size);
    
    std::cout << "Loaded " << code.size() << " words" << std::endl;
    
    // Validate magic number
    if (code[0] != 0x07230203) {
        std::cerr << "Invalid magic: 0x" << std::hex << code[0] << std::dec << std::endl;
        return false;
    }
    std::cout << "✅ Magic number valid" << std::endl;
    
    // Create shader module
    VkShaderModuleCreateInfo module_info = {};
    module_info.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    module_info.codeSize = code.size() * sizeof(uint32_t);
    module_info.pCode = code.data();
    
    VkShaderModule module = VK_NULL_HANDLE;
    VkResult result = vkCreateShaderModule(device, &module_info, nullptr, &module);
    if (result != VK_SUCCESS) {
        std::cerr << "Failed to create shader module: " << result << std::endl;
        return false;
    }
    std::cout << "✅ Shader module created" << std::endl;
    
    // Create pipeline layout
    VkPipelineLayoutCreateInfo layout_info = {};
    layout_info.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    
    VkPipelineLayout layout = VK_NULL_HANDLE;
    result = vkCreatePipelineLayout(device, &layout_info, nullptr, &layout);
    if (result != VK_SUCCESS) {
        std::cerr << "Failed to create pipeline layout: " << result << std::endl;
        vkDestroyShaderModule(device, module, nullptr);
        return false;
    }
    std::cout << "✅ Pipeline layout created" << std::endl;
    
    // Create compute pipeline
    std::cout << "Creating compute pipeline (may hang)..." << std::endl;
    
    VkPipelineShaderStageCreateInfo stage_info = {};
    stage_info.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stage_info.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stage_info.module = module;
    stage_info.pName = "main";
    
    VkComputePipelineCreateInfo pipeline_info = {};
    pipeline_info.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipeline_info.stage = stage_info;
    pipeline_info.layout = layout;
    
    VkPipeline pipeline = VK_NULL_HANDLE;
    result = vkCreateComputePipelines(device, VK_NULL_HANDLE, 1, &pipeline_info, nullptr, &pipeline);
    
    if (result != VK_SUCCESS) {
        std::cerr << "Failed to create compute pipeline: " << result << std::endl;
        vkDestroyPipelineLayout(device, layout, nullptr);
        vkDestroyShaderModule(device, module, nullptr);
        return false;
    }
    std::cout << "✅ Compute pipeline created" << std::endl;
    
    // Cleanup
    vkDestroyPipeline(device, pipeline, nullptr);
    vkDestroyPipelineLayout(device, layout, nullptr);
    vkDestroyShaderModule(device, module, nullptr);
    
    return true;
}

int main() {
    std::cout << "================================================================================" << std::endl;
    std::cout << "Minimal SPIR-V Shader Test" << std::endl;
    std::cout << "================================================================================" << std::endl;
    
    // Create Vulkan instance
    VkApplicationInfo app_info = {};
    app_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app_info.apiVersion = VK_API_VERSION_1_2;
    
    VkInstanceCreateInfo instance_info = {};
    instance_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instance_info.pApplicationInfo = &app_info;
    
    VkInstance instance = VK_NULL_HANDLE;
    VkResult result = vkCreateInstance(&instance_info, nullptr, &instance);
    if (result != VK_SUCCESS) {
        std::cerr << "Failed to create instance: " << result << std::endl;
        return 1;
    }
    std::cout << "✅ Instance created" << std::endl;
    
    // Get physical device
    uint32_t device_count = 0;
    vkEnumeratePhysicalDevices(instance, &device_count, nullptr);
    std::vector<VkPhysicalDevice> devices(device_count);
    vkEnumeratePhysicalDevices(instance, &device_count, devices.data());
    
    VkPhysicalDevice physical_device = devices[0];
    VkPhysicalDeviceProperties props;
    vkGetPhysicalDeviceProperties(physical_device, &props);
    std::cout << "Device: " << props.deviceName << std::endl;
    
    // Find compute queue
    uint32_t queue_family = UINT32_MAX;
    uint32_t queue_count = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(physical_device, &queue_count, nullptr);
    std::vector<VkQueueFamilyProperties> families(queue_count);
    vkGetPhysicalDeviceQueueFamilyProperties(physical_device, &queue_count, families.data());
    
    for (uint32_t i = 0; i < queue_count; i++) {
        if (families[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            queue_family = i;
            break;
        }
    }
    
    // Create device
    float priority = 1.0f;
    VkDeviceQueueCreateInfo queue_info = {};
    queue_info.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queue_info.queueFamilyIndex = queue_family;
    queue_info.queueCount = 1;
    queue_info.pQueuePriorities = &priority;
    
    VkDeviceCreateInfo device_info = {};
    device_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    device_info.queueCreateInfoCount = 1;
    device_info.pQueueCreateInfos = &queue_info;
    
    VkDevice device = VK_NULL_HANDLE;
    result = vkCreateDevice(physical_device, &device_info, nullptr, &device);
    if (result != VK_SUCCESS) {
        std::cerr << "Failed to create device: " << result << std::endl;
        vkDestroyInstance(instance, nullptr);
        return 1;
    }
    std::cout << "✅ Device created" << std::endl;
    
    // Run tests
    bool success = true;
    
    // Test 1: Minimal embedded shader
    success &= TestMinimalShader(device);
    
    // Test 2: File-based shader (if exists)
    if (std::ifstream("d:/rawrxd/src/inference/shaders/rms_norm_fp16.spv").good()) {
        success &= TestFileShader(device, "d:/rawrxd/src/inference/shaders/rms_norm_fp16.spv");
    }
    
    // Cleanup
    vkDestroyDevice(device, nullptr);
    vkDestroyInstance(instance, nullptr);
    
    std::cout << "\n================================================================================" << std::endl;
    std::cout << (success ? "✅ All tests passed" : "❌ Some tests failed") << std::endl;
    std::cout << "================================================================================" << std::endl;
    
    return success ? 0 : 1;
}
