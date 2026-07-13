// ============================================================================
// GPU Setup Validation - Quick Check
// ============================================================================

#include <iostream>
#include <vector>
#include <fstream>

#define VK_USE_PLATFORM_WIN32_KHR
#include <vulkan/vulkan.h>

std::vector<uint32_t> LoadSPIRV(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return {};
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint32_t> code(size / 4);
    file.read(reinterpret_cast<char*>(code.data()), size);
    return code;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "GPU Setup Validation" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    int checksPassed = 0;
    int checksTotal = 6;

    // 1. Vulkan Instance
    std::cout << "[1/6] Creating Vulkan instance..." << std::endl;
    VkApplicationInfo appInfo = {};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.apiVersion = VK_API_VERSION_1_2;

    VkInstanceCreateInfo createInfo = {};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &appInfo;

    VkInstance instance;
    if (vkCreateInstance(&createInfo, nullptr, &instance) == VK_SUCCESS) {
        std::cout << "      ✓ Instance created" << std::endl;
        checksPassed++;
    } else {
        std::cout << "      ✗ Failed" << std::endl;
        return 1;
    }

    // 2. Physical Device
    std::cout << "[2/6] Finding GPU..." << std::endl;
    uint32_t deviceCount = 0;
    vkEnumeratePhysicalDevices(instance, &deviceCount, nullptr);
    std::vector<VkPhysicalDevice> devices(deviceCount);
    vkEnumeratePhysicalDevices(instance, &deviceCount, devices.data());
    
    VkPhysicalDevice gpu = devices[0];
    VkPhysicalDeviceProperties props;
    vkGetPhysicalDeviceProperties(gpu, &props);
    std::cout << "      ✓ GPU: " << props.deviceName << std::endl;
    checksPassed++;

    // 3. Logical Device
    std::cout << "[3/6] Creating logical device..." << std::endl;
    float priority = 1.0f;
    VkDeviceQueueCreateInfo queueInfo = {};
    queueInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueInfo.queueFamilyIndex = 0;
    queueInfo.queueCount = 1;
    queueInfo.pQueuePriorities = &priority;

    VkDeviceCreateInfo devInfo = {};
    devInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    devInfo.queueCreateInfoCount = 1;
    devInfo.pQueueCreateInfos = &queueInfo;

    VkDevice device;
    if (vkCreateDevice(gpu, &devInfo, nullptr, &device) == VK_SUCCESS) {
        std::cout << "      ✓ Device created" << std::endl;
        checksPassed++;
    } else {
        std::cout << "      ✗ Failed" << std::endl;
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    // 4. Load Shader
    std::cout << "[4/6] Loading SPIR-V shader..." << std::endl;
    auto code = LoadSPIRV("d:/rawrxd/src/inference/shaders/matmul_fp16.spv");
    if (!code.empty()) {
        std::cout << "      ✓ Shader loaded: " << code.size() * 4 << " bytes" << std::endl;
        checksPassed++;
    } else {
        std::cout << "      ✗ Failed to load shader" << std::endl;
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    // 5. Create Shader Module
    std::cout << "[5/6] Creating shader module..." << std::endl;
    VkShaderModuleCreateInfo shaderInfo = {};
    shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    shaderInfo.codeSize = code.size() * sizeof(uint32_t);
    shaderInfo.pCode = code.data();

    VkShaderModule shader;
    if (vkCreateShaderModule(device, &shaderInfo, nullptr, &shader) == VK_SUCCESS) {
        std::cout << "      ✓ Shader module created" << std::endl;
        checksPassed++;
    } else {
        std::cout << "      ✗ Failed" << std::endl;
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        return 1;
    }

    // 6. Validate SPIR-V
    std::cout << "[6/6] Validating SPIR-V..." << std::endl;
    if (code[0] == 0x07230203) {
        std::cout << "      ✓ Valid SPIR-V (magic: 0x" << std::hex << code[0] << std::dec << ")" << std::endl;
        std::cout << "      ✓ Version: " << ((code[1] >> 16) & 0xFF) << "." << ((code[1] >> 8) & 0xFF) << std::endl;
        checksPassed++;
    } else {
        std::cout << "      ✗ Invalid SPIR-V" << std::endl;
    }

    // Cleanup
    vkDestroyShaderModule(device, shader, nullptr);
    vkDestroyDevice(device, nullptr);
    vkDestroyInstance(instance, nullptr);

    // Results
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Validation Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Checks passed: " << checksPassed << "/" << checksTotal << std::endl;
    std::cout << std::endl;

    if (checksPassed == checksTotal) {
        std::cout << "✅ ALL CHECKS PASSED" << std::endl;
        std::cout << "GPU setup is ready for transformer inference" << std::endl;
        return 0;
    } else {
        std::cout << "⚠ SOME CHECKS FAILED" << std::endl;
        return 1;
    }
}
