// Test SPIR-V version compatibility
#include <vulkan/vulkan.h>
#include <iostream>
#include <fstream>
#include <vector>

int main() {
    // Create instance with version 1.3
    VkApplicationInfo app_info = {};
    app_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app_info.apiVersion = VK_API_VERSION_1_3;  // Try 1.3 instead of 1.2
    
    VkInstanceCreateInfo instance_info = {};
    instance_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instance_info.pApplicationInfo = &app_info;
    
    VkInstance instance = VK_NULL_HANDLE;
    VkResult result = vkCreateInstance(&instance_info, nullptr, &instance);
    if (result != VK_SUCCESS) {
        std::cerr << "Failed to create instance: " << result << std::endl;
        return 1;
    }
    
    // Get physical device
    uint32_t device_count = 0;
    vkEnumeratePhysicalDevices(instance, &device_count, nullptr);
    std::vector<VkPhysicalDevice> devices(device_count);
    vkEnumeratePhysicalDevices(instance, &device_count, devices.data());
    
    VkPhysicalDevice physical_device = devices[0];
    
    // Check device properties
    VkPhysicalDeviceProperties props;
    vkGetPhysicalDeviceProperties(physical_device, &props);
    std::cout << "Device: " << props.deviceName << std::endl;
    std::cout << "API Version: " << VK_VERSION_MAJOR(props.apiVersion) << "."
              << VK_VERSION_MINOR(props.apiVersion) << "."
              << VK_VERSION_PATCH(props.apiVersion) << std::endl;
    std::cout << "Driver Version: " << props.driverVersion << std::endl;
    
    // Check SPIR-V version support
    // Vulkan 1.3 requires SPIR-V 1.5
    // Vulkan 1.2 requires SPIR-V 1.5
    // Vulkan 1.1 requires SPIR-V 1.3
    // Vulkan 1.0 requires SPIR-V 1.0
    
    // The shaders are SPIR-V 1.6, which requires Vulkan 1.3+
    // Let's check if the device supports Vulkan 1.3
    
    uint32_t api_major = VK_VERSION_MAJOR(props.apiVersion);
    uint32_t api_minor = VK_VERSION_MINOR(props.apiVersion);
    
    std::cout << "\nSPIR-V Version Support:" << std::endl;
    if (api_major >= 1 && api_minor >= 3) {
        std::cout << "  ✅ Vulkan 1.3+ - Supports SPIR-V 1.6" << std::endl;
    } else if (api_major >= 1 && api_minor >= 2) {
        std::cout << "  ⚠️ Vulkan 1.2 - Supports SPIR-V 1.5 (shaders are 1.6!)" << std::endl;
    } else if (api_major >= 1 && api_minor >= 1) {
        std::cout << "  ❌ Vulkan 1.1 - Supports SPIR-V 1.3 (shaders are 1.6!)" << std::endl;
    } else {
        std::cout << "  ❌ Vulkan 1.0 - Supports SPIR-V 1.0 (shaders are 1.6!)" << std::endl;
    }
    
    // Create device with maintenance4 feature (needed for SPIR-V 1.6)
    VkPhysicalDeviceMaintenance4Features maint4 = {};
    maint4.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_4_FEATURES;
    maint4.maintenance4 = VK_TRUE;
    
    VkPhysicalDeviceFeatures2 features2 = {};
    features2.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2;
    features2.pNext = &maint4;
    
    vkGetPhysicalDeviceFeatures2(physical_device, &features2);
    
    std::cout << "\nMaintenance4 support: " << (maint4.maintenance4 ? "Yes" : "No") << std::endl;
    
    vkDestroyInstance(instance, nullptr);
    
    return 0;
}
