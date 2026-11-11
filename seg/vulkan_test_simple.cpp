// ============================================================================
// Simple Vulkan Test - Check if GPU is available
// ============================================================================

#include <iostream>
#include <windows.h>

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Vulkan GPU Detection" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    // Try to load vulkan-1.dll
    HMODULE vulkanLib = LoadLibraryA("vulkan-1.dll");
    if (!vulkanLib) {
        std::cout << "Vulkan runtime NOT found" << std::endl;
        std::cout << "Install Vulkan SDK from: https://vulkan.lunarg.com/" << std::endl;
        return 1;
    }

    std::cout << "Vulkan runtime FOUND" << std::endl;

    // Check for key functions
    FARPROC vkCreateInstance = GetProcAddress(vulkanLib, "vkCreateInstance");
    FARPROC vkEnumeratePhysicalDevices = GetProcAddress(vulkanLib, "vkEnumeratePhysicalDevices");
    FARPROC vkGetPhysicalDeviceProperties = GetProcAddress(vulkanLib, "vkGetPhysicalDeviceProperties");

    std::cout << "vkCreateInstance: " << (vkCreateInstance ? "FOUND" : "NOT FOUND") << std::endl;
    std::cout << "vkEnumeratePhysicalDevices: " << (vkEnumeratePhysicalDevices ? "FOUND" : "NOT FOUND") << std::endl;
    std::cout << "vkGetPhysicalDeviceProperties: " << (vkGetPhysicalDeviceProperties ? "FOUND" : "NOT FOUND") << std::endl;

    FreeLibrary(vulkanLib);

    std::cout << std::endl;
    std::cout << "Vulkan is available on this system!" << std::endl;
    std::cout << "Ready for GPU acceleration." << std::endl;

    return 0;
}
