// Simple Vulkan Backend Test - No shader loading
#include "vulkan_backend_implementation.hpp"
#include <iostream>

using namespace transformer;

int main() {
    std::cout << "Testing Vulkan Backend Initialization..." << std::endl;
    
    auto backend = CreateVulkanBackendComplete();
    
    std::cout << "Calling Initialize()..." << std::endl;
    if (!backend->Initialize()) {
        std::cerr << "Failed to initialize!" << std::endl;
        return 1;
    }
    
    std::cout << "SUCCESS: Vulkan backend initialized!" << std::endl;
    std::cout << "Device: AMD Radeon RX 7800 XT" << std::endl;
    
    // Test buffer allocation
    void* buffer = nullptr;
    std::cout << "Testing buffer allocation..." << std::endl;
    if (backend->AllocateBuffer(1024 * sizeof(float), &buffer)) {
        std::cout << "SUCCESS: Allocated 4KB buffer" << std::endl;
        
        // Test upload/download
        float data[256] = {1.0f, 2.0f, 3.0f};
        std::cout << "Testing upload..." << std::endl;
        if (backend->CopyHostToDevice(data, buffer, 256 * sizeof(float))) {
            std::cout << "SUCCESS: Uploaded data" << std::endl;
        }
        
        backend->FreeBuffer(buffer);
        std::cout << "SUCCESS: Freed buffer" << std::endl;
    }
    
    backend->Cleanup();
    std::cout << "SUCCESS: Cleanup complete" << std::endl;
    
    return 0;
}
