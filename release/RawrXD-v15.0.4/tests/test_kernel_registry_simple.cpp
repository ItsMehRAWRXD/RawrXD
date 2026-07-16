//==============================================================================
// test_kernel_registry_simple.cpp
// Simple test for KernelRegistry only
//==============================================================================

#include <iostream>
#include "../src/core/execution/KernelRegistry.hpp"
#include "../src/core/execution/IKernelBackend.hpp"

using namespace sovereign;

int main() {
    std::cout << "Starting KernelRegistry test...\n";
    
    // Test 1: Get registry instance
    std::cout << "[Test 1] Get Registry Instance\n";
    KernelRegistry& registry = KernelRegistry::Instance();
    std::cout << "  Got registry instance\n";
    
    // Test 2: List backends (should be empty initially)
    std::cout << "[Test 2] List Backends\n";
    auto backends = registry.ListBackends();
    std::cout << "  Backends registered: " << backends.size() << "\n";
    
    // Test 3: Register Reference backend
    std::cout << "[Test 3] Register Reference Backend\n";
    auto refBackend = std::unique_ptr<IKernelBackend>(CreateReferenceBackend());
    if (!refBackend) {
        std::cout << "  FAILED: CreateReferenceBackend returned nullptr\n";
        return 1;
    }
    std::cout << "  Created backend\n";
    
    if (!refBackend->Initialize()) {
        std::cout << "  FAILED: Initialize returned false\n";
        return 1;
    }
    std::cout << "  Initialized backend\n";
    
    uint32_t refId = registry.RegisterBackend(std::move(refBackend));
    std::cout << "  Registered with ID: " << refId << "\n";
    
    // Test 4: List backends again
    std::cout << "[Test 4] List Backends After Registration\n";
    backends = registry.ListBackends();
    std::cout << "  Backends registered: " << backends.size() << "\n";
    for (const auto& [id, info] : backends) {
        std::cout << "    [" << id << "] " << info.name << " v" << info.version << "\n";
    }
    
    // Test 5: Get backend by ID
    std::cout << "[Test 5] Get Backend by ID\n";
    IKernelBackend* backend = registry.GetBackend(refId);
    if (backend) {
        std::cout << "  Got backend: " << backend->GetInfo().name << "\n";
    } else {
        std::cout << "  FAILED: GetBackend returned nullptr\n";
    }
    
    // Test 6: Get backend by name
    std::cout << "[Test 6] Get Backend by Name\n";
    backend = registry.GetBackend("Reference");
    if (backend) {
        std::cout << "  Got backend: " << backend->GetInfo().name << "\n";
    } else {
        std::cout << "  FAILED: GetBackend returned nullptr\n";
    }
    
    // Test 7: Shutdown
    std::cout << "[Test 7] Shutdown\n";
    registry.ShutdownAll();
    std::cout << "  Shutdown complete\n";
    
    std::cout << "\nAll tests passed!\n";
    return 0;
}
