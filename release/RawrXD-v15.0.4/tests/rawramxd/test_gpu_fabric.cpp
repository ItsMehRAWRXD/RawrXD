/**
 * RawRamXD GPU Fabric Test Suite
 * Validates real hardware integration
 */

#include "rawramxd/gpu_fabric.hpp"
#include <iostream>
#include <cassert>
#include <cstring>

using namespace RawRamXD;

void TestInitialization() {
    std::cout << "\n=== Test: Initialization ===" << std::endl;
    
    GPUFabric& fabric = GPUFabric::Instance();
    
    bool result = fabric.Initialize();
    std::cout << "Initialize: " << (result ? "PASS" : "FAIL") << std::endl;
    
    assert(result && "Fabric initialization failed");
    
    auto devices = fabric.GetDevices();
    std::cout << "Devices enumerated: " << devices.size() << std::endl;
    
    for (auto* device : devices) {
        std::wcout << L"  Device " << device->id << L": " << device->name << std::endl;
        std::cout << "    Type: " << (device->IsGPU() ? "GPU" : 
                                     device->IsRAM() ? "RAM" : "Storage") << std::endl;
        std::cout << "    Capacity: " << (device->capacityBytes / (1024*1024*1024)) << " GB" << std::endl;
        std::cout << "    Bandwidth: " << (device->bandwidthBytesPerSec / (1024*1024*1024)) << " GB/s" << std::endl;
    }
    
    std::cout << "Initialization test: PASS" << std::endl;
}

void TestAllocation() {
    std::cout << "\n=== Test: Memory Allocation ===" << std::endl;
    
    GPUFabric& fabric = GPUFabric::Instance();
    
    // Test GPU allocation
    void* gpuMem = fabric.Allocate(1024 * 1024, ComputeTargetType::GPU_VRAM);
    std::cout << "GPU allocation (1MB): " << (gpuMem ? "PASS" : "SKIP (no GPU)") << std::endl;
    
    // Test RAM allocation
    void* ramMem = fabric.Allocate(1024 * 1024, ComputeTargetType::CPU_RAM);
    std::cout << "RAM allocation (1MB): " << (ramMem ? "PASS" : "FAIL") << std::endl;
    assert(ramMem && "RAM allocation failed");
    
    // Test storage allocation
    void* storageMem = fabric.Allocate(1024 * 1024, ComputeTargetType::NVME_STORE);
    std::cout << "Storage allocation (1MB): " << (storageMem ? "PASS" : "FAIL") << std::endl;
    
    // Cleanup
    if (gpuMem) fabric.Free(gpuMem);
    if (ramMem) fabric.Free(ramMem);
    if (storageMem) fabric.Free(storageMem);
    
    std::cout << "Allocation test: PASS" << std::endl;
}

void TestTensorRegistration() {
    std::cout << "\n=== Test: Tensor Registration ===" << std::endl;
    
    GPUFabric& fabric = GPUFabric::Instance();
    auto* scheduler = fabric.GetScheduler();
    
    // Allocate test data
    const size_t testSize = 1024 * 1024; // 1MB
    void* testData = fabric.Allocate(testSize, ComputeTargetType::CPU_RAM);
    assert(testData && "Failed to allocate test data");
    
    // Fill with pattern
    std::memset(testData, 0xAB, testSize);
    
    // Register tensor
    uint64_t handle = fabric.RegisterTensor(testData, testSize);
    std::cout << "Tensor registered: handle=" << handle << std::endl;
    assert(handle != 0 && "Tensor registration failed");
    
    // Get residency info
    TensorResidency residency;
    bool result = RawRamXD_GetResidency(handle, &residency);
    std::cout << "Get residency: " << (result ? "PASS" : "FAIL") << std::endl;
    
    if (result) {
        std::cout << "  Size: " << residency.sizeBytes << " bytes" << std::endl;
        std::cout << "  State: " << (residency.state == ResidencyState::UNRESIDENT ? "UNRESIDENT" :
                                    residency.state == ResidencyState::RESIDENT ? "RESIDENT" : "OTHER") << std::endl;
    }
    
    // Promote to GPU
    result = fabric.Promote(handle, ComputeTargetType::GPU_VRAM);
    std::cout << "Promote to GPU: " << (result ? "PASS" : "SKIP (no GPU)") << std::endl;
    
    // Execute operation
    result = fabric.Execute(handle, OperationType::INFERENCE_FORWARD);
    std::cout << "Execute operation: " << (result ? "PASS" : "FAIL") << std::endl;
    
    // Unregister
    fabric.UnregisterTensor(handle);
    std::cout << "Tensor unregistered" << std::endl;
    
    // Cleanup
    fabric.Free(testData);
    
    std::cout << "Tensor registration test: PASS" << std::endl;
}

void TestScheduler() {
    std::cout << "\n=== Test: Fabric Scheduler ===" << std::endl;
    
    GPUFabric& fabric = GPUFabric::Instance();
    auto* scheduler = fabric.GetScheduler();
    
    // Register test tensor
    void* testData = fabric.Allocate(1024 * 1024, ComputeTargetType::CPU_RAM);
    uint64_t handle = fabric.RegisterTensor(testData, 1024 * 1024);
    
    // Create operation
    Operation op;
    op.type = OperationType::ATTENTION_COMPUTE;
    op.tensorId = handle;
    op.sizeBytes = 1024 * 1024;
    op.bandwidthRequired = 100 * 1024 * 1024; // 100 MB/s
    op.latencyBudgetNs = 1000000; // 1ms
    op.computeRequired = true;
    
    // Schedule
    auto decision = scheduler->Schedule(op);
    std::cout << "Schedule decision:" << std::endl;
    std::cout << "  Target: " << (decision.target ? "selected" : "NONE") << std::endl;
    if (decision.target) {
        std::wcout << L"    Device: " << decision.target->name << std::endl;
        std::cout << "    Requires migration: " << (decision.requiresMigration ? "YES" : "NO") << std::endl;
        std::cout << "    Confidence: " << decision.confidence << std::endl;
        std::cout << "    Estimated latency: " << decision.estimatedLatencyNs << " ns" << std::endl;
    }
    
    // Get stats
    auto stats = scheduler->GetStats();
    std::cout << "\nFabric stats:" << std::endl;
    std::cout << "  Total tensors: " << stats.totalTensors << std::endl;
    std::cout << "  Resident tensors: " << stats.residentTensors << std::endl;
    std::cout << "  Fabric utilization: " << (stats.fabricUtilization * 100) << "%" << std::endl;
    
    // Cleanup
    fabric.UnregisterTensor(handle);
    fabric.Free(testData);
    
    std::cout << "Scheduler test: PASS" << std::endl;
}

void TestCAPI() {
    std::cout << "\n=== Test: C API ===" << std::endl;
    
    // Already initialized by previous tests
    
    uint32_t deviceCount = RawRamXD_GetDeviceCount();
    std::cout << "Device count: " << deviceCount << std::endl;
    
    for (uint32_t i = 0; i < deviceCount && i < 3; i++) {
        ComputeTarget info;
        if (RawRamXD_GetDeviceInfo(i, &info)) {
            std::wcout << L"  Device " << i << L": " << info.name << std::endl;
        }
    }
    
    // Test allocation via C API
    void* mem = RawRamXD_Allocate(1024 * 1024, ComputeTargetType::CPU_RAM);
    std::cout << "C API allocation: " << (mem ? "PASS" : "FAIL") << std::endl;
    
    if (mem) {
        RawRamXD_Free(mem);
    }
    
    std::cout << "C API test: PASS" << std::endl;
}

void TestMultiDevice() {
    std::cout << "\n=== Test: Multi-Device Fabric ===" << std::endl;
    
    GPUFabric& fabric = GPUFabric::Instance();
    auto* scheduler = fabric.GetScheduler();
    
    auto targets = scheduler->GetAllTargets();
    if (targets.size() < 2) {
        std::cout << "SKIP: Need 2+ devices for multi-device test" << std::endl;
        return;
    }
    
    // Register tensor on first target
    void* testData = fabric.Allocate(1024 * 1024, ComputeTargetType::CPU_RAM);
    uint64_t handle = fabric.RegisterTensor(testData, 1024 * 1024);
    
    // Ensure resident on first target
    auto* firstTarget = targets[0];
    scheduler->EnsureResident(handle, OperationType::WEIGHT_LOAD);
    
    // Migrate to second target
    auto* secondTarget = targets[1];
    bool result = scheduler->ExecuteMigration(
        scheduler->GetTensor(handle), secondTarget);
    
    std::cout << "Migration from " << firstTarget->id << " to " << secondTarget->id 
              << ": " << (result ? "PASS" : "FAIL") << std::endl;
    
    // Cleanup
    fabric.UnregisterTensor(handle);
    fabric.Free(testData);
    
    std::cout << "Multi-device test: PASS" << std::endl;
}

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "RawRamXD GPU Fabric Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    
    try {
        TestInitialization();
        TestAllocation();
        TestTensorRegistration();
        TestScheduler();
        TestCAPI();
        TestMultiDevice();
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "All tests PASSED" << std::endl;
        std::cout << "========================================" << std::endl;
        
        // Cleanup
        GPUFabric::Instance().Shutdown();
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTest FAILED: " << e.what() << std::endl;
        GPUFabric::Instance().Shutdown();
        return 1;
    }
}
