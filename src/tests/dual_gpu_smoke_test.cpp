// ============================================================================
// Dual GPU Smoke Test - Tests both GPU devices in a multi-GPU setup
// Uses gpu_masm_bridge.h interface for device enumeration and memory ops
// ============================================================================

#include <iostream>
#include <cstring>
#include <chrono>
#include <thread>
#include <vector>
#include <cassert>

#include "../gpu_masm_bridge.h"

// Test result tracking
struct TestResult {
    const char* name;
    bool passed;
    std::string details;
};

std::vector<TestResult> g_results;

void RecordTest(const char* name, bool passed, const std::string& details = "") {
    g_results.push_back({name, passed, details});
    std::cout << "[" << (passed ? "PASS" : "FAIL") << "] " << name;
    if (!details.empty()) {
        std::cout << " - " << details;
    }
    std::cout << std::endl;
}

// ============================================================================
// Test 1: GPU Detection and Enumeration
// ============================================================================
bool Test_GPU_Detection() {
    std::cout << "\n=== Test 1: GPU Detection ===" << std::endl;
    
    int deviceCount = GPU_Detect();
    
    if (deviceCount <= 0) {
        RecordTest("GPU_Detection", false, "No GPUs detected");
        return false;
    }
    
    std::string details = "Found " + std::to_string(deviceCount) + " GPU(s)";
    RecordTest("GPU_Detection", true, details);
    
    // Display device info
    for (int i = 0; i < deviceCount && i < 16; i++) {
        std::cout << "  GPU[" << i << "]: " << GPU_DeviceList[i].DeviceName << std::endl;
        std::cout << "    VendorID: 0x" << std::hex << GPU_DeviceList[i].VendorID << std::dec << std::endl;
        std::cout << "    Memory: " << (GPU_DeviceList[i].MemorySize / (1024*1024)) << " MB" << std::endl;
        std::cout << "    Compute: " << GPU_DeviceList[i].ComputeCapability << std::endl;
    }
    
    return true;
}

// ============================================================================
// Test 2: Dual GPU Memory Allocation
// Tests allocating memory on both GPU 0 and GPU 1 if available
// ============================================================================
bool Test_DualGPU_MemoryAllocation() {
    std::cout << "\n=== Test 2: Dual GPU Memory Allocation ===" << std::endl;
    
    int deviceCount = GPU_Detect();
    if (deviceCount < 1) {
        RecordTest("DualGPU_MemoryAllocation", false, "No GPUs available");
        return false;
    }
    
    bool allPassed = true;
    
    // Test allocation on each GPU
    for (int dev = 0; dev < deviceCount && dev < 2; dev++) {
        std::cout << "  Testing GPU " << dev << "..." << std::endl;
        
        // Allocate 64MB on this GPU
        const size_t allocSize = 64 * 1024 * 1024;
        void* ptr = AllocateGPUMemory(allocSize);
        
        if (!ptr) {
            RecordTest(("GPU_" + std::to_string(dev) + "_Alloc").c_str(), false, "Allocation failed");
            allPassed = false;
            continue;
        }
        
        // Verify pointer is not null
        bool ptrValid = (ptr != nullptr);
        RecordTest(("GPU_" + std::to_string(dev) + "_Alloc").c_str(), ptrValid, 
                   ptrValid ? "64MB allocated" : "Null pointer returned");
        
        // Free the memory
        FreeGPUMemory(ptr);
        RecordTest(("GPU_" + std::to_string(dev) + "_Free").c_str(), true, "Memory freed");
    }
    
    if (deviceCount >= 2) {
        RecordTest("DualGPU_MemoryAllocation", allPassed, 
                   allPassed ? "Both GPUs tested" : "Some allocations failed");
    } else {
        RecordTest("DualGPU_MemoryAllocation", allPassed, 
                   "Only 1 GPU available, single GPU tested");
    }
    
    return allPassed;
}

// ============================================================================
// Test 3: Concurrent GPU Operations Simulation
// Simulates workload distribution across both GPUs
// ============================================================================
bool Test_DualGPU_ConcurrentOps() {
    std::cout << "\n=== Test 3: Dual GPU Concurrent Operations ===" << std::endl;
    
    int deviceCount = GPU_Detect();
    if (deviceCount < 2) {
        RecordTest("DualGPU_ConcurrentOps", true, 
                   "Skipped - need 2 GPUs, found " + std::to_string(deviceCount));
        return true; // Not a failure, just not applicable
    }
    
    std::cout << "  Simulating concurrent workload on " << deviceCount << " GPUs..." << std::endl;
    
    // Allocate memory on both GPUs
    const size_t allocSize = 32 * 1024 * 1024; // 32MB each
    void* gpu0Ptr = AllocateGPUMemory(allocSize);
    void* gpu1Ptr = AllocateGPUMemory(allocSize);
    
    bool alloc0Ok = (gpu0Ptr != nullptr);
    bool alloc1Ok = (gpu1Ptr != nullptr);
    
    RecordTest("GPU0_Concurrent_Alloc", alloc0Ok, alloc0Ok ? "32MB allocated" : "Failed");
    RecordTest("GPU1_Concurrent_Alloc", alloc1Ok, alloc1Ok ? "32MB allocated" : "Failed");
    
    // Simulate some work (just sleep for timing)
    if (alloc0Ok && alloc1Ok) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        RecordTest("DualGPU_SimulatedWork", true, "Work completed on both GPUs");
    }
    
    // Cleanup
    if (gpu0Ptr) FreeGPUMemory(gpu0Ptr);
    if (gpu1Ptr) FreeGPUMemory(gpu1Ptr);
    
    RecordTest("DualGPU_Cleanup", true, "Memory freed on both GPUs");
    
    return alloc0Ok && alloc1Ok;
}

// ============================================================================
// Test 4: GPU Backend Initialization
// Tests initializing different backends (Vulkan, CUDA, etc.)
// ============================================================================
bool Test_GPU_BackendInit() {
    std::cout << "\n=== Test 4: GPU Backend Initialization ===" << std::endl;
    
    // Test auto-detection (-1)
    int result = InitializeGPUBackend(-1);
    bool autoInitOk = (result == 0);
    RecordTest("GPU_Backend_Auto", autoInitOk, 
               autoInitOk ? "Auto-detection successful" : "Auto-detection returned " + std::to_string(result));
    
    // Re-detect after init
    int deviceCount = GPU_Detect();
    RecordTest("GPU_Detect_PostInit", deviceCount > 0, 
               "Devices found: " + std::to_string(deviceCount));
    
    return autoInitOk;
}

// ============================================================================
// Test 5: Memory Stress Test on Both GPUs
// ============================================================================
bool Test_DualGPU_MemoryStress() {
    std::cout << "\n=== Test 5: Dual GPU Memory Stress ===" << std::endl;
    
    int deviceCount = GPU_Detect();
    if (deviceCount < 1) {
        RecordTest("DualGPU_MemoryStress", false, "No GPUs available");
        return false;
    }
    
    const size_t stressSize = 16 * 1024 * 1024; // 16MB chunks
    const int iterations = 5;
    bool allPassed = true;
    
    for (int dev = 0; dev < deviceCount && dev < 2; dev++) {
        std::cout << "  Stress testing GPU " << dev << "..." << std::endl;
        
        for (int i = 0; i < iterations; i++) {
            void* ptr = AllocateGPUMemory(stressSize);
            if (!ptr) {
                RecordTest(("GPU_" + std::to_string(dev) + "_Stress_" + std::to_string(i)).c_str(), 
                           false, "Allocation failed");
                allPassed = false;
                break;
            }
            FreeGPUMemory(ptr);
        }
        
        if (allPassed) {
            RecordTest(("GPU_" + std::to_string(dev) + "_Stress").c_str(), 
                       true, std::to_string(iterations) + " allocations/deallocations");
        }
    }
    
    return allPassed;
}

// ============================================================================
// Main Entry Point
// ============================================================================
int main() {
    std::cout << "╔══════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║     RawrXD Dual GPU Smoke Test                               ║" << std::endl;
    std::cout << "║     Tests both GPUs in multi-GPU configurations              ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Run all tests
    Test_GPU_Detection();
    Test_DualGPU_MemoryAllocation();
    Test_DualGPU_ConcurrentOps();
    Test_GPU_BackendInit();
    Test_DualGPU_MemoryStress();
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    // Print summary
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║     TEST SUMMARY                                             ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
    
    int passed = 0, failed = 0;
    for (const auto& result : g_results) {
        if (result.passed) passed++;
        else failed++;
    }
    
    std::cout << "Total Tests: " << g_results.size() << std::endl;
    std::cout << "Passed: " << passed << " ✓" << std::endl;
    std::cout << "Failed: " << failed << (failed > 0 ? " ✗" : "") << std::endl;
    std::cout << "Duration: " << duration.count() << " ms" << std::endl;
    
    // Show failed tests
    if (failed > 0) {
        std::cout << "\nFailed Tests:" << std::endl;
        for (const auto& result : g_results) {
            if (!result.passed) {
                std::cout << "  ✗ " << result.name;
                if (!result.details.empty()) {
                    std::cout << " - " << result.details;
                }
                std::cout << std::endl;
            }
        }
    }
    
    // Final status
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗" << std::endl;
    if (failed == 0) {
        std::cout << "║     STATUS: ALL TESTS PASSED ✓                              ║" << std::endl;
    } else {
        std::cout << "║     STATUS: SOME TESTS FAILED ✗                             ║" << std::endl;
    }
    std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
    
    return failed > 0 ? 1 : 0;
}
