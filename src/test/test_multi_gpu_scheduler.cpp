// ============================================================================
// Multi-GPU Scheduler Test Suite
// Validates capability-based device enumeration, tensor placement policies,
// and AMD AI PRO R9700 + RX 7800 XT specific scheduling.
// ============================================================================

#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include <string>

#include "../gpu/multi_gpu_scheduler.hpp"

using namespace RawrXD::GPU;

// Test result tracking
struct TestResults {
    int passed = 0;
    int failed = 0;
    std::vector<std::string> failures;
    
    void check(bool condition, const std::string& testName) {
        if (condition) {
            passed++;
            std::cout << "[PASS] " << testName << std::endl;
        } else {
            failed++;
            failures.push_back(testName);
            std::cerr << "[FAIL] " << testName << std::endl;
        }
    }
};

// ============================================================================
// Test 1: Singleton Pattern
// ============================================================================
bool test_singleton() {
    MultiGPUScheduler& scheduler1 = MultiGPUScheduler::instance();
    MultiGPUScheduler& scheduler2 = MultiGPUScheduler::instance();
    return &scheduler1 == &scheduler2;
}

// ============================================================================
// Test 2: Initialization
// ============================================================================
bool test_initialization() {
    MultiGPUScheduler& scheduler = MultiGPUScheduler::instance();
    bool initResult = scheduler.initialize();
    return initResult;
}

// ============================================================================
// Test 3: Device Enumeration (may return 0 on non-GPU systems)
// ============================================================================
bool test_device_enumeration() {
    MultiGPUScheduler& scheduler = MultiGPUScheduler::instance();
    scheduler.initialize();
    
    uint32_t deviceCount = scheduler.enumerateDevices();
    const auto& devices = scheduler.getDevices();
    
    // Device count should match vector size
    return devices.size() == deviceCount;
}

// ============================================================================
// Test 4: Device Queries
// ============================================================================
bool test_device_queries() {
    MultiGPUScheduler& scheduler = MultiGPUScheduler::instance();
    scheduler.initialize();
    scheduler.enumerateDevices();
    
    const auto& devices = scheduler.getDevices();
    if (devices.empty()) {
        // No devices is valid on CPU-only systems
        return true;
    }
    
    // Test getLargestDevice
    const DeviceCapability* largest = scheduler.getLargestDevice();
    bool hasLargest = largest != nullptr;
    
    // Test getFastestDevice
    const DeviceCapability* fastest = scheduler.getFastestDevice();
    bool hasFastest = fastest != nullptr;
    
    // Test getDevice for each device
    bool allDevicesValid = true;
    for (uint32_t i = 0; i < devices.size(); ++i) {
        const DeviceCapability* device = scheduler.getDevice(i);
        if (device == nullptr || device->deviceId != i) {
            allDevicesValid = false;
            break;
        }
    }
    
    return hasLargest && hasFastest && allDevicesValid;
}

// ============================================================================
// Test 5: Memory Tier Assignment
// ============================================================================
bool test_memory_tier_assignment() {
    MultiGPUScheduler& scheduler = MultiGPUScheduler::instance();
    scheduler.initialize();
    scheduler.enumerateDevices();
    
    const auto& devices = scheduler.getDevices();
    if (devices.empty()) {
        return true; // No devices to test
    }
    
    // Check that devices have valid memory tiers
    bool allValid = true;
    for (const auto& device : devices) {
        bool validTier = device.preferredTier == DeviceCapability::MemoryTier::Hot ||
                        device.preferredTier == DeviceCapability::MemoryTier::Warm ||
                        device.preferredTier == DeviceCapability::MemoryTier::Cold;
        if (!validTier) {
            allValid = false;
            break;
        }
    }
    
    return allValid;
}

// ============================================================================
// Test 6: Tensor Placement - LargestFirst Policy
// ============================================================================
bool test_tensor_placement_largest_first() {
    MultiGPUScheduler& scheduler = MultiGPUScheduler::instance();
    scheduler.initialize();
    scheduler.enumerateDevices();
    scheduler.setPolicy(PlacementPolicy::LargestFirst);
    
    const auto& devices = scheduler.getDevices();
    if (devices.empty()) {
        return true; // No devices to test
    }
    
    // Place a tensor
    TensorPlacement placement = scheduler.placeTensor(1024 * 1024 * 100, "test_tensor"); // 100MB
    
    // Should be placed on largest device
    const DeviceCapability* largest = scheduler.getLargestDevice();
    bool correctDevice = placement.deviceId == largest->deviceId;
    bool correctSize = placement.size == 1024 * 1024 * 100;
    bool notSharded = !placement.isSharded;
    
    return correctDevice && correctSize && notSharded;
}

// ============================================================================
// Test 7: Tensor Placement - EmbeddingOffload Policy
// ============================================================================
bool test_tensor_placement_embedding_offload() {
    MultiGPUScheduler& scheduler = MultiGPUScheduler::instance();
    scheduler.initialize();
    scheduler.enumerateDevices();
    
    const auto& devices = scheduler.getDevices();
    if (devices.size() < 2) {
        // Need at least 2 devices for embedding offload
        return true;
    }
    
    scheduler.setPolicy(PlacementPolicy::EmbeddingOffload);
    
    // Place an embedding tensor
    TensorPlacement placement = scheduler.placeTensor(1024 * 1024 * 50, "embedding_weights"); // 50MB
    
    // Should be placed on secondary device for embeddings
    uint32_t secondaryId = scheduler.getSecondaryDevice();
    bool correctDevice = placement.deviceId == secondaryId;
    
    return correctDevice;
}

// ============================================================================
// Test 8: Tensor Sharding
// ============================================================================
bool test_tensor_sharding() {
    MultiGPUScheduler& scheduler = MultiGPUScheduler::instance();
    scheduler.initialize();
    scheduler.enumerateDevices();
    
    const auto& devices = scheduler.getDevices();
    if (devices.empty()) {
        return true; // No devices to test
    }
    
    // Shard a tensor across 4 shards
    size_t tensorSize = 1024 * 1024 * 400; // 400MB
    uint32_t numShards = 4;
    std::vector<TensorPlacement> placements = scheduler.placeTensorSharded(tensorSize, numShards);
    
    // Should have 4 placements
    bool correctCount = placements.size() == numShards;
    if (!correctCount) {
        return false;
    }
    
    // Each should be marked as sharded
    bool allSharded = true;
    size_t totalSize = 0;
    for (uint32_t i = 0; i < numShards; ++i) {
        if (!placements[i].isSharded || 
            placements[i].shardIndex != i ||
            placements[i].shardCount != numShards) {
            allSharded = false;
            break;
        }
        totalSize += placements[i].size;
    }
    
    // Total size should approximately equal original (may have remainder)
    bool sizeCorrect = totalSize >= tensorSize && totalSize <= tensorSize + numShards;
    
    return correctCount && allSharded && sizeCorrect;
}

// ============================================================================
// Test 9: Policy Management
// ============================================================================
bool test_policy_management() {
    MultiGPUScheduler& scheduler = MultiGPUScheduler::instance();
    
    // Test all policies
    std::vector<PlacementPolicy> policies = {
        PlacementPolicy::LargestFirst,
        PlacementPolicy::Striped,
        PlacementPolicy::Pipeline,
        PlacementPolicy::TensorParallel,
        PlacementPolicy::MoEExpert,
        PlacementPolicy::EmbeddingOffload
    };
    
    bool allPoliciesWork = true;
    for (auto policy : policies) {
        scheduler.setPolicy(policy);
        if (scheduler.getPolicy() != policy) {
            allPoliciesWork = false;
            break;
        }
    }
    
    return allPoliciesWork;
}

// ============================================================================
// Test 10: Total VRAM Calculation
// ============================================================================
bool test_vram_calculation() {
    MultiGPUScheduler& scheduler = MultiGPUScheduler::instance();
    scheduler.initialize();
    scheduler.enumerateDevices();
    
    const auto& devices = scheduler.getDevices();
    
    size_t totalVRAM = scheduler.getTotalVRAM();
    size_t availableVRAM = scheduler.getAvailableVRAM();
    
    // Calculate expected total
    size_t expectedTotal = 0;
    for (const auto& device : devices) {
        expectedTotal += device.totalVRAM;
    }
    
    bool totalCorrect = totalVRAM == expectedTotal;
    bool availableValid = availableVRAM <= totalVRAM;
    
    return totalCorrect && availableValid;
}

// ============================================================================
// Test 11: PCIe Speed Detection
// ============================================================================
bool test_pcie_speed_detection() {
    MultiGPUScheduler& scheduler = MultiGPUScheduler::instance();
    scheduler.initialize();
    scheduler.enumerateDevices();
    
    const auto& devices = scheduler.getDevices();
    
    // All devices should have valid PCIe speeds
    bool allValid = true;
    for (const auto& device : devices) {
        bool validSpeed = device.pcieSpeed >= PCIeLinkSpeed::Gen3_x4 &&
                         device.pcieSpeed <= PCIeLinkSpeed::Gen5_x16;
        if (!validSpeed) {
            allValid = false;
            break;
        }
    }
    
    return allValid;
}

// ============================================================================
// Test 12: Compute Score Calculation
// ============================================================================
bool test_compute_score() {
    MultiGPUScheduler& scheduler = MultiGPUScheduler::instance();
    scheduler.initialize();
    scheduler.enumerateDevices();
    
    const auto& devices = scheduler.getDevices();
    
    // All devices should have valid compute scores
    bool allValid = true;
    for (const auto& device : devices) {
        if (device.computeScore < 0.0f || device.computeScore > 1.0f) {
            allValid = false;
            break;
        }
    }
    
    return allValid;
}

// ============================================================================
// Test 13: Shutdown and Reinitialization
// ============================================================================
bool test_shutdown_reinit() {
    MultiGPUScheduler& scheduler = MultiGPUScheduler::instance();
    
    // Initialize
    scheduler.initialize();
    scheduler.enumerateDevices();
    
    // Shutdown
    scheduler.shutdown();
    
    // Reinitialize
    bool reinitSuccess = scheduler.initialize();
    
    return reinitSuccess;
}

// ============================================================================
// Test 14: AMD Setup Detection (simulated)
// ============================================================================
bool test_amd_setup_detection() {
    MultiGPUScheduler& scheduler = MultiGPUScheduler::instance();
    scheduler.initialize();
    scheduler.enumerateDevices();
    
    // isAMDSetup returns true only if exactly 2 AMD GPUs detected
    // On non-AMD systems, this will be false - that's expected
    bool amdSetup = scheduler.isAMDSetup();
    
    // If we have devices, check primary/secondary
    const auto& devices = scheduler.getDevices();
    if (devices.size() >= 2) {
        uint32_t primary = scheduler.getPrimaryDevice();
        uint32_t secondary = scheduler.getSecondaryDevice();
        
        // Primary should be 0 (largest), secondary should be 1
        bool validIds = primary == 0 && secondary == 1;
        return validIds;
    }
    
    return true; // No devices is valid
}

// ============================================================================
// Main Test Runner
// ============================================================================
int main(int argc, char* argv[]) {
    std::cout << "========================================================================" << std::endl;
    std::cout << "  RawrXD Multi-GPU Scheduler Test Suite" << std::endl;
    std::cout << "  Target: AMD AI PRO R9700 (32GB) + RX 7800 XT (16GB)" << std::endl;
    std::cout << "========================================================================" << std::endl;
    std::cout << std::endl;
    
    TestResults results;
    
    // Run all tests
    results.check(test_singleton(), "Singleton Pattern");
    results.check(test_initialization(), "Initialization");
    results.check(test_device_enumeration(), "Device Enumeration");
    results.check(test_device_queries(), "Device Queries");
    results.check(test_memory_tier_assignment(), "Memory Tier Assignment");
    results.check(test_tensor_placement_largest_first(), "Tensor Placement - LargestFirst");
    results.check(test_tensor_placement_embedding_offload(), "Tensor Placement - EmbeddingOffload");
    results.check(test_tensor_sharding(), "Tensor Sharding");
    results.check(test_policy_management(), "Policy Management");
    results.check(test_vram_calculation(), "VRAM Calculation");
    results.check(test_pcie_speed_detection(), "PCIe Speed Detection");
    results.check(test_compute_score(), "Compute Score Calculation");
    results.check(test_shutdown_reinit(), "Shutdown and Reinitialization");
    results.check(test_amd_setup_detection(), "AMD Setup Detection");
    
    // Summary
    std::cout << std::endl;
    std::cout << "========================================================================" << std::endl;
    std::cout << "  Test Summary" << std::endl;
    std::cout << "========================================================================" << std::endl;
    std::cout << "  Passed: " << results.passed << std::endl;
    std::cout << "  Failed: " << results.failed << std::endl;
    std::cout << "  Total:  " << (results.passed + results.failed) << std::endl;
    std::cout << std::endl;
    
    if (!results.failures.empty()) {
        std::cout << "  Failed Tests:" << std::endl;
        for (const auto& failure : results.failures) {
            std::cout << "    - " << failure << std::endl;
        }
    }
    
    std::cout << std::endl;
    std::cout << "========================================================================" << std::endl;
    std::cout << "  Note: Tests validate scheduler interface and logic." << std::endl;
    std::cout << "        Actual GPU detection requires HIP/Vulkan runtime." << std::endl;
    std::cout << "========================================================================" << std::endl;
    
    return results.failed > 0 ? 1 : 0;
}
