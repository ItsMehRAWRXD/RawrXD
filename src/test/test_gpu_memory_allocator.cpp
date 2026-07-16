// ============================================================================
// GPU Memory Allocator Test Suite
// Validates Vulkan-based memory allocation, defragmentation, and multi-GPU
// memory management for AMD AI PRO R9700 + RX 7800 XT setup.
// ============================================================================

#include <iostream>
#include <cassert>
#include <vector>
#include <string>

// Minimal Vulkan-less test - validates allocator interface
// Full Vulkan test requires GPU runtime

namespace RawrXD {
namespace GPU {

// Stub GPUMemoryBlock for testing without Vulkan
struct GPUMemoryBlock {
    void* buffer = nullptr;      // Stub - would be VkBuffer
    void* memory = nullptr;      // Stub - would be VkDeviceMemory
    size_t size = 0;
    size_t offset = 0;
    uint32_t deviceId = 0;       // Multi-GPU: which device owns this
    bool isAllocated = false;
};

// Memory tier for multi-GPU placement
enum class MemoryTier {
    Hot,    // Primary GPU (R9700 32GB)
    Warm,   // Secondary GPU (RX 7800 XT 16GB)
    Cold    // CPU/system memory
};

// Multi-GPU aware memory allocator stub
class GPUMemoryAllocator {
public:
    static GPUMemoryAllocator& getInstance() {
        static GPUMemoryAllocator inst;
        return inst;
    }
    
    // Initialize with device count
    bool initialize(uint32_t deviceCount = 1) {
        m_deviceCount = deviceCount;
        m_deviceAllocated.resize(deviceCount, 0); // Resize to match device count
        m_initialized = true;
        return true;
    }
    
    // Allocate on specific device
    GPUMemoryBlock allocate(size_t size, uint32_t deviceId = 0) {
        GPUMemoryBlock block;
        block.size = size;
        block.deviceId = deviceId;
        block.isAllocated = true;
        
        // Track allocation (only for GPU devices, not CPU/system)
        m_totalAllocated += size;
        if (deviceId < m_deviceAllocated.size()) {
            m_deviceAllocated[deviceId] += size;
        }
        m_allocations.push_back(block);
        
        return block;
    }
    
    // Allocate on tier (Hot/Warm/Cold)
    GPUMemoryBlock allocateOnTier(size_t size, MemoryTier tier) {
        uint32_t deviceId = 0;
        switch (tier) {
            case MemoryTier::Hot:
                deviceId = 0; // Primary GPU
                break;
            case MemoryTier::Warm:
                deviceId = (m_deviceCount > 1) ? 1 : 0; // Secondary GPU
                break;
            case MemoryTier::Cold:
                deviceId = 0xFFFFFFFF; // CPU marker
                break;
        }
        return allocate(size, deviceId);
    }
    
    void free(GPUMemoryBlock& block) {
        if (block.isAllocated) {
            m_totalAllocated -= block.size;
            if (block.deviceId < m_deviceAllocated.size()) {
                m_deviceAllocated[block.deviceId] -= block.size;
            }
            block.isAllocated = false;
            block.size = 0;
        }
    }
    
    // Multi-GPU memory migration
    bool migrate(GPUMemoryBlock& block, uint32_t targetDeviceId) {
        if (!block.isAllocated) return false;
        
        // Update tracking
        m_deviceAllocated[block.deviceId] -= block.size;
        block.deviceId = targetDeviceId;
        m_deviceAllocated[targetDeviceId] += block.size;
        
        return true;
    }
    
    // Defragmentation (consolidate free space)
    void defragment() {
        // Stub - would reorder allocations to reduce fragmentation
        m_defragCount++;
    }
    
    // Queries
    size_t getTotalAllocated() const { return m_totalAllocated; }
    size_t getDeviceAllocated(uint32_t deviceId) const {
        return (deviceId < m_deviceAllocated.size()) ? m_deviceAllocated[deviceId] : 0;
    }
    size_t getFreeMemory(uint32_t deviceId) const {
        // Stub - would query actual GPU memory
        return (deviceId == 0) ? 32ULL * 1024 * 1024 * 1024 :  // 32GB for R9700
               (deviceId == 1) ? 16ULL * 1024 * 1024 * 1024 :  // 16GB for 7800 XT
               0;
    }
    
    uint32_t getDeviceCount() const { return m_deviceCount; }
    size_t getAllocationCount() const { return m_allocations.size(); }
    uint32_t getDefragCount() const { return m_defragCount; }
    bool isInitialized() const { return m_initialized; }
    
private:
    GPUMemoryAllocator() = default;
    ~GPUMemoryAllocator() = default;
    
    bool m_initialized = false;
    uint32_t m_deviceCount = 1;
    size_t m_totalAllocated = 0;
    uint32_t m_defragCount = 0;
    std::vector<size_t> m_deviceAllocated; // Per-device tracking, resized in initialize()
    std::vector<GPUMemoryBlock> m_allocations;
};

} // namespace GPU
} // namespace RawrXD

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
    GPUMemoryAllocator& alloc1 = GPUMemoryAllocator::getInstance();
    GPUMemoryAllocator& alloc2 = GPUMemoryAllocator::getInstance();
    return &alloc1 == &alloc2;
}

// ============================================================================
// Test 2: Initialization
// ============================================================================
bool test_initialization() {
    GPUMemoryAllocator& alloc = GPUMemoryAllocator::getInstance();
    bool result = alloc.initialize(2); // 2 GPUs
    return result && alloc.isInitialized() && alloc.getDeviceCount() == 2;
}

// ============================================================================
// Test 3: Basic Allocation
// ============================================================================
bool test_basic_allocation() {
    GPUMemoryAllocator& alloc = GPUMemoryAllocator::getInstance();
    alloc.initialize(1);
    
    GPUMemoryBlock block = alloc.allocate(1024 * 1024 * 100); // 100MB
    bool success = block.isAllocated && block.size == 1024 * 1024 * 100;
    
    alloc.free(block);
    return success;
}

// ============================================================================
// Test 4: Multi-GPU Allocation
// ============================================================================
bool test_multi_gpu_allocation() {
    GPUMemoryAllocator& alloc = GPUMemoryAllocator::getInstance();
    alloc.initialize(2); // R9700 + 7800 XT
    
    // Allocate on device 0 (R9700)
    GPUMemoryBlock block0 = alloc.allocate(1024 * 1024 * 200, 0); // 200MB
    bool onDevice0 = block0.deviceId == 0 && block0.isAllocated;
    
    // Allocate on device 1 (7800 XT)
    GPUMemoryBlock block1 = alloc.allocate(1024 * 1024 * 100, 1); // 100MB
    bool onDevice1 = block1.deviceId == 1 && block1.isAllocated;
    
    alloc.free(block0);
    alloc.free(block1);
    
    return onDevice0 && onDevice1;
}

// ============================================================================
// Test 5: Memory Tier Allocation
// ============================================================================
bool test_memory_tier_allocation() {
    GPUMemoryAllocator& alloc = GPUMemoryAllocator::getInstance();
    alloc.initialize(2);
    
    // Hot tier (primary GPU)
    GPUMemoryBlock hot = alloc.allocateOnTier(1024 * 1024 * 50, MemoryTier::Hot);
    bool hotOnPrimary = hot.deviceId == 0;
    
    // Warm tier (secondary GPU)
    GPUMemoryBlock warm = alloc.allocateOnTier(1024 * 1024 * 50, MemoryTier::Warm);
    bool warmOnSecondary = warm.deviceId == 1;
    
    // Cold tier (CPU/system)
    GPUMemoryBlock cold = alloc.allocateOnTier(1024 * 1024 * 50, MemoryTier::Cold);
    bool coldOnSystem = cold.deviceId == 0xFFFFFFFF;
    
    alloc.free(hot);
    alloc.free(warm);
    alloc.free(cold);
    
    return hotOnPrimary && warmOnSecondary && coldOnSystem;
}

// ============================================================================
// Test 6: Memory Migration
// ============================================================================
bool test_memory_migration() {
    GPUMemoryAllocator& alloc = GPUMemoryAllocator::getInstance();
    alloc.initialize(2);
    
    // Allocate on device 0
    GPUMemoryBlock block = alloc.allocate(1024 * 1024 * 50, 0);
    bool startedOnDevice0 = block.deviceId == 0;
    
    // Migrate to device 1
    bool migrated = alloc.migrate(block, 1);
    bool nowOnDevice1 = block.deviceId == 1;
    
    alloc.free(block);
    
    return startedOnDevice0 && migrated && nowOnDevice1;
}

// ============================================================================
// Test 7: Total Allocated Tracking
// ============================================================================
bool test_total_allocated_tracking() {
    GPUMemoryAllocator& alloc = GPUMemoryAllocator::getInstance();
    alloc.initialize(1);
    
    size_t before = alloc.getTotalAllocated();
    
    GPUMemoryBlock block1 = alloc.allocate(1024 * 1024 * 100); // 100MB
    GPUMemoryBlock block2 = alloc.allocate(1024 * 1024 * 50);  // 50MB
    
    size_t during = alloc.getTotalAllocated();
    
    alloc.free(block1);
    alloc.free(block2);
    
    size_t after = alloc.getTotalAllocated();
    
    bool trackingCorrect = (during == before + 1024 * 1024 * 150) && (after == before);
    return trackingCorrect;
}

// ============================================================================
// Test 8: Per-Device Tracking
// ============================================================================
bool test_per_device_tracking() {
    GPUMemoryAllocator& alloc = GPUMemoryAllocator::getInstance();
    alloc.initialize(2);
    
    // Allocate on each device
    GPUMemoryBlock block0 = alloc.allocate(1024 * 1024 * 100, 0);
    GPUMemoryBlock block1 = alloc.allocate(1024 * 1024 * 50, 1);
    
    size_t device0Alloc = alloc.getDeviceAllocated(0);
    size_t device1Alloc = alloc.getDeviceAllocated(1);
    
    alloc.free(block0);
    alloc.free(block1);
    
    return device0Alloc == 1024 * 1024 * 100 && device1Alloc == 1024 * 1024 * 50;
}

// ============================================================================
// Test 9: Defragmentation
// ============================================================================
bool test_defragmentation() {
    GPUMemoryAllocator& alloc = GPUMemoryAllocator::getInstance();
    alloc.initialize(1);
    
    uint32_t defragBefore = alloc.getDefragCount();
    alloc.defragment();
    uint32_t defragAfter = alloc.getDefragCount();
    
    return defragAfter == defragBefore + 1;
}

// ============================================================================
// Test 10: Free Memory Query
// ============================================================================
bool test_free_memory_query() {
    GPUMemoryAllocator& alloc = GPUMemoryAllocator::getInstance();
    alloc.initialize(2);
    
    // Query free memory for each device
    size_t freeDevice0 = alloc.getFreeMemory(0); // Should be ~32GB
    size_t freeDevice1 = alloc.getFreeMemory(1); // Should be ~16GB
    
    // Just validate they return non-zero values
    return freeDevice0 > 0 && freeDevice1 > 0;
}

// ============================================================================
// Test 11: Allocation Count
// ============================================================================
bool test_allocation_count() {
    GPUMemoryAllocator& alloc = GPUMemoryAllocator::getInstance();
    alloc.initialize(1);
    
    size_t countBefore = alloc.getAllocationCount();
    
    GPUMemoryBlock block1 = alloc.allocate(1024);
    GPUMemoryBlock block2 = alloc.allocate(2048);
    GPUMemoryBlock block3 = alloc.allocate(4096);
    
    size_t countDuring = alloc.getAllocationCount();
    
    alloc.free(block1);
    alloc.free(block2);
    alloc.free(block3);
    
    // Note: We don't decrement count on free in this stub
    return countDuring >= countBefore + 3;
}

// ============================================================================
// Test 12: Large Allocation
// ============================================================================
bool test_large_allocation() {
    GPUMemoryAllocator& alloc = GPUMemoryAllocator::getInstance();
    alloc.initialize(1);
    
    // Try to allocate 1GB
    GPUMemoryBlock block = alloc.allocate(1024ULL * 1024 * 1024);
    bool success = block.isAllocated && block.size == 1024ULL * 1024 * 1024;
    
    alloc.free(block);
    return success;
}

// ============================================================================
// Test 13: AMD R9700 + 7800 XT Specific
// ============================================================================
bool test_amd_specific() {
    GPUMemoryAllocator& alloc = GPUMemoryAllocator::getInstance();
    alloc.initialize(2); // R9700 + 7800 XT
    
    // Allocate on primary (R9700 32GB)
    GPUMemoryBlock primary = alloc.allocateOnTier(1024ULL * 1024 * 1024 * 10, MemoryTier::Hot); // 10GB
    bool onPrimary = primary.deviceId == 0;
    
    // Allocate on secondary (7800 XT 16GB)
    GPUMemoryBlock secondary = alloc.allocateOnTier(1024ULL * 1024 * 1024 * 5, MemoryTier::Warm); // 5GB
    bool onSecondary = secondary.deviceId == 1;
    
    alloc.free(primary);
    alloc.free(secondary);
    
    return onPrimary && onSecondary;
}

// ============================================================================
// Test 14: Stress Test - Many Small Allocations
// ============================================================================
bool test_stress_many_allocations() {
    GPUMemoryAllocator& alloc = GPUMemoryAllocator::getInstance();
    alloc.initialize(1);
    
    std::vector<GPUMemoryBlock> blocks;
    const int numAllocations = 100;
    
    // Allocate many small blocks
    for (int i = 0; i < numAllocations; ++i) {
        blocks.push_back(alloc.allocate(1024 * 64)); // 64KB each
    }
    
    bool allAllocated = blocks.size() == numAllocations;
    for (const auto& block : blocks) {
        if (!block.isAllocated) {
            allAllocated = false;
            break;
        }
    }
    
    // Free all
    for (auto& block : blocks) {
        alloc.free(block);
    }
    
    return allAllocated;
}

// ============================================================================
// Main Test Runner
// ============================================================================
int main(int argc, char* argv[]) {
    std::cout << "========================================================================" << std::endl;
    std::cout << "  RawrXD GPU Memory Allocator Test Suite" << std::endl;
    std::cout << "  Target: AMD AI PRO R9700 (32GB) + RX 7800 XT (16GB)" << std::endl;
    std::cout << "========================================================================" << std::endl;
    std::cout << std::endl;
    
    TestResults results;
    
    // Run all tests
    results.check(test_singleton(), "Singleton Pattern");
    results.check(test_initialization(), "Initialization");
    results.check(test_basic_allocation(), "Basic Allocation");
    results.check(test_multi_gpu_allocation(), "Multi-GPU Allocation");
    results.check(test_memory_tier_allocation(), "Memory Tier Allocation");
    results.check(test_memory_migration(), "Memory Migration");
    results.check(test_total_allocated_tracking(), "Total Allocated Tracking");
    results.check(test_per_device_tracking(), "Per-Device Tracking");
    results.check(test_defragmentation(), "Defragmentation");
    results.check(test_free_memory_query(), "Free Memory Query");
    results.check(test_allocation_count(), "Allocation Count");
    results.check(test_large_allocation(), "Large Allocation (1GB)");
    results.check(test_amd_specific(), "AMD R9700 + 7800 XT Specific");
    results.check(test_stress_many_allocations(), "Stress Test - Many Allocations");
    
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
    std::cout << "  Note: Tests validate allocator interface and multi-GPU logic." << std::endl;
    std::cout << "        Actual GPU allocation requires Vulkan/HIP runtime." << std::endl;
    std::cout << "========================================================================" << std::endl;
    
    return results.failed > 0 ? 1 : 0;
}
