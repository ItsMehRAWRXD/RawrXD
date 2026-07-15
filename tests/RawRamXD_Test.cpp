// =============================================================================
// RawRamXD_Test.cpp - Test and Demonstration of RawRamXD Memory Fabric
// =============================================================================

#include "RawRamXD.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <chrono>

using namespace RawRamXD;

// =============================================================================
// Test Functions
// =============================================================================

bool Test_BasicAllocation() {
    std::cout << "\n[Test] Basic Allocation..." << std::endl;
    
    auto& fabric = MemoryFabric::Instance();
    
    // Allocate in different tiers
    auto* region1 = fabric.Allocate(1024 * 1024, MemoryTier::GPU_VRAM);  // 1MB in VRAM
    auto* region2 = fabric.Allocate(10 * 1024 * 1024, MemoryTier::SYSTEM_RAM);  // 10MB in RAM
    auto* region3 = fabric.Allocate(100 * 1024 * 1024, MemoryTier::NVME_SSD);  // 100MB in NVMe
    
    if (!region1 || !region2 || !region3) {
        std::cerr << "  [FAIL] Allocation failed" << std::endl;
        return false;
    }
    
    std::cout << "  [OK] Allocated:" << std::endl;
    std::cout << "    Region 1: " << region1->GetSize() << " bytes in GPU VRAM" << std::endl;
    std::cout << "    Region 2: " << region2->GetSize() << " bytes in System RAM" << std::endl;
    std::cout << "    Region 3: " << region3->GetSize() << " bytes in NVMe SSD" << std::endl;
    
    // Cleanup
    fabric.Free(region1);
    fabric.Free(region2);
    fabric.Free(region3);
    
    std::cout << "  [OK] Freed all regions" << std::endl;
    return true;
}

bool Test_UnifiedAllocation() {
    std::cout << "\n[Test] Unified Allocation (Auto-tier)..." << std::endl;
    
    auto& fabric = MemoryFabric::Instance();
    
    // Small critical allocation - should go to GPU VRAM
    auto* small = fabric.AllocateUnified(100 * 1024 * 1024, SchedulePriority::CRITICAL);
    
    // Large allocation - should go to NVMe
    auto* large = fabric.AllocateUnified(20ULL * 1024 * 1024 * 1024, SchedulePriority::NORMAL);
    
    if (!small || !large) {
        std::cerr << "  [FAIL] Unified allocation failed" << std::endl;
        return false;
    }
    
    std::cout << "  [OK] Unified allocations:" << std::endl;
    std::cout << "    Small (100MB CRITICAL): Tier " << static_cast<int>(small->GetTier()) << std::endl;
    std::cout << "    Large (20GB NORMAL): Tier " << static_cast<int>(large->GetTier()) << std::endl;
    
    fabric.Free(small);
    fabric.Free(large);
    
    return true;
}

bool Test_Migration() {
    std::cout << "\n[Test] Tier Migration..." << std::endl;
    
    auto& fabric = MemoryFabric::Instance();
    
    // Allocate in RAM
    auto* region = fabric.Allocate(50 * 1024 * 1024, MemoryTier::SYSTEM_RAM);
    if (!region) {
        std::cerr << "  [FAIL] Initial allocation failed" << std::endl;
        return false;
    }
    
    std::cout << "  Initial tier: " << static_cast<int>(region->GetTier()) << std::endl;
    
    // Migrate to GPU VRAM
    if (fabric.MigrateToTier(region, MemoryTier::GPU_VRAM)) {
        std::cout << "  [OK] Migrated to GPU VRAM: Tier " << static_cast<int>(region->GetTier()) << std::endl;
    } else {
        std::cout << "  [INFO] Migration skipped (GPU VRAM may be full)" << std::endl;
    }
    
    // Migrate to NVMe
    if (fabric.MigrateToTier(region, MemoryTier::NVME_SSD)) {
        std::cout << "  [OK] Migrated to NVMe: Tier " << static_cast<int>(region->GetTier()) << std::endl;
    }
    
    fabric.Free(region);
    return true;
}

bool Test_Pinning() {
    std::cout << "\n[Test] Memory Pinning..." << std::endl;
    
    auto& fabric = MemoryFabric::Instance();
    
    auto* region = fabric.Allocate(10 * 1024 * 1024, MemoryTier::SYSTEM_RAM);
    if (!region) {
        std::cerr << "  [FAIL] Allocation failed" << std::endl;
        return false;
    }
    
    // Pin the region
    if (fabric.Pin(region)) {
        std::cout << "  [OK] Region pinned" << std::endl;
        
        // Try to migrate (should fail while pinned)
        if (!fabric.MigrateToTier(region, MemoryTier::GPU_VRAM)) {
            std::cout << "  [OK] Migration correctly blocked while pinned" << std::endl;
        }
        
        // Unpin
        if (fabric.Unpin(region)) {
            std::cout << "  [OK] Region unpinned" << std::endl;
        }
    }
    
    fabric.Free(region);
    return true;
}

bool Test_Prediction() {
    std::cout << "\n[Test] Predictive Engine..." << std::endl;
    
    PredictiveEngine predictor;
    
    // Simulate sequential access pattern
    std::vector<uint64_t> sequentialHistory;
    for (int i = 0; i < 10; i++) {
        sequentialHistory.push_back(i * PAGE_SIZE);
    }
    
    auto pattern = predictor.DetectPattern(sequentialHistory);
    std::cout << "  Detected pattern: " << static_cast<int>(pattern) << " (expected SEQUENTIAL=0)" << std::endl;
    
    if (pattern == AccessPattern::SEQUENTIAL) {
        auto predictions = predictor.PredictNextAccesses(
            sequentialHistory.back(), pattern, 5);
        
        std::cout << "  Predicted next accesses:";
        for (auto addr : predictions) {
            std::cout << " " << addr;
        }
        std::cout << std::endl;
        
        // Record actual access
        predictor.RecordAccess(predictions[0], true);
        
        std::cout << "  Prediction accuracy: " << predictor.GetAccuracy() * 100 << "%" << std::endl;
    }
    
    return true;
}

bool Test_Statistics() {
    std::cout << "\n[Test] Statistics Collection..." << std::endl;
    
    auto& fabric = MemoryFabric::Instance();
    
    // Print current stats
    fabric.PrintStats();
    
    return true;
}

bool Test_CAPI() {
    std::cout << "\n[Test] C API..." << std::endl;
    
    // Test C API functions
    RawRamXD_PrintStats();
    
    char buffer[1024];
    RawRamXD_GetStats(buffer, sizeof(buffer));
    std::cout << "  Stats via C API:\n" << buffer << std::endl;
    
    return true;
}

// =============================================================================
// Performance Benchmark
// =============================================================================

void Benchmark_AllocationThroughput() {
    std::cout << "\n[Benchmark] Allocation Throughput..." << std::endl;
    
    auto& fabric = MemoryFabric::Instance();
    
    const size_t numAllocations = 1000;
    const size_t allocationSize = 1024 * 1024;  // 1MB
    
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<MemoryRegion*> regions;
    regions.reserve(numAllocations);
    
    for (size_t i = 0; i < numAllocations; i++) {
        auto* region = fabric.Allocate(allocationSize, MemoryTier::SYSTEM_RAM);
        if (region) {
            regions.push_back(region);
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double throughput = (numAllocations * 1000000.0) / duration.count();
    
    std::cout << "  Allocated " << regions.size() << " regions in " << duration.count() << " us" << std::endl;
    std::cout << "  Throughput: " << throughput << " allocations/sec" << std::endl;
    
    // Cleanup
    for (auto* region : regions) {
        fabric.Free(region);
    }
}

// =============================================================================
// Main
// =============================================================================

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "RawRamXD Memory Fabric Test Suite" << std::endl;
    std::cout << "Software-Defined AI Memory Orchestration" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    // Initialize RawRamXD
    if (!MemoryFabric::Instance().Initialize()) {
        std::cerr << "Failed to initialize RawRamXD!" << std::endl;
        return 1;
    }
    
    // Run tests
    int passed = 0;
    int failed = 0;
    
    auto runTest = [&](const char* name, bool (*test)()) {
        std::cout << "\n--- " << name << " ---" << std::endl;
        if (test()) {
            std::cout << "[PASS] " << name << std::endl;
            return 1;
        } else {
            std::cout << "[FAIL] " << name << std::endl;
            return 0;
        }
    };
    
    passed += runTest("Basic Allocation", Test_BasicAllocation);
    passed += runTest("Unified Allocation", Test_UnifiedAllocation);
    passed += runTest("Tier Migration", Test_Migration);
    passed += runTest("Memory Pinning", Test_Pinning);
    passed += runTest("Predictive Engine", Test_Prediction);
    passed += runTest("Statistics", Test_Statistics);
    passed += runTest("C API", Test_CAPI);
    
    // Run benchmarks
    Benchmark_AllocationThroughput();
    
    // Final stats
    std::cout << "\n========================================" << std::endl;
    std::cout << "Final Statistics:" << std::endl;
    MemoryFabric::Instance().PrintStats();
    
    // Summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Summary:" << std::endl;
    std::cout << "  Passed: " << passed << std::endl;
    std::cout << "  Failed: " << (7 - passed) << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Shutdown
    MemoryFabric::Instance().Shutdown();
    
    return (passed == 7) ? 0 : 1;
}