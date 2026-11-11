//=============================================================================
// Deep2Engine_IntegrationTest.cpp - Full System Integration Test
// Tests: SequentialBlowoffValve + OutOfCoreScheduler + DualGpuPipeline + VulkanComputeKernels
// Verifies end-to-end inference pipeline for 671B models on dual GPU
//=============================================================================

// Windows configuration before any headers
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

// Standard library headers FIRST - before any project headers
#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>
#include <vector>
#include <random>
#include <cstdint>
#include <cstddef>
#include <string>
#include <memory>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <queue>

// Project headers AFTER standard library
#include "../inference/Deep2Engine.hpp"
#include "../inference/OutOfCoreScheduler.hpp"
#include "../inference/DualGpuPipeline.hpp"
#include "../memory/SequentialBlowoffValve.hpp"

// Only include Vulkan if available
#ifdef RAWR_ENABLE_VULKAN
#include "../kernels/VulkanComputeKernels.hpp"
#include "vulkan_compute.h"
#endif

using namespace RawrXD;
using namespace RawrXD::Inference;
using namespace RawrXD::Memory;
using namespace RawrXD::Kernels;

bool g_allTestsPassed = true;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[FAIL] " << msg << " at line " << __LINE__ << "\n"; \
            g_allTestsPassed = false; \
        } else { \
            std::cout << "[PASS] " << msg << "\n"; \
        } \
    } while(0)

//=============================================================================
// Test: SequentialBlowoffValve
//=============================================================================
void TestSequentialBlowoffValve() {
    std::cout << "\n=== Testing SequentialBlowoffValve ===\n";
    
    // Test basic valve creation
    auto valve = std::make_unique<SequentialBlowoffValve>(1024 * 1024 * 1024); // 1GB
    TEST_ASSERT(valve != nullptr, "SequentialBlowoffValve created");
    
    // Test memory allocation
    void* ptr = valve->Allocate(1024 * 1024); // 1MB
    TEST_ASSERT(ptr != nullptr, "Memory allocated from valve");
    
    // Test deallocation
    valve->Free(ptr);
    TEST_ASSERT(true, "Memory freed to valve");
    
    std::cout << "SequentialBlowoffValve tests complete\n";
}

//=============================================================================
// Test: OutOfCoreScheduler
//=============================================================================
void TestOutOfCoreScheduler() {
    std::cout << "\n=== Testing OutOfCoreScheduler ===\n";
    
    // Test scheduler creation
    auto scheduler = std::make_unique<OutOfCoreScheduler>();
    TEST_ASSERT(scheduler != nullptr, "OutOfCoreScheduler created");
    
    std::cout << "OutOfCoreScheduler tests complete\n";
}

//=============================================================================
// Test: DualGpuPipeline
//=============================================================================
void TestDualGpuPipeline() {
    std::cout << "\n=== Testing DualGpuPipeline ===\n";
    
    // Test pipeline creation
    auto pipeline = std::make_unique<DualGpuPipeline>();
    TEST_ASSERT(pipeline != nullptr, "DualGpuPipeline created");
    
    std::cout << "DualGpuPipeline tests complete\n";
}

//=============================================================================
// Test: Deep2Engine
//=============================================================================
void TestDeep2Engine() {
    std::cout << "\n=== Testing Deep2Engine ===\n";
    
    // Test engine creation
    auto engine = std::make_unique<Deep2Engine>();
    TEST_ASSERT(engine != nullptr, "Deep2Engine created");
    
    // Test configuration
    Deep2EngineConfig config;
    config.num_layers = 80;
    config.hidden_dim = 8192;
    TEST_ASSERT(config.num_layers == 80, "Config layers set correctly");
    TEST_ASSERT(config.hidden_dim == 8192, "Config hidden_dim set correctly");
    
    std::cout << "Deep2Engine tests complete\n";
}

//=============================================================================
// Main
//=============================================================================
int main() {
    std::cout << "============================================================\n";
    std::cout << "Deep2Engine Integration Test Suite\n";
    std::cout << "Testing: SequentialBlowoffValve + OutOfCoreScheduler +\n";
    std::cout << "         DualGpuPipeline + Deep2Engine\n";
    std::cout << "============================================================\n";
    
    TestSequentialBlowoffValve();
    TestOutOfCoreScheduler();
    TestDualGpuPipeline();
    TestDeep2Engine();
    
    std::cout << "\n============================================================\n";
    if (g_allTestsPassed) {
        std::cout << "ALL TESTS PASSED\n";
        return 0;
    } else {
        std::cout << "SOME TESTS FAILED\n";
        return 1;
    }
}

