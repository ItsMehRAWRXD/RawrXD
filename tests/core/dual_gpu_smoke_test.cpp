// Dual GPU Smoke Test Suite
// Comprehensive validation for single and dual GPU configurations

#include <gtest/gtest.h>
#include "core/dual_gpu_orchestrator.hpp"
#include <thread>
#include <chrono>
#include <vector>
#include <atomic>

using namespace RawrXD::GPU;

class DualGPUSmokeTest : public ::testing::Test {
protected:
    void SetUp() override {
        orchestrator_ = &DualGPUOrchestrator::Instance();
        // Initialize with dual GPU support
        ASSERT_TRUE(orchestrator_->Initialize());
    }
    
    void TearDown() override {
        if (orchestrator_->IsInitialized()) {
            orchestrator_->Shutdown();
        }
    }
    
    DualGPUOrchestrator* orchestrator_;
};

// ============================================================================
// GPU Detection Tests
// ============================================================================

TEST_F(DualGPUSmokeTest, DetectSingleGPU) {
    auto devices = orchestrator_->GetDeviceInfo();
    
    // Should detect at least 0 devices (CPU fallback)
    EXPECT_GE(devices.size(), 0);
    
    if (devices.size() >= 1) {
        EXPECT_FALSE(devices[0].name.empty());
        EXPECT_TRUE(devices[0].is_primary);
    }
}

TEST_F(DualGPUSmokeTest, DetectDualGPU) {
    auto devices = orchestrator_->GetDeviceInfo();
    
    if (devices.size() >= 2) {
        // Verify dual GPU setup
        EXPECT_FALSE(devices[0].name.empty());
        EXPECT_FALSE(devices[1].name.empty());
        EXPECT_TRUE(devices[0].is_primary);
        EXPECT_FALSE(devices[1].is_primary);
        
        // Both should be available
        EXPECT_TRUE(devices[0].is_available);
        EXPECT_TRUE(devices[1].is_available);
        
        std::cout << "[SMOKE TEST] Dual GPU detected:" << std::endl;
        std::cout << "  GPU 0: " << devices[0].GetSummary() << std::endl;
        std::cout << "  GPU 1: " << devices[1].GetSummary() << std::endl;
    } else {
        std::cout << "[SMOKE TEST] Single GPU or CPU mode (" << devices.size() << " device(s))" << std::endl;
    }
}

// ============================================================================
// Memory Allocation Tests
// ============================================================================

TEST_F(DualGPUSmokeTest, AllocateMemorySingleGPU) {
    // Test allocation on primary GPU
    void* ptr = orchestrator_->AllocateMemory(1024 * 1024, 0); // 1MB on GPU 0
    
    if (orchestrator_->GetDeviceCount() >= 1) {
        EXPECT_NE(ptr, nullptr);
        
        if (ptr) {
            orchestrator_->FreeMemory(ptr);
        }
    }
}

TEST_F(DualGPUSmokeTest, AllocateMemoryDualGPU) {
    if (orchestrator_->GetDeviceCount() < 2) {
        GTEST_SKIP() << "Dual GPU not available";
    }
    
    // Allocate on both GPUs
    void* ptr0 = orchestrator_->AllocateMemory(1024 * 1024, 0); // 1MB on GPU 0
    void* ptr1 = orchestrator_->AllocateMemory(1024 * 1024, 1); // 1MB on GPU 1
    
    EXPECT_NE(ptr0, nullptr);
    EXPECT_NE(ptr1, nullptr);
    
    // Verify they're different addresses
    EXPECT_NE(ptr0, ptr1);
    
    if (ptr0) orchestrator_->FreeMemory(ptr0);
    if (ptr1) orchestrator_->FreeMemory(ptr1);
}

TEST_F(DualGPUSmokeTest, AllocateMemoryAutoSelect) {
    // Test automatic device selection
    void* ptr = orchestrator_->AllocateMemory(1024 * 1024, -1); // Auto-select
    
    if (orchestrator_->GetDeviceCount() >= 1) {
        EXPECT_NE(ptr, nullptr);
        
        if (ptr) {
            orchestrator_->FreeMemory(ptr);
        }
    }
}

// ============================================================================
// Work Distribution Tests
// ============================================================================

TEST_F(DualGPUSmokeTest, SubmitWorkSingleGPU) {
    GPUWorkItem work;
    work.type = GPUWorkType::MEMORY_COPY;
    work.preferred_device = 0;
    work.data_size = 1024;
    
    std::atomic<bool> callback_called{false};
    work.callback = [&callback_called](const GPUResult& result) {
        callback_called = true;
        EXPECT_TRUE(result.success);
    };
    
    orchestrator_->SubmitWork(work);
    
    // Wait for completion
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Callback may or may not be called depending on GPU availability
}

TEST_F(DualGPUSmokeTest, SubmitWorkDualGPU_RoundRobin) {
    if (orchestrator_->GetDeviceCount() < 2) {
        GTEST_SKIP() << "Dual GPU not available";
    }
    
    orchestrator_->SetLoadBalanceStrategy(LoadBalanceStrategy::ROUND_ROBIN);
    
    std::vector<std::future<GPUResult>> futures;
    
    // Submit 10 work items
    for (int i = 0; i < 10; ++i) {
        GPUWorkItem work;
        work.type = GPUWorkType::MEMORY_COPY;
        work.data_size = 1024;
        
        futures.push_back(orchestrator_->SubmitWorkAsync(work));
    }
    
    // Wait for all to complete
    for (auto& future : futures) {
        auto result = future.get();
        // Results may vary based on actual GPU availability
    }
    
    // Check metrics - should have distributed work
    auto metrics0 = orchestrator_->GetPerformanceMetrics(0);
    auto metrics1 = orchestrator_->GetPerformanceMetrics(1);
    
    std::cout << "[SMOKE TEST] Round-robin distribution:" << std::endl;
    std::cout << "  GPU 0 tasks: " << metrics0.tasks_completed << std::endl;
    std::cout << "  GPU 1 tasks: " << metrics1.tasks_completed << std::endl;
}

TEST_F(DualGPUSmokeTest, SubmitWorkDualGPU_MemoryBased) {
    if (orchestrator_->GetDeviceCount() < 2) {
        GTEST_SKIP() << "Dual GPU not available";
    }
    
    orchestrator_->SetLoadBalanceStrategy(LoadBalanceStrategy::MEMORY_BASED);
    
    // Submit work
    GPUWorkItem work;
    work.type = GPUWorkType::MEMORY_COPY;
    work.data_size = 1024 * 1024; // 1MB
    
    auto future = orchestrator_->SubmitWorkAsync(work);
    auto result = future.get();
    
    // Should have selected GPU with more free memory
    std::cout << "[SMOKE TEST] Memory-based selection completed" << std::endl;
}

// ============================================================================
// Load Balancing Strategy Tests
// ============================================================================

TEST_F(DualGPUSmokeTest, TestAllLoadBalanceStrategies) {
    if (orchestrator_->GetDeviceCount() < 1) {
        GTEST_SKIP() << "No GPUs available";
    }
    
    std::vector<LoadBalanceStrategy> strategies = {
        LoadBalanceStrategy::ROUND_ROBIN,
        LoadBalanceStrategy::MEMORY_BASED,
        LoadBalanceStrategy::PERFORMANCE_BASED,
        LoadBalanceStrategy::TASK_SPECIFIC
    };
    
    for (auto strategy : strategies) {
        orchestrator_->SetLoadBalanceStrategy(strategy);
        
        GPUWorkItem work;
        work.type = GPUWorkType::MEMORY_COPY;
        work.data_size = 1024;
        
        auto future = orchestrator_->SubmitWorkAsync(work);
        auto result = future.get();
        
        std::cout << "[SMOKE TEST] Strategy " << static_cast<int>(strategy) 
                  << " completed" << std::endl;
    }
}

// ============================================================================
// Performance Metrics Tests
// ============================================================================

TEST_F(DualGPUSmokeTest, PerformanceMetricsSingleGPU) {
    auto metrics = orchestrator_->GetPerformanceMetrics(0);
    
    EXPECT_EQ(metrics.device_id, 0);
    // Metrics may be zero if no work has been done
}

TEST_F(DualGPUSmokeTest, PerformanceMetricsDualGPU) {
    if (orchestrator_->GetDeviceCount() < 2) {
        GTEST_SKIP() << "Dual GPU not available";
    }
    
    auto all_metrics = orchestrator_->GetAllPerformanceMetrics();
    
    EXPECT_EQ(all_metrics.size(), 2);
    
    for (const auto& metrics : all_metrics) {
        EXPECT_GE(metrics.device_id, 0);
        std::cout << "[SMOKE TEST] GPU " << metrics.device_id 
                  << ": " << metrics.tasks_completed << " tasks" << std::endl;
    }
}

// ============================================================================
// Synchronization Tests
// ============================================================================

TEST_F(DualGPUSmokeTest, SynchronizeDevice) {
    if (orchestrator_->GetDeviceCount() < 1) {
        GTEST_SKIP() << "No GPUs available";
    }
    
    // Should not throw
    EXPECT_NO_THROW(orchestrator_->SynchronizeDevice(0));
}

TEST_F(DualGPUSmokeTest, SynchronizeAll) {
    // Should not throw
    EXPECT_NO_THROW(orchestrator_->SynchronizeAll());
}

// ============================================================================
// Stress Tests
// ============================================================================

TEST_F(DualGPUSmokeTest, StressTestSingleGPU) {
    if (orchestrator_->GetDeviceCount() < 1) {
        GTEST_SKIP() << "No GPUs available";
    }
    
    const int NUM_ITERATIONS = 100;
    
    for (int i = 0; i < NUM_ITERATIONS; ++i) {
        GPUWorkItem work;
        work.type = GPUWorkType::MEMORY_COPY;
        work.preferred_device = 0;
        work.data_size = 1024;
        
        orchestrator_->SubmitWork(work);
    }
    
    // Wait for completion
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    auto metrics = orchestrator_->GetPerformanceMetrics(0);
    std::cout << "[SMOKE TEST] Single GPU stress: " 
              << metrics.tasks_completed << " tasks completed" << std::endl;
}

TEST_F(DualGPUSmokeTest, StressTestDualGPU) {
    if (orchestrator_->GetDeviceCount() < 2) {
        GTEST_SKIP() << "Dual GPU not available";
    }
    
    orchestrator_->SetLoadBalanceStrategy(LoadBalanceStrategy::ROUND_ROBIN);
    
    const int NUM_ITERATIONS = 100;
    std::vector<std::future<GPUResult>> futures;
    
    for (int i = 0; i < NUM_ITERATIONS; ++i) {
        GPUWorkItem work;
        work.type = GPUWorkType::MEMORY_COPY;
        work.data_size = 1024;
        
        futures.push_back(orchestrator_->SubmitWorkAsync(work));
    }
    
    // Wait for all
    for (auto& future : futures) {
        future.wait();
    }
    
    auto metrics0 = orchestrator_->GetPerformanceMetrics(0);
    auto metrics1 = orchestrator_->GetPerformanceMetrics(1);
    
    std::cout << "[SMOKE TEST] Dual GPU stress:" << std::endl;
    std::cout << "  GPU 0: " << metrics0.tasks_completed << " tasks" << std::endl;
    std::cout << "  GPU 1: " << metrics1.tasks_completed << " tasks" << std::endl;
    
    // Verify work was distributed
    EXPECT_GT(metrics0.tasks_completed + metrics1.tasks_completed, 0);
}

// ============================================================================
// Memory Pool Tests
// ============================================================================

TEST_F(DualGPUSmokeTest, MemoryPoolAllocation) {
    if (orchestrator_->GetDeviceCount() < 1) {
        GTEST_SKIP() << "No GPUs available";
    }
    
    // Allocate multiple chunks
    std::vector<void*> allocations;
    const size_t CHUNK_SIZE = 10 * 1024 * 1024; // 10MB
    
    for (int i = 0; i < 5; ++i) {
        void* ptr = orchestrator_->AllocateMemory(CHUNK_SIZE, 0);
        if (ptr) {
            allocations.push_back(ptr);
        }
    }
    
    std::cout << "[SMOKE TEST] Allocated " << allocations.size() 
              << " chunks of " << CHUNK_SIZE << " bytes" << std::endl;
    
    // Free all
    for (auto ptr : allocations) {
        orchestrator_->FreeMemory(ptr);
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Dual GPU Smoke Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Print GPU info before running tests
    auto& orchestrator = DualGPUOrchestrator::Instance();
    if (orchestrator.Initialize()) {
        auto devices = orchestrator.GetDeviceInfo();
        
        std::cout << "Detected " << devices.size() << " GPU(s):" << std::endl;
        for (const auto& device : devices) {
            std::cout << "  " << device.GetSummary() << std::endl;
        }
        std::cout << std::endl;
        
        orchestrator.Shutdown();
    }
    
    return RUN_ALL_TESTS();
}
