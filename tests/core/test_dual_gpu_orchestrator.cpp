// Dual GPU Orchestrator Tests
// Comprehensive test suite for multi-GPU support

#include <gtest/gtest.h>
#include "core/dual_gpu_orchestrator.hpp"
#include <thread>
#include <chrono>

using namespace RawrXD::GPU;

class DualGPUOrchestratorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize if GPUs are available
        orchestrator_ = &DualGPUOrchestrator::Instance();
    }
    
    void TearDown() override {
        if (orchestrator_->IsInitialized()) {
            orchestrator_->Shutdown();
        }
    }
    
    DualGPUOrchestrator* orchestrator_;
};

TEST_F(DualGPUOrchestratorTest, InitializeAndShutdown) {
    bool initialized = orchestrator_->Initialize();
    
    // Should initialize even if no GPUs (falls back to CPU mode)
    EXPECT_TRUE(initialized);
    EXPECT_TRUE(orchestrator_->IsInitialized());
    
    orchestrator_->Shutdown();
    EXPECT_FALSE(orchestrator_->IsInitialized());
}

TEST_F(DualGPUOrchestratorTest, GetDeviceInfo) {
    orchestrator_->Initialize();
    
    auto devices = orchestrator_->GetDeviceInfo();
    
    // Should return at least 0 devices (even if no GPUs)
    EXPECT_GE(devices.size(), 0);
    
    for (const auto& device : devices) {
        EXPECT_FALSE(device.name.empty());
        EXPECT_GE(device.device_id, 0);
    }
}

TEST_F(DualGPUOrchestratorTest, GetDeviceCount) {
    orchestrator_->Initialize();
    
    size_t count = orchestrator_->GetDeviceCount();
    EXPECT_GE(count, 0);
}

TEST_F(DualGPUOrchestratorTest, SetLoadBalanceStrategy) {
    orchestrator_->Initialize();
    
    // Test all strategies
    orchestrator_->SetLoadBalanceStrategy(LoadBalanceStrategy::ROUND_ROBIN);
    EXPECT_EQ(orchestrator_->GetLoadBalanceStrategy(), LoadBalanceStrategy::ROUND_ROBIN);
    
    orchestrator_->SetLoadBalanceStrategy(LoadBalanceStrategy::MEMORY_BASED);
    EXPECT_EQ(orchestrator_->GetLoadBalanceStrategy(), LoadBalanceStrategy::MEMORY_BASED);
    
    orchestrator_->SetLoadBalanceStrategy(LoadBalanceStrategy::PERFORMANCE_BASED);
    EXPECT_EQ(orchestrator_->GetLoadBalanceStrategy(), LoadBalanceStrategy::PERFORMANCE_BASED);
    
    orchestrator_->SetLoadBalanceStrategy(LoadBalanceStrategy::TASK_SPECIFIC);
    EXPECT_EQ(orchestrator_->GetLoadBalanceStrategy(), LoadBalanceStrategy::TASK_SPECIFIC);
}

TEST_F(DualGPUOrchestratorTest, SelectDeviceForWork) {
    orchestrator_->Initialize();
    
    GPUWorkItem work;
    work.type = GPUWorkType::INFERENCE;
    
    int device = orchestrator_->SelectDeviceForWork(work);
    
    // Should return valid device index
    EXPECT_GE(device, 0);
}

TEST_F(DualGPUOrchestratorTest, SubmitWork) {
    orchestrator_->Initialize();
    
    GPUWorkItem work;
    work.type = GPUWorkType::MEMORY_COPY;
    work.preferred_device = 0;
    
    // Should not throw
    EXPECT_NO_THROW(orchestrator_->SubmitWork(work));
}

TEST_F(DualGPUOrchestratorTest, SubmitWorkAsync) {
    orchestrator_->Initialize();
    
    GPUWorkItem work;
    work.type = GPUWorkType::MEMORY_COPY;
    work.preferred_device = 0;
    
    auto future = orchestrator_->SubmitWorkAsync(work);
    
    // Wait for completion (with timeout)
    auto status = future.wait_for(std::chrono::seconds(5));
    EXPECT_NE(status, std::future_status::timeout);
}

TEST_F(DualGPUOrchestratorTest, GetPerformanceMetrics) {
    orchestrator_->Initialize();
    
    auto metrics = orchestrator_->GetPerformanceMetrics(0);
    
    EXPECT_EQ(metrics.device_id, 0);
    // Other metrics depend on actual GPU usage
}

TEST_F(DualGPUOrchestratorTest, GetAllPerformanceMetrics) {
    orchestrator_->Initialize();
    
    auto all_metrics = orchestrator_->GetAllPerformanceMetrics();
    
    size_t device_count = orchestrator_->GetDeviceCount();
    EXPECT_EQ(all_metrics.size(), device_count);
}

TEST_F(DualGPUOrchestratorTest, SynchronizeAll) {
    orchestrator_->Initialize();
    
    // Should not throw
    EXPECT_NO_THROW(orchestrator_->SynchronizeAll());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
