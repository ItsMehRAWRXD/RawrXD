// VAL-076: Fault Injection Tests
// Resilience validation test suite

#include <gtest/gtest.h>
#include "certification/fault_injection.hpp"
#include <thread>
#include <chrono>

using namespace RawrXD::Certification;

class FaultInjectionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Clear any existing fault points
        auto& registry = FaultRegistry::Instance();
        registry.ClearEvents();
    }
    
    void TearDown() override {
        FaultInjector::Instance().Disable();
    }
};

TEST_F(FaultInjectionTest, FaultRegistry_RegisterAndRetrieve) {
    FaultPoint point;
    point.id = "test_fault";
    point.name = "Test Fault Point";
    point.category = FaultCategory::MEMORY;
    point.severity = FaultSeverity::HIGH;
    point.probability = 0.5;
    point.description = "Test fault for unit testing";
    
    FaultRegistry::Instance().RegisterFaultPoint(point);
    
    auto retrieved = FaultRegistry::Instance().GetFaultPoint("test_fault");
    EXPECT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->id, "test_fault");
    EXPECT_EQ(retrieved->category, FaultCategory::MEMORY);
}

TEST_F(FaultInjectionTest, FaultInjector_EnableDisable) {
    auto& injector = FaultInjector::Instance();
    
    EXPECT_FALSE(injector.IsEnabled());
    
    injector.Enable();
    EXPECT_TRUE(injector.IsEnabled());
    
    injector.Disable();
    EXPECT_FALSE(injector.IsEnabled());
}

TEST_F(FaultInjectionTest, FaultInjector_InjectionProbability) {
    // Register a fault point with 100% probability
    FaultPoint point;
    point.id = "always_inject";
    point.name = "Always Inject";
    point.category = FaultCategory::COMPUTE;
    point.severity = FaultSeverity::CRITICAL;
    point.probability = 1.0;
    point.description = "Always injects";
    
    FaultRegistry::Instance().RegisterFaultPoint(point);
    
    auto& injector = FaultInjector::Instance();
    injector.SetGlobalProbability(1.0);
    injector.Enable();
    
    // Should inject with 100% probability
    bool injected = injector.InjectFault("always_inject");
    EXPECT_TRUE(injected);
    
    // Check event was recorded
    auto events = FaultRegistry::Instance().GetEventsByFaultPoint("always_inject");
    EXPECT_EQ(events.size(), 1);
    EXPECT_TRUE(events[0].injected);
}

TEST_F(FaultInjectionTest, FaultInjector_ZeroProbability) {
    FaultPoint point;
    point.id = "never_inject";
    point.name = "Never Inject";
    point.category = FaultCategory::IO;
    point.severity = FaultSeverity::LOW;
    point.probability = 0.0;
    point.description = "Never injects";
    
    FaultRegistry::Instance().RegisterFaultPoint(point);
    
    auto& injector = FaultInjector::Instance();
    injector.SetGlobalProbability(1.0);
    injector.Enable();
    
    // Should not inject with 0% probability
    bool injected = injector.InjectFault("never_inject");
    EXPECT_FALSE(injected);
}

TEST_F(FaultInjectionTest, ResilienceValidator_RunValidation) {
    // Inject some faults first
    FaultPoint point;
    point.id = "resilience_test";
    point.name = "Resilience Test";
    point.category = FaultCategory::TIMING;
    point.severity = FaultSeverity::MEDIUM;
    point.probability = 1.0;
    point.description = "Test resilience";
    
    FaultRegistry::Instance().RegisterFaultPoint(point);
    
    auto& injector = FaultInjector::Instance();
    injector.Enable();
    injector.SetGlobalProbability(1.0);
    
    // Inject and recover
    injector.InjectFault("resilience_test");
    injector.RecordRecovery("resilience_test", 100, true);
    
    ResilienceConfig config;
    config.min_resilience_score = 0.5;
    config.max_acceptable_recovery_time_ms = 1000;
    
    ResilienceValidator validator(config);
    auto metrics = validator.RunValidation();
    
    EXPECT_EQ(metrics.total_faults_injected, 1);
    EXPECT_EQ(metrics.successful_recoveries, 1);
    EXPECT_EQ(metrics.failed_recoveries, 0);
    EXPECT_GE(metrics.resilience_score, 0.0);
    EXPECT_LE(metrics.resilience_score, 1.0);
}

TEST_F(FaultInjectionTest, ControlledFailureHandler_Recovery) {
    auto& handler = ControlledFailureHandler::Instance();
    
    bool callback_called = false;
    handler.RegisterCallback([&callback_called](const FaultEvent& event) {
        callback_called = true;
        EXPECT_TRUE(event.injected);
    });
    
    FaultEvent event;
    event.fault_point_id = "test";
    event.injected = true;
    event.recovered = false;
    
    handler.HandleFailure(event);
    
    EXPECT_TRUE(callback_called);
}

TEST_F(FaultInjectionTest, FaultRegistry_GetByCategory) {
    // Register multiple fault points in different categories
    FaultPoint mem_fault;
    mem_fault.id = "mem_fault";
    mem_fault.name = "Memory Fault";
    mem_fault.category = FaultCategory::MEMORY;
    mem_fault.severity = FaultSeverity::CRITICAL;
    mem_fault.probability = 0.5;
    FaultRegistry::Instance().RegisterFaultPoint(mem_fault);
    
    FaultPoint io_fault;
    io_fault.id = "io_fault";
    io_fault.name = "IO Fault";
    io_fault.category = FaultCategory::IO;
    io_fault.severity = FaultSeverity::HIGH;
    io_fault.probability = 0.3;
    FaultRegistry::Instance().RegisterFaultPoint(io_fault);
    
    auto mem_faults = FaultRegistry::Instance().GetFaultPointsByCategory(FaultCategory::MEMORY);
    EXPECT_EQ(mem_faults.size(), 1);
    EXPECT_EQ(mem_faults[0].id, "mem_fault");
    
    auto io_faults = FaultRegistry::Instance().GetFaultPointsByCategory(FaultCategory::IO);
    EXPECT_EQ(io_faults.size(), 1);
    EXPECT_EQ(io_faults[0].id, "io_fault");
}

TEST_F(FaultInjectionTest, FaultInjector_ConcurrentAccess) {
    FaultPoint point;
    point.id = "concurrent_test";
    point.name = "Concurrent Test";
    point.category = FaultCategory::NETWORK;
    point.severity = FaultSeverity::HIGH;
    point.probability = 0.5;
    FaultRegistry::Instance().RegisterFaultPoint(point);
    
    auto& injector = FaultInjector::Instance();
    injector.Enable();
    injector.SetGlobalProbability(0.5);
    
    std::vector<std::thread> threads;
    std::atomic<int> injection_count{0};
    
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&]() {
            for (int j = 0; j < 100; ++j) {
                if (injector.InjectFault("concurrent_test")) {
                    injection_count++;
                }
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    // Should have some injections (not all, not none due to probability)
    EXPECT_GT(injection_count, 0);
    EXPECT_LE(injection_count, 1000);
    
    auto events = FaultRegistry::Instance().GetEvents();
    EXPECT_EQ(events.size(), injection_count);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
