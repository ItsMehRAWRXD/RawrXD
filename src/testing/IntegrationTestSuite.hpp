// RawrXD Integration Test Suite
// Phase T.2: End-to-end integration tests
// Tests component interactions and API workflows

#pragma once

#include "TestFramework.hpp"
#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <chrono>

namespace RawrXD {
namespace Testing {

// Forward declarations
class InferenceEngine;
class ModelManager;
class APIGateway;
class DistributedRuntime;

// Integration test configuration
struct IntegrationTestConfig {
    std::string name;
    std::string description;
    std::vector<std::string> components;  // Components under test
    std::vector<std::string> dependencies; // Required services
    std::chrono::seconds timeout{60};
    bool cleanupAfterTest{true};
    bool isolatedEnvironment{true};  // Use isolated test environment
};

// Test scenario
struct TestScenario {
    std::string name;
    std::string description;
    std::vector<std::string> steps;
    std::map<std::string, std::string> expectedResults;
};

// Component stub for testing
class ComponentStub {
public:
    virtual ~ComponentStub() = default;
    virtual bool initialize() = 0;
    virtual bool shutdown() = 0;
    virtual bool isHealthy() const = 0;
    virtual std::string getName() const = 0;
};

// Integration test base
class IntegrationTest : public TestFixture {
public:
    IntegrationTest(const IntegrationTestConfig& config);
    virtual ~IntegrationTest();
    
    // Lifecycle
    virtual void setUp() override;
    virtual void tearDown() override;
    
    // Component management
    template<typename T>
    std::shared_ptr<T> getComponent(const std::string& name);
    
    template<typename T>
    void registerComponent(const std::string& name, std::shared_ptr<T> component);
    
    void registerStub(const std::string& name, std::shared_ptr<ComponentStub> stub);
    
    // Test execution
    void runScenario(const TestScenario& scenario);
    void waitForComponent(const std::string& name, std::chrono::seconds timeout);
    void waitForCondition(std::function<bool()> condition, std::chrono::seconds timeout);
    
    // Assertions
    void assertComponentHealthy(const std::string& name);
    void assertComponentResponds(const std::string& name, std::chrono::milliseconds timeout);
    void assertDataConsistency(const std::string& dataId);
    void assertEventReceived(const std::string& eventType, std::chrono::seconds timeout);
    
    // Event tracking
    void trackEvent(const std::string& eventType, const std::string& data);
    bool wasEventReceived(const std::string& eventType) const;
    std::vector<std::string> getReceivedEvents() const;
    
    // Cleanup
    void cleanupTestData();
    void resetComponents();

protected:
    IntegrationTestConfig config_;
    std::map<std::string, std::shared_ptr<void>> components_;
    std::map<std::string, std::shared_ptr<ComponentStub>> stubs_;
    std::vector<std::string> receivedEvents_;
    mutable std::mutex mutex_;
};

// API integration tests
class APIIntegrationTest : public IntegrationTest {
public:
    APIIntegrationTest();
    
    // HTTP API tests
    void testHealthEndpoint();
    void testInferenceEndpoint();
    void testModelListEndpoint();
    void testMetricsEndpoint();
    void testAuthenticationFlow();
    void testRateLimiting();
    void testErrorHandling();
    
    // WebSocket tests
    void testStreamingInference();
    void testRealTimeUpdates();
    void testConnectionRecovery();
    
    // gRPC tests (if applicable)
    void testGRPCInference();
    void testGRPCStreaming();
};

// Model integration tests
class ModelIntegrationTest : public IntegrationTest {
public:
    ModelIntegrationTest();
    
    // Loading tests
    void testModelLoading();
    void testModelQuantization();
    void testModelCaching();
    void testModelVersioning();
    void testModelHotSwap();
    
    // Inference tests
    void testBasicInference();
    void testBatchInference();
    void testStreamingInference();
    void testConcurrentInference();
    void testMultiModelInference();
    
    // Performance tests
    void testInferenceLatency();
    void testThroughputUnderLoad();
    void testMemoryEfficiency();
};

// Distributed system tests
class DistributedIntegrationTest : public IntegrationTest {
public:
    DistributedIntegrationTest();
    
    // Cluster tests
    void testNodeJoin();
    void testNodeLeave();
    void testLeaderElection();
    void testDataReplication();
    void testFailover();
    void testSplitBrainRecovery();
    
    // Workload tests
    void testWorkDistribution();
    void testLoadBalancing();
    void testRequestRouting();
    void testSessionAffinity();
    
    // Network partition tests
    void testNetworkPartition();
    void testPartitionRecovery();
    void testQuorumMaintenance();
};

// Database integration tests
class DatabaseIntegrationTest : public IntegrationTest {
public:
    DatabaseIntegrationTest();
    
    // Connection tests
    void testConnectionPool();
    void testConnectionRecovery();
    void testTransactionManagement();
    
    // Data tests
    void testDataPersistence();
    void testDataMigration();
    void testBackupRestore();
    void testConcurrentAccess();
};

// Security integration tests
class SecurityIntegrationTest : public IntegrationTest {
public:
    SecurityIntegrationTest();
    
    // Authentication tests
    void testTokenValidation();
    void testSessionManagement();
    void testMFAFlow();
    void testSSOIntegration();
    
    // Authorization tests
    void testRBACEnforcement();
    void testPermissionChecks();
    void testResourceAccess();
    
    // Encryption tests
    void testDataEncryption();
    void testTLSHandshake();
    void testCertificateValidation();
    
    // Audit tests
    void testAuditLogging();
    void testTamperDetection();
};

// End-to-end workflow tests
class EndToEndTest : public IntegrationTest {
public:
    EndToEndTest();
    
    // Complete workflows
    void testFullInferenceWorkflow();
    void testModelDeploymentWorkflow();
    void testUserOnboardingWorkflow();
    void testBillingWorkflow();
    void testMonitoringWorkflow();
    
    // Multi-tenant tests
    void testTenantIsolation();
    void testResourceQuotaEnforcement();
    void testCrossTenantAccess();
};

// Test data builder
class TestDataBuilder {
public:
    TestDataBuilder& withModel(const std::string& name, const std::string& format);
    TestDataBuilder& withUser(const std::string& username, const std::vector<std::string>& roles);
    TestDataBuilder& withConfig(const std::map<std::string, std::string>& config);
    TestDataBuilder& withRequest(const std::string& type, const std::string& payload);
    
    void build();
    void cleanup();
    
private:
    std::vector<std::string> createdResources_;
};

// Test environment manager
class TestEnvironment {
public:
    static TestEnvironment& instance();
    
    bool initialize();
    bool shutdown();
    
    // Service management
    bool startService(const std::string& name);
    bool stopService(const std::string& name);
    bool restartService(const std::string& name);
    bool isServiceRunning(const std::string& name) const;
    
    // Database
    void resetDatabase();
    void loadFixture(const std::string& fixtureName);
    
    // Network
    void simulateNetworkLatency(std::chrono::milliseconds latency);
    void simulatePacketLoss(double percentage);
    void simulatePartition(const std::vector<std::string>& nodes);
    void restoreNetwork();
    
    // Time
    void freezeTime(std::chrono::system_clock::time_point time);
    void advanceTime(std::chrono::seconds duration);
    void restoreTime();

private:
    TestEnvironment() = default;
    std::map<std::string, bool> services_;
};

// Integration test runner
class IntegrationTestRunner {
public:
    void registerTest(const std::string& name, std::function<void()> test);
    void runAll();
    void runByTag(const std::string& tag);
    void runByComponent(const std::string& component);
    
    // Results
    struct Results {
        uint32_t total;
        uint32_t passed;
        uint32_t failed;
        uint32_t skipped;
        std::chrono::milliseconds duration;
        std::vector<std::string> failures;
    };
    Results getResults() const;
    
    // Reporting
    void generateReport(const std::string& path) const;
    void generateCoverageReport(const std::string& path) const;

private:
    std::map<std::string, std::function<void()>> tests_;
    Results results_{};
};

} // namespace Testing
} // namespace RawrXD
