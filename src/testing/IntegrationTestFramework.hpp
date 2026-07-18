/**
 * IntegrationTestFramework.hpp
 *
 * Phase I Batch 2/5: Integration Testing Framework
 *
 * Integration testing with component interaction, API testing,
 * database testing, and service testing.
 */

#pragma once

#include "UnitTestFramework.hpp"

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Testing {

// ============================================================================
// Forward Declarations
// ============================================================================

class IntegrationTest;
class IntegrationTestSuite;
class ComponentUnderTest;
class TestEnvironment;

// ============================================================================
// Component Interface
// ============================================================================

/**
 * Interface for components under test.
 */
class ComponentUnderTest {
public:
    virtual ~ComponentUnderTest() = default;
    
    virtual std::string GetName() const = 0;
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual bool IsHealthy() const = 0;
    
    // Dependencies
    virtual std::vector<std::string> GetDependencies() const { return {}; }
    virtual void InjectDependency(const std::string& name, ComponentUnderTest* component) {}
};

// ============================================================================
// Test Environment
// ============================================================================

/**
 * Test environment for integration tests.
 */
class TestEnvironment {
public:
    struct Config {
        bool isolated = true;
        bool persistent = false;
        std::string databaseUrl;
        std::string tempDirectory;
        std::map<std::string, std::string> environmentVariables;
    };
    
    explicit TestEnvironment(const Config& config);
    ~TestEnvironment();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    
    // Components
    void RegisterComponent(std::shared_ptr<ComponentUnderTest> component);
    void UnregisterComponent(const std::string& name);
    ComponentUnderTest* GetComponent(const std::string& name);
    
    // Setup/Teardown
    void SetUp();
    void TearDown();
    
    // State
    bool IsInitialized() const { return initialized_; }
    std::string GetTempDirectory() const { return config_.tempDirectory; }
    
    // Utilities
    std::string CreateTempFile(const std::string& prefix = "test");
    std::string CreateTempDirectory(const std::string& prefix = "test");
    void CleanUpTempFiles();
    
private:
    Config config_;
    bool initialized_ = false;
    std::map<std::string, std::shared_ptr<ComponentUnderTest>> components_;
    std::vector<std::string> tempFiles_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Integration Test
// ============================================================================

/**
 * Integration test case.
 */
class IntegrationTest {
public:
    using SetupFunc = std::function<void(TestEnvironment*)>;
    using TestFunc = std::function<void(TestEnvironment*)>;
    using TeardownFunc = std::function<void(TestEnvironment*)>;
    using ValidationFunc = std::function<bool(TestEnvironment*)>;
    
    struct Config {
        std::string name;
        std::string description;
        std::vector<std::string> requiredComponents;
        uint64_t timeoutMs = 60000;
        bool requiresDatabase = false;
        bool requiresNetwork = false;
        bool requiresFilesystem = false;
    };
    
    explicit IntegrationTest(const Config& config);
    
    // Callbacks
    void SetSetup(SetupFunc func);
    void SetTest(TestFunc func);
    void SetTeardown(TeardownFunc func);
    void SetValidation(ValidationFunc func);
    
    // Execution
    TestExecutionResult Run(TestEnvironment* env);
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    
private:
    Config config_;
    SetupFunc setup_;
    TestFunc test_;
    TeardownFunc teardown_;
    ValidationFunc validation_;
};

// ============================================================================
// API Test
// ============================================================================

/**
 * API integration test.
 */
class ApiTest {
public:
    enum class HttpMethod {
        GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
    };
    
    struct Request {
        HttpMethod method;
        std::string url;
        std::map<std::string, std::string> headers;
        std::string body;
        std::map<std::string, std::string> queryParams;
        uint64_t timeoutMs = 30000;
    };
    
    struct Response {
        int statusCode;
        std::map<std::string, std::string> headers;
        std::string body;
        uint64_t responseTimeMs;
        std::string errorMessage;
        bool success;
    };
    
    struct Config {
        std::string baseUrl;
        std::map<std::string, std::string> defaultHeaders;
        bool followRedirects = true;
        bool verifySsl = true;
        uint32_t maxRetries = 3;
    };
    
    explicit ApiTest(const Config& config);
    
    // HTTP methods
    Response Get(const std::string& path);
    Response Get(const std::string& path, const std::map<std::string, std::string>& headers);
    
    Response Post(const std::string& path, const std::string& body);
    Response Post(const std::string& path, const std::string& body,
                  const std::map<std::string, std::string>& headers);
    
    Response Put(const std::string& path, const std::string& body);
    Response Put(const std::string& path, const std::string& body,
                 const std::map<std::string, std::string>& headers);
    
    Response Delete(const std::string& path);
    Response Delete(const std::string& path, const std::map<std::string, std::string>& headers);
    
    Response Send(const Request& request);
    
    // Assertions
    void AssertStatus(const Response& response, int expected);
    void AssertSuccess(const Response& response);
    void AssertHeader(const Response& response, const std::string& name, const std::string& expected);
    void AssertBodyContains(const Response& response, const std::string& expected);
    void AssertJsonField(const Response& response, const std::string& path, const std::string& expected);
    void AssertResponseTime(const Response& response, uint64_t maxMs);
    
private:
    Config config_;
    
    Response ExecuteRequest(const Request& request);
};

// ============================================================================
// Database Test
// ============================================================================

/**
 * Database integration test.
 */
class DatabaseTest {
public:
    struct Config {
        std::string connectionString;
        std::string driver;
        std::string database;
        bool createSchema = true;
        bool seedData = false;
        bool rollbackAfterTest = true;
    };
    
    explicit DatabaseTest(const Config& config);
    ~DatabaseTest();
    
    // Lifecycle
    bool Connect();
    void Disconnect();
    bool IsConnected() const;
    
    // Transactions
    void BeginTransaction();
    void Commit();
    void Rollback();
    
    // Queries
    struct QueryResult {
        bool success;
        std::vector<std::map<std::string, std::string>> rows;
        uint64_t rowCount;
        std::string errorMessage;
    };
    
    QueryResult ExecuteQuery(const std::string& sql);
    QueryResult ExecuteQuery(const std::string& sql, const std::vector<std::string>& params);
    
    int ExecuteUpdate(const std::string& sql);
    int ExecuteUpdate(const std::string& sql, const std::vector<std::string>& params);
    
    // Schema
    bool ExecuteScript(const std::string& script);
    bool CreateTable(const std::string& name, const std::map<std::string, std::string>& columns);
    bool DropTable(const std::string& name);
    bool TruncateTable(const std::string& name);
    
    // Data
    bool Insert(const std::string& table, const std::map<std::string, std::string>& values);
    bool Update(const std::string& table, const std::map<std::string, std::string>& values,
                const std::string& whereClause);
    bool Delete(const std::string& table, const std::string& whereClause);
    
    // Assertions
    void AssertTableExists(const std::string& table);
    void AssertRowCount(const std::string& table, uint64_t expected);
    void AssertRowExists(const std::string& table, const std::string& whereClause);
    void AssertColumnValue(const std::string& table, const std::string& column,
                           const std::string& whereClause, const std::string& expected);
    
private:
    Config config_;
    bool connected_ = false;
    bool inTransaction_ = false;
    void* connection_ = nullptr;  // Database-specific handle
};

// ============================================================================
// Message Queue Test
// ============================================================================

/**
 * Message queue integration test.
 */
class MessageQueueTest {
public:
    struct Config {
        std::string brokerUrl;
        std::string username;
        std::string password;
        std::string virtualHost = "/";
        uint32_t connectionTimeoutMs = 5000;
    };
    
    struct Message {
        std::string body;
        std::map<std::string, std::string> headers;
        std::string contentType = "application/json";
        uint32_t priority = 0;
        uint64_t expirationMs = 0;
    };
    
    explicit MessageQueueTest(const Config& config);
    ~MessageQueueTest();
    
    // Lifecycle
    bool Connect();
    void Disconnect();
    bool IsConnected() const;
    
    // Queues
    bool DeclareQueue(const std::string& name, bool durable = true, bool exclusive = false);
    bool DeleteQueue(const std::string& name);
    bool PurgeQueue(const std::string& name);
    uint64_t GetQueueDepth(const std::string& name);
    
    // Exchanges
    bool DeclareExchange(const std::string& name, const std::string& type = "direct");
    bool BindQueue(const std::string& queue, const std::string& exchange, const std::string& routingKey);
    
    // Messages
    bool Publish(const std::string& exchange, const std::string& routingKey, const Message& message);
    bool PublishToQueue(const std::string& queue, const Message& message);
    
    std::optional<Message> Consume(const std::string& queue, uint64_t timeoutMs = 5000);
    std::vector<Message> ConsumeBatch(const std::string& queue, uint32_t count, uint64_t timeoutMs = 5000);
    
    // Assertions
    void AssertQueueExists(const std::string& queue);
    void AssertQueueEmpty(const std::string& queue);
    void AssertMessageReceived(const std::string& queue, const std::string& expectedBody);
    
private:
    Config config_;
    bool connected_ = false;
    void* connection_ = nullptr;
    void* channel_ = nullptr;
};

// ============================================================================
// Service Test
// ============================================================================

/**
 * Service integration test.
 */
class ServiceTest {
public:
    struct ServiceConfig {
        std::string name;
        std::string executable;
        std::vector<std::string> arguments;
        std::map<std::string, std::string> environment;
        std::string workingDirectory;
        uint64_t startupTimeoutMs = 30000;
        uint64_t shutdownTimeoutMs = 10000;
        int expectedExitCode = 0;
    };
    
    struct HealthCheck {
        std::string endpoint;
        uint64_t intervalMs = 1000;
        uint32_t maxRetries = 30;
    };
    
    explicit ServiceTest(const ServiceConfig& config);
    ~ServiceTest();
    
    // Lifecycle
    bool Start();
    bool Stop();
    bool Restart();
    bool IsRunning() const;
    
    // Health
    void SetHealthCheck(const HealthCheck& check);
    bool WaitForHealthy(uint64_t timeoutMs = 30000);
    bool IsHealthy() const;
    
    // Process
    int GetExitCode() const;
    std::string GetStdout() const;
    std::string GetStderr() const;
    void ClearOutput();
    
    // Signals
    bool SendSignal(int signal);
    bool Kill();
    
    // Assertions
    void AssertRunning();
    void AssertHealthy();
    void AssertExitCode(int expected);
    void AssertOutputContains(const std::string& expected);
    void AssertNoErrors();
    
private:
    ServiceConfig config_;
    HealthCheck healthCheck_;
    
    bool running_ = false;
    int exitCode_ = -1;
    std::string stdout_;
    std::string stderr_;
    
#ifdef _WIN32
    void* processHandle_ = nullptr;
    void* threadHandle_ = nullptr;
#else
    int pid_ = -1;
#endif
    
    bool StartProcess();
    bool StopProcess();
    void ReadOutput();
};

// ============================================================================
// Integration Test Suite
// ============================================================================

/**
 * Suite of integration tests.
 */
class IntegrationTestSuite {
public:
    explicit IntegrationTestSuite(const std::string& name);
    
    // Environment
    void SetEnvironment(std::shared_ptr<TestEnvironment> env);
    void CreateEnvironment(const TestEnvironment::Config& config);
    
    // Tests
    void AddTest(std::shared_ptr<IntegrationTest> test);
    void AddTests(const std::vector<std::shared_ptr<IntegrationTest>>& tests);
    
    // Execution
    struct Summary {
        uint32_t total;
        uint32_t passed;
        uint32_t failed;
        uint32_t skipped;
        uint64_t durationMs;
    };
    
    Summary RunAll();
    TestExecutionResult Run(const std::string& testName);
    
    // Ordering
    void SetExecutionOrder(const std::vector<std::string>& order);
    void AddDependency(const std::string& test, const std::string& dependsOn);
    
private:
    std::string name_;
    std::shared_ptr<TestEnvironment> environment_;
    std::vector<std::shared_ptr<IntegrationTest>> tests_;
    std::map<std::string, std::vector<std::string>> dependencies_;
    std::vector<std::string> executionOrder_;
    
    std::vector<std::shared_ptr<IntegrationTest>> GetOrderedTests();
    bool CheckDependenciesMet(const std::string& test, const std::set<std::string>& completed);
};

// ============================================================================
// Integration Test Runner
// ============================================================================

/**
 * Runner for integration tests.
 */
class IntegrationTestRunner {
public:
    struct Config {
        bool parallel = false;
        uint32_t parallelSuites = 2;
        bool stopOnFailure = false;
        bool cleanupAfterTest = true;
        std::string reportFormat = "console";
        std::string reportPath;
    };
    
    explicit IntegrationTestRunner(const Config& config = Config{});
    
    // Registration
    void RegisterSuite(std::shared_ptr<IntegrationTestSuite> suite);
    
    // Execution
    bool RunAll();
    bool RunSuite(const std::string& name);
    bool RunTest(const std::string& suite, const std::string& test);
    
    // Results
    struct Summary {
        uint32_t totalSuites;
        uint32_t totalTests;
        uint32_t passed;
        uint32_t failed;
        uint32_t skipped;
        uint64_t durationMs;
    };
    Summary GetSummary() const;
    
    // Export
    void ExportResults(const std::string& filepath);
    
private:
    Config config_;
    std::vector<std::shared_ptr<IntegrationTestSuite>> suites_;
    std::vector<TestExecutionResult> results_;
    
    void PrintSummary(const Summary& summary);
};

// ============================================================================
// Test Data Builders
// ============================================================================

/**
 * Builder for test data.
 */
template<typename T>
class TestDataBuilder {
public:
    TestDataBuilder& WithField(const std::string& name, const std::string& value);
    TestDataBuilder& WithField(const std::string& name, int value);
    TestDataBuilder& WithField(const std::string& name, double value);
    TestDataBuilder& WithField(const std::string& name, bool value);
    
    T Build() const;
    
private:
    std::map<std::string, std::string> fields_;
};

/**
 * Test data factory.
 */
class TestDataFactory {
public:
    // Users
    static std::map<std::string, std::string> CreateUser(const std::string& username = "");
    static std::vector<std::map<std::string, std::string>> CreateUsers(uint32_t count);
    
    // Products
    static std::map<std::string, std::string> CreateProduct(const std::string& name = "");
    static std::vector<std::map<std::string, std::string>> CreateProducts(uint32_t count);
    
    // Orders
    static std::map<std::string, std::string> CreateOrder(const std::string& userId = "");
    
    // Random data
    static std::string RandomString(uint32_t length);
    static int RandomInt(int min, int max);
    static double RandomDouble(double min, double max);
    static std::string RandomEmail();
    static std::string RandomUuid();
    
    // Time
    static std::string CurrentTimestamp();
    static std::string FutureTimestamp(uint64_t offsetSeconds);
    static std::string PastTimestamp(uint64_t offsetSeconds);
};

// ============================================================================
// Convenience Macros
// ============================================================================

#define INTEGRATION_TEST(name) \
    static void IntegrationTest_##name(Testing::TestEnvironment*); \
    static struct IntegrationTestReg_##name { \
        IntegrationTestReg_##name() { \
            Testing::IntegrationTest::Config config; \
            config.name = #name; \
            auto test = std::make_shared<Testing::IntegrationTest>(config); \
            test->SetTest(IntegrationTest_##name); \
        } \
    } _integration_test_reg_##name; \
    static void IntegrationTest_##name(Testing::TestEnvironment* env)

#define INTEGRATION_TEST_WITH_SETUP(name) \
    static void IntegrationTest_##name(Testing::TestEnvironment*); \
    static void IntegrationTest_##name##_setup(Testing::TestEnvironment*); \
    static void IntegrationTest_##name##_teardown(Testing::TestEnvironment*); \
    static struct IntegrationTestReg_##name { \
        IntegrationTestReg_##name() { \
            Testing::IntegrationTest::Config config; \
            config.name = #name; \
            auto test = std::make_shared<Testing::IntegrationTest>(config); \
            test->SetTest(IntegrationTest_##name); \
            test->SetSetup(IntegrationTest_##name##_setup); \
            test->SetTeardown(IntegrationTest_##name##_teardown); \
        } \
    } _integration_test_reg_##name; \
    static void IntegrationTest_##name##_setup(Testing::TestEnvironment* env) \
    static void IntegrationTest_##name##_teardown(Testing::TestEnvironment* env) \
    static void IntegrationTest_##name(Testing::TestEnvironment* env)

} // namespace Testing
