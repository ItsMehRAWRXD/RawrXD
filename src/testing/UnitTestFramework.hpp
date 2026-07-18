/**
 * UnitTestFramework.hpp
 *
 * Phase I Batch 1/5: Unit Testing Framework
 *
 * Comprehensive unit testing with assertions, fixtures, parameterized tests,
 * and mocking capabilities.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <sstream>
#include <iostream>

namespace Testing {

// ============================================================================
// Test Types
// ============================================================================

enum class TestResult {
    PASSED,
    FAILED,
    SKIPPED,
    TIMEOUT,
    CRASHED
};

enum class TestPriority {
    CRITICAL,   // Must pass
    HIGH,       // Important functionality
    MEDIUM,     // Standard tests
    LOW,        // Nice to have
    TRIVIAL     // Documentation/tests
};

// ============================================================================
// Test Assertion
// ============================================================================

class AssertionException : public std::exception {
public:
    explicit AssertionException(const std::string& msg) : message_(msg) {}
    const char* what() const noexcept override { return message_.c_str(); }
    
private:
    std::string message_;
};

// Assertion macros
#define ASSERT_TRUE(expr) \
    do { if (!(expr)) throw Testing::AssertionException("Assertion failed: " #expr); } while(0)

#define ASSERT_FALSE(expr) \
    do { if (expr) throw Testing::AssertionException("Assertion failed: expected false, got true"); } while(0)

#define ASSERT_EQ(expected, actual) \
    do { if ((expected) != (actual)) { \
        std::ostringstream oss; \
        oss << "Expected: " << (expected) << ", Actual: " << (actual); \
        throw Testing::AssertionException(oss.str()); \
    } } while(0)

#define ASSERT_NE(expected, actual) \
    do { if ((expected) == (actual)) { \
        std::ostringstream oss; \
        oss << "Expected not equal, both are: " << (expected); \
        throw Testing::AssertionException(oss.str()); \
    } } while(0)

#define ASSERT_LT(left, right) \
    do { if (!((left) < (right))) { \
        std::ostringstream oss; \
        oss << "Expected " << (left) << " < " << (right); \
        throw Testing::AssertionException(oss.str()); \
    } } while(0)

#define ASSERT_LE(left, right) \
    do { if (!((left) <= (right))) { \
        std::ostringstream oss; \
        oss << "Expected " << (left) << " <= " << (right); \
        throw Testing::AssertionException(oss.str()); \
    } } while(0)

#define ASSERT_GT(left, right) \
    do { if (!((left) > (right))) { \
        std::ostringstream oss; \
        oss << "Expected " << (left) << " > " << (right); \
        throw Testing::AssertionException(oss.str()); \
    } } while(0)

#define ASSERT_GE(left, right) \
    do { if (!((left) >= (right))) { \
        std::ostringstream oss; \
        oss << "Expected " << (left) << " >= " << (right); \
        throw Testing::AssertionException(oss.str()); \
    } } while(0)

#define ASSERT_NULL(ptr) \
    do { if ((ptr) != nullptr) throw Testing::AssertionException("Expected null pointer"); } while(0)

#define ASSERT_NOT_NULL(ptr) \
    do { if ((ptr) == nullptr) throw Testing::AssertionException("Expected non-null pointer"); } while(0)

#define ASSERT_THROW(expr, exception_type) \
    do { \
        bool caught = false; \
        try { expr; } \
        catch (const exception_type&) { caught = true; } \
        catch (...) { throw Testing::AssertionException("Wrong exception type thrown"); } \
        if (!caught) throw Testing::AssertionException("Expected exception not thrown"); \
    } while(0)

#define ASSERT_NO_THROW(expr) \
    do { try { expr; } catch (...) { throw Testing::AssertionException("Unexpected exception thrown"); } } while(0)

#define ASSERT_NEAR(expected, actual, tolerance) \
    do { \
        auto diff = std::abs((expected) - (actual)); \
        if (diff > (tolerance)) { \
            std::ostringstream oss; \
            oss << "Expected near " << (expected) << ", Actual: " << (actual) \
                << ", Diff: " << diff << " > " << (tolerance); \
            throw Testing::AssertionException(oss.str()); \
        } \
    } while(0)

#define ASSERT_CONTAINS(container, value) \
    do { \
        if (std::find((container).begin(), (container).end(), (value)) == (container).end()) { \
            throw Testing::AssertionException("Container does not contain expected value"); \
        } \
    } while(0)

#define ASSERT_EMPTY(container) \
    do { \
        if (!(container).empty()) { \
            throw Testing::AssertionException("Expected empty container"); \
        } \
    } while(0)

#define ASSERT_NOT_EMPTY(container) \
    do { \
        if ((container).empty()) { \
            throw Testing::AssertionException("Expected non-empty container"); \
        } \
    } while(0)

#define FAIL(msg) throw Testing::AssertionException(msg)

// ============================================================================
// Test Info
// ============================================================================

/**
 * Information about a test.
 */
struct TestInfo {
    std::string name;
    std::string suite;
    std::string description;
    std::string file;
    uint32_t line;
    TestPriority priority;
    std::vector<std::string> tags;
    uint64_t timeoutMs;
    bool disabled;
    std::string skipReason;
    
    TestInfo() : line(0), priority(TestPriority::MEDIUM), timeoutMs(30000), disabled(false) {}
};

// ============================================================================
// Test Result
// ============================================================================

/**
 * Result of a single test execution.
 */
struct TestExecutionResult {
    TestInfo info;
    TestResult result;
    std::string message;
    uint64_t durationNs;
    std::string output;
    std::string stackTrace;
    
    // Assertions
    uint32_t assertionsPassed;
    uint32_t assertionsFailed;
    
    // Coverage
    std::map<std::string, double> coverage;  // file -> percentage
    
    TestExecutionResult() : result(TestResult::PASSED), durationNs(0),
                           assertionsPassed(0), assertionsFailed(0) {}
    
    bool Passed() const { return result == TestResult::PASSED; }
    bool Failed() const { return result == TestResult::FAILED; }
    
    std::string ToJson() const;
};

// ============================================================================
// Test Fixture
// ============================================================================

/**
 * Base class for test fixtures.
 */
class TestFixture {
public:
    virtual ~TestFixture() = default;
    
    // Called before each test
    virtual void SetUp() {}
    
    // Called after each test
    virtual void TearDown() {}
    
    // Called once before all tests in suite
    virtual void SetUpTestSuite() {}
    
    // Called once after all tests in suite
    virtual void TearDownTestSuite() {}
};

// ============================================================================
// Test Case
// ============================================================================

/**
 * Single test case.
 */
class TestCase {
public:
    using TestFunc = std::function<void()>;
    using FixtureFactory = std::function<std::unique_ptr<TestFixture>()>;
    
    TestCase(const TestInfo& info, TestFunc func);
    TestCase(const TestInfo& info, TestFunc func, FixtureFactory fixtureFactory);
    
    // Execute test
    TestExecutionResult Run();
    
    // Accessors
    const TestInfo& GetInfo() const { return info_; }
    
private:
    TestInfo info_;
    TestFunc func_;
    FixtureFactory fixtureFactory_;
};

// ============================================================================
// Test Suite
// ============================================================================

/**
 * Collection of test cases.
 */
class TestSuite {
public:
    explicit TestSuite(const std::string& name);
    
    // Add tests
    void AddTest(std::shared_ptr<TestCase> test);
    void AddTests(const std::vector<std::shared_ptr<TestCase>>& tests);
    
    // Fixtures
    void SetFixtureFactory(TestCase::FixtureFactory factory);
    
    // Accessors
    std::string GetName() const { return name_; }
    std::vector<std::shared_ptr<TestCase>> GetTests() const;
    std::vector<std::shared_ptr<TestCase>> GetTestsByTag(const std::string& tag) const;
    std::vector<std::shared_ptr<TestCase>> GetTestsByPriority(TestPriority priority) const;
    
    // Execution
    std::vector<TestExecutionResult> RunAll();
    TestExecutionResult Run(const std::string& testName);
    
private:
    std::string name_;
    std::vector<std::shared_ptr<TestCase>> tests_;
    TestCase::FixtureFactory fixtureFactory_;
};

// ============================================================================
// Parameterized Test
// ============================================================================

/**
 * Parameterized test case.
 */
template<typename T>
class ParameterizedTestCase {
public:
    using TestFunc = std::function<void(const T&)>;
    
    ParameterizedTestCase(const TestInfo& info, TestFunc func);
    
    void AddParameter(const T& param);
    void AddParameters(const std::vector<T>& params);
    
    std::vector<TestExecutionResult> Run();
    
private:
    TestInfo info_;
    TestFunc func_;
    std::vector<T> parameters_;
};

// ============================================================================
// Mock Framework
// ============================================================================

/**
 * Mock function call record.
 */
template<typename ReturnType, typename... Args>
class MockFunction {
public:
    using Func = std::function<ReturnType(Args...)>;
    
    MockFunction() : defaultReturn_{} {}
    explicit MockFunction(ReturnType defaultReturn) : defaultReturn_(defaultReturn) {}
    
    // Set return value for specific arguments
    void SetReturn(Args... args, ReturnType returnValue) {
        auto key = MakeKey(args...);
        returns_[key] = returnValue;
    }
    
    // Set default return value
    void SetDefaultReturn(ReturnType value) {
        defaultReturn_ = value;
    }
    
    // Set side effect
    void SetSideEffect(Func sideEffect) {
        sideEffect_ = sideEffect;
    }
    
    // Call operator
    ReturnType operator()(Args... args) {
        callCount_++;
        calls_.push_back(std::make_tuple(args...));
        
        if (sideEffect_) {
            return sideEffect_(args...);
        }
        
        auto key = MakeKey(args...);
        auto it = returns_.find(key);
        if (it != returns_.end()) {
            return it->second;
        }
        
        return defaultReturn_;
    }
    
    // Verification
    uint32_t GetCallCount() const { return callCount_; }
    bool WasCalled() const { return callCount_ > 0; }
    bool WasCalledWith(Args... args) const {
        auto key = MakeKey(args...);
        for (const auto& call : calls_) {
            if (call == key) return true;
        }
        return false;
    }
    
    void Reset() {
        callCount_ = 0;
        calls_.clear();
        returns_.clear();
    }
    
private:
    using Key = std::tuple<typename std::decay<Args>::type...>;
    
    ReturnType defaultReturn_;
    std::map<Key, ReturnType> returns_;
    std::vector<Key> calls_;
    std::atomic<uint32_t> callCount_{0};
    Func sideEffect_;
    
    Key MakeKey(Args... args) const {
        return std::make_tuple(args...);
    }
};

/**
 * Mock object base.
 */
class MockObject {
public:
    virtual ~MockObject() = default;
    
    void VerifyAll() const;
    void VerifyAndClear();
    
protected:
    std::vector<std::function<void()>> verifiers_;
};

// ============================================================================
// Test Runner
// ============================================================================

/**
 * Test execution engine.
 */
class TestRunner {
public:
    struct Config {
        // Execution
        bool parallel = false;
        uint32_t parallelWorkers = 4;
        bool stopOnFailure = false;
        bool shuffle = false;
        uint32_t seed = 0;
        
        // Filtering
        std::string filter;  // Regex pattern
        std::vector<std::string> includeTags;
        std::vector<std::string> excludeTags;
        TestPriority minPriority = TestPriority::TRIVIAL;
        
        // Output
        bool verbose = false;
        bool colorOutput = true;
        std::string outputFormat = "console";  // console, json, xml, html
        std::string outputFile;
        
        // Coverage
        bool collectCoverage = false;
        std::string coverageReportPath;
        
        // Timeout
        uint64_t globalTimeoutMs = 300000;  // 5 minutes
    };
    
    explicit TestRunner(const Config& config = Config{});
    
    // Registration
    void RegisterSuite(std::shared_ptr<TestSuite> suite);
    void RegisterTest(std::shared_ptr<TestCase> test);
    
    // Execution
    bool RunAll();
    bool RunSuite(const std::string& suiteName);
    bool RunTest(const std::string& testName);
    
    // Results
    struct Summary {
        uint32_t totalTests;
        uint32_t passed;
        uint32_t failed;
        uint32_t skipped;
        uint32_t timedOut;
        uint32_t crashed;
        uint64_t totalDurationMs;
        double successRate;
    };
    Summary GetSummary() const;
    std::vector<TestExecutionResult> GetResults() const;
    
    // Export
    void ExportResults(const std::string& filepath) const;
    
    // List
    void ListTests() const;
    
private:
    Config config_;
    std::vector<std::shared_ptr<TestSuite>> suites_;
    std::vector<std::shared_ptr<TestCase>> standaloneTests_;
    std::vector<TestExecutionResult> results_;
    
    std::vector<std::shared_ptr<TestCase>> FilterTests() const;
    TestExecutionResult ExecuteTest(TestCase* test);
    void PrintResult(const TestExecutionResult& result) const;
    void PrintSummary() const;
};

// ============================================================================
// Test Registration
// ============================================================================

/**
 * Global test registry.
 */
class TestRegistry {
public:
    static TestRegistry& GetInstance();
    
    void RegisterTest(const std::string& suite, std::shared_ptr<TestCase> test);
    void RegisterSuite(std::shared_ptr<TestSuite> suite);
    
    std::vector<std::shared_ptr<TestSuite>> GetSuites() const;
    std::shared_ptr<TestSuite> GetSuite(const std::string& name) const;
    
private:
    TestRegistry() = default;
    std::map<std::string, std::shared_ptr<TestSuite>> suites_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Test Macros
// ============================================================================

#define TEST(suite, name) \
    static void Test_##suite##_##name(); \
    static struct TestReg_##suite##_##name { \
        TestReg_##suite##_##name() { \
            Testing::TestInfo info; \
            info.name = #name; \
            info.suite = #suite; \
            info.file = __FILE__; \
            info.line = __LINE__; \
            auto test = std::make_shared<Testing::TestCase>(info, Test_##suite##_##name); \
            Testing::TestRegistry::GetInstance().RegisterTest(#suite, test); \
        } \
    } _test_reg_##suite##_##name; \
    static void Test_##suite##_##name()

#define TEST_F(fixture, name) \
    static void Test_##fixture##_##name(Testing::TestFixture*); \
    static struct TestReg_##fixture##_##name { \
        TestReg_##fixture##_##name() { \
            Testing::TestInfo info; \
            info.name = #name; \
            info.suite = #fixture; \
            info.file = __FILE__; \
            info.line = __LINE__; \
            auto test = std::make_shared<Testing::TestCase>(info, \
                []() { \
                    auto fixture = std::make_unique<fixture>(); \
                    fixture->SetUp(); \
                    Test_##fixture##_##name(fixture.get()); \
                    fixture->TearDown(); \
                }); \
            Testing::TestRegistry::GetInstance().RegisterTest(#fixture, test); \
        } \
    } _test_reg_##fixture##_##name; \
    static void Test_##fixture##_##name(Testing::TestFixture* fixture)

#define TEST_DISABLED(suite, name, reason) \
    static void Test_##suite##_##name(); \
    static struct TestReg_##suite##_##name { \
        TestReg_##suite##_##name() { \
            Testing::TestInfo info; \
            info.name = #name; \
            info.suite = #suite; \
            info.file = __FILE__; \
            info.line = __LINE__; \
            info.disabled = true; \
            info.skipReason = reason; \
            auto test = std::make_shared<Testing::TestCase>(info, Test_##suite##_##name); \
            Testing::TestRegistry::GetInstance().RegisterTest(#suite, test); \
        } \
    } _test_reg_##suite##_##name; \
    static void Test_##suite##_##name()

#define TEST_WITH_TAGS(suite, name, ...) \
    static void Test_##suite##_##name(); \
    static struct TestReg_##suite##_##name { \
        TestReg_##suite##_##name() { \
            Testing::TestInfo info; \
            info.name = #name; \
            info.suite = #suite; \
            info.file = __FILE__; \
            info.line = __LINE__; \
            info.tags = {__VA_ARGS__}; \
            auto test = std::make_shared<Testing::TestCase>(info, Test_##suite##_##name); \
            Testing::TestRegistry::GetInstance().RegisterTest(#suite, test); \
        } \
    } _test_reg_##suite##_##name; \
    static void Test_##suite##_##name()

// ============================================================================
// Main Entry Point
// ============================================================================

/**
 * Main entry point for tests.
 */
int RunTests(int argc, char** argv);

} // namespace Testing
