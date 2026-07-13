// RawrXD Test Framework
// Phase T.1: Comprehensive testing framework with mocking and fixtures
// Supports unit, integration, and end-to-end tests

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <sstream>

namespace RawrXD {
namespace Testing {

// Test result types
enum class TestResult {
    PASSED,
    FAILED,
    SKIPPED,
    ERROR
};

// Test assertion exception
class AssertionError : public std::exception {
public:
    explicit AssertionError(const std::string& message) : message_(message) {}
    const char* what() const noexcept override { return message_.c_str(); }
private:
    std::string message_;
};

// Test case information
struct TestCase {
    std::string name;
    std::string suite;
    std::vector<std::string> tags;
    std::function<void()> test;
    std::chrono::milliseconds timeout{5000};
    bool enabled{true};
};

// Test result details
struct TestResultDetail {
    std::string testName;
    std::string suite;
    TestResult result;
    std::string message;
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
    std::chrono::milliseconds duration;
    std::vector<std::string> logOutput;
    std::exception_ptr error;
};

// Test suite configuration
struct TestSuiteConfig {
    std::string name;
    std::vector<std::string> setupSteps;
    std::vector<std::string> teardownSteps;
    std::map<std::string, std::string> fixtures;
    bool parallel{false};
    uint32_t maxParallelTests{4};
};

// Mock object base
class MockBase {
public:
    virtual ~MockBase() = default;
    
    template<typename T>
    void setReturnValue(const std::string& method, T value) {
        returnValues_[method] = std::any(value);
    }
    
    template<typename T>
    T getReturnValue(const std::string& method) {
        auto it = returnValues_.find(method);
        if (it != returnValues_.end()) {
            return std::any_cast<T>(it->second);
        }
        return T{};
    }
    
    void recordCall(const std::string& method, const std::vector<std::any>& args) {
        callLog_.push_back({method, args, std::chrono::steady_clock::now()});
    }
    
    uint32_t getCallCount(const std::string& method) const {
        return std::count_if(callLog_.begin(), callLog_.end(),
            [&method](const auto& call) { return call.method == method; });
    }
    
    bool wasCalled(const std::string& method) const {
        return getCallCount(method) > 0;
    }
    
    void reset() {
        callLog_.clear();
        returnValues_.clear();
    }
    
private:
    struct CallRecord {
        std::string method;
        std::vector<std::any> args;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::vector<CallRecord> callLog_;
    std::map<std::string, std::any> returnValues_;
};

// Test fixture base
class TestFixture {
public:
    virtual ~TestFixture() = default;
    
    virtual void setUp() {}
    virtual void tearDown() {}
    
    // Dependency injection helpers
    template<typename T>
    void injectMock(const std::string& name, std::shared_ptr<T> mock) {
        mocks_[name] = mock;
    }
    
    template<typename T>
    std::shared_ptr<T> getMock(const std::string& name) {
        auto it = mocks_.find(name);
        if (it != mocks_.end()) {
            return std::static_pointer_cast<T>(it->second);
        }
        return nullptr;
    }
    
private:
    std::map<std::string, std::shared_ptr<void>> mocks_;
};

// Assertion macros helpers
class Assert {
public:
    static void isTrue(bool condition, const std::string& message = "");
    static void isFalse(bool condition, const std::string& message = "");
    
    template<typename T, typename U>
    static void equals(const T& expected, const U& actual, const std::string& message = "");
    
    template<typename T, typename U>
    static void notEquals(const T& expected, const U& actual, const std::string& message = "");
    
    template<typename T>
    static void isNull(const T* ptr, const std::string& message = "");
    
    template<typename T>
    static void isNotNull(const T* ptr, const std::string& message = "");
    
    template<typename T>
    static void throws(std::function<void()> func, const std::string& message = "");
    
    template<typename T>
    static void noThrow(std::function<void()> func, const std::string& message = "");
    
    static void fail(const std::string& message);
    static void pass();
    
    // Floating point comparisons
    static void floatEquals(double expected, double actual, double epsilon = 1e-6, 
                           const std::string& message = "");
    
    // String assertions
    static void contains(const std::string& haystack, const std::string& needle,
                        const std::string& message = "");
    static void startsWith(const std::string& str, const std::string& prefix,
                          const std::string& message = "");
    static void endsWith(const std::string& str, const std::string& suffix,
                        const std::string& message = "");
    
    // Collection assertions
    template<typename Container>
    static void contains(const Container& container, const typename Container::value_type& item,
                        const std::string& message = "");
    
    template<typename Container>
    static void isEmpty(const Container& container, const std::string& message = "");
    
    template<typename Container>
    static void hasSize(const Container& container, size_t size, const std::string& message = "");
    
    // Performance assertions
    static void completesWithin(std::function<void()> func, std::chrono::milliseconds timeout,
                               const std::string& message = "");
};

// Test runner
class TestRunner {
public:
    TestRunner();
    ~TestRunner();
    
    // Registration
    void registerTest(const TestCase& test);
    void registerSuite(const TestSuiteConfig& suite);
    void registerFixture(const std::string& name, std::function<std::unique_ptr<TestFixture>()> factory);
    
    // Execution
    std::vector<TestResultDetail> runAll();
    std::vector<TestResultDetail> runSuite(const std::string& suiteName);
    std::vector<TestResultDetail> runTest(const std::string& testName);
    std::vector<TestResultDetail> runWithTag(const std::string& tag);
    
    // Configuration
    void setParallel(bool parallel) { parallel_ = parallel; }
    void setMaxParallel(uint32_t max) { maxParallel_ = max; }
    void setOutputFormat(const std::string& format) { outputFormat_ = format; } // "console", "json", "xml", "junit"
    void setFilter(const std::string& filter) { filter_ = filter; }
    
    // Results
    void printResults(const std::vector<TestResultDetail>& results);
    std::string exportResults(const std::vector<TestResultDetail>& results, const std::string& format);
    
    // Statistics
    struct TestStats {
        uint32_t totalTests;
        uint32_t passed;
        uint32_t failed;
        uint32_t skipped;
        uint32_t errors;
        std::chrono::milliseconds totalDuration;
        std::map<std::string, uint32_t> bySuite;
        std::map<std::string, uint32_t> byTag;
    };
    TestStats getStats(const std::vector<TestResultDetail>& results) const;

private:
    TestResultDetail executeTest(const TestCase& test);
    bool shouldRun(const TestCase& test) const;
    
    std::vector<TestCase> tests_;
    std::map<std::string, TestSuiteConfig> suites_;
    std::map<std::string, std::function<std::unique_ptr<TestFixture>()>> fixtures_;
    
    bool parallel_{false};
    uint32_t maxParallel_{4};
    std::string outputFormat_{"console"};
    std::string filter_;
};

// Test macros
#define TEST(suite, name) \
    static void test_##suite##_##name(); \
    static struct test_##suite##_##name##_registrar { \
        test_##suite##_##name##_registrar() { \
            RawrXD::Testing::TestRunner::instance().registerTest({#name, #suite, {}, test_##suite##_##name}); \
        } \
    } test_##suite##_##name##_instance; \
    static void test_##suite##_##name()

#define TEST_WITH_TAGS(suite, name, ...) \
    static void test_##suite##_##name(); \
    static struct test_##suite##_##name##_registrar { \
        test_##suite##_##name##_registrar() { \
            RawrXD::Testing::TestRunner::instance().registerTest({#name, #suite, {__VA_ARGS__}, test_##suite##_##name}); \
        } \
    } test_##suite##_##name##_instance; \
    static void test_##suite##_##name()

#define ASSERT_TRUE(condition) \
    RawrXD::Testing::Assert::isTrue(condition, "Assertion failed: " #condition)

#define ASSERT_FALSE(condition) \
    RawrXD::Testing::Assert::isFalse(condition, "Assertion failed: NOT " #condition)

#define ASSERT_EQ(expected, actual) \
    RawrXD::Testing::Assert::equals(expected, actual, "Expected equality")

#define ASSERT_NE(expected, actual) \
    RawrXD::Testing::Assert::notEquals(expected, actual, "Expected inequality")

#define ASSERT_NULL(ptr) \
    RawrXD::Testing::Assert::isNull(ptr, "Expected null pointer")

#define ASSERT_NOT_NULL(ptr) \
    RawrXD::Testing::Assert::isNotNull(ptr, "Expected non-null pointer")

#define ASSERT_THROWS(type, code) \
    RawrXD::Testing::Assert::throws<type>([&](){ code; }, "Expected exception")

#define ASSERT_NO_THROW(code) \
    RawrXD::Testing::Assert::noThrow<void>([&](){ code; }, "Unexpected exception")

#define ASSERT_FLOAT_EQ(expected, actual) \
    RawrXD::Testing::Assert::floatEquals(expected, actual)

#define FAIL(message) \
    RawrXD::Testing::Assert::fail(message)

// Benchmark support
struct BenchmarkResult {
    std::string name;
    uint64_t iterations;
    std::chrono::nanoseconds totalTime;
    std::chrono::nanoseconds avgTime;
    std::chrono::nanoseconds minTime;
    std::chrono::nanoseconds maxTime;
    double throughput; // ops/sec
};

class Benchmark {
public:
    static BenchmarkResult run(const std::string& name, std::function<void()> func, 
                              uint64_t iterations = 1000);
    static void compare(const std::vector<BenchmarkResult>& results);
    static void print(const BenchmarkResult& result);
};

} // namespace Testing
} // namespace RawrXD
