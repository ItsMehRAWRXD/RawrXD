//============================================================================
// test_framework.hpp
// RawrXD N-EVM - Lightweight Test Framework
//============================================================================

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <iostream>
#include <sstream>
#include <math>
#include <json/json.h>

namespace RawrXD {
namespace NEVM {
namespace Tests {

//============================================================================
// Test Result
//============================================================================

struct TestResult {
    std::string name;
    std::string suite;
    bool passed;
    std::string message;
    double duration_ms;
    std::string file;
    int line;
};

//============================================================================
// Test Statistics
//============================================================================

struct TestStatistics {
    int total_tests = 0;
    int passed = 0;
    int failed = 0;
    int skipped = 0;
    double duration_ms = 0.0;
    std::vector<TestResult> results;
};

//============================================================================
// Test Assertion Macros
//============================================================================

#define TEST_ASSERT(condition) \
    do { \
        if (!(condition)) { \
            return TestFailure("Assertion failed: " #condition, __FILE__, __LINE__); \
        } \
    } while(0)

#define TEST_ASSERT_EQ(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            std::stringstream ss; \
            ss << "Expected: " << (expected) << ", Actual: " << (actual); \
            return TestFailure(ss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define TEST_ASSERT_NEAR(expected, actual, tolerance) \
    do { \
        if (std::abs((expected) - (actual)) > (tolerance)) { \
            std::stringstream ss; \
            ss << "Expected: " << (expected) << " ± " << (tolerance) << ", Actual: " << (actual); \
            return TestFailure(ss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define TEST_ASSERT_TRUE(condition) TEST_ASSERT(condition)
#define TEST_ASSERT_FALSE(condition) TEST_ASSERT(!(condition))

#define TEST_SUCCESS() return TestSuccess()

//============================================================================
// Test Function Type
//============================================================================

using TestFunction = std::function<TestResult()>;

//============================================================================
// Test Framework
//============================================================================

class TestFramework {
public:
    struct TestCase {
        std::string name;
        std::string suite;
        TestFunction func;
        std::string file;
        int line;
    };
    
    void RegisterTest(const std::string& name, const std::string& suite,
                     TestFunction func, const std::string& file, int line) {
        TestCase test;
        test.name = name;
        test.suite = suite;
        test.func = func;
        test.file = file;
        test.line = line;
        tests_.push_back(test);
    }
    
    void SetVerbose(bool verbose) { verbose_ = verbose; }
    void SetFilter(const std::string& filter) { filter_ = filter; }
    
    TestStatistics RunAll() {
        TestStatistics stats;
        auto start = std::chrono::high_resolution_clock::now();
        
        for (const auto& test : tests_) {
            // Apply filter
            if (!filter_.empty()) {
                std::string full_name = test.suite + "." + test.name;
                if (full_name.find(filter_) == std::string::npos) {
                    stats.skipped++;
                    continue;
                }
            }
            
            if (verbose_) {
                std::cout << "Running: " << test.suite << "." << test.name << "... ";
            }
            
            auto test_start = std::chrono::high_resolution_clock::now();
            TestResult result = test.func();
            auto test_end = std::chrono::high_resolution_clock::now();
            
            result.duration_ms = std::chrono::duration_cast<std::chrono::microseconds>(
                test_end - test_start).count() / 1000.0;
            result.name = test.name;
            result.suite = test.suite;
            result.file = test.file;
            result.line = test.line;
            
            stats.results.push_back(result);
            stats.total_tests++;
            
            if (result.passed) {
                stats.passed++;
                if (verbose_) {
                    std::cout << "PASSED (" << std::fixed << std::setprecision(2) << result.duration_ms << " ms)\n";
                }
            } else {
                stats.failed++;
                std::cout << "FAILED: " << test.suite << "." << test.name << "\n";
                std::cout << "  " << result.message << "\n";
                std::cout << "  at " << result.file << ":" << result.line << "\n";
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        stats.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            end - start).count();
        
        return stats;
    }
    
    void ExportJSONReport(const std::string& path, const TestStatistics& stats) {
        Json::Value root;
        root["total_tests"] = stats.total_tests;
        root["passed"] = stats.passed;
        root["failed"] = stats.failed;
        root["skipped"] = stats.skipped;
        root["duration_ms"] = stats.duration_ms;
        
        Json::Value results_json(Json::arrayValue);
        for (const auto& result : stats.results) {
            Json::Value r;
            r["name"] = result.name;
            r["suite"] = result.suite;
            r["passed"] = result.passed;
            r["message"] = result.message;
            r["duration_ms"] = result.duration_ms;
            r["file"] = result.file;
            r["line"] = result.line;
            results_json.append(r);
        }
        root["results"] = results_json;
        
        std::ofstream file(path);
        Json::StreamWriterBuilder builder;
        std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
        writer->write(root, &file);
    }

private:
    std::vector<TestCase> tests_;
    bool verbose_ = false;
    std::string filter_;
};

//============================================================================
// Test Registration Helper
//============================================================================

#define REGISTER_TEST(framework, suite, name) \
    framework.RegisterTest(#name, #suite, &suite##_##name, __FILE__, __LINE__)

//============================================================================
// Test Result Helpers
//============================================================================

inline TestResult TestSuccess() {
    TestResult result;
    result.passed = true;
    return result;
}

inline TestResult TestFailure(const std::string& message, const std::string& file, int line) {
    TestResult result;
    result.passed = false;
    result.message = message;
    result.file = file;
    result.line = line;
    return result;
}

} // namespace Tests
} // namespace NEVM
} // namespace RawrXD
