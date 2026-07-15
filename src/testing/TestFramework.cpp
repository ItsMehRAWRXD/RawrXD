// RawrXD Test Framework Implementation
// Phase T.1: Comprehensive testing framework

#include "TestFramework.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <future>

namespace RawrXD {
namespace Testing {

// ============================================================================
// Assert Implementation
// ============================================================================

void Assert::isTrue(bool condition, const std::string& message) {
    if (!condition) {
        throw AssertionError(message.empty() ? "Expected true, got false" : message);
    }
}

void Assert::isFalse(bool condition, const std::string& message) {
    if (condition) {
        throw AssertionError(message.empty() ? "Expected false, got true" : message);
    }
}

template<typename T, typename U>
void Assert::equals(const T& expected, const U& actual, const std::string& message) {
    if (!(expected == actual)) {
        std::stringstream ss;
        ss << (message.empty() ? "Values not equal" : message);
        throw AssertionError(ss.str());
    }
}

template<typename T, typename U>
void Assert::notEquals(const T& expected, const U& actual, const std::string& message) {
    if (expected == actual) {
        std::stringstream ss;
        ss << (message.empty() ? "Values should not be equal" : message);
        throw AssertionError(ss.str());
    }
}

template<typename T>
void Assert::isNull(const T* ptr, const std::string& message) {
    if (ptr != nullptr) {
        throw AssertionError(message.empty() ? "Expected null pointer" : message);
    }
}

template<typename T>
void Assert::isNotNull(const T* ptr, const std::string& message) {
    if (ptr == nullptr) {
        throw AssertionError(message.empty() ? "Expected non-null pointer" : message);
    }
}

template<typename T>
void Assert::throws(std::function<void()> func, const std::string& message) {
    bool thrown = false;
    try {
        func();
    } catch (const T&) {
        thrown = true;
    } catch (...) {
        throw AssertionError(message.empty() ? "Wrong exception type thrown" : message);
    }
    if (!thrown) {
        throw AssertionError(message.empty() ? "Expected exception not thrown" : message);
    }
}

template<typename T>
void Assert::noThrow(std::function<void()> func, const std::string& message) {
    try {
        func();
    } catch (const std::exception& e) {
        std::stringstream ss;
        ss << (message.empty() ? "Unexpected exception: " : message + ": ") << e.what();
        throw AssertionError(ss.str());
    } catch (...) {
        throw AssertionError(message.empty() ? "Unexpected unknown exception" : message);
    }
}

void Assert::fail(const std::string& message) {
    throw AssertionError(message);
}

void Assert::pass() {
    // No-op, test passes
}

void Assert::floatEquals(double expected, double actual, double epsilon, const std::string& message) {
    if (std::abs(expected - actual) > epsilon) {
        std::stringstream ss;
        ss << (message.empty() ? "Floating point values not equal" : message)
           << " (expected: " << expected << ", actual: " << actual 
           << ", epsilon: " << epsilon << ")";
        throw AssertionError(ss.str());
    }
}

void Assert::contains(const std::string& haystack, const std::string& needle, const std::string& message) {
    if (haystack.find(needle) == std::string::npos) {
        std::stringstream ss;
        ss << (message.empty() ? "String does not contain expected substring" : message);
        throw AssertionError(ss.str());
    }
}

void Assert::startsWith(const std::string& str, const std::string& prefix, const std::string& message) {
    if (str.find(prefix) != 0) {
        std::stringstream ss;
        ss << (message.empty() ? "String does not start with expected prefix" : message);
        throw AssertionError(ss.str());
    }
}

void Assert::endsWith(const std::string& str, const std::string& suffix, const std::string& message) {
    if (str.size() < suffix.size() || str.substr(str.size() - suffix.size()) != suffix) {
        std::stringstream ss;
        ss << (message.empty() ? "String does not end with expected suffix" : message);
        throw AssertionError(ss.str());
    }
}

void Assert::completesWithin(std::function<void()> func, std::chrono::milliseconds timeout,
                            const std::string& message) {
    auto start = std::chrono::steady_clock::now();
    func();
    auto elapsed = std::chrono::steady_clock::now() - start;
    if (elapsed > timeout) {
        std::stringstream ss;
        ss << (message.empty() ? "Operation exceeded timeout" : message)
           << " (timeout: " << timeout.count() << "ms, elapsed: " 
           << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << "ms)";
        throw AssertionError(ss.str());
    }
}

// ============================================================================
// TestRunner Implementation
// ============================================================================

TestRunner::TestRunner() : parallel_(false), maxParallel_(4), outputFormat_("console") {}

TestRunner::~TestRunner() = default;

void TestRunner::registerTest(const TestCase& test) {
    tests_.push_back(test);
}

void TestRunner::registerSuite(const TestSuiteConfig& suite) {
    suites_[suite.name] = suite;
}

void TestRunner::registerFixture(const std::string& name, 
                                 std::function<std::unique_ptr<TestFixture>()> factory) {
    fixtures_[name] = factory;
}

std::vector<TestResultDetail> TestRunner::runAll() {
    std::vector<TestResultDetail> results;
    
    if (parallel_ && maxParallel_ > 1) {
        // Parallel execution
        std::vector<std::future<TestResultDetail>> futures;
        
        for (const auto& test : tests_) {
            if (shouldRun(test)) {
                futures.push_back(std::async(std::launch::async, [this, &test]() {
                    return executeTest(test);
                }));
                
                // Limit concurrent tests
                if (futures.size() >= maxParallel_) {
                    for (auto& f : futures) {
                        results.push_back(f.get());
                    }
                    futures.clear();
                }
            }
        }
        
        // Wait for remaining tests
        for (auto& f : futures) {
            results.push_back(f.get());
        }
    } else {
        // Sequential execution
        for (const auto& test : tests_) {
            if (shouldRun(test)) {
                results.push_back(executeTest(test));
            }
        }
    }
    
    return results;
}

std::vector<TestResultDetail> TestRunner::runSuite(const std::string& suiteName) {
    std::vector<TestResultDetail> results;
    
    for (const auto& test : tests_) {
        if (test.suite == suiteName && shouldRun(test)) {
            results.push_back(executeTest(test));
        }
    }
    
    return results;
}

std::vector<TestResultDetail> TestRunner::runTest(const std::string& testName) {
    std::vector<TestResultDetail> results;
    
    for (const auto& test : tests_) {
        if (test.name == testName && shouldRun(test)) {
            results.push_back(executeTest(test));
            break;
        }
    }
    
    return results;
}

std::vector<TestResultDetail> TestRunner::runWithTag(const std::string& tag) {
    std::vector<TestResultDetail> results;
    
    for (const auto& test : tests_) {
        if (std::find(test.tags.begin(), test.tags.end(), tag) != test.tags.end() && shouldRun(test)) {
            results.push_back(executeTest(test));
        }
    }
    
    return results;
}

TestResultDetail TestRunner::executeTest(const TestCase& test) {
    TestResultDetail result;
    result.testName = test.name;
    result.suite = test.suite;
    result.startTime = std::chrono::steady_clock::now();
    
    if (!test.enabled) {
        result.result = TestResult::SKIPPED;
        result.message = "Test disabled";
        result.endTime = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(result.endTime - result.startTime);
        return result;
    }
    
    try {
        // Setup fixture if available
        std::unique_ptr<TestFixture> fixture;
        auto suiteIt = suites_.find(test.suite);
        if (suiteIt != suites_.end() && !suiteIt->second.fixtures.empty()) {
            auto fixtureIt = fixtures_.find(suiteIt->second.fixtures.begin()->second);
            if (fixtureIt != fixtures_.end()) {
                fixture = fixtureIt->second();
                fixture->setUp();
            }
        }
        
        // Run test with timeout
        auto testFuture = std::async(std::launch::async, test.test);
        
        if (testFuture.wait_for(test.timeout) == std::future_status::timeout) {
            result.result = TestResult::FAILED;
            result.message = "Test timed out after " + std::to_string(test.timeout.count()) + "ms";
        } else {
            testFuture.get();
            result.result = TestResult::PASSED;
            result.message = "Test passed";
        }
        
        // Teardown fixture
        if (fixture) {
            fixture->tearDown();
        }
        
    } catch (const AssertionError& e) {
        result.result = TestResult::FAILED;
        result.message = e.what();
    } catch (const std::exception& e) {
        result.result = TestResult::ERROR;
        result.message = std::string("Exception: ") + e.what();
        result.error = std::current_exception();
    } catch (...) {
        result.result = TestResult::ERROR;
        result.message = "Unknown exception";
    }
    
    result.endTime = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(result.endTime - result.startTime);
    
    return result;
}

bool TestRunner::shouldRun(const TestCase& test) const {
    if (!filter_.empty()) {
        // Simple filter matching
        return test.name.find(filter_) != std::string::npos ||
               test.suite.find(filter_) != std::string::npos;
    }
    return true;
}

void TestRunner::printResults(const std::vector<TestResultDetail>& results) {
    if (outputFormat_ == "console") {
        std::cout << "\n========== Test Results ==========\n\n";
        
        uint32_t passed = 0, failed = 0, skipped = 0, errors = 0;
        
        for (const auto& result : results) {
            switch (result.result) {
                case TestResult::PASSED:
                    std::cout << "[PASS] ";
                    passed++;
                    break;
                case TestResult::FAILED:
                    std::cout << "[FAIL] ";
                    failed++;
                    break;
                case TestResult::SKIPPED:
                    std::cout << "[SKIP] ";
                    skipped++;
                    break;
                case TestResult::ERROR:
                    std::cout << "[ERR ] ";
                    errors++;
                    break;
            }
            
            std::cout << result.suite << "::" << result.testName;
            std::cout << " (" << result.duration.count() << "ms)";
            
            if (result.result != TestResult::PASSED) {
                std::cout << "\n       " << result.message;
            }
            std::cout << "\n";
        }
        
        std::cout << "\n========== Summary ==========\n";
        std::cout << "Total:  " << results.size() << "\n";
        std::cout << "Passed: " << passed << "\n";
        std::cout << "Failed: " << failed << "\n";
        std::cout << "Skipped:" << skipped << "\n";
        std::cout << "Errors: " << errors << "\n";
        
        auto stats = getStats(results);
        std::cout << "Time:   " << stats.totalDuration.count() << "ms\n";
    }
}

std::string TestRunner::exportResults(const std::vector<TestResultDetail>& results, 
                                      const std::string& format) {
    std::stringstream ss;
    
    if (format == "json") {
        ss << "{\n";
        ss << "  \"tests\": [\n";
        
        bool first = true;
        for (const auto& result : results) {
            if (!first) ss << ",\n";
            first = false;
            
            ss << "    {\n";
            ss << "      \"name\": \"" << result.testName << "\",\n";
            ss << "      \"suite\": \"" << result.suite << "\",\n";
            ss << "      \"result\": \"";
            switch (result.result) {
                case TestResult::PASSED: ss << "passed"; break;
                case TestResult::FAILED: ss << "failed"; break;
                case TestResult::SKIPPED: ss << "skipped"; break;
                case TestResult::ERROR: ss << "error"; break;
            }
            ss << "\",\n";
            ss << "      \"duration\": " << result.duration.count() << ",\n";
            ss << "      \"message\": \"" << result.message << "\"\n";
            ss << "    }";
        }
        
        ss << "\n  ]\n";
        ss << "}\n";
    } else if (format == "junit") {
        // JUnit XML format
        ss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        ss << "<testsuites>\n";
        
        auto stats = getStats(results);
        ss << "  <testsuite name=\"RawrXD\" tests=\"" << stats.totalTests 
           << "\" failures=\"" << stats.failed 
           << "\" errors=\"" << stats.errors 
           << "\" skipped=\"" << stats.skipped 
           << "\" time=\"" << (stats.totalDuration.count() / 1000.0) << "\">\n";
        
        for (const auto& result : results) {
            ss << "    <testcase name=\"" << result.testName 
               << "\" classname=\"" << result.suite 
               << "\" time=\"" << (result.duration.count() / 1000.0) << "\"";
            
            if (result.result == TestResult::PASSED) {
                ss << "/>\n";
            } else {
                ss << ">\n";
                if (result.result == TestResult::FAILED) {
                    ss << "      <failure message=\"" << result.message << "\"/>\n";
                } else if (result.result == TestResult::ERROR) {
                    ss << "      <error message=\"" << result.message << "\"/>\n";
                } else if (result.result == TestResult::SKIPPED) {
                    ss << "      <skipped/>\n";
                }
                ss << "    </testcase>\n";
            }
        }
        
        ss << "  </testsuite>\n";
        ss << "</testsuites>\n";
    }
    
    return ss.str();
}

TestRunner::TestStats TestRunner::getStats(const std::vector<TestResultDetail>& results) const {
    TestStats stats{};
    stats.totalTests = results.size();
    
    for (const auto& result : results) {
        switch (result.result) {
            case TestResult::PASSED:
                stats.passed++;
                break;
            case TestResult::FAILED:
                stats.failed++;
                break;
            case TestResult::SKIPPED:
                stats.skipped++;
                break;
            case TestResult::ERROR:
                stats.errors++;
                break;
        }
        
        stats.totalDuration += result.duration;
        stats.bySuite[result.suite]++;
    }
    
    return stats;
}

// ============================================================================
// Benchmark Implementation
// ============================================================================

BenchmarkResult Benchmark::run(const std::string& name, std::function<void()> func, 
                               uint64_t iterations) {
    BenchmarkResult result;
    result.name = name;
    result.iterations = iterations;
    
    // Warmup
    for (uint64_t i = 0; i < std::min(iterations / 10, uint64_t(100)); ++i) {
        func();
    }
    
    // Actual benchmark
    auto start = std::chrono::steady_clock::now();
    auto minTime = std::chrono::nanoseconds::max();
    auto maxTime = std::chrono::nanoseconds::min();
    
    for (uint64_t i = 0; i < iterations; ++i) {
        auto iterStart = std::chrono::steady_clock::now();
        func();
        auto iterEnd = std::chrono::steady_clock::now();
        
        auto iterDuration = iterEnd - iterStart;
        if (iterDuration < minTime) minTime = iterDuration;
        if (iterDuration > maxTime) maxTime = iterDuration;
    }
    
    auto end = std::chrono::steady_clock::now();
    
    result.totalTime = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    result.avgTime = result.totalTime / iterations;
    result.minTime = minTime;
    result.maxTime = maxTime;
    result.throughput = static_cast<double>(iterations) / 
                        (std::chrono::duration_cast<std::chrono::duration<double>>(result.totalTime).count());
    
    return result;
}

void Benchmark::compare(const std::vector<BenchmarkResult>& results) {
    if (results.empty()) return;
    
    std::cout << "\n========== Benchmark Comparison ==========\n";
    std::cout << std::left << std::setw(30) << "Name" 
              << std::right << std::setw(15) << "Avg (ns)" 
              << std::setw(15) << "Min (ns)" 
              << std::setw(15) << "Max (ns)" 
              << std::setw(15) << "Ops/sec" << "\n";
    std::cout << std::string(90, '-') << "\n";
    
    auto baseline = results[0].avgTime;
    
    for (const auto& result : results) {
        double ratio = static_cast<double>(result.avgTime.count()) / baseline.count();
        
        std::cout << std::left << std::setw(30) << result.name
                  << std::right << std::setw(15) << result.avgTime.count()
                  << std::setw(15) << result.minTime.count()
                  << std::setw(15) << result.maxTime.count()
                  << std::setw(15) << std::fixed << std::setprecision(2) << result.throughput;
        
        if (&result != &results[0]) {
            std::cout << " (" << std::fixed << std::setprecision(2) << ratio << "x)";
        }
        std::cout << "\n";
    }
}

void Benchmark::print(const BenchmarkResult& result) {
    std::cout << "\n========== Benchmark: " << result.name << " ==========\n";
    std::cout << "Iterations: " << result.iterations << "\n";
    std::cout << "Total time: " << result.totalTime.count() << " ns\n";
    std::cout << "Avg time:   " << result.avgTime.count() << " ns\n";
    std::cout << "Min time:   " << result.minTime.count() << " ns\n";
    std::cout << "Max time:   " << result.maxTime.count() << " ns\n";
    std::cout << "Throughput: " << std::fixed << std::setprecision(2) << result.throughput << " ops/sec\n";
}

} // namespace Testing
} // namespace RawrXD
