//============================================================================
// test_runner.hpp
// RawrXD N-EVM - Enhanced Test Runner
//============================================================================

#pragma once

#include "test_report.hpp"
#include <string>
#include <vector>
#include <functional>
#include <algorithm>

namespace RawrXD {
namespace NEVM {
namespace TestRunner {

//============================================================================
// Command Line Options
//============================================================================

struct TestOptions {
    std::string filter;
    std::string output_format = "console";
    std::string output_file;
    bool verbose = false;
    bool list_tests = false;
    bool stop_on_failure = false;
    int repeat_count = 1;
    double timeout_seconds = 300.0; // 5 minutes default
    
    static TestOptions Parse(int argc, char** argv) {
        TestOptions options;
        
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            
            if (arg == "--filter" && i + 1 < argc) {
                options.filter = argv[++i];
            } else if (arg == "--format" && i + 1 < argc) {
                options.output_format = argv[++i];
            } else if (arg == "--output" && i + 1 < argc) {
                options.output_file = argv[++i];
            } else if (arg == "--verbose" || arg == "-v") {
                options.verbose = true;
            } else if (arg == "--list") {
                options.list_tests = true;
            } else if (arg == "--stop-on-failure") {
                options.stop_on_failure = true;
            } else if (arg == "--repeat" && i + 1 < argc) {
                options.repeat_count = std::atoi(argv[++i]);
            } else if (arg == "--timeout" && i + 1 < argc) {
                options.timeout_seconds = std::atof(argv[++i]);
            } else if (arg == "--help" || arg == "-h") {
                PrintHelp();
                std::exit(0);
            }
        }
        
        return options;
    }
    
    static void PrintHelp() {
        std::cout << "RawrXD N-EVM Test Runner\n";
        std::cout << "Usage: nevm_tests [options]\n\n";
        std::cout << "Options:\n";
        std::cout << "  --filter <pattern>     Run only tests matching pattern (supports * wildcards)\n";
        std::cout << "  --format <format>      Output format: console, junit, json (default: console)\n";
        std::cout << "  --output <file>         Write output to file\n";
        std::cout << "  --verbose, -v          Enable verbose output\n";
        std::cout << "  --list                 List all available tests\n";
        std::cout << "  --stop-on-failure      Stop after first failure\n";
        std::cout << "  --repeat <n>           Repeat tests n times\n";
        std::cout << "  --timeout <seconds>   Test timeout (default: 300)\n";
        std::cout << "  --help, -h             Show this help message\n";
    }
};

//============================================================================
// Test Filter
//============================================================================

class TestFilter {
public:
    explicit TestFilter(const std::string& pattern) : pattern_(pattern) {}
    
    bool Matches(const std::string& test_name) const {
        if (pattern_.empty()) {
            return true;
        }
        
        // Simple wildcard matching
        return WildcardMatch(test_name, pattern_);
    }
    
private:
    std::string pattern_;
    
    bool WildcardMatch(const std::string& text, const std::string& pattern) const {
        size_t text_idx = 0;
        size_t pattern_idx = 0;
        size_t star_idx = std::string::npos;
        size_t match_idx = 0;
        
        while (text_idx < text.size()) {
            if (pattern_idx < pattern.size() && 
                (pattern[pattern_idx] == '?' || pattern[pattern_idx] == text[text_idx])) {
                ++text_idx;
                ++pattern_idx;
            } else if (pattern_idx < pattern.size() && pattern[pattern_idx] == '*') {
                star_idx = pattern_idx;
                match_idx = text_idx;
                ++pattern_idx;
            } else if (star_idx != std::string::npos) {
                pattern_idx = star_idx + 1;
                text_idx = ++match_idx;
            } else {
                return false;
            }
        }
        
        while (pattern_idx < pattern.size() && pattern[pattern_idx] == '*') {
            ++pattern_idx;
        }
        
        return pattern_idx == pattern.size();
    }
};

//============================================================================
// Progress Reporter
//============================================================================

class ProgressReporter {
public:
    ProgressReporter(size_t total_tests, bool verbose) 
        : total_tests_(total_tests), verbose_(verbose), current_(0) {}
    
    void OnTestStart(const std::string& test_name) {
        ++current_;
        if (verbose_) {
            std::cout << "[" << current_ << "/" << total_tests_ << "] Running: " << test_name << "... ";
            std::cout.flush();
        } else {
            // Simple progress bar
            int percent = static_cast<int>((current_ * 100) / total_tests_);
            if (percent % 10 == 0) {
                std::cout << "\rProgress: [" << percent << "%] " << current_ << "/" << total_tests_;
                std::cout.flush();
            }
        }
    }
    
    void OnTestEnd(bool passed, double duration_ms) {
        if (verbose_) {
            if (passed) {
                std::cout << "PASSED (" << duration_ms << " ms)\n";
            } else {
                std::cout << "FAILED (" << duration_ms << " ms)\n";
            }
        }
    }
    
    void Finish() {
        if (!verbose_) {
            std::cout << "\r" << std::string(50, ' ') << "\r";
        }
    }
    
private:
    size_t total_tests_;
    bool verbose_;
    size_t current_;
};

//============================================================================
// Test Executor
//============================================================================

using TestFunction = std::function<bool()>;

struct TestCase {
    std::string name;
    TestFunction func;
    std::string file;
    int line;
    std::string suite;
};

class TestExecutor {
public:
    void RegisterTest(const std::string& name, TestFunction func, 
                      const std::string& file, int line) {
        TestCase test;
        test.name = name;
        test.func = func;
        test.file = file;
        test.line = line;
        
        // Extract suite name from test name (before first underscore)
        size_t pos = name.find('_');
        if (pos != std::string::npos) {
            test.suite = name.substr(0, pos);
        } else {
            test.suite = "Default";
        }
        
        tests_.push_back(test);
    }
    
    std::vector<std::string> GetTestNames() const {
        std::vector<std::string> names;
        for (const auto& test : tests_) {
            names.push_back(test.name);
        }
        return names;
    }
    
    TestReport::TestRunResult Execute(const TestOptions& options) {
        TestReport::TestRunResult result;
        result.start_time = std::chrono::system_clock::now();
        
        // Filter tests
        std::vector<TestCase> filtered_tests;
        TestFilter filter(options.filter);
        for (const auto& test : tests_) {
            if (filter.Matches(test.name)) {
                filtered_tests.push_back(test);
            }
        }
        
        if (filtered_tests.empty()) {
            std::cerr << "No tests match filter: " << options.filter << "\n";
            result.end_time = std::chrono::system_clock::now();
            return result;
        }
        
        // Group by suite
        std::map<std::string, std::vector<TestCase>> suites;
        for (const auto& test : filtered_tests) {
            suites[test.suite].push_back(test);
        }
        
        // Execute tests
        ProgressReporter reporter(filtered_tests.size() * options.repeat_count, options.verbose);
        
        for (int repeat = 0; repeat < options.repeat_count; ++repeat) {
            for (auto& suite_pair : suites) {
                TestReport::TestSuiteResult suite_result;
                suite_result.name = suite_pair.first;
                
                for (const auto& test : suite_pair.second) {
                    reporter.OnTestStart(test.name);
                    
                    auto test_result = ExecuteSingle(test, options.timeout_seconds);
                    
                    reporter.OnTestEnd(test_result.passed, test_result.duration_ms);
                    suite_result.tests.push_back(test_result);
                    
                    if (!test_result.passed && options.stop_on_failure) {
                        result.suites.push_back(suite_result);
                        result.end_time = std::chrono::system_clock::now();
                        reporter.Finish();
                        return result;
                    }
                }
                
                result.suites.push_back(suite_result);
            }
        }
        
        result.end_time = std::chrono::system_clock::now();
        reporter.Finish();
        
        return result;
    }
    
private:
    std::vector<TestCase> tests_;
    
    TestReport::TestCaseResult ExecuteSingle(const TestCase& test, double timeout_seconds) {
        TestReport::TestCaseResult result;
        result.name = test.name;
        result.file = test.file;
        result.line = test.line;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        try {
            // TODO: Add timeout handling using std::async or platform-specific timers
            result.passed = test.func();
            if (!result.passed) {
                result.error_message = "Assertion failed";
            }
        } catch (const std::exception& e) {
            result.passed = false;
            result.error_message = std::string("Exception: ") + e.what();
        } catch (...) {
            result.passed = false;
            result.error_message = "Unknown exception";
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        result.duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
        
        return result;
    }
};

//============================================================================
// Global Test Registry
//============================================================================

class GlobalTestRegistry {
public:
    static GlobalTestRegistry& Instance() {
        static GlobalTestRegistry instance;
        return instance;
    }
    
    void Register(const std::string& name, TestFunction func, 
                  const std::string& file, int line) {
        executor_.RegisterTest(name, func, file, line);
    }
    
    std::vector<std::string> GetTestNames() const {
        return executor_.GetTestNames();
    }
    
    TestReport::TestRunResult Execute(const TestOptions& options) {
        return executor_.Execute(options);
    }
    
private:
    TestExecutor executor_;
};

// Registration macro
#define REGISTER_TEST(name, func) \
    struct TestRegistrar_##name { \
        TestRegistrar_##name() { \
            RawrXD::NEVM::TestRunner::GlobalTestRegistry::Instance().Register( \
                #name, func, __FILE__, __LINE__); \
        } \
    } test_registrar_##name;

} // namespace TestRunner
} // namespace NEVM
} // namespace RawrXD
