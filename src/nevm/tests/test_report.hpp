//============================================================================
// test_report.hpp
// RawrXD N-EVM - Test Report Generator
//============================================================================

#pragma once

#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>

namespace RawrXD {
namespace NEVM {
namespace TestReport {

//============================================================================
// Test Result Structure
//============================================================================

struct TestCaseResult {
    std::string name;
    bool passed;
    double duration_ms;
    std::string error_message;
    std::string file;
    int line;
};

struct TestSuiteResult {
    std::string name;
    std::vector<TestCaseResult> tests;
    
    size_t GetPassedCount() const {
        size_t count = 0;
        for (const auto& test : tests) {
            if (test.passed) ++count;
        }
        return count;
    }
    
    size_t GetFailedCount() const {
        return tests.size() - GetPassedCount();
    }
    
    double GetTotalDuration() const {
        double total = 0.0;
        for (const auto& test : tests) {
            total += test.duration_ms;
        }
        return total;
    }
};

struct TestRunResult {
    std::vector<TestSuiteResult> suites;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    
    size_t GetTotalTests() const {
        size_t total = 0;
        for (const auto& suite : suites) {
            total += suite.tests.size();
        }
        return total;
    }
    
    size_t GetPassedCount() const {
        size_t count = 0;
        for (const auto& suite : suites) {
            count += suite.GetPassedCount();
        }
        return count;
    }
    
    size_t GetFailedCount() const {
        size_t count = 0;
        for (const auto& suite : suites) {
            count += suite.GetFailedCount();
        }
        return count;
    }
    
    double GetPassRate() const {
        size_t total = GetTotalTests();
        return total > 0 ? static_cast<double>(GetPassedCount()) / total : 0.0;
    }
    
    double GetTotalDuration() const {
        double total = 0.0;
        for (const auto& suite : suites) {
            total += suite.GetTotalDuration();
        }
        return total;
    }
};

//============================================================================
// Report Formatters
//============================================================================

class ReportFormatter {
public:
    virtual ~ReportFormatter() = default;
    virtual std::string Format(const TestRunResult& result) = 0;
};

// Console formatter with colors
class ConsoleFormatter : public ReportFormatter {
public:
    std::string Format(const TestRunResult& result) override {
        std::ostringstream oss;
        
        // Header
        oss << "\n";
        oss << "================================================================================\n";
        oss << "                         RawrXD N-EVM Test Results                              \n";
        oss << "================================================================================\n";
        oss << "\n";
        
        // Summary
        auto now = std::chrono::system_clock::to_time_t(result.end_time);
        oss << "Timestamp: " << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S") << "\n";
        oss << "Duration: " << std::fixed << std::setprecision(2) << result.GetTotalDuration() << " ms\n";
        oss << "\n";
        
        // Statistics
        oss << "Total Tests: " << result.GetTotalTests() << "\n";
        oss << "Passed: " << ColorGreen() << result.GetPassedCount() << ColorReset() << "\n";
        oss << "Failed: " << ColorRed() << result.GetFailedCount() << ColorReset() << "\n";
        oss << "Pass Rate: " << std::fixed << std::setprecision(1) << (result.GetPassRate() * 100.0) << "%\n";
        oss << "\n";
        
        // Suite details
        for (const auto& suite : result.suites) {
            if (suite.tests.empty()) continue;
            
            oss << "--------------------------------------------------------------------------------\n";
            oss << "Suite: " << suite.name << "\n";
            oss << "Tests: " << suite.tests.size() << " | ";
            oss << "Passed: " << ColorGreen() << suite.GetPassedCount() << ColorReset() << " | ";
            oss << "Failed: " << ColorRed() << suite.GetFailedCount() << ColorReset() << " | ";
            oss << "Duration: " << suite.GetTotalDuration() << " ms\n";
            oss << "--------------------------------------------------------------------------------\n";
            
            // Individual tests
            for (const auto& test : suite.tests) {
                if (test.passed) {
                    oss << "  [" << ColorGreen() << "PASS" << ColorReset() << "] ";
                } else {
                    oss << "  [" << ColorRed() << "FAIL" << ColorReset() << "] ";
                }
                oss << test.name;
                oss << " (" << std::fixed << std::setprecision(2) << test.duration_ms << " ms)";
                
                if (!test.passed && !test.error_message.empty()) {
                    oss << "\n      Error: " << test.error_message;
                }
                oss << "\n";
            }
            oss << "\n";
        }
        
        // Footer
        oss << "================================================================================\n";
        if (result.GetFailedCount() == 0) {
            oss << ColorGreen() << "All tests passed!" << ColorReset() << "\n";
        } else {
            oss << ColorRed() << "Some tests failed!" << ColorReset() << "\n";
        }
        oss << "================================================================================\n";
        
        return oss.str();
    }
    
private:
    std::string ColorGreen() const {
        #ifdef _WIN32
        return "";
        #else
        return "\033[32m";
        #endif
    }
    
    std::string ColorRed() const {
        #ifdef _WIN32
        return "";
        #else
        return "\033[31m";
        #endif
    }
    
    std::string ColorReset() const {
        #ifdef _WIN32
        return "";
        #else
        return "\033[0m";
        #endif
    }
};

// JUnit XML formatter for CI/CD
class JUnitFormatter : public ReportFormatter {
public:
    std::string Format(const TestRunResult& result) override {
        std::ostringstream oss;
        
        // XML header
        oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?\u003e\n";
        
        // Calculate totals
        size_t total_tests = result.GetTotalTests();
        size_t failures = result.GetFailedCount();
        double total_time = result.GetTotalDuration() / 1000.0; // Convert to seconds
        
        // Test suites
        oss << "<testsuites name=\"RawrXD N-EVM Tests\" tests=\"" << total_tests << "\"";
        oss << " failures=\"" << failures << "\"";
        oss << " time=\"" << std::fixed << std::setprecision(3) << total_time << "\"\u003e\n";
        
        for (const auto& suite : result.suites) {
            if (suite.tests.empty()) continue;
            
            double suite_time = suite.GetTotalDuration() / 1000.0;
            
            oss << "  <testsuite name=\"" << EscapeXml(suite.name) << "\"";
            oss << " tests=\"" << suite.tests.size() << "\"";
            oss << " failures=\"" << suite.GetFailedCount() << "\"";
            oss << " time=\"" << std::fixed << std::setprecision(3) << suite_time << "\"\u003e\n";
            
            for (const auto& test : suite.tests) {
                double test_time = test.duration_ms / 1000.0;
                
                oss << "    <testcase name=\"" << EscapeXml(test.name) << "\"";
                oss << " time=\"" << std::fixed << std::setprecision(3) << test_time << "\"";
                oss << " file=\"" << EscapeXml(test.file) << "\"";
                oss << " line=\"" << test.line << "\"\u003e\n";
                
                if (!test.passed) {
                    oss << "      <failure message=\"" << EscapeXml(test.error_message) << "\"\u003e\n";
                    oss << "        Test failed: " << EscapeXml(test.name) << "\n";
                    oss << "        Location: " << test.file << ":" << test.line << "\n";
                    oss << "      </failure\u003e\n";
                }
                
                oss << "    </testcase\u003e\n";
            }
            
            oss << "  </testsuite\u003e\n";
        }
        
        oss << "</testsuites\u003e\n";
        
        return oss.str();
    }
    
private:
    std::string EscapeXml(const std::string& input) {
        std::string output;
        for (char c : input) {
            switch (c) {
                case '&': output += "&amp;"; break;
                case '<': output += "&lt;"; break;
                case '>': output += "&gt;"; break;
                case '"': output += "&quot;"; break;
                case '\'': output += "&apos;"; break;
                default: output += c; break;
            }
        }
        return output;
    }
};

// JSON formatter
class JSONFormatter : public ReportFormatter {
public:
    std::string Format(const TestRunResult& result) override {
        std::ostringstream oss;
        
        oss << "{\n";
        
        // Summary
        auto now = std::chrono::system_clock::to_time_t(result.end_time);
        oss << "  \"timestamp\": \"" << std::put_time(std::localtime(&now), "%Y-%m-%dT%H:%M:%S") << "\",\n";
        oss << "  \"summary\": {\n";
        oss << "    \"total\": " << result.GetTotalTests() << ",\n";
        oss << "    \"passed\": " << result.GetPassedCount() << ",\n";
        oss << "    \"failed\": " << result.GetFailedCount() << ",\n";
        oss << "    \"pass_rate\": " << std::fixed << std::setprecision(4) << result.GetPassRate() << ",\n";
        oss << "    \"duration_ms\": " << std::fixed << std::setprecision(2) << result.GetTotalDuration() << "\n";
        oss << "  },\n";
        
        // Suites
        oss << "  \"suites\": [\n";
        bool first_suite = true;
        for (const auto& suite : result.suites) {
            if (suite.tests.empty()) continue;
            
            if (!first_suite) oss << ",\n";
            first_suite = false;
            
            oss << "    {\n";
            oss << "      \"name\": \"" << EscapeJson(suite.name) << "\",\n";
            oss << "      \"tests\": " << suite.tests.size() << ",\n";
            oss << "      \"passed\": " << suite.GetPassedCount() << ",\n";
            oss << "      \"failed\": " << suite.GetFailedCount() << ",\n";
            oss << "      \"duration_ms\": " << std::fixed << std::setprecision(2) << suite.GetTotalDuration() << ",\n";
            
            // Test cases
            oss << "      \"test_cases\": [\n";
            bool first_test = true;
            for (const auto& test : suite.tests) {
                if (!first_test) oss << ",\n";
                first_test = false;
                
                oss << "        {\n";
                oss << "          \"name\": \"" << EscapeJson(test.name) << "\",\n";
                oss << "          \"passed\": " << (test.passed ? "true" : "false") << ",\n";
                oss << "          \"duration_ms\": " << std::fixed << std::setprecision(2) << test.duration_ms;
                if (!test.error_message.empty()) {
                    oss << ",\n          \"error\": \"" << EscapeJson(test.error_message) << "\"";
                }
                oss << "\n        }";
            }
            oss << "\n      ]\n";
            oss << "    }";
        }
        oss << "\n  ]\n";
        
        oss << "}\n";
        
        return oss.str();
    }
    
private:
    std::string EscapeJson(const std::string& input) {
        std::string output;
        for (char c : input) {
            switch (c) {
                case '"': output += "\\\""; break;
                case '\\': output += "\\\\"; break;
                case '\b': output += "\\b"; break;
                case '\f': output += "\\f"; break;
                case '\n': output += "\\n"; break;
                case '\r': output += "\\r"; break;
                case '\t': output += "\\t"; break;
                default:
                    if (c >= 0x20 && c <= 0x7E) {
                        output += c;
                    } else {
                        char buf[7];
                        snprintf(buf, sizeof(buf), "\\u%04x", c);
                        output += buf;
                    }
                    break;
            }
        }
        return output;
    }
};

//============================================================================
// Report Writer
//============================================================================

class ReportWriter {
public:
    static bool WriteToFile(const std::string& filename, const std::string& content) {
        std::ofstream file(filename);
        if (!file.is_open()) {
            return false;
        }
        file << content;
        return file.good();
    }
    
    static void WriteToConsole(const std::string& content) {
        std::cout << content;
    }
};

} // namespace TestReport
} // namespace NEVM
} // namespace RawrXD
