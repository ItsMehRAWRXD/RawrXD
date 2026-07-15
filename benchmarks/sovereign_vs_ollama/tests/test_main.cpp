// Main Test Runner Entry Point
// Copyright (c) 2026 RawrXD Team

#include "http_client_tests.hpp"
#include "backend_adapter_tests.hpp"
#include "end_to_end_tests.hpp"
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <chrono>

using namespace rawrxd::benchmark::testing;

// ============================================================================
// Command Line Options
// ============================================================================

struct TestOptions {
    std::string category = "all";
    std::string output_format = "console";
    std::string output_file;
    bool verbose = false;
    bool use_mock = true;
    int timeout_seconds = 300;
    std::vector<std::string> specific_tests;
    bool list_tests = false;
    bool help = false;
};

TestOptions ParseArgs(int argc, char** argv) {
    TestOptions options;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--category" || arg == "-c") {
            if (i + 1 < argc) options.category = argv[++i];
        } else if (arg == "--output" || arg == "-o") {
            if (i + 1 < argc) options.output_file = argv[++i];
        } else if (arg == "--format" || arg == "-f") {
            if (i + 1 < argc) options.output_format = argv[++i];
        } else if (arg == "--verbose" || arg == "-v") {
            options.verbose = true;
        } else if (arg == "--real-backends" || arg == "-r") {
            options.use_mock = false;
        } else if (arg == "--timeout" || arg == "-t") {
            if (i + 1 < argc) options.timeout_seconds = std::stoi(argv[++i]);
        } else if (arg == "--test" || arg == "-T") {
            if (i + 1 < argc) options.specific_tests.push_back(argv[++i]);
        } else if (arg == "--list" || arg == "-l") {
            options.list_tests = true;
        } else if (arg == "--help" || arg == "-h") {
            options.help = true;
        }
    }
    
    return options;
}

void PrintHelp(const char* program_name) {
    std::cout << "RawrXD Benchmark Test Runner\n";
    std::cout << "Usage: " << program_name << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -c, --category <cat>     Test category (all|http|backend|e2e|smoke|integration|performance|regression|chaos)\n";
    std::cout << "  -o, --output <file>     Output file for results\n";
    std::cout << "  -f, --format <fmt>      Output format (console|json|html|junit)\n";
    std::cout << "  -v, --verbose            Enable verbose output\n";
    std::cout << "  -r, --real-backends      Use real backends (requires Sovereign at :8080, Ollama at :11434)\n";
    std::cout << "  -t, --timeout <sec>      Test timeout in seconds (default: 300)\n";
    std::cout << "  -T, --test <name>        Run specific test (can be specified multiple times)\n";
    std::cout << "  -l, --list               List available tests\n";
    std::cout << "  -h, --help               Show this help message\n";
}

void ListTests() {
    std::cout << "Available Tests:\n\n";
    
    std::cout << "HTTP Client Tests:\n";
    std::cout << "  - connection: Connection management tests\n";
    std::cout << "  - request: HTTP request tests\n";
    std::cout << "  - response: HTTP response tests\n";
    std::cout << "  - retry: Retry policy tests\n";
    std::cout << "  - timeout: Timeout handling tests\n";
    std::cout << "  - pool: Connection pool tests\n";
    std::cout << "  - url: URL parsing tests\n";
    std::cout << "  - utility: Utility function tests\n\n";
    
    std::cout << "Backend Adapter Tests:\n";
    std::cout << "  - sovereign: Sovereign backend tests\n";
    std::cout << "  - ollama: Ollama backend tests\n";
    std::cout << "  - comparison: Backend comparison tests\n";
    std::cout << "  - factory: Backend factory tests\n";
    std::cout << "  - health: Health check tests\n\n";
    
    std::cout << "End-to-End Tests:\n";
    std::cout << "  - smoke: Quick smoke tests\n";
    std::cout << "  - integration: Full integration tests\n";
    std::cout << "  - performance: Performance validation tests\n";
    std::cout << "  - regression: Regression detection tests\n";
    std::cout << "  - chaos: Chaos engineering tests\n";
}

// ============================================================================
// Test Execution
// ============================================================================

std::vector<TestResult> RunTests(const TestOptions& options) {
    std::vector<TestResult> results;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    if (options.category == "all" || options.category == "http") {
        if (options.verbose) std::cout << "\n=== Running HTTP Client Tests ===\n";
        auto http_results = HttpClientTestSuite::RunAllTests();
        results.insert(results.end(), http_results.begin(), http_results.end());
    }
    
    if (options.category == "all" || options.category == "backend") {
        if (options.verbose) std::cout << "\n=== Running Backend Adapter Tests ===\n";
        auto backend_results = BackendAdapterTestSuite::RunAllTests();
        results.insert(results.end(), backend_results.begin(), backend_results.end());
    }
    
    if (options.category == "all" || options.category == "e2e" || options.category == "smoke") {
        if (options.verbose) std::cout << "\n=== Running E2E Smoke Tests ===\n";
        auto smoke_results = EndToEndTestSuite::RunSmokeTests();
        results.insert(results.end(), smoke_results.begin(), smoke_results.end());
    }
    
    if (options.category == "all" || options.category == "integration") {
        if (options.verbose) std::cout << "\n=== Running Integration Tests ===\n";
        auto integration_results = EndToEndTestSuite::RunIntegrationTests();
        results.insert(results.end(), integration_results.begin(), integration_results.end());
    }
    
    if (options.category == "all" || options.category == "performance") {
        if (options.verbose) std::cout << "\n=== Running Performance Tests ===\n";
        auto perf_results = EndToEndTestSuite::RunPerformanceTests();
        results.insert(results.end(), perf_results.begin(), perf_results.end());
    }
    
    if (options.category == "all" || options.category == "regression") {
        if (options.verbose) std::cout << "\n=== Running Regression Tests ===\n";
        auto regression_results = EndToEndTestSuite::RunRegressionTests();
        results.insert(results.end(), regression_results.begin(), regression_results.end());
    }
    
    if (options.category == "all" || options.category == "chaos") {
        if (options.verbose) std::cout << "\n=== Running Chaos Tests ===\n";
        auto chaos_results = EndToEndTestSuite::RunChaosTests();
        results.insert(results.end(), chaos_results.begin(), chaos_results.end());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration<double>(end - start).count();
    
    if (options.verbose) {
        std::cout << "\nTotal test time: " << duration << " seconds\n";
    }
    
    return results;
}

// ============================================================================
// Report Generation
// ============================================================================

void PrintConsoleReport(const std::vector<TestResult>& results, bool verbose) {
    int passed = 0, failed = 0;
    
    std::cout << "\n========================================\n";
    std::cout << "Test Results\n";
    std::cout << "========================================\n\n";
    
    for (const auto& r : results) {
        if (r.passed) {
            passed++;
            if (verbose) {
                std::cout << "[PASS] " << r.test_name;
                if (r.duration_ms > 0) {
                    std::cout << " (" << r.duration_ms << " ms)";
                }
                std::cout << "\n";
            }
        } else {
            failed++;
            std::cout << "[FAIL] " << r.test_name;
            if (!r.error_message.empty()) {
                std::cout << ": " << r.error_message;
            }
            std::cout << "\n";
        }
    }
    
    std::cout << "\n========================================\n";
    std::cout << "Summary: " << passed << "/" << results.size() << " passed";
    if (failed > 0) {
        std::cout << " (" << failed << " failed)";
    }
    std::cout << "\n";
    std::cout << "========================================\n";
}

std::string GenerateJsonReport(const std::vector<TestResult>& results) {
    std::ostringstream oss;
    
    int passed = 0, failed = 0;
    for (const auto& r : results) {
        if (r.passed) passed++;
        else failed++;
    }
    
    oss << "{\n";
    oss << "  \"test_run\": {\n";
    oss << "    \"timestamp\": \"" << std::chrono::system_clock::now().time_since_epoch().count() << "\",\n";
    oss << "    \"total_tests\": " << results.size() << ",\n";
    oss << "    \"passed\": " << passed << ",\n";
    oss << "    \"failed\": " << failed << ",\n";
    oss << "    \"success_rate\": " << (100.0 * passed / results.size()) << ",\n";
    oss << "    \"tests\": [\n";
    
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        oss << "      {\n";
        oss << "        \"name\": \"" << r.test_name << "\",\n";
        oss << "        \"passed\": " << (r.passed ? "true" : "false") << ",\n";
        oss << "        \"duration_ms\": " << r.duration_ms << ",\n";
        oss << "        \"error_message\": \"" << r.error_message << "\"\n";
        oss << "      }";
        if (i < results.size() - 1) oss << ",";
        oss << "\n";
    }
    
    oss << "    ]\n";
    oss << "  }\n";
    oss << "}\n";
    
    return oss.str();
}

std::string GenerateHtmlReport(const std::vector<TestResult>& results) {
    std::ostringstream oss;
    
    int passed = 0, failed = 0;
    for (const auto& r : results) {
        if (r.passed) passed++;
        else failed++;
    }
    
    oss << "<!DOCTYPE html>\n";
    oss << "<html>\n";
    oss << "<head>\n";
    oss << "  <title>Test Results</title>\n";
    oss << "  <style>\n";
    oss << "    body { font-family: Arial, sans-serif; margin: 20px; }\n";
    oss << "    .summary { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }\n";
    oss << "    .pass { color: green; }\n";
    oss << "    .fail { color: red; }\n";
    oss << "    table { border-collapse: collapse; width: 100%; }\n";
    oss << "    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n";
    oss << "    th { background-color: #4CAF50; color: white; }\n";
    oss << "    tr:nth-child(even) { background-color: #f2f2f2; }\n";
    oss << "  </style>\n";
    oss << "</head>\n";
    oss << "<body>\n";
    oss << "  <h1>Test Results</h1>\n";
    oss << "  <div class='summary'>\n";
    oss << "    <p><strong>Total Tests:</strong> " << results.size() << "</p>\n";
    oss << "    <p><strong>Passed:</strong> <span class='pass'>" << passed << "</span></p>\n";
    oss << "    <p><strong>Failed:</strong> <span class='fail'>" << failed << "</span></p>\n";
    oss << "    <p><strong>Success Rate:</strong> " << (100.0 * passed / results.size()) << "%</p>\n";
    oss << "  </div>\n";
    oss << "  <table>\n";
    oss << "    <tr><th>Test Name</th><th>Status</th><th>Duration (ms)</th><th>Error</th></tr>\n";
    
    for (const auto& r : results) {
        oss << "    <tr>\n";
        oss << "      <td>" << r.test_name << "</td>\n";
        oss << "      <td class='" << (r.passed ? "pass" : "fail") << "'>" 
            << (r.passed ? "PASS" : "FAIL") << "</td>\n";
        oss << "      <td>" << r.duration_ms << "</td>\n";
        oss << "      <td>" << r.error_message << "</td>\n";
        oss << "    </tr>\n";
    }
    
    oss << "  </table>\n";
    oss << "</body>\n";
    oss << "</html>\n";
    
    return oss.str();
}

std::string GenerateJUnitReport(const std::vector<TestResult>& results) {
    std::ostringstream oss;
    
    int passed = 0, failed = 0;
    double total_time = 0.0;
    for (const auto& r : results) {
        if (r.passed) passed++;
        else failed++;
        total_time += r.duration_ms / 1000.0;
    }
    
    oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?\u003e\n";
    oss << "<testsuites tests=\"" << results.size() << "\" failures=\"" << failed << "\"\n";
    oss << "            time=\"" << total_time << "\"\u003e\n";
    oss << "  <testsuite name=\"RawrXD Benchmark Tests\" tests=\"" << results.size() << "\"\n";
    oss << "             failures=\"" << failed << "\" time=\"" << total_time << "\"\u003e\n";
    
    for (const auto& r : results) {
        oss << "    <testcase name=\"" << r.test_name << "\"\n";
        oss << "              time=\"" << (r.duration_ms / 1000.0) << "\"\u003e\n";
        if (!r.passed) {
            oss << "      <failure message=\"" << r.error_message << "\"/>\n";
        }
        oss << "    </testcase>\n";
    }
    
    oss << "  </testsuite>\n";
    oss << "</testsuites>\n";
    
    return oss.str();
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char** argv) {
    TestOptions options = ParseArgs(argc, argv);
    
    if (options.help) {
        PrintHelp(argv[0]);
        return 0;
    }
    
    if (options.list_tests) {
        ListTests();
        return 0;
    }
    
    std::cout << "RawrXD Benchmark Test Runner\n";
    std::cout << "============================\n";
    std::cout << "Category: " << options.category << "\n";
    std::cout << "Using " << (options.use_mock ? "mock" : "real") << " backends\n";
    std::cout << "Timeout: " << options.timeout_seconds << " seconds\n\n";
    
    // Run tests
    auto results = RunTests(options);
    
    // Generate report
    if (options.output_format == "console") {
        PrintConsoleReport(results, options.verbose);
    }
    
    // Write to file if specified
    if (!options.output_file.empty()) {
        std::ofstream file(options.output_file);
        if (file.is_open()) {
            if (options.output_format == "json") {
                file << GenerateJsonReport(results);
            } else if (options.output_format == "html") {
                file << GenerateHtmlReport(results);
            } else if (options.output_format == "junit") {
                file << GenerateJUnitReport(results);
            } else {
                // Default to text
                for (const auto& r : results) {
                    file << (r.passed ? "[PASS] " : "[FAIL] ") << r.test_name << "\n";
                }
            }
            file.close();
            std::cout << "\nReport written to: " << options.output_file << "\n";
        } else {
            std::cerr << "Failed to write report to: " << options.output_file << "\n";
        }
    }
    
    // Return exit code
    int passed = 0;
    for (const auto& r : results) {
        if (r.passed) passed++;
    }
    
    return (passed == results.size()) ? 0 : 1;
}
