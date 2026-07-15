// Bug Classification System Implementation

#include "bug_classifier.hpp"
#include "../runtime/runtime_minimal.hpp"
#include "../lexer/lexer.hpp"
#include "../parser/parser.hpp"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace RawrXD {
namespace Script {
namespace Tools {

BugClassifier::BugClassifier() {
    // Initialize default classification rules
    
    // Lexer errors
    AddRule({"lexer_error", 
        [](const TestExecution& e) { 
            return e.error_message.find("[Lexer Error]") != std::string::npos;
        },
        BugCategory::LEXER_BUG, "Lexer failed to tokenize valid JavaScript"});
    
    // Parser errors  
    AddRule({"parser_error",
        [](const TestExecution& e) {
            return e.error_message.find("[Parser Error]") != std::string::npos;
        },
        BugCategory::PARSER_BUG, "Parser failed to parse valid JavaScript"});
    
    // Crash detection
    AddRule({"crash",
        [](const TestExecution& e) {
            return e.exit_code < 0 || e.exit_code == 255;
        },
        BugCategory::RUNTIME_BUG, "Process crashed during execution"});
    
    // Timeout
    AddRule({"timeout",
        [](const TestExecution& e) {
            return e.execution_time_ms >= e.test.timeout_ms;
        },
        BugCategory::PERFORMANCE_BUG, "Execution exceeded time limit"});
    
    // Output mismatch
    AddRule({"wrong_output",
        [](const TestExecution& e) {
            return e.result == TestResult::FAIL && e.exit_code == 0;
        },
        BugCategory::SEMANTIC_BUG, "Produced incorrect output"});
}

TestExecution BugClassifier::ExecuteAndClassify(const TestCase& test) {
    TestExecution exec(test);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Execute the test
    FILE* pipe = _popen(("echo \"" + EscapeString(test.source) + "\" | .\\bin\\RawrXD_Script.exe -").c_str(), "r");
    if (!pipe) {
        exec.result = TestResult::UNKNOWN;
        exec.error_message = "Failed to launch process";
        return exec;
    }
    
    char buffer[4096];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    
    exec.exit_code = _pclose(pipe);
    
    auto end = std::chrono::high_resolution_clock::now();
    exec.execution_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    // Trim whitespace from output
    output.erase(0, output.find_first_not_of(" \t\r\n"));
    output.erase(output.find_last_not_of(" \t\r\n") + 1);
    exec.actual_output = output;
    
    // Classify result
    exec.result = ClassifyResult(exec);
    exec.category = CategorizeBug(exec);
    exec.fingerprint = GenerateFingerprint(exec);
    
    return exec;
}

std::vector<TestExecution> BugClassifier::ExecuteSuite(const std::vector<TestCase>& tests) {
    std::vector<TestExecution> results;
    results.reserve(tests.size());
    
    for (const auto& test : tests) {
        results.push_back(ExecuteAndClassify(test));
    }
    
    return results;
}

void BugClassifier::GenerateReport(const std::vector<TestExecution>& results, 
                                   const std::string& output_path) {
    FILE* fp = fopen(output_path.c_str(), "w");
    if (!fp) return;
    
    fprintf(fp, "# RawrXD-Script Bug Classification Report\n\n");
    fprintf(fp, "Generated: %s\n\n", "2026-07-03");
    
    // Summary statistics
    int passed = 0, failed = 0, crashed = 0, timeout = 0, errors = 0;
    std::map<BugCategory, int> category_counts;
    
    for (const auto& r : results) {
        switch (r.result) {
            case TestResult::PASS: passed++; break;
            case TestResult::FAIL: failed++; break;
            case TestResult::CRASH: crashed++; break;
            case TestResult::TIMEOUT: timeout++; break;
            default: errors++; break;
        }
        category_counts[r.category]++;
    }
    
    fprintf(fp, "## Summary\n\n");
    fprintf(fp, "- Total Tests: %zu\n", results.size());
    fprintf(fp, "- Passed: %d (%.1f%%)\n", passed, 100.0 * passed / results.size());
    fprintf(fp, "- Failed: %d\n", failed);
    fprintf(fp, "- Crashed: %d\n", crashed);
    fprintf(fp, "- Timeout: %d\n", timeout);
    fprintf(fp, "- Errors: %d\n\n", errors);
    
    fprintf(fp, "## Bug Categories\n\n");
    for (const auto& [cat, count] : category_counts) {
        if (cat != BugCategory::NONE) {
            fprintf(fp, "- %s: %d\n", CategoryToString(cat).c_str(), count);
        }
    }
    
    fprintf(fp, "\n## Detailed Results\n\n");
    fprintf(fp, "| Test | Result | Category | Time (ms) | Output |\n");
    fprintf(fp, "|------|--------|----------|-----------|--------|\n");
    
    for (const auto& r : results) {
        fprintf(fp, "| %s | %s | %s | %d | %s |\n",
                r.test.name.c_str(),
                ResultToString(r.result).c_str(),
                CategoryToString(r.category).c_str(),
                r.execution_time_ms,
                r.actual_output.substr(0, 30).c_str());
    }
    
    fclose(fp);
}

void BugClassifier::AddRule(const ClassificationRule& rule) {
    rules_.push_back(rule);
}

TestResult BugClassifier::ClassifyResult(const TestExecution& exec) {
    if (exec.exit_code < 0) return TestResult::CRASH;
    if (exec.execution_time_ms >= exec.test.timeout_ms) return TestResult::TIMEOUT;
    if (exec.exit_code != 0) return TestResult::PARSE_ERROR;
    if (exec.actual_output == exec.test.expected_output) return TestResult::PASS;
    return TestResult::FAIL;
}

BugCategory BugClassifier::CategorizeBug(const TestExecution& exec) {
    for (const auto& rule : rules_) {
        if (rule.matcher(exec)) {
            return rule.category;
        }
    }
    return BugCategory::UNKNOWN_BUG;
}

std::string BugClassifier::GenerateFingerprint(const TestExecution& exec) {
    return ComputeFingerprint(exec.test.source, exec.actual_output);
}

std::string BugClassifier::ComputeFingerprint(const std::string& source, 
                                              const std::string& output) {
    // Simple hash for now - in production use SHA256
    std::hash<std::string> hasher;
    std::string combined = source + "::" + output;
    std::stringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << hasher(combined);
    return ss.str();
}

std::vector<TestExecution> BugClassifier::DetectRegressions(
    const std::vector<TestExecution>& baseline,
    const std::vector<TestExecution>& current) {
    
    std::vector<TestExecution> regressions;
    
    for (size_t i = 0; i < std::min(baseline.size(), current.size()); i++) {
        if (baseline[i].result == TestResult::PASS && current[i].result != TestResult::PASS) {
            regressions.push_back(current[i]);
        }
    }
    
    return regressions;
}

// Built-in test corpus
std::vector<TestCase> GetMinimalTestCorpus() {
    return {
        {"literal_42", "42", "42"},
        {"literal_0", "0", "0"},
        {"literal_negative", "-5", "-5"},
        {"literal_float", "3.14", "3.14"},
        {"literal_true", "true", "true"},
        {"literal_false", "false", "false"},
        {"literal_null", "null", "null"},
        {"literal_undefined", "undefined", "undefined"},
    };
}

std::vector<TestCase> GetES5TestCorpus() {
    auto tests = GetMinimalTestCorpus();
    
    // Add arithmetic tests
    tests.push_back({"add_simple", "2 + 3", "5"});
    tests.push_back({"sub_simple", "5 - 2", "3"});
    tests.push_back({"mul_simple", "3 * 4", "12"});
    tests.push_back({"div_simple", "10 / 2", "5"});
    
    // Add variable tests
    tests.push_back({"var_declare", "var x = 5; x", "5"});
    tests.push_back({"let_declare", "let x = 10; x", "10"});
    tests.push_back({"const_declare", "const x = 15; x", "15"});
    
    // Add function tests
    tests.push_back({"function_declare", "function f() { return 42; } f()", "42"});
    tests.push_back({"function_params", "function add(a, b) { return a + b; } add(2, 3)", "5"});
    
    return tests;
}

std::vector<TestCase> GetEdgeCaseCorpus() {
    return {
        {"empty", "", "undefined"},
        {"whitespace", "   \n\t  ", "undefined"},
        {"large_number", "9999999999999", "9999999999999"},
        {"small_number", "0.0000001", "1e-07"},
        {"unicode_string", "'hello'", "hello"},
    };
}

std::string ResultToString(TestResult result) {
    switch (result) {
        case TestResult::PASS: return "PASS";
        case TestResult::FAIL: return "FAIL";
        case TestResult::CRASH: return "CRASH";
        case TestResult::TIMEOUT: return "TIMEOUT";
        case TestResult::PARSE_ERROR: return "PARSE_ERROR";
        case TestResult::LEX_ERROR: return "LEX_ERROR";
        case TestResult::UNIMPLEMENTED: return "UNIMPLEMENTED";
        default: return "UNKNOWN";
    }
}

std::string CategoryToString(BugCategory category) {
    switch (category) {
        case BugCategory::NONE: return "NONE";
        case BugCategory::LEXER_BUG: return "LEXER";
        case BugCategory::PARSER_BUG: return "PARSER";
        case BugCategory::SEMANTIC_BUG: return "SEMANTIC";
        case BugCategory::CODEGEN_BUG: return "CODEGEN";
        case BugCategory::RUNTIME_BUG: return "RUNTIME";
        case BugCategory::MEMORY_BUG: return "MEMORY";
        case BugCategory::PERFORMANCE_BUG: return "PERFORMANCE";
        case BugCategory::COMPATIBILITY_BUG: return "COMPATIBILITY";
        default: return "UNKNOWN";
    }
}

std::string EscapeString(const std::string& input) {
    std::string output;
    for (char c : input) {
        switch (c) {
            case '"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default: output += c; break;
        }
    }
    return output;
}

} // namespace Tools
} // namespace Script
} // namespace RawrXD
