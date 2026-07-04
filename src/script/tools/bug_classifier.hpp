// Bug Classification System for RawrXD-Script
// Automated test classification and fingerprinting

#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <cstdint>

namespace RawrXD {
namespace Script {
namespace Tools {

// Test result categories
enum class TestResult {
    PASS,           // Test executed and produced expected output
    FAIL,           // Test executed but produced wrong output
    CRASH,          // Test caused a crash/segfault
    TIMEOUT,        // Test exceeded time limit
    PARSE_ERROR,    // Parser rejected valid syntax
    LEX_ERROR,      // Lexer rejected valid tokens
    UNIMPLEMENTED,  // Feature not yet implemented
    UNKNOWN         // Could not determine result
};

// Bug classification categories
enum class BugCategory {
    NONE,                   // No bug - test passed
    LEXER_BUG,              // Tokenization issue
    PARSER_BUG,             // AST construction issue
    SEMANTIC_BUG,           // Type checking/validation issue
    CODEGEN_BUG,            // Bytecode generation issue
    RUNTIME_BUG,            // Execution issue
    MEMORY_BUG,             // Memory corruption/leak
    PERFORMANCE_BUG,        // Performance regression
    COMPATIBILITY_BUG,      // ES5 spec violation
    UNKNOWN_BUG
};

// Test case structure
struct TestCase {
    std::string name;
    std::string source;
    std::string expected_output;
    int timeout_ms;
    std::vector<std::string> tags;
    
    TestCase(const std::string& n, const std::string& src, 
             const std::string& exp, int timeout = 5000)
        : name(n), source(src), expected_output(exp), timeout_ms(timeout) {}
};

// Test execution result
struct TestExecution {
    TestCase test;
    TestResult result;
    BugCategory category;
    std::string actual_output;
    std::string error_message;
    int exit_code;
    int execution_time_ms;
    uint64_t memory_used_kb;
    std::string fingerprint;  // SHA256 hash of (source + result)
    
    TestExecution(const TestCase& t) : test(t), result(TestResult::UNKNOWN),
        category(BugCategory::NONE), exit_code(-1), execution_time_ms(0),
        memory_used_kb(0) {}
};

// Classification rule
struct ClassificationRule {
    std::string name;
    std::function<bool(const TestExecution&)> matcher;
    BugCategory category;
    std::string description;
};

// Bug Classifier - Main class
class BugClassifier {
public:
    BugClassifier();
    
    // Execute a single test and classify result
    TestExecution ExecuteAndClassify(const TestCase& test);
    
    // Execute test suite
    std::vector<TestExecution> ExecuteSuite(const std::vector<TestCase>& tests);
    
    // Generate report
    void GenerateReport(const std::vector<TestExecution>& results, 
                       const std::string& output_path);
    
    // Add custom classification rule
    void AddRule(const ClassificationRule& rule);
    
    // Get built-in test corpus
    std::vector<TestCase> GetBuiltInTests();
    
    // Fingerprinting
    static std::string ComputeFingerprint(const std::string& source, 
                                          const std::string& output);
    
    // Regression detection
    std::vector<TestExecution> DetectRegressions(
        const std::vector<TestExecution>& baseline,
        const std::vector<TestExecution>& current);

private:
    std::vector<ClassificationRule> rules_;
    
    TestResult ClassifyResult(const TestExecution& exec);
    BugCategory CategorizeBug(const TestExecution& exec);
    std::string GenerateFingerprint(const TestExecution& exec);
};

// Built-in test corpus
std::vector<TestCase> GetMinimalTestCorpus();
std::vector<TestCase> GetES5TestCorpus();
std::vector<TestCase> GetEdgeCaseCorpus();

// Utility functions
std::string ResultToString(TestResult result);
std::string CategoryToString(BugCategory category);
std::string EscapeString(const std::string& input);

} // namespace Tools
} // namespace Script
} // namespace RawrXD
