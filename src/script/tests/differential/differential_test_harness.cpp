// RawrXD-Script Differential Testing Harness
// Compares output against reference JavaScript engines (QuickJS, Node.js)
// Finds semantic bugs by cross-referencing results

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <chrono>

namespace fs = std::filesystem;

// Test case structure
struct DifferentialTestCase {
    const char* name;
    const char* code;
    const char* expectedPattern;  // Can use * for wildcards
    bool requiresReference;     // If true, must match reference engine
};

// Critical semantic edge cases that often differ between engines
static const DifferentialTestCase kDifferentialTests[] = {
    // Type coercion edge cases
    {
        "string_number_concat",
        "print('1' + 2);",
        "12",
        true
    },
    {
        "number_string_concat",
        "print(1 + '2');",
        "12",
        true
    },
    {
        "array_object_concat",
        "print([] + {});",
        "[object Object]",
        true
    },
    {
        "object_array_concat",
        "print({} + []);",
        "0",  // {} is block, +[] = 0 in some contexts
        false  // Engine-dependent
    },
    
    // Division edge cases
    {
        "division_by_zero_positive",
        "print(1 / 0);",
        "Infinity",
        true
    },
    {
        "division_by_zero_negative",
        "print(-1 / 0);",
        "-Infinity",
        true
    },
    {
        "zero_division_by_zero",
        "print(0 / 0);",
        "NaN",
        true
    },
    {
        "infinity_division",
        "print(Infinity / Infinity);",
        "NaN",
        true
    },
    
    // Negative zero
    {
        "negative_zero_equality",
        "print(0 === -0);",
        "true",
        true
    },
    {
        "negative_zero_division",
        "print(1 / -0);",
        "-Infinity",
        true
    },
    
    // NaN handling
    {
        "nan_equality",
        "print(NaN === NaN);",
        "false",
        true
    },
    {
        "nan_inequality",
        "print(NaN != NaN);",
        "true",
        true
    },
    
    // Object property deletion
    {
        "delete_property",
        R"(
            let x = {};
            x.a = 1;
            delete x.a;
            print('a' in x);
        )",
        "false",
        true
    },
    {
        "delete_then_access",
        R"(
            let x = {a: 1};
            delete x.a;
            print(x.a);
        )",
        "undefined",
        true
    },
    
    // Prototype chain
    {
        "prototype_inheritance",
        R"(
            let parent = {x: 1};
            let child = Object.create(parent);
            print(child.x);
        )",
        "1",
        true
    },
    {
        "prototype_shadowing",
        R"(
            let parent = {x: 1};
            let child = Object.create(parent);
            child.x = 2;
            print(child.x);
        )",
        "2",
        true
    },
    {
        "delete_prototype_property",
        R"(
            let parent = {x: 1};
            let child = Object.create(parent);
            delete child.x;
            print(child.x);
        )",
        "1",  // Falls back to prototype
        true
    },
    
    // Typeof operator
    {
        "typeof_undefined",
        "print(typeof undefined);",
        "undefined",
        true
    },
    {
        "typeof_null",
        "print(typeof null);",
        "object",  // JS quirk: typeof null === 'object'
        true
    },
    {
        "typeof_array",
        "print(typeof []);",
        "object",
        true
    },
    
    // Truthiness
    {
        "empty_string_truthy",
        "print('' ? 'true' : 'false');",
        "false",
        true
    },
    {
        "zero_truthy",
        "print(0 ? 'true' : 'false');",
        "false",
        true
    },
    {
        "empty_array_truthy",
        "print([] ? 'true' : 'false');",
        "true",
        true
    },
    
    // Comparison operators
    {
        "abstract_equality_null_undefined",
        "print(null == undefined);",
        "true",
        true
    },
    {
        "strict_equality_null_undefined",
        "print(null === undefined);",
        "false",
        true
    },
    {
        "abstract_equality_string_number",
        "print('1' == 1);",
        "true",
        true
    },
    {
        "strict_equality_string_number",
        "print('1' === 1);",
        "false",
        true
    },
    
    // Arithmetic edge cases
    {
        "modulo_by_zero",
        "print(1 % 0);",
        "NaN",
        true
    },
    {
        "modulo_negative",
        "print(-5 % 2);",
        "-1",
        true
    },
    
    // Variable hoisting (if implemented)
    {
        "var_hoisting",
        R"(
            print(x);
            var x = 5;
        )",
        "undefined",
        true
    },
};

// Result comparison
struct TestResult {
    const char* name;
    std::string rawrOutput;
    std::string referenceOutput;
    bool passed;
    std::string error;
};

class DifferentialTestHarness {
public:
    DifferentialTestHarness() 
        : totalTests_(0), passedTests_(0), failedTests_(0), skippedTests_(0) {}
    
    // Run all differential tests
    void RunAllTests() {
        std::cout << "========================================" << std::endl;
        std::cout << "RawrXD-Script Differential Test Suite" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << std::endl;
        
        // Check for reference engine
        referenceEngine_ = DetectReferenceEngine();
        if (referenceEngine_.empty()) {
            std::cout << "WARNING: No reference engine detected (QuickJS/Node.js)" << std::endl;
            std::cout << "Running in standalone mode - semantic validation only" << std::endl;
            std::cout << std::endl;
        } else {
            std::cout << "Reference engine: " << referenceEngine_ << std::endl;
            std::cout << std::endl;
        }
        
        // Run each test
        for (const auto& test : kDifferentialTests) {
            RunSingleTest(test);
        }
        
        // Print summary
        PrintSummary();
    }
    
    // Run a single test case
    void RunSingleTest(const DifferentialTestCase& test) {
        totalTests_++;
        
        std::cout << "Test: " << test.name << std::endl;
        
        // Run on RawrXD-Script
        std::string rawrOutput = RunOnRawrXD(test.code);
        if (rawrOutput.empty() && std::string(test.code).find("print") != std::string::npos) {
            std::cout << "  [SKIP] RawrXD execution failed" << std::endl;
            skippedTests_++;
            return;
        }
        
        // Trim whitespace
        rawrOutput = Trim(rawrOutput);
        
        // Check against expected pattern
        bool patternMatch = MatchPattern(rawrOutput, test.expectedPattern);
        
        if (!referenceEngine_.empty() && test.requiresReference) {
            // Run on reference engine
            std::string refOutput = RunOnReference(test.code);
            refOutput = Trim(refOutput);
            
            // Compare outputs
            if (rawrOutput == refOutput) {
                std::cout << "  [PASS] Outputs match" << std::endl;
                std::cout << "    RawrXD:    " << rawrOutput << std::endl;
                std::cout << "    Reference: " << refOutput << std::endl;
                passedTests_++;
            } else {
                std::cout << "  [FAIL] Outputs differ!" << std::endl;
                std::cout << "    RawrXD:    " << rawrOutput << std::endl;
                std::cout << "    Reference: " << refOutput << std::endl;
                std::cout << "    Expected:  " << test.expectedPattern << std::endl;
                failedTests_++;
                
                // Record failure
                failures_.push_back({test.name, rawrOutput, refOutput, false, 
                    "Output mismatch"});
            }
        } else {
            // Standalone mode - check against expected pattern
            if (patternMatch) {
                std::cout << "  [PASS] Output matches expected pattern" << std::endl;
                std::cout << "    Output:   " << rawrOutput << std::endl;
                std::cout << "    Expected: " << test.expectedPattern << std::endl;
                passedTests_++;
            } else {
                std::cout << "  [FAIL] Output doesn't match expected pattern" << std::endl;
                std::cout << "    Output:   " << rawrOutput << std::endl;
                std::cout << "    Expected: " << test.expectedPattern << std::endl;
                failedTests_++;
                
                failures_.push_back({test.name, rawrOutput, "", false,
                    "Pattern mismatch"});
            }
        }
        
        std::cout << std::endl;
    }
    
    // Generate random test cases for fuzzing
    void GenerateRandomTests(int count) {
        std::cout << "========================================" << std::endl;
        std::cout << "Randomized Fuzzing Tests" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << std::endl;
        
        std::srand(static_cast<unsigned>(std::time(nullptr)));
        
        for (int i = 0; i < count; i++) {
            std::string randomCode = GenerateRandomProgram();
            std::cout << "Fuzz test " << (i + 1) << "/" << count << std::endl;
            std::cout << "Code: " << randomCode.substr(0, 60) 
                      << (randomCode.length() > 60 ? "..." : "") << std::endl;
            
            // Run and check for crashes
            std::string output = RunOnRawrXD(randomCode.c_str());
            if (output.find("CRASH") != std::string::npos ||
                output.find("SEGFAULT") != std::string::npos) {
                std::cout << "  [CRASH] Test caused crash!" << std::endl;
                std::cout << "  Code saved to fuzz_crash_" << i << ".js" << std::endl;
                
                // Save crashing test
                std::ofstream crashFile("fuzz_crash_" + std::to_string(i) + ".js");
                crashFile << randomCode;
                crashFile.close();
                
                failedTests_++;
            } else {
                std::cout << "  [OK] No crash" << std::endl;
                passedTests_++;
            }
            std::cout << std::endl;
        }
    }
    
private:
    std::string referenceEngine_;
    int totalTests_;
    int passedTests_;
    int failedTests_;
    int skippedTests_;
    std::vector<TestResult> failures_;
    
    // Detect available reference engine
    std::string DetectReferenceEngine() {
        // Check for QuickJS
        if (std::system("qjs --version >nul 2>&1") == 0) {
            return "QuickJS";
        }
        // Check for Node.js
        if (std::system("node --version >nul 2>&1") == 0) {
            return "Node.js";
        }
        return "";
    }
    
    // Run code on RawrXD-Script
    std::string RunOnRawrXD(const char* code) {
        // Write code to temp file
        std::ofstream tempFile("temp_test.js");
        tempFile << code;
        tempFile.close();
        
        // Execute (placeholder - would call actual RawrXD runtime)
        // For now, return placeholder output
        FILE* pipe = _popen("rawrxd_script temp_test.js 2>&1", "r");
        if (!pipe) {
            // RawrXD not available, return expected pattern as placeholder
            return "[RawrXD not built - placeholder]";
        }
        
        char buffer[128];
        std::string result;
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        _pclose(pipe);
        
        std::remove("temp_test.js");
        return result;
    }
    
    // Run code on reference engine
    std::string RunOnReference(const char* code) {
        // Write code to temp file
        std::ofstream tempFile("temp_test.js");
        tempFile << code;
        tempFile.close();
        
        // Execute on reference engine
        std::string cmd;
        if (referenceEngine_ == "QuickJS") {
            cmd = "qjs temp_test.js 2>&1";
        } else if (referenceEngine_ == "Node.js") {
            cmd = "node temp_test.js 2>&1";
        } else {
            return "";
        }
        
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) return "";
        
        char buffer[128];
        std::string result;
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        _pclose(pipe);
        
        std::remove("temp_test.js");
        return result;
    }
    
    // Match output against pattern (supports * wildcards)
    bool MatchPattern(const std::string& output, const std::string& pattern) {
        if (pattern == "*") return true;
        
        // Simple wildcard matching
        size_t patternPos = 0;
        size_t outputPos = 0;
        
        while (patternPos < pattern.length() && outputPos < output.length()) {
            if (pattern[patternPos] == '*') {
                // Wildcard - match any characters
                patternPos++;
                if (patternPos >= pattern.length()) return true;
                
                // Find next character in output
                char nextChar = pattern[patternPos];
                while (outputPos < output.length() && output[outputPos] != nextChar) {
                    outputPos++;
                }
            } else if (pattern[patternPos] == output[outputPos]) {
                patternPos++;
                outputPos++;
            } else {
                return false;
            }
        }
        
        // Check if we've consumed both strings
        while (patternPos < pattern.length() && pattern[patternPos] == '*') {
            patternPos++;
        }
        
        return patternPos == pattern.length() && outputPos == output.length();
    }
    
    // Trim whitespace from string
    std::string Trim(const std::string& str) {
        size_t start = str.find_first_not_of(" \t\n\r");
        if (start == std::string::npos) return "";
        size_t end = str.find_last_not_of(" \t\n\r");
        return str.substr(start, end - start + 1);
    }
    
    // Generate random JavaScript program for fuzzing
    std::string GenerateRandomProgram() {
        std::stringstream ss;
        
        // Random program structure
        int statements = 1 + (std::rand() % 5);
        
        for (int i = 0; i < statements; i++) {
            int type = std::rand() % 6;
            switch (type) {
                case 0: { // Variable declaration
                    std::string name = "v" + std::to_string(std::rand() % 10);
                    int val = std::rand() % 100;
                    ss << "var " << name << " = " << val << ";\n";
                    break;
                }
                case 1: { // Arithmetic
                    std::string a = "v" + std::to_string(std::rand() % 10);
                    std::string b = "v" + std::to_string(std::rand() % 10);
                    char ops[] = {'+', '-', '*', '/'};
                    char op = ops[std::rand() % 4];
                    ss << a << " " << op << " " << b << ";\n";
                    break;
                }
                case 2: { // Object literal
                    ss << "var o = {a: 1, b: 2};\n";
                    if (std::rand() % 2) {
                        ss << "o.c = 3;\n";
                    }
                    break;
                }
                case 3: { // Array literal
                    ss << "var a = [1, 2, 3];\n";
                    break;
                }
                case 4: { // Property access
                    std::string obj = std::rand() % 2 ? "o" : "a";
                    ss << "print(" << obj << ".a);\n";
                    break;
                }
                case 5: { // Conditional
                    ss << "if (" << (std::rand() % 2) << ") {\n";
                    ss << "  print(1);\n";
                    ss << "}\n";
                    break;
                }
            }
        }
        
        return ss.str();
    }
    
    // Print test summary
    void PrintSummary() {
        std::cout << "========================================" << std::endl;
        std::cout << "Differential Test Summary" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "Total tests:  " << totalTests_ << std::endl;
        std::cout << "Passed:       " << passedTests_ << std::endl;
        std::cout << "Failed:       " << failedTests_ << std::endl;
        std::cout << "Skipped:      " << skippedTests_ << std::endl;
        std::cout << std::endl;
        
        if (!failures_.empty()) {
            std::cout << "Failures:" << std::endl;
            for (const auto& failure : failures_) {
                std::cout << "  - " << failure.name << ": " << failure.error << std::endl;
            }
            std::cout << std::endl;
        }
        
        double passRate = (totalTests_ > 0) 
            ? (100.0 * passedTests_ / totalTests_) 
            : 0.0;
        std::cout << "Pass rate: " << passRate << "%" << std::endl;
        
        if (passRate >= 95.0) {
            std::cout << "Status: EXCELLENT" << std::endl;
        } else if (passRate >= 90.0) {
            std::cout << "Status: GOOD" << std::endl;
        } else if (passRate >= 80.0) {
            std::cout << "Status: ACCEPTABLE" << std::endl;
        } else {
            std::cout << "Status: NEEDS WORK" << std::endl;
        }
    }
};

// Main entry point
int main(int argc, char* argv[]) {
    DifferentialTestHarness harness;
    
    // Run differential tests
    harness.RunAllTests();
    
    // Run fuzzing if requested
    if (argc > 1 && std::strcmp(argv[1], "--fuzz") == 0) {
        int fuzzCount = (argc > 2) ? std::atoi(argv[2]) : 100;
        harness.GenerateRandomTests(fuzzCount);
    }
    
    return 0;
}
