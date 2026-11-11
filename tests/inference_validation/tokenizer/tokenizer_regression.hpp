#pragma once

#include <vector>
#include <string>
#include <json/json.h>

namespace rawrxd {
namespace validation {

/**
 * Single tokenizer test case
 */
struct TokenizerTestCase {
    std::string input;
    std::vector<int> expected_tokens;
    std::string description;
};

/**
 * Tokenizer regression test suite
 */
class TokenizerRegression {
public:
    /**
     * Load test cases from JSON file
     */
    bool loadFromFile(const char* path);
    
    /**
     * Add a test case
     */
    void addTestCase(const TokenizerTestCase& test);
    
    /**
     * Run all tests
     * @param encode_func Function to encode text to tokens
     * @param decode_func Function to decode tokens to text
     * @return Number of passed tests
     */
    int runTests(
        std::function<std::vector<int>(const std::string&)> encode_func,
        std::function<std::string(const std::vector<int>&)> decode_func
    );
    
    /**
     * Get test results
     */
    const std::vector<std::pair<TokenizerTestCase, bool>>& getResults() const {
        return results_;
    }
    
    /**
     * Print detailed report
     */
    void printReport() const;

private:
    std::vector<TokenizerTestCase> test_cases_;
    std::vector<std::pair<TokenizerTestCase, bool>> results_;
};

/**
 * Standard test cases for BPE tokenizers
 */
std::vector<TokenizerTestCase> getStandardB PETestCases();

} // namespace validation
} // namespace rawrxd
