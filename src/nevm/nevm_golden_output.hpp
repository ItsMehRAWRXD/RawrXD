//============================================================================
// nevm_golden_output.hpp
// RawrXD N-EVM - Golden Output Comparison Tests
// Exact match comparison for deterministic mode
//============================================================================

#pragma once

#include <string>
#include <fstream>
#include <vector>
#include <json/json.h>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Golden Output Record
//============================================================================

struct GoldenOutput {
    std::vector<int32_t> expected_tokens;
    std::string model_hash;
    std::string prompt_hash;
    std::string math_mode;
    int max_tokens;
    float temperature;
    
    bool Compare(const std::vector<int32_t>& actual) const {
        if (expected_tokens.size() != actual.size()) {
            return false;
        }
        for (size_t i = 0; i < expected_tokens.size(); ++i) {
            if (expected_tokens[i] != actual[i]) {
                return false;
            }
        }
        return true;
    }
    
    Json::Value ToJSON() const {
        Json::Value gold;
        
        Json::Value tokens(Json::arrayValue);
        for (int32_t t : expected_tokens) {
            tokens.append(t);
        }
        gold["expected_tokens"] = tokens;
        gold["model_hash"] = model_hash;
        gold["prompt_hash"] = prompt_hash;
        gold["math_mode"] = math_mode;
        gold["max_tokens"] = max_tokens;
        gold["temperature"] = temperature;
        
        return gold;
    }
    
    static GoldenOutput FromJSON(const Json::Value& json) {
        GoldenOutput gold;
        
        const Json::Value& tokens = json["expected_tokens"];
        for (const auto& t : tokens) {
            gold.expected_tokens.push_back(t.asInt());
        }
        
        gold.model_hash = json.get("model_hash", "").asString();
        gold.prompt_hash = json.get("prompt_hash", "").asString();
        gold.math_mode = json.get("math_mode", "BitExact").asString();
        gold.max_tokens = json.get("max_tokens", 128).asInt();
        gold.temperature = json.get("temperature", 0.0f).asFloat();
        
        return gold;
    }
    
    // Load from binary file (prompt.bin + tokens.bin format)
    static GoldenOutput LoadFromBinary(const std::string& prompt_path,
                                        const std::string& tokens_path,
                                        const std::string& metadata_path) {
        GoldenOutput gold;
        
        // Load prompt (for hash calculation)
        std::ifstream prompt_file(prompt_path, std::ios::binary);
        std::vector<char> prompt_data((std::istreambuf_iterator<char>(prompt_file)),
                                       std::istreambuf_iterator<char>());
        
        // Load expected tokens
        std::ifstream tokens_file(tokens_path, std::ios::binary);
        int32_t token;
        while (tokens_file.read(reinterpret_cast<char*>(&token), sizeof(token))) {
            gold.expected_tokens.push_back(token);
        }
        
        // Load metadata if available
        std::ifstream meta_file(metadata_path);
        if (meta_file) {
            Json::Value meta;
            meta_file >> meta;
            gold.model_hash = meta.get("model_hash", "").asString();
            gold.math_mode = meta.get("math_mode", "BitExact").asString();
            gold.max_tokens = meta.get("max_tokens", 128).asInt();
            gold.temperature = meta.get("temperature", 0.0f).asFloat();
        }
        
        return gold;
    }
};

//============================================================================
// Golden Output Test Runner
//============================================================================

class GoldenOutputTester {
public:
    struct TestResult {
        std::string test_name;
        bool passed;
        std::string message;
        size_t mismatch_position;
        int32_t expected_token;
        int32_t actual_token;
    };
    
    std::vector<TestResult> results;
    
    void RunTest(const std::string& name, 
                 const GoldenOutput& expected,
                 const std::vector<int32_t>& actual) {
        TestResult result;
        result.test_name = name;
        result.mismatch_position = 0;
        result.expected_token = 0;
        result.actual_token = 0;
        
        if (expected.expected_tokens.size() != actual.size()) {
            result.passed = false;
            result.message = "Token count mismatch: expected " +
                           std::to_string(expected.expected_tokens.size()) +
                           ", got " + std::to_string(actual.size());
            results.push_back(result);
            return;
        }
        
        for (size_t i = 0; i < expected.expected_tokens.size(); ++i) {
            if (expected.expected_tokens[i] != actual[i]) {
                result.passed = false;
                result.mismatch_position = i;
                result.expected_token = expected.expected_tokens[i];
                result.actual_token = actual[i];
                result.message = "Token mismatch at position " + std::to_string(i) +
                             ": expected " + std::to_string(result.expected_token) +
                             ", got " + std::to_string(result.actual_token);
                results.push_back(result);
                return;
            }
        }
        
        result.passed = true;
        result.message = "Exact match (" + std::to_string(actual.size()) + " tokens)";
        results.push_back(result);
    }
    
    bool AllPassed() const {
        for (const auto& r : results) {
            if (!r.passed) return false;
        }
        return true;
    }
    
    void PrintReport() const {
        std::cout << "\n=== Golden Output Test Report ===\n";
        for (const auto& r : results) {
            std::cout << r.test_name << ": ";
            std::cout << (r.passed ? "PASS" : "FAIL") << "\n";
            std::cout << "  " << r.message << "\n";
        }
        std::cout << "\n";
    }
    
    Json::Value ToJSON() const {
        Json::Value report;
        for (const auto& r : results) {
            Json::Value test;
            test["name"] = r.test_name;
            test["passed"] = r.passed;
            test["message"] = r.message;
            if (!r.passed) {
                test["mismatch_position"] = static_cast<Json::UInt64>(r.mismatch_position);
                test["expected_token"] = r.expected_token;
                test["actual_token"] = r.actual_token;
            }
            report.append(test);
        }
        return report;
    }
};

} // namespace NEVM
} // namespace RawrXD
