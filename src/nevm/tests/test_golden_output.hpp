//============================================================================
// test_golden_output.hpp
// RawrXD N-EVM - Golden Output Unit Tests
//============================================================================

#pragma once

#include "test_framework.hpp"
#include "../nevm_golden_output.hpp"

namespace RawrXD {
namespace NEVM {
namespace Tests {

//============================================================================
// Golden Output Tests
//============================================================================

TestResult GoldenOutputTests_BasicComparison() {
    GoldenOutput gold;
    gold.expected_tokens = {1, 2, 3, 4, 5};
    
    std::vector<int32_t> actual = {1, 2, 3, 4, 5};
    
    TEST_ASSERT_EQ(true, gold.Compare(actual));
    
    TEST_SUCCESS();
}

TestResult GoldenOutputTests_Mismatch() {
    GoldenOutput gold;
    gold.expected_tokens = {1, 2, 3, 4, 5};
    
    std::vector<int32_t> actual = {1, 2, 99, 4, 5};  // Different at position 2
    
    TEST_ASSERT_EQ(false, gold.Compare(actual));
    
    TEST_SUCCESS();
}

TestResult GoldenOutputTests_DifferentLength() {
    GoldenOutput gold;
    gold.expected_tokens = {1, 2, 3, 4, 5};
    
    std::vector<int32_t> actual = {1, 2, 3};  // Shorter
    
    TEST_ASSERT_EQ(false, gold.Compare(actual));
    
    TEST_SUCCESS();
}

TestResult GoldenOutputTests_Empty() {
    GoldenOutput gold;
    gold.expected_tokens = {};
    
    std::vector<int32_t> actual = {};
    
    TEST_ASSERT_EQ(true, gold.Compare(actual));
    
    TEST_SUCCESS();
}

TestResult GoldenOutputTests_JSONSerialization() {
    GoldenOutput gold;
    gold.expected_tokens = {1, 2, 3, 4, 5};
    gold.model_hash = "sha256:abc123";
    gold.prompt_hash = "sha256:def456";
    gold.math_mode = "BitExact";
    gold.max_tokens = 128;
    gold.temperature = 0.0f;
    
    Json::Value json = gold.ToJSON();
    
    TEST_ASSERT_EQ(5ULL, json["expected_tokens"].size());
    TEST_ASSERT_EQ(std::string("sha256:abc123"), json["model_hash"].asString());
    TEST_ASSERT_EQ(std::string("BitExact"), json["math_mode"].asString());
    
    // Round-trip
    GoldenOutput restored = GoldenOutput::FromJSON(json);
    TEST_ASSERT_EQ(gold.expected_tokens.size(), restored.expected_tokens.size());
    TEST_ASSERT_EQ(gold.model_hash, restored.model_hash);
    
    TEST_SUCCESS();
}

TestResult GoldenOutputTests_TesterPass() {
    GoldenOutput gold;
    gold.expected_tokens = {1, 2, 3, 4, 5};
    
    std::vector<int32_t> actual = {1, 2, 3, 4, 5};
    
    GoldenOutputTester tester;
    tester.RunTest("test1", gold, actual);
    
    TEST_ASSERT_EQ(true, tester.AllPassed());
    TEST_ASSERT_EQ(1ULL, tester.results.size());
    TEST_ASSERT_EQ(true, tester.results[0].passed);
    
    TEST_SUCCESS();
}

TestResult GoldenOutputTests_TesterFail() {
    GoldenOutput gold;
    gold.expected_tokens = {1, 2, 3, 4, 5};
    
    std::vector<int32_t> actual = {1, 2, 99, 4, 5};  // Mismatch at position 2
    
    GoldenOutputTester tester;
    tester.RunTest("test1", gold, actual);
    
    TEST_ASSERT_EQ(false, tester.AllPassed());
    TEST_ASSERT_EQ(1ULL, tester.results.size());
    TEST_ASSERT_EQ(false, tester.results[0].passed);
    TEST_ASSERT_EQ(2ULL, tester.results[0].mismatch_position);
    TEST_ASSERT_EQ(3, tester.results[0].expected_token);
    TEST_ASSERT_EQ(99, tester.results[0].actual_token);
    
    TEST_SUCCESS();
}

TestResult GoldenOutputTests_TesterMultiple() {
    GoldenOutput gold1;
    gold1.expected_tokens = {1, 2, 3};
    
    GoldenOutput gold2;
    gold2.expected_tokens = {4, 5, 6};
    
    GoldenOutputTester tester;
    tester.RunTest("test1", gold1, std::vector<int32_t>{1, 2, 3});
    tester.RunTest("test2", gold2, std::vector<int32_t>{4, 5, 99});  // Fail
    
    TEST_ASSERT_EQ(false, tester.AllPassed());
    TEST_ASSERT_EQ(2ULL, tester.results.size());
    TEST_ASSERT_EQ(true, tester.results[0].passed);
    TEST_ASSERT_EQ(false, tester.results[1].passed);
    
    TEST_SUCCESS();
}

//============================================================================
// Registration
//============================================================================

void RegisterGoldenOutputTests(TestFramework& framework) {
    REGISTER_TEST(framework, GoldenOutputTests, BasicComparison);
    REGISTER_TEST(framework, GoldenOutputTests, Mismatch);
    REGISTER_TEST(framework, GoldenOutputTests, DifferentLength);
    REGISTER_TEST(framework, GoldenOutputTests, Empty);
    REGISTER_TEST(framework, GoldenOutputTests, JSONSerialization);
    REGISTER_TEST(framework, GoldenOutputTests, TesterPass);
    REGISTER_TEST(framework, GoldenOutputTests, TesterFail);
    REGISTER_TEST(framework, GoldenOutputTests, TesterMultiple);
}

} // namespace Tests
} // namespace NEVM
} // namespace RawrXD
