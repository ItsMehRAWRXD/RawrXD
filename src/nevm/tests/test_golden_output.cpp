//============================================================================
// test_golden_output.cpp
// RawrXD N-EVM - Unit Tests for Golden Output Comparison
//============================================================================

#include "../nevm_golden_output.hpp"

using namespace RawrXD::NEVM;

TEST(GoldenOutput_Create) {
    GoldenOutput output;
    output.name = "test_output";
    output.version = "1.0.0";
    output.timestamp = 1234567890;
    output.seed = 42;
    output.tokens = {1, 2, 3, 4, 5};
    output.logits = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f};
    output.metadata["model"] = "test_model";
    output.metadata["quantization"] = "Q4_0";
    
    ASSERT_EQ(std::string("test_output"), output.name);
    ASSERT_EQ(std::string("1.0.0"), output.version);
    ASSERT_EQ(5ULL, output.tokens.size());
    ASSERT_EQ(5ULL, output.logits.size());
    ASSERT_EQ(1ULL, output.metadata.size());
    
    return true;
}

TEST(GoldenOutput_ComputeHash) {
    GoldenOutput output;
    output.tokens = {1, 2, 3, 4, 5};
    
    std::string hash = output.ComputeHash();
    ASSERT_FALSE(hash.empty());
    
    // Same tokens should produce same hash
    GoldenOutput output2;
    output2.tokens = {1, 2, 3, 4, 5};
    std::string hash2 = output2.ComputeHash();
    ASSERT_EQ(hash, hash2);
    
    // Different tokens should produce different hash
    GoldenOutput output3;
    output3.tokens = {1, 2, 3, 4, 6};
    std::string hash3 = output3.ComputeHash();
    ASSERT_NE(hash, hash3);
    
    return true;
}

TEST(GoldenOutput_ToJSON) {
    GoldenOutput output;
    output.name = "test";
    output.version = "1.0.0";
    output.seed = 42;
    output.tokens = {1, 2, 3};
    output.logits = {0.1f, 0.2f, 0.3f};
    output.metadata["key"] = "value";
    
    auto json = output.ToJSON();
    
    ASSERT_EQ(std::string("test"), json["name"].asString());
    ASSERT_EQ(std::string("1.0.0"), json["version"].asString());
    ASSERT_EQ(42, json["seed"].asInt());
    ASSERT_EQ(3U, json["tokens"].size());
    ASSERT_EQ(3U, json["logits"].size());
    ASSERT_EQ(std::string("value"), json["metadata"]["key"].asString());
    
    return true;
}

TEST(GoldenOutput_FromJSON) {
    Json::Value json;
    json["name"] = "test";
    json["version"] = "1.0.0";
    json["timestamp"] = 1234567890;
    json["seed"] = 42;
    json["tokens"].append(1);
    json["tokens"].append(2);
    json["tokens"].append(3);
    json["logits"].append(0.1);
    json["logits"].append(0.2);
    json["logits"].append(0.3);
    json["hash"] = "abc123";
    json["metadata"]["model"] = "test_model";
    
    auto output = GoldenOutput::FromJSON(json);
    
    ASSERT_EQ(std::string("test"), output.name);
    ASSERT_EQ(std::string("1.0.0"), output.version);
    ASSERT_EQ(42, output.seed);
    ASSERT_EQ(3ULL, output.tokens.size());
    ASSERT_EQ(3ULL, output.logits.size());
    ASSERT_EQ(std::string("test_model"), output.metadata["model"]);
    
    return true;
}

TEST(GoldenOutput_Compare_Exact) {
    GoldenOutput expected;
    expected.tokens = {1, 2, 3, 4, 5};
    expected.logits = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f};
    
    GoldenOutput actual;
    actual.tokens = {1, 2, 3, 4, 5};
    actual.logits = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f};
    
    auto result = expected.Compare(actual);
    
    ASSERT_TRUE(result.matches);
    ASSERT_EQ(0ULL, result.token_mismatches);
    ASSERT_EQ(0ULL, result.logit_mismatches);
    ASSERT_NEAR(0.0f, result.max_logit_diff, 0.0001f);
    
    return true;
}

TEST(GoldenOutput_Compare_TokenMismatch) {
    GoldenOutput expected;
    expected.tokens = {1, 2, 3, 4, 5};
    
    GoldenOutput actual;
    actual.tokens = {1, 2, 99, 4, 5};  // Token 3 changed to 99
    
    auto result = expected.Compare(actual);
    
    ASSERT_FALSE(result.matches);
    ASSERT_EQ(1ULL, result.token_mismatches);
    
    return true;
}

TEST(GoldenOutput_Compare_LengthMismatch) {
    GoldenOutput expected;
    expected.tokens = {1, 2, 3, 4, 5};
    
    GoldenOutput actual;
    actual.tokens = {1, 2, 3};  // Shorter
    
    auto result = expected.Compare(actual);
    
    ASSERT_FALSE(result.matches);
    ASSERT_EQ(0ULL, result.token_mismatches);  // Only compares common length
    
    return true;
}

TEST(GoldenOutput_Compare_LogitWithinTolerance) {
    GoldenOutput expected;
    expected.logits = {0.1f, 0.2f, 0.3f};
    
    GoldenOutput actual;
    actual.logits = {0.10001f, 0.20001f, 0.30001f};  // Small differences
    
    auto result = expected.Compare(actual, 0.001f);  // Tolerance of 0.001
    
    ASSERT_TRUE(result.matches);
    ASSERT_EQ(0ULL, result.logit_mismatches);
    
    return true;
}

TEST(GoldenOutput_Compare_LogitOutsideTolerance) {
    GoldenOutput expected;
    expected.logits = {0.1f, 0.2f, 0.3f};
    
    GoldenOutput actual;
    actual.logits = {0.15f, 0.25f, 0.35f};  // Larger differences
    
    auto result = expected.Compare(actual, 0.001f);  // Tolerance of 0.001
    
    ASSERT_FALSE(result.matches);
    ASSERT_EQ(3ULL, result.logit_mismatches);
    ASSERT_GT(result.max_logit_diff, 0.04f);
    
    return true;
}

TEST(GoldenOutputTester_Register) {
    GoldenOutputTester tester;
    
    GoldenOutput output;
    output.name = "test_case_1";
    output.tokens = {1, 2, 3};
    
    tester.RegisterGoldenOutput(output);
    
    ASSERT_TRUE(tester.HasGoldenOutput("test_case_1"));
    ASSERT_FALSE(tester.HasGoldenOutput("nonexistent"));
    
    return true;
}

TEST(GoldenOutputTester_Validate_Pass) {
    GoldenOutputTester tester;
    
    GoldenOutput expected;
    expected.name = "test_case";
    expected.tokens = {1, 2, 3};
    expected.logits = {0.1f, 0.2f, 0.3f};
    tester.RegisterGoldenOutput(expected);
    
    GoldenOutput actual;
    actual.tokens = {1, 2, 3};
    actual.logits = {0.1f, 0.2f, 0.3f};
    
    auto result = tester.ValidateOutput("test_case", actual);
    
    ASSERT_TRUE(result.passed);
    ASSERT_TRUE(result.comparison.matches);
    
    return true;
}

TEST(GoldenOutputTester_Validate_Fail) {
    GoldenOutputTester tester;
    
    GoldenOutput expected;
    expected.name = "test_case";
    expected.tokens = {1, 2, 3};
    tester.RegisterGoldenOutput(expected);
    
    GoldenOutput actual;
    actual.tokens = {1, 2, 99};  // Different
    
    auto result = tester.ValidateOutput("test_case", actual);
    
    ASSERT_FALSE(result.passed);
    ASSERT_FALSE(result.comparison.matches);
    
    return true;
}

TEST(GoldenOutputTester_Validate_Unknown) {
    GoldenOutputTester tester;
    
    GoldenOutput actual;
    actual.tokens = {1, 2, 3};
    
    auto result = tester.ValidateOutput("unknown_case", actual);
    
    ASSERT_FALSE(result.passed);
    ASSERT_EQ(std::string("No golden output registered"), result.error_message);
    
    return true;
}

TEST(GoldenOutputTester_GetStats) {
    GoldenOutputTester tester;
    
    GoldenOutput expected;
    expected.name = "test1";
    expected.tokens = {1, 2, 3};
    tester.RegisterGoldenOutput(expected);
    
    GoldenOutput actual1;
    actual1.tokens = {1, 2, 3};
    tester.ValidateOutput("test1", actual1);
    
    GoldenOutput actual2;
    actual2.tokens = {1, 2, 99};
    tester.ValidateOutput("test1", actual2);
    
    auto stats = tester.GetStats();
    
    ASSERT_EQ(2ULL, stats.total_tests);
    ASSERT_EQ(1ULL, stats.passed_tests);
    ASSERT_EQ(1ULL, stats.failed_tests);
    ASSERT_EQ(0.5f, stats.pass_rate);
    
    return true;
}

TEST(GoldenOutputTester_Clear) {
    GoldenOutputTester tester;
    
    GoldenOutput output;
    output.name = "test";
    tester.RegisterGoldenOutput(output);
    
    ASSERT_TRUE(tester.HasGoldenOutput("test"));
    
    tester.Clear();
    
    ASSERT_FALSE(tester.HasGoldenOutput("test"));
    ASSERT_EQ(0ULL, tester.GetStats().total_tests);
    
    return true;
}
