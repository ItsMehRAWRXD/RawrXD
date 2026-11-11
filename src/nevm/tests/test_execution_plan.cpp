//============================================================================
// test_execution_plan.cpp
// RawrXD N-EVM - Unit Tests for Execution Plan Versioning
//============================================================================

#include "../nevm_execution_plan_version.hpp"

using namespace RawrXD::NEVM;

TEST(ExecutionPlanVersion_Current) {
    // Current version should be defined
    ASSERT_EQ(1, ExecutionPlanVersion::CURRENT_MAJOR);
    ASSERT_EQ(0, ExecutionPlanVersion::CURRENT_MINOR);
    ASSERT_EQ(0, ExecutionPlanVersion::CURRENT_PATCH);
    
    return true;
}

TEST(ExecutionPlanVersion_String) {
    std::string version = ExecutionPlanVersion::GetCurrentVersionString();
    ASSERT_FALSE(version.empty());
    
    // Should contain major.minor.patch format
    ASSERT_TRUE(version.find('.') != std::string::npos);
    
    return true;
}

TEST(ExecutionPlanVersion_Parse) {
    // Valid version strings
    auto v1 = ExecutionPlanVersion::Parse("1.0.0");
    ASSERT_EQ(1, v1.major);
    ASSERT_EQ(0, v1.minor);
    ASSERT_EQ(0, v1.patch);
    
    auto v2 = ExecutionPlanVersion::Parse("2.5.3");
    ASSERT_EQ(2, v2.major);
    ASSERT_EQ(5, v2.minor);
    ASSERT_EQ(3, v2.patch);
    
    // Invalid version should return 0.0.0
    auto v3 = ExecutionPlanVersion::Parse("invalid");
    ASSERT_EQ(0, v3.major);
    ASSERT_EQ(0, v3.minor);
    ASSERT_EQ(0, v3.patch);
    
    return true;
}

TEST(ExecutionPlanVersion_Compatibility_Same) {
    // Same version should be compatible
    ExecutionPlanVersion::Version v1 = {1, 0, 0};
    ExecutionPlanVersion::Version v2 = {1, 0, 0};
    
    ASSERT_TRUE(ExecutionPlanVersion::IsCompatible(v1, v2));
    
    return true;
}

TEST(ExecutionPlanVersion_Compatibility_Patch) {
    // Different patch should be compatible
    ExecutionPlanVersion::Version v1 = {1, 0, 0};
    ExecutionPlanVersion::Version v2 = {1, 0, 5};
    
    ASSERT_TRUE(ExecutionPlanVersion::IsCompatible(v1, v2));
    
    return true;
}

TEST(ExecutionPlanVersion_Compatibility_Minor) {
    // Different minor should be compatible (backward compatible)
    ExecutionPlanVersion::Version v1 = {1, 0, 0};
    ExecutionPlanVersion::Version v2 = {1, 2, 0};
    
    ASSERT_TRUE(ExecutionPlanVersion::IsCompatible(v1, v2));
    
    return true;
}

TEST(ExecutionPlanVersion_Compatibility_Major) {
    // Different major should NOT be compatible
    ExecutionPlanVersion::Version v1 = {1, 0, 0};
    ExecutionPlanVersion::Version v2 = {2, 0, 0};
    
    ASSERT_FALSE(ExecutionPlanVersion::IsCompatible(v1, v2));
    
    return true;
}

TEST(ExecutionPlanVersion_Compatibility_Backward) {
    // Older version should be compatible with newer (backward)
    ExecutionPlanVersion::Version old = {1, 0, 0};
    ExecutionPlanVersion::Version newer = {1, 5, 3};
    
    ASSERT_TRUE(ExecutionPlanVersion::IsCompatible(old, newer));
    
    return true;
}

TEST(ExecutionPlanVersion_Compare) {
    ExecutionPlanVersion::Version v1 = {1, 0, 0};
    ExecutionPlanVersion::Version v2 = {1, 0, 0};
    ExecutionPlanVersion::Version v3 = {1, 1, 0};
    ExecutionPlanVersion::Version v4 = {2, 0, 0};
    
    // Equal versions
    ASSERT_TRUE(ExecutionPlanVersion::Compare(v1, v2) == 0);
    
    // v1 < v3 (minor difference)
    ASSERT_TRUE(ExecutionPlanVersion::Compare(v1, v3) < 0);
    ASSERT_TRUE(ExecutionPlanVersion::Compare(v3, v1) > 0);
    
    // v1 < v4 (major difference)
    ASSERT_TRUE(ExecutionPlanVersion::Compare(v1, v4) < 0);
    ASSERT_TRUE(ExecutionPlanVersion::Compare(v4, v1) > 0);
    
    return true;
}

TEST(ExecutionPlanVersion_ValidatePlan) {
    // Valid plan with current version
    std::string plan = R"({"version": "1.0.0", "kernels": []})";
    ASSERT_TRUE(ExecutionPlanVersion::ValidatePlan(plan));
    
    // Valid plan with compatible version
    std::string plan2 = R"({"version": "1.5.3", "kernels": []})";
    ASSERT_TRUE(ExecutionPlanVersion::ValidatePlan(plan2));
    
    // Invalid JSON
    std::string plan3 = "invalid json";
    ASSERT_FALSE(ExecutionPlanVersion::ValidatePlan(plan3));
    
    return true;
}

TEST(ExecutionPlanVersion_ValidatePlan_Incompatible) {
    // Plan with incompatible version (major version different)
    std::string plan = R"({"version": "2.0.0", "kernels": []})";
    ASSERT_FALSE(ExecutionPlanVersion::ValidatePlan(plan));
    
    return true;
}

TEST(ExecutionPlanVersion_ToJSON) {
    ExecutionPlanVersion::Version v = {1, 2, 3};
    auto json = ExecutionPlanVersion::ToJSON(v);
    
    ASSERT_EQ(1, json["major"].asInt());
    ASSERT_EQ(2, json["minor"].asInt());
    ASSERT_EQ(3, json["patch"].asInt());
    ASSERT_EQ(std::string("1.2.3"), json["version_string"].asString());
    
    return true;
}
