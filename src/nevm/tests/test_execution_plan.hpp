//============================================================================
// test_execution_plan.hpp
// RawrXD N-EVM - Execution Plan Version Unit Tests
//============================================================================

#pragma once

#include "test_framework.hpp"
#include "../nevm_execution_plan_version.hpp"

namespace RawrXD {
namespace NEVM {
namespace Tests {

//============================================================================
// Execution Plan Tests
//============================================================================

TestResult ExecutionPlanTests_VersionCompatibility() {
    ExecutionPlanVersion v1;
    v1.model_hash = "abc123";
    v1.tensor_layout_hash = "def456";
    v1.kernel_registry_hash = "ghi789";
    v1.precision_policy_hash = "jkl012";
    v1.residency_policy_hash = "mno345";
    v1.math_mode_hash = "pqr678";
    
    ExecutionPlanVersion v2 = v1;  // Copy
    
    // Same version should be compatible
    TEST_ASSERT_EQ(true, v1.IsCompatibleWith(v2));
    TEST_ASSERT_EQ(true, v2.IsCompatibleWith(v1));
    
    // Change one hash
    v2.model_hash = "different";
    
    // Should no longer be compatible
    TEST_ASSERT_EQ(false, v1.IsCompatibleWith(v2));
    
    TEST_SUCCESS();
}

TestResult ExecutionPlanTests_VersionToString() {
    ExecutionPlanVersion version;
    version.model_hash = "abcdef1234567890";
    version.tensor_layout_hash = "fedcba0987654321";
    version.kernel_registry_hash = "1234567890abcdef";
    
    std::string str = version.ToString();
    
    // Should be truncated to 8 chars each
    TEST_ASSERT(str.find("abcdef12") != std::string::npos);
    TEST_ASSERT(str.find("fedcba09") != std::string::npos);
    
    TEST_SUCCESS();
}

TestResult ExecutionPlanTests_VersionJSON() {
    ExecutionPlanVersion version;
    version.model_hash = "abc123";
    version.tensor_layout_hash = "def456";
    version.kernel_registry_hash = "ghi789";
    version.timestamp = 1234567890;
    
    Json::Value json = version.ToJSON();
    
    TEST_ASSERT_EQ(std::string("abc123"), json["model_hash"].asString());
    TEST_ASSERT_EQ(std::string("def456"), json["tensor_layout_hash"].asString());
    TEST_ASSERT_EQ(1234567890ULL, json["timestamp"].asUInt64());
    
    // Round-trip
    ExecutionPlanVersion restored = ExecutionPlanVersion::FromJSON(json);
    TEST_ASSERT_EQ(version.model_hash, restored.model_hash);
    TEST_ASSERT_EQ(version.timestamp, restored.timestamp);
    
    TEST_SUCCESS();
}

TestResult ExecutionPlanTests_RegistryBasic() {
    ExecutionPlanRegistry registry;
    
    ExecutionPlanVersion version;
    version.model_hash = "abc123";
    
    // Register a plan
    registry.RegisterPlan("plan1", version);
    
    // Should be valid
    TEST_ASSERT_EQ(true, registry.IsPlanValid("plan1", version));
    
    // Different version should be invalid
    ExecutionPlanVersion different;
    different.model_hash = "different";
    TEST_ASSERT_EQ(false, registry.IsPlanValid("plan1", different));
    
    TEST_SUCCESS();
}

TestResult ExecutionPlanTests_RegistryInvalidate() {
    ExecutionPlanRegistry registry;
    
    ExecutionPlanVersion old_version;
    old_version.model_hash = "old123";
    
    ExecutionPlanVersion new_version;
    new_version.model_hash = "new456";
    
    // Register old plan
    registry.RegisterPlan("plan1", old_version);
    registry.RegisterPlan("plan2", old_version);
    
    // Invalidate stale plans
    registry.InvalidateStalePlans(new_version);
    
    // Old plans should be removed
    TEST_ASSERT_EQ(false, registry.IsPlanValid("plan1", old_version));
    TEST_ASSERT_EQ(false, registry.IsPlanValid("plan2", old_version));
    
    TEST_SUCCESS();
}

TestResult ExecutionPlanTests_RegistryCount() {
    ExecutionPlanRegistry registry;
    
    TEST_ASSERT_EQ(0ULL, registry.GetPlanCount());
    
    ExecutionPlanVersion version;
    registry.RegisterPlan("plan1", version);
    registry.RegisterPlan("plan2", version);
    
    TEST_ASSERT_EQ(2ULL, registry.GetPlanCount());
    
    registry.Clear();
    
    TEST_ASSERT_EQ(0ULL, registry.GetPlanCount());
    
    TEST_SUCCESS();
}

//============================================================================
// Registration
//============================================================================

void RegisterExecutionPlanTests(TestFramework& framework) {
    REGISTER_TEST(framework, ExecutionPlanTests, VersionCompatibility);
    REGISTER_TEST(framework, ExecutionPlanTests, VersionToString);
    REGISTER_TEST(framework, ExecutionPlanTests, VersionJSON);
    REGISTER_TEST(framework, ExecutionPlanTests, RegistryBasic);
    REGISTER_TEST(framework, ExecutionPlanTests, RegistryInvalidate);
    REGISTER_TEST(framework, ExecutionPlanTests, RegistryCount);
}

} // namespace Tests
} // namespace NEVM
} // namespace RawrXD
