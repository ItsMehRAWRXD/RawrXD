//============================================================================
// test_validation_schema.cpp
// RawrXD N-EVM - Unit Tests for Validation Schema
//============================================================================

#include "../nevm_validation_schema.hpp"

using namespace RawrXD::NEVM;

TEST(ValidationSchema_Defaults) {
    ValidationSchema schema;
    
    // Default schema should have standard gates
    ASSERT_TRUE(schema.HasGate("load_model"));
    ASSERT_TRUE(schema.HasGate("inference"));
    ASSERT_TRUE(schema.HasGate("determinism"));
    ASSERT_TRUE(schema.HasGate("kv_integrity"));
    ASSERT_TRUE(schema.HasGate("math_mode"));
    ASSERT_TRUE(schema.HasGate("performance"));
    ASSERT_TRUE(schema.HasGate("golden_output"));
    ASSERT_TRUE(schema.HasGate("execution_plan"));
    ASSERT_TRUE(schema.HasGate("regression"));
    ASSERT_TRUE(schema.HasGate("ab_test"));
    ASSERT_TRUE(schema.HasGate("stress"));
    
    return true;
}

TEST(ValidationSchema_GetGate) {
    ValidationSchema schema;
    
    auto gate = schema.GetGate("load_model");
    ASSERT_EQ(std::string("load_model"), gate.name);
    ASSERT_TRUE(gate.required);
    ASSERT_TRUE(gate.enabled);
    
    return true;
}

TEST(ValidationSchema_GetGate_Invalid) {
    ValidationSchema schema;
    
    auto gate = schema.GetGate("nonexistent");
    ASSERT_EQ(std::string(""), gate.name);  // Empty name indicates not found
    
    return true;
}

TEST(ValidationSchema_AddGate) {
    ValidationSchema schema;
    
    ValidationGate newGate;
    newGate.name = "custom_gate";
    newGate.description = "A custom validation gate";
    newGate.required = false;
    newGate.enabled = true;
    newGate.timeout_seconds = 60;
    
    schema.AddGate(newGate);
    
    ASSERT_TRUE(schema.HasGate("custom_gate"));
    auto retrieved = schema.GetGate("custom_gate");
    ASSERT_EQ(std::string("A custom validation gate"), retrieved.description);
    ASSERT_EQ(60, retrieved.timeout_seconds);
    
    return true;
}

TEST(ValidationSchema_RemoveGate) {
    ValidationSchema schema;
    
    ASSERT_TRUE(schema.HasGate("stress"));
    schema.RemoveGate("stress");
    ASSERT_FALSE(schema.HasGate("stress"));
    
    return true;
}

TEST(ValidationSchema_EnableDisable) {
    ValidationSchema schema;
    
    // Disable a gate
    schema.DisableGate("stress");
    auto gate = schema.GetGate("stress");
    ASSERT_FALSE(gate.enabled);
    
    // Enable it back
    schema.EnableGate("stress");
    gate = schema.GetGate("stress");
    ASSERT_TRUE(gate.enabled);
    
    return true;
}

TEST(ValidationSchema_GetEnabledGates) {
    ValidationSchema schema;
    
    // Disable some gates
    schema.DisableGate("stress");
    schema.DisableGate("ab_test");
    
    auto enabled = schema.GetEnabledGates();
    
    // Should have 9 gates (11 total - 2 disabled)
    ASSERT_EQ(9ULL, enabled.size());
    
    // Verify disabled gates are not in the list
    for (const auto& gate : enabled) {
        ASSERT_NE(std::string("stress"), gate.name);
        ASSERT_NE(std::string("ab_test"), gate.name);
    }
    
    return true;
}

TEST(ValidationSchema_GetRequiredGates) {
    ValidationSchema schema;
    
    auto required = schema.GetRequiredGates();
    
    // All default gates are required
    ASSERT_EQ(11ULL, required.size());
    
    return true;
}

TEST(ValidationSchema_ToJSON) {
    ValidationSchema schema;
    
    auto json = schema.ToJSON();
    
    ASSERT_TRUE(json.isArray());
    ASSERT_EQ(11U, json.size());
    
    // Check first gate structure
    auto firstGate = json[0];
    ASSERT_TRUE(firstGate.isMember("name"));
    ASSERT_TRUE(firstGate.isMember("description"));
    ASSERT_TRUE(firstGate.isMember("required"));
    ASSERT_TRUE(firstGate.isMember("enabled"));
    ASSERT_TRUE(firstGate.isMember("timeout_seconds"));
    
    return true;
}

TEST(ValidationSchema_FromJSON) {
    Json::Value json(Json::arrayValue);
    
    Json::Value gate1;
    gate1["name"] = "custom1";
    gate1["description"] = "Custom gate 1";
    gate1["required"] = true;
    gate1["enabled"] = true;
    gate1["timeout_seconds"] = 30;
    json.append(gate1);
    
    Json::Value gate2;
    gate2["name"] = "custom2";
    gate2["description"] = "Custom gate 2";
    gate2["required"] = false;
    gate2["enabled"] = true;
    gate2["timeout_seconds"] = 60;
    json.append(gate2);
    
    ValidationSchema schema;
    schema.FromJSON(json);
    
    ASSERT_TRUE(schema.HasGate("custom1"));
    ASSERT_TRUE(schema.HasGate("custom2"));
    
    auto g1 = schema.GetGate("custom1");
    ASSERT_EQ(std::string("Custom gate 1"), g1.description);
    ASSERT_TRUE(g1.required);
    
    auto g2 = schema.GetGate("custom2");
    ASSERT_EQ(std::string("Custom gate 2"), g2.description);
    ASSERT_FALSE(g2.required);
    
    return true;
}

TEST(ExitCodeMapper_Success) {
    ExitCodeMapper mapper;
    
    ValidationResult result;
    result.success = true;
    result.gate_name = "test";
    
    int code = mapper.MapToExitCode(result);
    ASSERT_EQ(0, code);
    
    return true;
}

TEST(ExitCodeMapper_Failure_Generic) {
    ExitCodeMapper mapper;
    
    ValidationResult result;
    result.success = false;
    result.gate_name = "unknown_gate";
    result.error_message = "Something failed";
    
    int code = mapper.MapToExitCode(result);
    ASSERT_EQ(1, code);  // Generic failure
    
    return true;
}

TEST(ExitCodeMapper_Failure_LoadModel) {
    ExitCodeMapper mapper;
    
    ValidationResult result;
    result.success = false;
    result.gate_name = "load_model";
    result.error_message = "Failed to load";
    
    int code = mapper.MapToExitCode(result);
    ASSERT_EQ(10, code);  // Load model failure
    
    return true;
}

TEST(ExitCodeMapper_Failure_Inference) {
    ExitCodeMapper mapper;
    
    ValidationResult result;
    result.success = false;
    result.gate_name = "inference";
    result.error_message = "Inference error";
    
    int code = mapper.MapToExitCode(result);
    ASSERT_EQ(11, code);  // Inference failure
    
    return true;
}

TEST(ExitCodeMapper_Failure_Determinism) {
    ExitCodeMapper mapper;
    
    ValidationResult result;
    result.success = false;
    result.gate_name = "determinism";
    result.error_message = "Non-deterministic";
    
    int code = mapper.MapToExitCode(result);
    ASSERT_EQ(12, code);  // Determinism failure
    
    return true;
}

TEST(ExitCodeMapper_Failure_KVIntegrity) {
    ExitCodeMapper mapper;
    
    ValidationResult result;
    result.success = false;
    result.gate_name = "kv_integrity";
    result.error_message = "Checksum mismatch";
    
    int code = mapper.MapToExitCode(result);
    ASSERT_EQ(13, code);  // KV integrity failure
    
    return true;
}

TEST(ExitCodeMapper_Failure_Performance) {
    ExitCodeMapper mapper;
    
    ValidationResult result;
    result.success = false;
    result.gate_name = "performance";
    result.error_message = "Too slow";
    
    int code = mapper.MapToExitCode(result);
    ASSERT_EQ(14, code);  // Performance failure
    
    return true;
}

TEST(ExitCodeMapper_Failure_GoldenOutput) {
    ExitCodeMapper mapper;
    
    ValidationResult result;
    result.success = false;
    result.gate_name = "golden_output";
    result.error_message = "Output mismatch";
    
    int code = mapper.MapToExitCode(result);
    ASSERT_EQ(15, code);  // Golden output failure
    
    return true;
}

TEST(ExitCodeMapper_GetDescription) {
    ExitCodeMapper mapper;
    
    ASSERT_EQ(std::string("Success"), mapper.GetDescription(0));
    ASSERT_EQ(std::string("Generic failure"), mapper.GetDescription(1));
    ASSERT_EQ(std::string("Load model failed"), mapper.GetDescription(10));
    ASSERT_EQ(std::string("Inference failed"), mapper.GetDescription(11));
    ASSERT_EQ(std::string("Determinism check failed"), mapper.GetDescription(12));
    ASSERT_EQ(std::string("Unknown exit code"), mapper.GetDescription(999));
    
    return true;
}

TEST(ExitCodeMapper_IsSuccess) {
    ExitCodeMapper mapper;
    
    ASSERT_TRUE(mapper.IsSuccess(0));
    ASSERT_FALSE(mapper.IsSuccess(1));
    ASSERT_FALSE(mapper.IsSuccess(10));
    ASSERT_FALSE(mapper.IsSuccess(15));
    
    return true;
}
