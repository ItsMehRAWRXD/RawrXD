#include "execution_gateway.hpp"
#include "attestation_record.hpp"
#include <iostream>
#include <set>
#include <assert>

using namespace val063;

// ============================================================================
// Mock v1.0 Runtime for Testing
// ============================================================================

class MockV10Runtime : public V10Runtime {
public:
    bool should_fail{false};
    std::string mock_output{"Hello, World!"};
    Hash256 mock_runtime_hash;

    MockV10Runtime() {
        mock_runtime_hash = hash::of_string("v1.0-certified-runtime");
    }

    bool initialize() override { return true; }
    
    std::string execute(const std::string& prompt, 
                        const ExecutionRequest::Configuration& config) override {
        if (should_fail) {
            throw std::runtime_error("Mock execution failure");
        }
        return mock_output;
    }
    
    Hash256 get_runtime_hash() const override { return mock_runtime_hash; }
};

// ============================================================================
// Test Results
// ============================================================================

struct TestResults {
    int passed = 0;
    int failed = 0;
    
    void check(bool condition, const char* test_name) {
        if (condition) {
            std::cout << "[PASS] " << test_name << std::endl;
            ++passed;
        } else {
            std::cout << "[FAIL] " << test_name << std::endl;
            ++failed;
        }
    }
};

// ============================================================================
// Gate B Tests
// ============================================================================

void test_identity_survives_roundtrip(TestResults& results) {
    std::cout << "\n=== Test: Identity Survives Gateway Round-trip ===" << std::endl;
    
    MockV10Runtime runtime;
    RuntimeVersion version{1, 1, 0, "gate-b", "2026-07-24"};
    
    auto gateway = create_gateway(&runtime, version);
    
    ExecutionRequest request;
    request.prompt = "Test prompt";
    request.configuration.temperature = 0.7f;
    request.model_path = "model.gguf";
    
    auto result = gateway->execute(request);
    
    // Verify identity in attestation matches expected
    ExecutionIdentity expected_identity;
    expected_identity.prompt_hash = hash::of_string(request.prompt);
    expected_identity.configuration_hash = request.configuration.hash();
    expected_identity.model_hash = hash::of_string(request.model_path);
    expected_identity.runtime_hash = runtime.mock_runtime_hash;
    
    results.check(result.attestation.verify_identity(expected_identity),
                  "Identity survives gateway round-trip");
    results.check(result.attestation.identity.is_complete(),
                  "Attestation contains complete identity");
}

void test_gateway_cannot_alter_identity(TestResults& results) {
    std::cout << "\n=== Test: Gateway Cannot Alter Identity Hash ===" << std::endl;
    
    MockV10Runtime runtime;
    RuntimeVersion version{1, 1, 0, "gate-b", "2026-07-24"};
    
    auto gateway = create_gateway(&runtime, version);
    
    // Execute same request twice
    ExecutionRequest request;
    request.prompt = "Same prompt";
    request.configuration.temperature = 0.8f;
    request.model_path = "same.gguf";
    
    auto result1 = gateway->execute(request);
    auto result2 = gateway->execute(request);
    
    // Identity hashes should be identical
    results.check(result1.attestation.identity == result2.attestation.identity,
                  "Same request produces identical identity");
    
    // Combined identity should also match
    results.check(result1.attestation.identity.combined_identity() == 
                  result2.attestation.identity.combined_identity(),
                  "Combined identity is deterministic");
}

void test_different_configurations_different_attestations(TestResults& results) {
    std::cout << "\n=== Test: Different Configurations → Different Attestations ===" << std::endl;
    
    MockV10Runtime runtime;
    RuntimeVersion version{1, 1, 0, "gate-b", "2026-07-24"};
    
    auto gateway = create_gateway(&runtime, version);
    
    // Same prompt, different temperature
    ExecutionRequest request1;
    request1.prompt = "Same prompt";
    request1.configuration.temperature = 0.5f;
    request1.model_path = "model.gguf";
    
    ExecutionRequest request2;
    request2.prompt = "Same prompt";
    request2.configuration.temperature = 0.9f;  // Different
    request2.model_path = "model.gguf";
    
    auto result1 = gateway->execute(request1);
    auto result2 = gateway->execute(request2);
    
    // Prompt hash should be same
    results.check(result1.attestation.identity.prompt_hash == 
                  result2.attestation.identity.prompt_hash,
                  "Same prompt produces same prompt_hash");
    
    // Configuration hash should be different
    results.check(result1.attestation.identity.configuration_hash != 
                  result2.attestation.identity.configuration_hash,
                  "Different config produces different configuration_hash");
    
    // Combined identity should be different
    results.check(result1.attestation.identity.combined_identity() != 
                  result2.attestation.identity.combined_identity(),
                  "Different config produces different combined identity");
    
    // Execution IDs should be different
    results.check(result1.attestation.execution_id != result2.attestation.execution_id,
                  "Different executions have different UUIDs");
}

void test_uuid_uniqueness(TestResults& results) {
    std::cout << "\n=== Test: UUID Uniqueness Across Executions ===" << std::endl;
    
    MockV10Runtime runtime;
    RuntimeVersion version{1, 1, 0, "gate-b", "2026-07-24"};
    
    auto gateway = create_gateway(&runtime, version);
    
    std::set<std::string> execution_ids;
    bool all_unique = true;
    
    for (int i = 0; i < 100; ++i) {
        ExecutionRequest request;
        request.prompt = "Prompt " + std::to_string(i);
        request.model_path = "model.gguf";
        
        auto result = gateway->execute(request);
        auto id_str = result.attestation.execution_id.to_string();
        
        if (execution_ids.count(id_str) > 0) {
            all_unique = false;
            break;
        }
        execution_ids.insert(id_str);
    }
    
    results.check(all_unique, "100 executions have unique UUIDs");
    results.check(execution_ids.size() == 100, "All 100 UUIDs recorded");
}

void test_timestamp_monotonicity(TestResults& results) {
    std::cout << "\n=== Test: Timestamp Monotonicity ===" << std::endl;
    
    MockV10Runtime runtime;
    RuntimeVersion version{1, 1, 0, "gate-b", "2026-07-24"};
    
    auto gateway = create_gateway(&runtime, version);
    
    ExecutionRequest request;
    request.prompt = "Test";
    request.model_path = "model.gguf";
    
    auto result = gateway->execute(request);
    
    // Start time should be before completion
    results.check(result.attestation.completed_at.has_value(),
                  "Attestation has completion timestamp");
    
    if (result.attestation.completed_at) {
        results.check(TimestampProvider::is_monotonic(
                          result.attestation.started_at, 
                          result.attestation.completed_at.value()),
                      "Completion is after start");
        
        results.check(result.attestation.completed_at->wall_ns_since_epoch() >= 
                      result.attestation.started_at.wall_ns_since_epoch(),
                      "Wall clock time is monotonic");
    }
}

void test_failed_executions_produce_attestations(TestResults& results) {
    std::cout << "\n=== Test: Failed Executions Produce Attestations ===" << std::endl;
    
    MockV10Runtime runtime;
    runtime.should_fail = true;  // Force failure
    
    RuntimeVersion version{1, 1, 0, "gate-b", "2026-07-24"};
    auto gateway = create_gateway(&runtime, version);
    
    ExecutionRequest request;
    request.prompt = "This will fail";
    request.model_path = "model.gguf";
    
    auto result = gateway->execute(request);
    
    // Should have attestation even on failure
    results.check(!result.success, "Execution failed as expected");
    results.check(result.attestation.status == ExecutionStatus::Failed,
                  "Attestation status is 'failed'");
    results.check(result.attestation.error_message.has_value(),
                  "Attestation contains error message");
    results.check(result.attestation.identity.is_complete(),
                  "Failed execution still has complete identity");
    results.check(!result.attestation.execution_id.to_string().empty(),
                  "Failed execution has execution ID");
}

void test_serialization_preserves_bytes(TestResults& results) {
    std::cout << "\n=== Test: Serialization Preserves Identity ===" << std::endl;
    
    MockV10Runtime runtime;
    RuntimeVersion version{1, 1, 0, "gate-b", "2026-07-24"};
    
    auto gateway = create_gateway(&runtime, version);
    
    ExecutionRequest request;
    request.prompt = "Serialization test";
    request.configuration.temperature = 0.7f;
    request.model_path = "model.gguf";
    
    auto result = gateway->execute(request);
    
    // Serialize to JSON
    auto json = result.attestation.to_json();
    
    // Verify JSON contains expected fields
    results.check(json.find("execution_id") != std::string::npos,
                  "JSON contains execution_id");
    results.check(json.find("configuration_hash") != std::string::npos,
                  "JSON contains configuration_hash");
    results.check(json.find("identity") != std::string::npos,
                  "JSON contains identity section");
    results.check(json.find("started_at") != std::string::npos,
                  "JSON contains started_at");
    results.check(json.find("status") != std::string::npos,
                  "JSON contains status");
    
    // Verify identity hashes are in hex format (64 chars)
    auto prompt_hash_pos = json.find("\"prompt_hash\": \"");
    if (prompt_hash_pos != std::string::npos) {
        auto hash_start = prompt_hash_pos + 16;  // Length of '"prompt_hash": "'
        auto hash_end = json.find('\"', hash_start);
        auto hash_len = hash_end - hash_start;
        results.check(hash_len == 64, "Hash is 64 hex characters");
    }
}

void test_gateway_integrity(TestResults& results) {
    std::cout << "\n=== Test: Gateway Integrity Verification ===" << std::endl;
    
    MockV10Runtime runtime;
    RuntimeVersion version{1, 1, 0, "gate-b", "2026-07-24"};
    
    auto gateway = create_gateway(&runtime, version);
    
    // Execute a few times
    for (int i = 0; i < 5; ++i) {
        ExecutionRequest request;
        request.prompt = "Test " + std::to_string(i);
        request.model_path = "model.gguf";
        gateway->execute(request);
    }
    
    // Verify gateway integrity
    results.check(gateway->verify_integrity(),
                  "Gateway integrity check passes");
    
    // Validate gateway
    results.check(validate_gateway(*gateway),
                  "Gateway validation passes");
    
    // Check statistics
    auto stats = gateway->get_statistics();
    results.check(stats.executions_total == 5,
                  "Statistics track 5 executions");
    results.check(stats.identity_verifications_failed == 0,
                  "No identity verification failures");
}

void test_configuration_hash_distinction(TestResults& results) {
    std::cout << "\n=== Test: Configuration Hash Distinguishes Settings ===" << std::endl;
    
    // Test that different sampler settings produce different hashes
    ExecutionRequest::Configuration config1;
    config1.temperature = 0.7f;
    config1.seed = 42;
    
    ExecutionRequest::Configuration config2;
    config2.temperature = 0.7f;
    config2.seed = 43;  // Different seed
    
    ExecutionRequest::Configuration config3;
    config3.temperature = 0.8f;  // Different temperature
    config3.seed = 42;
    
    auto hash1 = config1.hash();
    auto hash2 = config2.hash();
    auto hash3 = config3.hash();
    
    results.check(hash1 != hash2,
                  "Different seed produces different config hash");
    results.check(hash1 != hash3,
                  "Different temperature produces different config hash");
    results.check(hash2 != hash3,
                  "Both changes produce different config hashes");
    
    // Same config should produce same hash
    ExecutionRequest::Configuration config1_copy;
    config1_copy.temperature = 0.7f;
    config1_copy.seed = 42;
    
    auto hash1_copy = config1_copy.hash();
    results.check(hash1 == hash1_copy,
                  "Same config produces identical hash");
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "VAL-063 Gate B: Gateway Binding Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    TestResults results;
    
    test_identity_survives_roundtrip(results);
    test_gateway_cannot_alter_identity(results);
    test_different_configurations_different_attestations(results);
    test_uuid_uniqueness(results);
    test_timestamp_monotonicity(results);
    test_failed_executions_produce_attestations(results);
    test_serialization_preserves_bytes(results);
    test_gateway_integrity(results);
    test_configuration_hash_distinction(results);
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << results.passed << " passed, " 
              << results.failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Generate Gate B evidence
    GateBEvidence evidence;
    evidence.status = (results.failed == 0) ? "PASS" : "FAIL";
    evidence.observes_identity = true;
    evidence.mutates_identity = false;
    
    // Get a sample execution for the evidence
    MockV10Runtime runtime;
    RuntimeVersion version{1, 1, 0, "gate-b", "2026-07-24"};
    auto gateway = create_gateway(&runtime, version);
    
    ExecutionRequest request;
    request.prompt = "Evidence generation";
    request.model_path = "model.gguf";
    auto result = gateway->execute(request);
    
    evidence.execution_attestation.uuid = result.attestation.execution_id.to_string();
    evidence.execution_attestation.timestamp = result.attestation.started_at.iso8601();
    evidence.execution_attestation.backend = "native";
    evidence.captured_at = timestamp::now();
    
    std::ofstream evidence_file("gateway_binding.json");
    evidence_file << evidence.to_json();
    evidence_file.close();
    
    std::cout << "\nEvidence written to: gateway_binding.json" << std::endl;
    
    return results.failed > 0 ? 1 : 0;
}
