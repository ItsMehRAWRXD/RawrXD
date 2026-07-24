// RC-1.1: Gateway Threat Boundary Tests
// Negative validation - ensuring mutations are detected and rejected

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Certification {

// ============================================================================
// Threat Test Result
// ============================================================================

enum class ThreatTestOutcome {
    Pass,           // Attack was correctly detected and blocked
    Fail,           // Attack was NOT detected (security hole)
    Error           // Test execution failed
};

struct ThreatTestResult {
    std::string test_name;
    ThreatTestOutcome outcome;
    std::string description;
    std::string attack_vector;
    std::string defense_response;
    bool witness_marked_invalid;
    
    std::string Serialize() const;
};

// ============================================================================
// Threat Test Suite
// ============================================================================

class ThreatBoundaryTests {
public:
    ThreatBoundaryTests();
    ~ThreatBoundaryTests();
    
    // Run all threat boundary tests
    std::vector<ThreatTestResult> RunAllTests();
    
    // Individual threat tests
    ThreatTestResult TestIdentityMutation();
    ThreatTestResult TestGatewayBypass();
    ThreatTestResult TestAlteredModelHash();
    ThreatTestResult TestAlteredConfigurationHash();
    ThreatTestResult TestReplayWithModifiedPayload();
    ThreatTestResult TestEvidenceTampering();
    ThreatTestResult TestRuntimeSubstitution();
    ThreatTestResult TestUnauthorizedDirectAccess();
    
    // Get summary
    struct Summary {
        int total_tests;
        int passed;
        int failed;
        int errors;
        bool all_defenses_active;
    };
    Summary GetSummary() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Attack Simulators
// ============================================================================

namespace AttackSimulators {

    // Simulate identity mutation attempt
    bool AttemptIdentityMutation(
        const std::string& original_request_id,
        std::string& mutated_request_id
    );
    
    // Simulate gateway bypass attempt
    bool AttemptGatewayBypass(
        const std::string& model_path,
        const std::string& prompt
    );
    
    // Simulate altered model hash
    bool AttemptModelHashSubstitution(
        const std::string& original_hash,
        std::string& substituted_hash
    );
    
    // Simulate altered configuration
    bool AttemptConfigurationTampering(
        float original_temperature,
        float& tampered_temperature
    );
    
    // Simulate replay with modified payload
    bool AttemptReplayModification(
        const std::vector<int32_t>& original_tokens,
        std::vector<int32_t>& modified_tokens
    );
    
    // Simulate evidence tampering
    bool AttemptEvidenceTampering(
        const std::string& evidence_path,
        std::string& tampered_content
    );

} // namespace AttackSimulators

// ============================================================================
// Defense Validators
// ============================================================================

namespace DefenseValidators {

    // Validate identity integrity
    bool ValidateIdentityIntegrity(
        const std::string& request_id,
        const std::string& expected_hash
    );
    
    // Validate gateway path enforcement
    bool ValidateGatewayEnforcement(
        const std::string& execution_context
    );
    
    // Validate model hash lock
    bool ValidateModelHashLock(
        const std::string& model_path,
        const std::string& expected_hash,
        const std::string& actual_hash
    );
    
    // Validate configuration integrity
    bool ValidateConfigurationIntegrity(
        const std::string& config_hash,
        const std::string& expected_hash
    );
    
    // Validate replay integrity
    bool ValidateReplayIntegrity(
        const std::vector<int32_t>& tokens,
        const std::string& expected_hash
    );
    
    // Mark witness as invalid
    void MarkWitnessInvalid(
        const std::string& witness_id,
        const std::string& reason
    );

} // namespace DefenseValidators

// ============================================================================
// C API
// ============================================================================

extern "C" {

// Threat tests
typedef struct Val063ThreatTests* Val063ThreatHandle;

Val063ThreatHandle val063_threat_tests_create();
int val063_threat_run_all(Val063ThreatHandle handle);
const char* val063_threat_get_results_json(Val063ThreatHandle handle);
void val063_threat_destroy(Val063ThreatHandle handle);

// Individual tests
int val063_threat_test_identity_mutation();
int val063_threat_test_gateway_bypass();
int val063_threat_test_model_hash_alteration();
int val063_threat_test_config_alteration();
int val063_threat_test_replay_modification();

} // extern "C"

} // namespace Certification
} // namespace RawrXD
