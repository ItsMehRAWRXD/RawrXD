/**
 * StabilityValidator.hpp
 *
 * Phase C.4 Batch 5/5: Autonomous Stability Validator
 *
 * The qualification gate for the entire autonomous safety system.
 * Validates that the stability envelope, oscillation dampener,
 * rollback engine, and safety gate work together correctly.
 */

#pragma once

#include "StabilityEnvelope.hpp"
#include "OscillationDampener.hpp"
#include "RollbackEngine.hpp"
#include "DecisionRiskScorer.hpp"
#include "SafetyProfile.hpp"
#include "../core/SovereignState.hpp"

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <chrono>
#include <optional>
#include <memory>

namespace Autonomy {

/**
 * Test result for a single validation
 */
struct ValidationResult {
    std::string testName;
    bool passed{false};
    std::string description;
    std::string errorMessage;
    double durationMs{0.0};
    std::map<std::string, double> metrics;
    int64_t timestampMs{0};
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Test suite results
 */
struct ValidationSuiteResults {
    std::string suiteName;
    std::vector<ValidationResult> results;
    int totalTests{0};
    int passedTests{0};
    int failedTests{0};
    double totalDurationMs{0.0};
    int64_t startTimeMs{0};
    int64_t endTimeMs{0};
    
    double GetPassRate() const;
    bool AllPassed() const;
    std::string ToJson() const;
    void PrintSummary() const;
};

/**
 * Stability metrics collected during validation
 */
struct StabilityMetrics {
    double avgStability{0.0};
    double minStability{1.0};
    double maxStability{0.0};
    double stabilityVariance{0.0};
    int oscillationCount{0};
    int rollbackCount{0};
    int blockedDecisionCount{0};
    int mutationCount{0};
    double avgDecisionLatencyMs{0.0};
    double maxDecisionLatencyMs{0.0};
    int resourcePressureEvents{0};
    int safetyViolations{0};
    int recoveryEvents{0};
    
    std::string ToJson() const;
    bool IsStable() const;
};

/**
 * Chaos injection configuration for stress testing
 */
struct ChaosConfig {
    bool enableDecisionChaos{false};      // Random decision failures
    bool enableMutationChaos{false};    // Random mutation failures
    bool enableResourceChaos{false};    // Resource pressure spikes
    bool enableOscillationChaos{false};   // Induced oscillations
    bool enableNetworkChaos{false};       // Network delays (if applicable)
    
    double chaosProbability{0.1};         // Probability of chaos event (0-1)
    int maxChaosEventsPerMinute{10};      // Rate limiting
    
    std::string ToJson() const;
};

/**
 * Long-run simulation configuration
 */
struct SimulationConfig {
    int durationSeconds{60};              // Simulation duration
    int decisionRateHz{10};                 // Decisions per second
    int mutationRateHz{2};                  // Mutations per second
    bool enableChaos{false};                // Enable chaos injection
    ChaosConfig chaosConfig;
    double targetStability{0.8};              // Minimum acceptable stability
    double maxOscillationSeverity{0.5};       // Maximum allowed oscillation
    int maxRollbacksPerMinute{5};           // Maximum rollbacks allowed
    
    std::string ToJson() const;
};

/**
 * Autonomous Stability Validator
 * 
 * Validates the entire safety loop:
 * Telemetry → Patterns → Roles → Intents → Decisions → Mutations → Execution → Feedback → Learning
 */
class StabilityValidator {
public:
    StabilityValidator();
    ~StabilityValidator();
    
    // Initialize with all safety components
    bool Initialize(
        StabilityEnvelope* envelope,
        OscillationManager* oscillationManager,
        RollbackEngine* rollbackEngine,
        SafetyGate* safetyGate,
        DecisionHistory* decisionHistory
    );
    
    // Core validation suites
    ValidationSuiteResults ValidateEnvelopeEnforcement();
    ValidationSuiteResults ValidateOscillationControl();
    ValidationSuiteResults ValidateRollbackEngine();
    ValidationSuiteResults ValidateSafetyGate();
    ValidationSuiteResults ValidateAutonomousLoop();
    ValidationSuiteResults ValidateLongRunStability(const SimulationConfig& config);
    
    // Run all validation suites
    ValidationSuiteResults RunAllValidations();
    ValidationSuiteResults RunAllValidations(const SimulationConfig& longRunConfig);
    
    // Individual test execution
    ValidationResult RunTest(const std::string& testName, 
                              std::function<bool()> testFunc);
    
    // Chaos injection for stress testing
    void EnableChaos(const ChaosConfig& config);
    void DisableChaos();
    bool IsChaosEnabled() const;
    
    // Metrics and reporting
    StabilityMetrics GetCurrentMetrics() const;
    void ResetMetrics();
    void PrintStatus() const;
    
    // Certification
    bool IsPhaseC4Complete() const;
    std::string GenerateCertificationReport() const;
    
private:
    // Component references
    StabilityEnvelope* envelope_{nullptr};
    OscillationManager* oscillationManager_{nullptr};
    RollbackEngine* rollbackEngine_{nullptr};
    SafetyGate* safetyGate_{nullptr};
    DecisionHistory* decisionHistory_{nullptr};
    
    // State
    bool initialized_{false};
    bool chaosEnabled_{false};
    ChaosConfig chaosConfig_;
    
    // Metrics tracking
    StabilityMetrics accumulatedMetrics_;
    std::vector<double> stabilitySamples_;
    std::vector<double> decisionLatencies_;
    int64_t metricsStartTimeMs_{0};
    
    // Test helpers
    bool SimulateEnvelopeViolation();
    bool SimulateOscillation(const std::string& pattern);
    bool SimulateMutation(const std::string& mutationType);
    bool SimulateDecision(const std::string& decisionType, double confidence);
    bool WaitForStability(double targetStability, int timeoutMs);
    bool WaitForConvergence(double targetConvergence, int timeoutMs);
    
    // Chaos injection
    void MaybeInjectChaos();
    void InjectDecisionChaos();
    void InjectMutationChaos();
    void InjectResourceChaos();
    void InjectOscillationChaos();
    
    // Metrics collection
    void CollectSample();
    void RecordDecisionLatency(double latencyMs);
    void RecordOscillation();
    void RecordRollback();
    void RecordBlockedDecision();
    void RecordMutation();
    void RecordResourcePressure();
    void RecordSafetyViolation();
    void RecordRecovery();
    
    // Finalize metrics
    StabilityMetrics CalculateFinalMetrics() const;
    
    // Time utilities
    int64_t GetCurrentTimeMs() const;
    void SleepMs(int ms) const;
};

/**
 * CLI interface for running validations
 */
class StabilityValidatorCLI {
public:
    static void PrintBanner();
    static void PrintUsage();
    static int Run(int argc, char* argv[]);
    
private:
    static void InteractiveMode(StabilityValidator& validator);
    static void RunSpecificSuite(StabilityValidator& validator, const std::string& suiteName);
    static void RunLongRunSimulation(StabilityValidator& validator, int durationSeconds);
    static void PrintCertification(const ValidationSuiteResults& results);
};

} // namespace Autonomy
