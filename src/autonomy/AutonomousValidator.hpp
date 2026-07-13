/**
 * AutonomousValidator.hpp
 *
 * Phase C.3 Batch 5/5: Autonomous Validation
 *
 * Validation targets:
 *   - Repeatable convergence
 *   - Decision accuracy
 *   - Recovery success
 *   - Performance improvement
 *   - No oscillating behavior
 *
 * Benchmark: Baseline execution vs Autonomous execution
 */

#pragma once

#include "AutonomousController.hpp"
#include "AutonomousDecisionEngine.hpp"
#include "../telemetry/PerformanceBaseline.hpp"

#include <vector>
#include <map>
#include <functional>

namespace Autonomy {

/**
 * Validation result
 */
struct ValidationResult {
    bool passed{false};
    std::string testName;
    std::string description;
    double score{0.0};              // 0-1, higher is better
    double threshold{0.8};          // Minimum to pass
    std::string failureReason;
    int64_t executionTimeMs{0};
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Convergence metrics
 */
struct ConvergenceMetrics {
    int iterationsToConverge{0};
    double finalStability{0.0};
    double stabilityVariance{0.0};
    bool didConverge{false};
    std::vector<double> stabilityHistory;
    
    std::string ToJson() const;
};

/**
 * Decision accuracy metrics
 */
struct DecisionAccuracyMetrics {
    int totalDecisions{0};
    int correctDecisions{0};
    double precision{0.0};
    double recall{0.0};
    double f1Score{0.0};
    double averagePredictionError{0.0};
    
    void Calculate();
    std::string ToJson() const;
};

/**
 * Oscillation detection
 */
struct OscillationMetrics {
    bool detected{false};
    int oscillationCount{0};
    double averagePeriodMs{0.0};
    double amplitude{0.0};
    std::vector<std::pair<int64_t, double>> detectedOscillations;
    
    std::string ToJson() const;
};

/**
 * Performance comparison
 */
struct PerformanceComparison {
    Telemetry::PerformanceBaseline baseline;
    Telemetry::PerformanceBaseline autonomous;
    
    double tpsImprovement{0.0};
    double latencyImprovement{0.0};
    double resourceEfficiency{0.0};
    double failedTaskReduction{0.0};
    
    void Calculate();
    std::string ToJson() const;
    void Print() const;
};

/**
 * Validation suite configuration
 */
struct ValidationConfig {
    int convergenceIterations{100};      // Max iterations for convergence test
    double convergenceThreshold{0.9};     // Min stability to consider converged
    int decisionAccuracySamples{50};     // Number of decisions to evaluate
    double oscillationThreshold{0.1};    // Min amplitude to detect oscillation
    int performanceTestDurationMs{10000}; // Duration of performance comparison
    
    std::string ToJson() const;
};

/**
 * Autonomous Validator
 *
 * Comprehensive validation of the autonomous control system.
 */
class AutonomousValidator {
public:
    AutonomousValidator();
    ~AutonomousValidator();

    /**
     * Initialize validator
     */
    bool Initialize(const ValidationConfig& config);

    /**
     * Run complete validation suite
     */
    std::vector<ValidationResult> RunValidationSuite();

    /**
     * Individual validation tests
     */
    ValidationResult ValidateConvergence();
    ValidationResult ValidateDecisionAccuracy();
    ValidationResult ValidateRecoverySuccess();
    ValidationResult ValidatePerformanceImprovement();
    ValidationResult ValidateNoOscillation();
    ValidationResult ValidateRepeatability();

    /**
     * Benchmark: Baseline vs Autonomous
     */
    PerformanceComparison RunBenchmark();

    /**
     * Get metrics
     */
    ConvergenceMetrics GetConvergenceMetrics() const;
    DecisionAccuracyMetrics GetDecisionAccuracyMetrics() const;
    OscillationMetrics GetOscillationMetrics() const;

    /**
     * Generate validation report
     */
    std::string GenerateReport() const;
    bool SaveReport(const std::string& path) const;

    /**
     * Print summary
     */
    void PrintSummary() const;

private:
    ValidationConfig config_;
    bool initialized_{false};
    
    // Metrics storage
    ConvergenceMetrics convergenceMetrics_;
    DecisionAccuracyMetrics accuracyMetrics_;
    OscillationMetrics oscillationMetrics_;
    PerformanceComparison benchmark_;
    
    // Test results
    std::vector<ValidationResult> results_;
    
    // Helpers
    bool CheckConvergence(const std::vector<double>& stabilityHistory);
    OscillationMetrics DetectOscillations(const std::vector<double>& values);
    double CalculateVariance(const std::vector<double>& values) const;
};

/**
 * Validation CLI
 */
class AutonomousValidatorCLI {
public:
    static void PrintBanner();
    static void PrintUsage();
    static int Run(int argc, char* argv[]);
    
private:
    static ValidationConfig ParseArgs(int argc, char* argv[]);
};

} // namespace Autonomy
