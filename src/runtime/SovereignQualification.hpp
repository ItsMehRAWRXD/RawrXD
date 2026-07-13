#pragma once

/**
 * SovereignQualification.hpp
 *
 * Phase C.1: Sovereign Runtime Qualification
 *
 * One-command qualification suite for the complete runtime.
 */

#include "RuntimeIntegration.hpp"
#include <vector>
#include <map>

namespace Sovereign {

/**
 * Qualification test result
 */
struct QualificationResult {
    std::string component;
    std::string test;
    bool passed;
    std::string message;
    int64_t durationMs;
    std::map<std::string, std::string> metrics;

    std::string ToJson() const;
};

/**
 * Component qualification status
 */
struct ComponentStatus {
    std::string name;
    bool available;
    bool functional;
    int itemCount;
    std::map<std::string, std::string> details;

    std::string ToJson() const;
};

/**
 * Performance metrics from qualification
 */
struct QualificationPerformance {
    int64_t startupMs = 0;
    int64_t graphBuildMs = 0;
    int64_t workflowMs = 0;
    int64_t checkpointSaveMs = 0;
    int64_t checkpointRestoreMs = 0;
    int64_t totalQualificationMs = 0;
    size_t memoryBaselineMb = 0;
    size_t memoryPeakMb = 0;

    std::string ToJson() const;
};

/**
 * Complete qualification report
 */
struct QualificationReport {
    std::string runtimeVersion = "1.0.0";
    std::string timestamp;
    std::string overallResult;

    ComponentStatus segStatus;
    ComponentStatus engineStatus;
    ComponentStatus swarmStatus;
    ComponentStatus telemetryStatus;
    ComponentStatus checkpointStatus;

    QualificationPerformance performance;
    std::vector<QualificationResult> testResults;

    std::string ToJson() const;
    void PrintSummary() const;
};

/**
 * Sovereign Runtime Qualification Suite
 *
 * Executes comprehensive qualification tests and generates report.
 */
class SovereignQualification {
public:
    SovereignQualification();
    ~SovereignQualification();

    // Run full qualification suite
    QualificationReport RunQualification();

    // Run specific component tests
    QualificationResult TestSEG();
    QualificationResult TestEngine();
    QualificationResult TestSwarm();
    QualificationResult TestTelemetry();
    QualificationResult TestCheckpoint();
    QualificationResult TestIntegration();

    // Performance benchmarks
    QualificationPerformance RunPerformanceBenchmarks();

    // Export report
    bool SaveReport(const std::string& path) const;

private:
    std::unique_ptr<IntegratedSovereignRuntime> runtime_;
    QualificationReport report_;

    bool InitializeRuntime();
    void ShutdownRuntime();
    ComponentStatus CheckComponent(const std::string& name);
};

/**
 * CLI entry point for qualification
 */
class SovereignQualificationCLI {
public:
    static int Run(int argc, char* argv[]);

private:
    static void PrintBanner();
    static void PrintUsage();
};

} // namespace Sovereign
