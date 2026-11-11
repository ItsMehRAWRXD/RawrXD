#pragma once

/**
 * SEGValidationSuite.hpp
 * 
 * Phase B.4 Batch 5/5: SEG Validation
 * 
 * Comprehensive validation suite for the Sovereign Execution Graph.
 * Validates the entire stack from graph construction to harmonic convergence.
 */

#include "SovereignExecutionGraph.hpp"
#include "SovereignExecutionGraphBuilder.hpp"
#include "../swarm/SovereignSwarm.hpp"
#include "../swarm/InfinitePerfectionTelemetry.hpp"
#include "../infinite/InfinitePerfectionEngine.hpp"
#include <vector>
#include <string>
#include <functional>

namespace Sovereign {

// Forward declarations
class ExecutionGraph;
class ExecutionPlanner;
struct ExecutionPlan;

/**
 * Validation test result
 */
struct ValidationResult {
    std::string testName;
    bool passed;
    std::string message;
    int64_t durationMs;
    double metricValue;
};

/**
 * SEG Validation Suite
 * 
 * End-to-end validation of the Sovereign Execution Graph:
 * 1. Graph construction
 * 2. Graph validation
 * 3. Plan execution
 * 4. Swarm dispatch
 * 5. Engine cycle invocation
 * 6. Telemetry reception
 * 7. Topology adaptation
 * 8. Harmonic convergence
 * 9. Checkpoint/restore
 * 10. Full workflow execution
 */
class SEGValidationSuite {
public:
    SEGValidationSuite();
    ~SEGValidationSuite();
    
    // Initialize with required components
    bool Initialize(
        InfinitePerfection::InfinitePerfectionEngine* engine,
        SovereignSwarm* swarm,
        InfinitePerfectionTelemetry* telemetry
    );
    
    // Run all validation tests
    std::vector<ValidationResult> RunAllTests();
    
    // Individual test suites
    ValidationResult TestGraphConstruction();
    ValidationResult TestGraphValidation();
    ValidationResult TestPlanExecution();
    ValidationResult TestSwarmDispatch();
    ValidationResult TestEngineInvocation();
    ValidationResult TestTelemetryReception();
    ValidationResult TestTopologyAdaptation();
    ValidationResult TestHarmonicConvergence();
    ValidationResult TestCheckpointRestore();
    ValidationResult TestFullWorkflow();
    
    // Get summary report
    std::string GetSummaryReport() const;
    
    // Export results to JSON
    std::string ExportToJson() const;
    
    // Performance metrics
    struct PerformanceMetrics {
        double graphBuildTimeMs;
        double planGenerationTimeMs;
        double cycleThroughput;
        double telemetryOverheadMs;
        double schedulerAdaptationLatencyMs;
        size_t memoryFootprintBytes;
    };
    
    PerformanceMetrics GetPerformanceMetrics() const;
    
private:
    InfinitePerfection::InfinitePerfectionEngine* engine_;
    SovereignSwarm* swarm_;
    InfinitePerfectionTelemetry* telemetry_;
    std::unique_ptr<SovereignExecutionGraphBuilderEnhanced> builder_;
    std::unique_ptr<ExecutionGraph> graph_;
    std::unique_ptr<ExecutionPlanner> planner_;
    
    std::vector<ValidationResult> results_;
    PerformanceMetrics metrics_;
    
    bool initialized_;
    
    // Helper methods
    bool ValidateGraphTopology(const ExecutionGraph& graph);
    bool ValidateNodeConnectivity(const ExecutionGraph& graph);
    bool ValidateHarmonicAlignment(const ExecutionGraph& graph);
    double MeasureConvergence(const ExecutionPlan& plan);
};

/**
 * CLI entry point for validation
 */
class SEGValidationCLI {
public:
    static int Run(int argc, char* argv[]);
    
private:
    static void PrintUsage();
    static void PrintResults(const std::vector<ValidationResult>& results);
};

} // namespace Sovereign
