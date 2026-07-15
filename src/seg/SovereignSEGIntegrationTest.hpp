/**
 * SovereignSEGIntegrationTest.hpp
 * 
 * Phase B.4 Batch 5/5: SEG Validation
 * 
 * End-to-end integration test suite that validates:
 * - Graph discovery and integrity
 * - Planner topological validity
 * - Runtime execution (Engine cycles + Swarm tasks)
 * - Telemetry capture
 * - Checkpoint persistence and recovery
 * - Deterministic execution
 */

#pragma once

#include "SovereignExecutionGraph.hpp"
#include "SovereignExecutionGraphBuilder.hpp"
#include "SovereignExecutionPlanner.hpp"
#include "SovereignSEGCLI.hpp"
#include <string>
#include <vector>
#include <map>
#include <functional>

namespace Sovereign {
namespace SEG {

/**
 * Validation result for a single test phase
 */
struct SEGValidationResult {
    bool passed{false};
    std::string phase;
    std::string description;
    std::string details;
    std::map<std::string, std::string> metrics;
    
    void AddMetric(const std::string& key, const std::string& value) {
        metrics[key] = value;
    }
    
    void AddMetric(const std::string& key, int value) {
        metrics[key] = std::to_string(value);
    }
    
    void AddMetric(const std::string& key, double value) {
        metrics[key] = std::to_string(value);
    }
};

/**
 * Complete validation report
 */
struct SEGValidationReport {
    std::vector<SEGValidationResult> results;
    bool allPassed{false};
    std::string timestamp;
    std::string segVersion{"1.0.0"};
    
    int GetPassCount() const;
    int GetFailCount() const;
    std::string ToJson() const;
    void PrintReport() const;
};

/**
 * Unity sequence execution results
 */
struct UnitySequenceResults {
    bool success{false};
    int cyclesExecuted{0};
    int tasksExecuted{0};
    double totalDurationMs{0.0};
    double harmonyIndex{0.0};
    bool converged{false};
    std::vector<std::string> executedCycles;
    std::vector<std::string> executedTasks;
    std::map<std::string, double> cycleTimings;
    std::map<std::string, double> taskTimings;
};

/**
 * Telemetry validation data
 */
struct TelemetryValidationData {
    bool segExecutionComplete{false};
    int nodesExecuted{0};
    int failures{0};
    bool unityConverged{false};
    double harmonyIndex{0.0};
    std::map<std::string, std::string> rawTelemetry;
};

/**
 * Checkpoint validation results
 */
struct CheckpointValidationResults {
    bool saveSuccessful{false};
    bool restoreSuccessful{false};
    bool graphIntegrityMaintained{false};
    bool resumePointCorrect{false};
    std::string checkpointId;
    std::string originalGraphHash;
    std::string restoredGraphHash;
};

/**
 * Main integration test suite
 */
class SovereignSEGIntegrationTest {
public:
    SovereignSEGIntegrationTest();
    ~SovereignSEGIntegrationTest();
    
    // Configuration
    void SetBatchRange(int startBatch, int endBatch);
    void SetEnableTelemetry(bool enable);
    void SetEnableCheckpoints(bool enable);
    void SetCheckpointDirectory(const std::string& dir);
    
    // Main validation entry point
    SEGValidationReport RunFullValidation();
    
    // Individual phase validations (can be run standalone)
    SEGValidationResult ValidateGraphIntegrity();
    SEGValidationResult ValidatePlannerTopology();
    SEGValidationResult ValidateRuntimeExecution();
    SEGValidationResult ValidateTelemetryFlow();
    SEGValidationResult ValidateCheckpointRecovery();
    SEGValidationResult ValidateDeterministicExecution();
    
    // Unity sequence execution
    UnitySequenceResults ExecuteUnitySequence();
    
    // Results access
    const SEGValidationReport& GetLastReport() const { return lastReport_; }
    
private:
    // Configuration
    int startBatch_{243};
    int endBatch_{256};
    bool enableTelemetry_{true};
    bool enableCheckpoints_{true};
    std::string checkpointDir_{"./seg_checkpoints"};
    
    // Runtime state
    std::unique_ptr<ExecutionGraph> graph_;
    std::unique_ptr<SovereignExecutionPlanner::ExecutionPlan> plan_;
    std::unique_ptr<SovereignParallelExecutor> executor_;
    std::unique_ptr<ExecutionMonitor> monitor_;
    SEGValidationReport lastReport_;
    
    // Validation helpers
    bool ValidateNodeCounts();
    bool ValidateDependencyGraph();
    bool ValidateTopologicalOrder();
    bool ValidateCriticalPath();
    bool ValidateExecutionOrderDeterministic();
    
    // Execution helpers
    bool ExecutePlanWithMonitoring();
    TelemetryValidationData CaptureTelemetry();
    CheckpointValidationResults TestCheckpointRecovery();
    
    // Utility
    std::string ComputeGraphHash(const ExecutionGraph& graph);
    std::string GetCurrentTimestamp();
};

/**
 * Quick validation runner for CI/CD
 */
bool RunSEGQuickValidation();

/**
 * Full validation runner with detailed reporting
 */
SEGValidationReport RunSEGFullValidation();

/**
 * Export validation report to file
 */
bool ExportValidationReport(const SEGValidationReport& report, const std::string& filepath);

} // namespace SEG
} // namespace Sovereign
