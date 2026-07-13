/**
 * SovereignSEGCLI.hpp
 * 
 * Phase B.4 Batch 4/5: Runtime Integration
 * 
 * CLI integration layer that connects SEG to Engine/Swarm/Telemetry:
 * - CLI commands for graph operations
 * - Engine cycle invocation through SEG
 * - Swarm task dispatch through SEG
 * - Telemetry integration
 * - Real-time execution monitoring
 */

#pragma once

#include "SovereignExecutionGraph.hpp"
#include "SovereignExecutionGraphBuilder.hpp"
#include "SovereignExecutionPlanner.hpp"
#include <string>
#include <vector>
#include <memory>
#include <functional>

// Forward declarations
namespace Sovereign {
namespace InfinitePerfection { class InfinitePerfectionEngine; }
class SovereignSwarm;
class Telemetry;
}

namespace Sovereign {
namespace SEG {

/**
 * CLI command types
 */
enum class SEGCommandType {
    GraphCreate,
    GraphBuild,
    GraphValidate,
    GraphExport,
    GraphImport,
    PlanCreate,
    PlanExecute,
    PlanMonitor,
    PlanCancel,
    CycleInvoke,
    TaskDispatch,
    TelemetryShow,
    StatusQuery,
    CheckpointSave,
    CheckpointRestore,
    Help,
    Unknown
};

/**
 * CLI command structure
 */
struct SEGCommand {
    SEGCommandType type{SEGCommandType::Unknown};
    std::string name;
    std::vector<std::string> args;
    std::map<std::string, std::string> options;
};

/**
 * Command result
 */
struct SEGCommandResult {
    bool success{false};
    std::string message;
    std::string jsonOutput;
    int exitCode{0};
};

/**
 * Runtime context holding all system references
 */
struct SEGRuntimeContext {
    InfinitePerfection::InfinitePerfectionEngine* engine{nullptr};
    SovereignSwarm* swarm{nullptr};
    Telemetry* telemetry{nullptr};
    
    // Current execution state
    std::unique_ptr<ExecutionGraph> currentGraph;
    std::unique_ptr<SovereignExecutionPlanner::ExecutionPlan> currentPlan;
    std::unique_ptr<SovereignParallelExecutor> executor;
    std::unique_ptr<ExecutionMonitor> monitor;
    
    // Configuration
    ExecutionConfig executionConfig;
    bool autoSaveCheckpoints{true};
    std::string checkpointDir{"./seg_checkpoints"};
};

/**
 * SEG CLI handler
 */
class SovereignSEGCLI {
public:
    SovereignSEGCLI();
    ~SovereignSEGCLI();
    
    // Initialization
    void SetEngine(InfinitePerfection::InfinitePerfectionEngine* engine);
    void SetSwarm(SovereignSwarm* swarm);
    void SetTelemetry(Telemetry* telemetry);
    void SetRuntimeContext(std::shared_ptr<SEGRuntimeContext> context);
    
    // Command parsing and execution
    SEGCommand ParseCommand(const std::string& commandLine);
    SEGCommand ParseCommand(int argc, const char* argv[]);
    SEGCommandResult ExecuteCommand(const SEGCommand& command);
    
    // Convenience methods
    SEGCommandResult Execute(const std::string& commandLine);
    
    // High-level operations
    SEGCommandResult CreateGraph(const std::string& name, int startBatch, int endBatch);
    SEGCommandResult BuildGraph(bool autoDiscover = true);
    SEGCommandResult ValidateGraph();
    SEGCommandResult ExportGraph(const std::string& filepath);
    SEGCommandResult ImportGraph(const std::string& filepath);
    
    SEGCommandResult CreatePlan(bool optimize = true);
    SEGCommandResult ExecutePlan(bool monitor = true);
    SEGCommandResult CancelExecution();
    SEGCommandResult GetExecutionStatus();
    
    SEGCommandResult InvokeCycle(const std::string& cycleName);
    SEGCommandResult DispatchTask(const std::string& taskName);
    
    SEGCommandResult ShowTelemetry();
    SEGCommandResult SaveCheckpoint(const std::string& name);
    SEGCommandResult RestoreCheckpoint(const std::string& name);
    
    // Interactive mode
    void RunInteractive();
    
    // Help
    std::string GetHelpText() const;
    std::string GetCommandHelp(SEGCommandType type) const;
    
private:
    std::shared_ptr<SEGRuntimeContext> context_;
    ExecutionCheckpointManager checkpointManager_;
    
    // Command handlers
    SEGCommandResult HandleGraphCreate(const SEGCommand& cmd);
    SEGCommandResult HandleGraphBuild(const SEGCommand& cmd);
    SEGCommandResult HandleGraphValidate(const SEGCommand& cmd);
    SEGCommandResult HandleGraphExport(const SEGCommand& cmd);
    SEGCommandResult HandleGraphImport(const SEGCommand& cmd);
    
    SEGCommandResult HandlePlanCreate(const SEGCommand& cmd);
    SEGCommandResult HandlePlanExecute(const SEGCommand& cmd);
    SEGCommandResult HandlePlanMonitor(const SEGCommand& cmd);
    SEGCommandResult HandlePlanCancel(const SEGCommand& cmd);
    
    SEGCommandResult HandleCycleInvoke(const SEGCommand& cmd);
    SEGCommandResult HandleTaskDispatch(const SEGCommand& cmd);
    
    SEGCommandResult HandleTelemetryShow(const SEGCommand& cmd);
    SEGCommandResult HandleStatusQuery(const SEGCommand& cmd);
    
    SEGCommandResult HandleCheckpointSave(const SEGCommand& cmd);
    SEGCommandResult HandleCheckpointRestore(const SEGCommand& cmd);
    
    // Utilities
    std::vector<std::string> Tokenize(const std::string& line);
    std::string ToLower(const std::string& str);
    SEGCommandType ParseCommandType(const std::string& name);
};

/**
 * SEG CLI main entry point for standalone execution
 */
int SEGCLIMain(int argc, const char* argv[]);

} // namespace SEG
} // namespace Sovereign
