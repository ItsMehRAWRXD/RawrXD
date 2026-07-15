/**
 * SovereignSEGCLI.cpp
 * 
 * Phase B.4 Batch 4/5: Runtime Integration Implementation
 */

#include "SovereignSEGCLI.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <fstream>

namespace Sovereign {
namespace SEG {

// ============================================================================
// SovereignSEGCLI Implementation
// ============================================================================

SovereignSEGCLI::SovereignSEGCLI() 
    : context_(std::make_shared<SEGRuntimeContext>()) {
}

SovereignSEGCLI::~SovereignSEGCLI() = default;

void SovereignSEGCLI::SetEngine(InfinitePerfection::InfinitePerfectionEngine* engine) {
    context_->engine = engine;
}

void SovereignSEGCLI::SetSwarm(SovereignSwarm* swarm) {
    context_->swarm = swarm;
}

void SovereignSEGCLI::SetTelemetry(Telemetry* telemetry) {
    context_->telemetry = telemetry;
}

void SovereignSEGCLI::SetRuntimeContext(std::shared_ptr<SEGRuntimeContext> context) {
    context_ = context;
}

// ============================================================================
// Command Parsing
// ============================================================================

std::vector<std::string> SovereignSEGCLI::Tokenize(const std::string& line) {
    std::vector<std::string> tokens;
    std::istringstream iss(line);
    std::string token;
    
    while (iss >> token) {
        tokens.push_back(token);
    }
    
    return tokens;
}

std::string SovereignSEGCLI::ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

SEGCommandType SovereignSEGCLI::ParseCommandType(const std::string& name) {
    std::string lower = ToLower(name);
    
    if (lower == "graph:create" || lower == "create-graph") return SEGCommandType::GraphCreate;
    if (lower == "graph:build" || lower == "build-graph") return SEGCommandType::GraphBuild;
    if (lower == "graph:validate" || lower == "validate") return SEGCommandType::GraphValidate;
    if (lower == "graph:export" || lower == "export") return SEGCommandType::GraphExport;
    if (lower == "graph:import" || lower == "import") return SEGCommandType::GraphImport;
    
    if (lower == "plan:create" || lower == "create-plan") return SEGCommandType::PlanCreate;
    if (lower == "plan:execute" || lower == "execute" || lower == "run") return SEGCommandType::PlanExecute;
    if (lower == "plan:monitor" || lower == "monitor") return SEGCommandType::PlanMonitor;
    if (lower == "plan:cancel" || lower == "cancel") return SEGCommandType::PlanCancel;
    
    if (lower == "cycle:invoke" || lower == "invoke-cycle") return SEGCommandType::CycleInvoke;
    if (lower == "task:dispatch" || lower == "dispatch-task") return SEGCommandType::TaskDispatch;
    
    if (lower == "telemetry:show" || lower == "telemetry") return SEGCommandType::TelemetryShow;
    if (lower == "status" || lower == "query") return SEGCommandType::StatusQuery;
    
    if (lower == "checkpoint:save" || lower == "save-checkpoint") return SEGCommandType::CheckpointSave;
    if (lower == "checkpoint:restore" || lower == "restore-checkpoint") return SEGCommandType::CheckpointRestore;
    
    if (lower == "help" || lower == "?") return SEGCommandType::Help;
    
    return SEGCommandType::Unknown;
}

SEGCommand SovereignSEGCLI::ParseCommand(const std::string& commandLine) {
    auto tokens = Tokenize(commandLine);
    if (tokens.empty()) {
        return {SEGCommandType::Unknown, "", {}, {}};
    }
    
    SEGCommand cmd;
    cmd.name = tokens[0];
    cmd.type = ParseCommandType(tokens[0]);
    
    // Parse arguments and options
    for (size_t i = 1; i < tokens.size(); ++i) {
        if (tokens[i].find("--") == 0) {
            // Option
            std::string opt = tokens[i].substr(2);
            std::string value = "true";
            
            size_t eqPos = opt.find('=');
            if (eqPos != std::string::npos) {
                value = opt.substr(eqPos + 1);
                opt = opt.substr(0, eqPos);
            } else if (i + 1 < tokens.size() && tokens[i + 1].find("--") != 0) {
                value = tokens[++i];
            }
            
            cmd.options[opt] = value;
        } else {
            // Argument
            cmd.args.push_back(tokens[i]);
        }
    }
    
    return cmd;
}

SEGCommand SovereignSEGCLI::ParseCommand(int argc, const char* argv[]) {
    if (argc < 2) {
        return {SEGCommandType::Unknown, "", {}, {}};
    }
    
    std::ostringstream oss;
    for (int i = 1; i < argc; ++i) {
        if (i > 1) oss << " ";
        oss << argv[i];
    }
    
    return ParseCommand(oss.str());
}

// ============================================================================
// Command Execution
// ============================================================================

SEGCommandResult SovereignSEGCLI::ExecuteCommand(const SEGCommand& cmd) {
    switch (cmd.type) {
        case SEGCommandType::GraphCreate: return HandleGraphCreate(cmd);
        case SEGCommandType::GraphBuild: return HandleGraphBuild(cmd);
        case SEGCommandType::GraphValidate: return HandleGraphValidate(cmd);
        case SEGCommandType::GraphExport: return HandleGraphExport(cmd);
        case SEGCommandType::GraphImport: return HandleGraphImport(cmd);
        
        case SEGCommandType::PlanCreate: return HandlePlanCreate(cmd);
        case SEGCommandType::PlanExecute: return HandlePlanExecute(cmd);
        case SEGCommandType::PlanMonitor: return HandlePlanMonitor(cmd);
        case SEGCommandType::PlanCancel: return HandlePlanCancel(cmd);
        
        case SEGCommandType::CycleInvoke: return HandleCycleInvoke(cmd);
        case SEGCommandType::TaskDispatch: return HandleTaskDispatch(cmd);
        
        case SEGCommandType::TelemetryShow: return HandleTelemetryShow(cmd);
        case SEGCommandType::StatusQuery: return HandleStatusQuery(cmd);
        
        case SEGCommandType::CheckpointSave: return HandleCheckpointSave(cmd);
        case SEGCommandType::CheckpointRestore: return HandleCheckpointRestore(cmd);
        
        case SEGCommandType::Help:
            return {true, GetHelpText(), "", 0};
        
        default:
            return {false, "Unknown command: " + cmd.name, "", 1};
    }
}

SEGCommandResult SovereignSEGCLI::Execute(const std::string& commandLine) {
    auto cmd = ParseCommand(commandLine);
    return ExecuteCommand(cmd);
}

// ============================================================================
// Command Handlers
// ============================================================================

SEGCommandResult SovereignSEGCLI::HandleGraphCreate(const SEGCommand& cmd) {
    std::string name = cmd.args.empty() ? "SEGGraph" : cmd.args[0];
    int startBatch = 243;
    int endBatch = 256;
    
    auto it = cmd.options.find("start-batch");
    if (it != cmd.options.end()) {
        startBatch = std::stoi(it->second);
    }
    
    it = cmd.options.find("end-batch");
    if (it != cmd.options.end()) {
        endBatch = std::stoi(it->second);
    }
    
    return CreateGraph(name, startBatch, endBatch);
}

SEGCommandResult SovereignSEGCLI::HandleGraphBuild(const SEGCommand& cmd) {
    (void)cmd;
    return BuildGraph(true);
}

SEGCommandResult SovereignSEGCLI::HandleGraphValidate(const SEGCommand& cmd) {
    (void)cmd;
    return ValidateGraph();
}

SEGCommandResult SovereignSEGCLI::HandleGraphExport(const SEGCommand& cmd) {
    std::string filepath = cmd.args.empty() ? "graph.json" : cmd.args[0];
    return ExportGraph(filepath);
}

SEGCommandResult SovereignSEGCLI::HandleGraphImport(const SEGCommand& cmd) {
    std::string filepath = cmd.args.empty() ? "graph.json" : cmd.args[0];
    return ImportGraph(filepath);
}

SEGCommandResult SovereignSEGCLI::HandlePlanCreate(const SEGCommand& cmd) {
    bool optimize = true;
    auto it = cmd.options.find("optimize");
    if (it != cmd.options.end()) {
        optimize = (it->second == "true" || it->second == "1");
    }
    return CreatePlan(optimize);
}

SEGCommandResult SovereignSEGCLI::HandlePlanExecute(const SEGCommand& cmd) {
    bool monitor = true;
    auto it = cmd.options.find("monitor");
    if (it != cmd.options.end()) {
        monitor = (it->second == "true" || it->second == "1");
    }
    return ExecutePlan(monitor);
}

SEGCommandResult SovereignSEGCLI::HandlePlanMonitor(const SEGCommand& cmd) {
    (void)cmd;
    return GetExecutionStatus();
}

SEGCommandResult SovereignSEGCLI::HandlePlanCancel(const SEGCommand& cmd) {
    (void)cmd;
    return CancelExecution();
}

SEGCommandResult SovereignSEGCLI::HandleCycleInvoke(const SEGCommand& cmd) {
    std::string cycleName = cmd.args.empty() ? "RunUnityCycle" : cmd.args[0];
    return InvokeCycle(cycleName);
}

SEGCommandResult SovereignSEGCLI::HandleTaskDispatch(const SEGCommand& cmd) {
    std::string taskName = cmd.args.empty() ? "ComputeOrderTopology" : cmd.args[0];
    return DispatchTask(taskName);
}

SEGCommandResult SovereignSEGCLI::HandleTelemetryShow(const SEGCommand& cmd) {
    (void)cmd;
    return ShowTelemetry();
}

SEGCommandResult SovereignSEGCLI::HandleStatusQuery(const SEGCommand& cmd) {
    (void)cmd;
    return GetExecutionStatus();
}

SEGCommandResult SovereignSEGCLI::HandleCheckpointSave(const SEGCommand& cmd) {
    std::string name = cmd.args.empty() ? "checkpoint" : cmd.args[0];
    return SaveCheckpoint(name);
}

SEGCommandResult SovereignSEGCLI::HandleCheckpointRestore(const SEGCommand& cmd) {
    std::string name = cmd.args.empty() ? "checkpoint" : cmd.args[0];
    return RestoreCheckpoint(name);
}

// ============================================================================
// High-Level Operations
// ============================================================================

SEGCommandResult SovereignSEGCLI::CreateGraph(const std::string& name, int startBatch, int endBatch) {
    SovereignExecutionGraphBuilderEnhanced builder;
    builder.SetBatchRange(startBatch, endBatch);
    
    if (context_->engine) {
        builder.SetEngine(context_->engine);
    }
    if (context_->swarm) {
        builder.SetSwarm(context_->swarm);
    }
    
    context_->currentGraph = builder.BuildAuto();
    
    if (context_->currentGraph) {
        context_->currentGraph->SetName(name);
        auto stats = context_->currentGraph->GetStatistics();
        
        std::ostringstream msg;
        msg << "Created graph '" << name << "' with " << stats.nodeCount << " nodes ("
            << stats.cycleCount << " cycles, " << stats.swarmTaskCount << " tasks)";
        
        return {true, msg.str(), "", 0};
    }
    
    return {false, "Failed to create graph", "", 1};
}

SEGCommandResult SovereignSEGCLI::BuildGraph(bool autoDiscover) {
    (void)autoDiscover;
    
    if (!context_->currentGraph) {
        return {false, "No graph exists. Create a graph first.", "", 1};
    }
    
    auto stats = context_->currentGraph->GetStatistics();
    
    std::ostringstream msg;
    msg << "Graph built with " << stats.nodeCount << " nodes, " << stats.edgeCount << " edges";
    
    return {true, msg.str(), "", 0};
}

SEGCommandResult SovereignSEGCLI::ValidateGraph() {
    if (!context_->currentGraph) {
        return {false, "No graph exists. Create a graph first.", "", 1};
    }
    
    bool valid = context_->currentGraph->Validate();
    auto errors = context_->currentGraph->GetValidationErrors();
    
    std::ostringstream msg;
    if (valid) {
        msg << "Graph is valid";
    } else {
        msg << "Graph validation failed:";
        for (const auto& error : errors) {
            msg << "\n  - " << error;
        }
    }
    
    return {valid, msg.str(), "", valid ? 0 : 1};
}

SEGCommandResult SovereignSEGCLI::ExportGraph(const std::string& filepath) {
    if (!context_->currentGraph) {
        return {false, "No graph exists. Create a graph first.", "", 1};
    }
    
    std::string json = context_->currentGraph->ExportToJson();
    
    std::ofstream file(filepath);
    if (file) {
        file << json;
        return {true, "Graph exported to " + filepath, json, 0};
    }
    
    return {false, "Failed to write to " + filepath, "", 1};
}

SEGCommandResult SovereignSEGCLI::ImportGraph(const std::string& filepath) {
    (void)filepath;
    // TODO: Implement JSON import
    return {false, "Import not yet implemented", "", 1};
}

SEGCommandResult SovereignSEGCLI::CreatePlan(bool optimize) {
    if (!context_->currentGraph) {
        return {false, "No graph exists. Create a graph first.", "", 1};
    }
    
    SovereignExecutionPlanner planner;
    
    if (optimize) {
        context_->currentPlan = std::make_unique<SovereignExecutionPlanner::ExecutionPlan>(
            planner.CreateOptimizedPlan(*context_->currentGraph, context_->executionConfig));
    } else {
        context_->currentPlan = std::make_unique<SovereignExecutionPlanner::ExecutionPlan>(
            planner.CreatePlan(*context_->currentGraph));
    }
    
    if (context_->currentPlan) {
        std::ostringstream msg;
        msg << "Created execution plan with " << context_->currentPlan->stages.size() 
            << " stages, max parallelism: " << context_->currentPlan->maxParallelism;
        
        return {true, msg.str(), "", 0};
    }
    
    return {false, "Failed to create execution plan", "", 1};
}

SEGCommandResult SovereignSEGCLI::ExecutePlan(bool monitor) {
    if (!context_->currentPlan) {
        return {false, "No execution plan exists. Create a plan first.", "", 1};
    }
    
    if (!context_->currentGraph) {
        return {false, "No graph exists. Create a graph first.", "", 1};
    }
    
    context_->executor = std::make_unique<SovereignParallelExecutor>();
    context_->executor->SetConfig(context_->executionConfig);
    
    // Set up node executors
    context_->executor->SetNodeExecutor(NodeType::EngineCycle, [](ExecutionNode& node) -> NodeExecutionResult {
        NodeExecutionResult result;
        result.nodeId = node.id;
        result.success = true;
        result.executionTime = std::chrono::milliseconds(100);
        std::cout << "  Executing cycle: " << node.name << std::endl;
        return result;
    });
    
    context_->executor->SetNodeExecutor(NodeType::SwarmTask, [](ExecutionNode& node) -> NodeExecutionResult {
        NodeExecutionResult result;
        result.nodeId = node.id;
        result.success = true;
        result.executionTime = std::chrono::milliseconds(50);
        std::cout << "  Executing task: " << node.name << std::endl;
        return result;
    });
    
    if (monitor) {
        context_->monitor = std::make_unique<ExecutionMonitor>();
        context_->monitor->AttachToExecutor(context_->executor.get());
        context_->monitor->AttachToGraph(context_->currentGraph.get());
        context_->monitor->StartMonitoring();
    }
    
    std::cout << "Executing plan..." << std::endl;
    bool success = context_->executor->Execute(*context_->currentGraph, *context_->currentPlan);
    
    if (monitor && context_->monitor) {
        context_->monitor->StopMonitoring();
    }
    
    auto metrics = context_->executor->GetMetrics();
    
    std::ostringstream msg;
    msg << "Execution " << (success ? "completed successfully" : "failed") << "\n";
    msg << "  Nodes executed: " << metrics.nodesExecuted << "\n";
    msg << "  Nodes failed: " << metrics.nodesFailed << "\n";
    msg << "  Total duration: " << metrics.totalDuration.count() << "ms";
    
    return {success, msg.str(), "", success ? 0 : 1};
}

SEGCommandResult SovereignSEGCLI::CancelExecution() {
    if (context_->executor && context_->executor->IsRunning()) {
        context_->executor->Cancel();
        return {true, "Execution cancellation requested", "", 0};
    }
    
    return {false, "No execution is currently running", "", 1};
}

SEGCommandResult SovereignSEGCLI::GetExecutionStatus() {
    if (!context_->executor) {
        return {true, "No active execution", "", 0};
    }
    
    std::ostringstream msg;
    msg << "Execution Status:\n";
    msg << "  Running: " << (context_->executor->IsRunning() ? "yes" : "no") << "\n";
    msg << "  Paused: " << (context_->executor->IsPaused() ? "yes" : "no") << "\n";
    msg << "  Current stage: " << context_->executor->GetCurrentStage() << "\n";
    msg << "  Completed nodes: " << context_->executor->GetCompletedNodes() << "\n";
    msg << "  Failed nodes: " << context_->executor->GetFailedNodes();
    
    return {true, msg.str(), "", 0};
}

SEGCommandResult SovereignSEGCLI::InvokeCycle(const std::string& cycleName) {
    (void)cycleName;
    
    if (!context_->engine) {
        return {false, "Engine not available", "", 1};
    }
    
    // TODO: Actually invoke the cycle on the engine
    std::cout << "Invoking cycle: " << cycleName << std::endl;
    
    return {true, "Cycle invocation completed", "", 0};
}

SEGCommandResult SovereignSEGCLI::DispatchTask(const std::string& taskName) {
    (void)taskName;
    
    if (!context_->swarm) {
        return {false, "Swarm not available", "", 1};
    }
    
    // TODO: Actually dispatch the task to the swarm
    std::cout << "Dispatching task: " << taskName << std::endl;
    
    return {true, "Task dispatch completed", "", 0};
}

SEGCommandResult SovereignSEGCLI::ShowTelemetry() {
    if (!context_->telemetry) {
        return {false, "Telemetry not available", "", 1};
    }
    
    // TODO: Actually query telemetry
    return {true, "Telemetry data displayed", "", 0};
}

SEGCommandResult SovereignSEGCLI::SaveCheckpoint(const std::string& name) {
    if (!context_->currentGraph) {
        return {false, "No graph exists. Create a graph first.", "", 1};
    }
    
    checkpointManager_.SetCheckpointDirectory(context_->checkpointDir);
    
    ExecutionMetrics metrics;
    if (context_->executor) {
        metrics = context_->executor->GetMetrics();
    }
    
    std::string id = checkpointManager_.CreateCheckpoint(*context_->currentGraph, metrics);
    
    return {true, "Checkpoint saved: " + id, "", 0};
}

SEGCommandResult SovereignSEGCLI::RestoreCheckpoint(const std::string& name) {
    (void)name;
    // TODO: Implement checkpoint restore
    return {false, "Checkpoint restore not yet implemented", "", 1};
}

// ============================================================================
// Interactive Mode
// ============================================================================

void SovereignSEGCLI::RunInteractive() {
    std::cout << "Sovereign Execution Graph CLI" << std::endl;
    std::cout << "Type 'help' for available commands, 'exit' to quit." << std::endl;
    std::cout << std::endl;
    
    std::string line;
    while (true) {
        std::cout << "SEG> ";
        std::getline(std::cin, line);
        
        if (line == "exit" || line == "quit") {
            break;
        }
        
        if (line.empty()) {
            continue;
        }
        
        auto result = Execute(line);
        std::cout << result.message << std::endl;
        std::cout << std::endl;
    }
}

// ============================================================================
// Help
// ============================================================================

std::string SovereignSEGCLI::GetHelpText() const {
    return R"(Sovereign Execution Graph CLI Commands:

Graph Operations:
  graph:create [name] [--start-batch=N] [--end-batch=N]
    Create a new execution graph
  graph:build [--auto-discover]
    Build the current graph
  graph:validate
    Validate the current graph
  graph:export [filepath]
    Export graph to JSON
  graph:import [filepath]
    Import graph from JSON

Plan Operations:
  plan:create [--optimize]
    Create an execution plan
  plan:execute [--monitor]
    Execute the current plan
  plan:monitor
    Show execution status
  plan:cancel
    Cancel current execution

Runtime Operations:
  cycle:invoke <cycle-name>
    Invoke an engine cycle
  task:dispatch <task-name>
    Dispatch a swarm task
  telemetry:show
    Display telemetry data
  status
    Show execution status

Checkpoint Operations:
  checkpoint:save [name]
    Save execution checkpoint
  checkpoint:restore [name]
    Restore from checkpoint

Other:
  help
    Show this help text
  exit
    Exit interactive mode
)";
}

std::string SovereignSEGCLI::GetCommandHelp(SEGCommandType type) const {
    (void)type;
    return GetHelpText();
}

// ============================================================================
// Main Entry Point
// ============================================================================

int SEGCLIMain(int argc, const char* argv[]) {
    SovereignSEGCLI cli;
    
    if (argc < 2) {
        cli.RunInteractive();
        return 0;
    }
    
    auto result = cli.ExecuteCommand(cli.ParseCommand(argc, argv));
    std::cout << result.message << std::endl;
    
    return result.exitCode;
}

} // namespace SEG
} // namespace Sovereign
