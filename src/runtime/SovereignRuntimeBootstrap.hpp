#pragma once

/**
 * SovereignRuntimeBootstrap.hpp
 * 
 * Phase B.5: Unified Sovereign Runtime Bootstrap
 * 
 * Single bootstrap executable that initializes the complete stack:
 * SEG → Engine → Swarm → Telemetry → Execution Graph → Adaptive Scheduler → Dashboard
 */

#include "../seg/SovereignExecutionGraph.hpp"
#include "../seg/SovereignExecutionGraphBuilder.hpp"
#include "../swarm/SovereignSwarm.hpp"
#include "../swarm/InfinitePerfectionTelemetry.hpp"
#include "../swarm/TelemetryDashboardServer.hpp"
#include "../infinite/InfinitePerfectionEngine.hpp"
#include <memory>
#include <string>
#include <atomic>

namespace Sovereign {

/**
 * Runtime configuration
 */
struct BootstrapConfig {
    // SEG settings
    bool enableSEG = true;
    int batchStart = 92;
    int batchEnd = 256;
    
    // Engine settings
    bool enableEngine = true;
    bool autoInitializeEngine = true;
    
    // Swarm settings
    bool enableSwarm = true;
    uint32_t workerCount = 8;
    bool enableAdaptiveScheduling = true;
    double targetConvergenceRate = 0.85;
    
    // Telemetry settings
    bool enableTelemetry = true;
    bool enableSQLitePersistence = false;
    std::string sqliteDbPath = "sovereign_runtime.db";
    
    // Dashboard settings
    bool enableDashboard = true;
    uint16_t dashboardPort = 8080;
    int dashboardUpdateIntervalMs = 1000;
    
    // Validation settings
    bool runValidationOnStartup = true;
    bool exitOnValidationFailure = false;
};

/**
 * Runtime status
 */
struct BootstrapStatus {
    bool segInitialized = false;
    bool engineInitialized = false;
    bool swarmInitialized = false;
    bool telemetryInitialized = false;
    bool dashboardInitialized = false;
    bool graphBuilt = false;
    bool schedulerRunning = false;
    
    int64_t startupTimeMs = 0;
    int64_t totalCyclesExecuted = 0;
    double currentConvergenceScore = 0.0;
    bool isConverged = false;
    
    std::string ToJson() const;
};

/**
 * Unified Sovereign Runtime Bootstrap
 * 
 * Manages the complete stack initialization and lifecycle
 */
class SovereignRuntimeBootstrap {
public:
    SovereignRuntimeBootstrap();
    ~SovereignRuntimeBootstrap();
    
    // Initialize with configuration
    bool Initialize(const BootstrapConfig& config = BootstrapConfig{});
    
    // Shutdown gracefully
    void Shutdown();
    
    // Check if running
    bool IsRunning() const { return running_.load(); }
    
    // Get current status
    BootstrapStatus GetStatus() const;
    
    // Run validation suite
    bool Validate();
    
    // Execute full workflow
    bool ExecuteWorkflow();
    
    // Run adaptive cycle until convergence
    bool RunUntilConvergence(double targetConvergence = 0.85, int maxIterations = 100);
    
    // Export runtime state
    std::string ExportStateToJson() const;
    
private:
    BootstrapConfig config_;
    BootstrapStatus status_;
    std::atomic<bool> running_{false};
    
    // Components
    std::unique_ptr<InfinitePerfection::InfinitePerfectionEngine> engine_;
    std::unique_ptr<SovereignSwarm> swarm_;
    std::unique_ptr<InfinitePerfectionTelemetry> telemetry_;
    std::unique_ptr<SovereignExecutionGraphBuilderEnhanced> builder_;
    std::unique_ptr<ExecutionGraph> graph_;
    std::unique_ptr<ExecutionPlanner> planner_;
    std::unique_ptr<TelemetryDashboardServer> dashboard_;
    
    int64_t startTime_;
    
    // Initialization steps
    bool InitializeSEG();
    bool InitializeEngine();
    bool InitializeSwarm();
    bool InitializeTelemetry();
    bool InitializeDashboard();
    bool BuildExecutionGraph();
    bool StartAdaptiveScheduler();
};

/**
 * CLI entry point
 */
class SovereignBootstrapCLI {
public:
    static int Run(int argc, char* argv[]);
    
private:
    static void PrintUsage();
    static void PrintBanner();
    static BootstrapConfig ParseArgs(int argc, char* argv[]);
};

} // namespace Sovereign
