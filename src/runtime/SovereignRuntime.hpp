#pragma once

/**
 * SovereignRuntime.hpp
 * 
 * Phase B.5: Unified Sovereign Runtime
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
struct RuntimeConfig {
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
struct RuntimeStatus {
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
 * Unified Sovereign Runtime
 * 
 * Manages the complete stack initialization and lifecycle
 */
class SovereignRuntime {
public:
    SovereignRuntime();
    ~SovereignRuntime();
    
    // Initialize with configuration
    bool Initialize(const RuntimeConfig& config = RuntimeConfig{});
    
    // Shutdown gracefully
    void Shutdown();
    
    // Check if running
    bool IsRunning() const { return running_.load(); }
    
    // Get current status
    RuntimeStatus GetStatus() const;
    
    // Run validation suite
    bool Validate();
    
    // Execute full workflow
    bool ExecuteWorkflow();
    
    // Run adaptive cycle until convergence
    bool RunUntilConvergence(double targetConvergence = 0.85, int maxIterations = 100);
    
    // Get performance metrics
    struct PerformanceMetrics {
        double graphBuildTimeMs;
        double planGenerationTimeMs;
        double cycleThroughput;
        double telemetryOverheadMs;
        double schedulerAdaptationLatencyMs;
        size_t memoryFootprintBytes;
        int64_t totalExecutionTimeMs;
    };
    
    PerformanceMetrics GetPerformanceMetrics() const;
    
    // Export runtime state
    std::string ExportStateToJson() const;
    bool SaveCheckpoint(const std::string& path) const;
    bool LoadCheckpoint(const std::string& path);
    
    // Access components
    InfinitePerfection::InfinitePerfectionEngine* GetEngine() { return engine_.get(); }
    SovereignSwarm* GetSwarm() { return swarm_.get(); }
    InfinitePerfectionTelemetry* GetTelemetry() { return telemetry_.get(); }
    ExecutionGraph* GetGraph() { return graph_.get(); }
    TelemetryDashboardServer* GetDashboard() { return dashboard_.get(); }
    
private:
    RuntimeConfig config_;
    RuntimeStatus status_;
    std::atomic<bool> running_{false};
    
    // Components
    std::unique_ptr<InfinitePerfection::InfinitePerfectionEngine> engine_;
    std::unique_ptr<SovereignSwarm> swarm_;
    std::unique_ptr<InfinitePerfectionTelemetry> telemetry_;
    std::unique_ptr<SovereignExecutionGraphBuilderEnhanced> builder_;
    std::unique_ptr<ExecutionGraph> graph_;
    std::unique_ptr<ExecutionPlanner> planner_;
    std::unique_ptr<TelemetryDashboardServer> dashboard_;
    
    PerformanceMetrics metrics_;
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
class SovereignRuntimeCLI {
public:
    static int Run(int argc, char* argv[]);
    
private:
    static void PrintUsage();
    static void PrintBanner();
    static RuntimeConfig ParseArgs(int argc, char* argv[]);
};

} // namespace Sovereign
