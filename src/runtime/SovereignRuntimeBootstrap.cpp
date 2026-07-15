/**
 * SovereignRuntimeBootstrap.cpp
 * 
 * Phase B.5: Unified Sovereign Runtime Bootstrap Implementation
 */

#include "SovereignRuntimeBootstrap.hpp"
#include "../seg/SEGValidationSuite.hpp"
#include <iostream>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <thread>

namespace Sovereign {

// BootstrapStatus implementation
std::string BootstrapStatus::ToJson() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"segInitialized\": " << (segInitialized ? "true" : "false") << ",\n";
    json << "  \"engineInitialized\": " << (engineInitialized ? "true" : "false") << ",\n";
    json << "  \"swarmInitialized\": " << (swarmInitialized ? "true" : "false") << ",\n";
    json << "  \"telemetryInitialized\": " << (telemetryInitialized ? "true" : "false") << ",\n";
    json << "  \"dashboardInitialized\": " << (dashboardInitialized ? "true" : "false") << ",\n";
    json << "  \"graphBuilt\": " << (graphBuilt ? "true" : "false") << ",\n";
    json << "  \"schedulerRunning\": " << (schedulerRunning ? "true" : "false") << ",\n";
    json << "  \"startupTimeMs\": " << startupTimeMs << ",\n";
    json << "  \"totalCyclesExecuted\": " << totalCyclesExecuted << ",\n";
    json << "  \"currentConvergenceScore\": " << std::fixed << std::setprecision(4) << currentConvergenceScore << ",\n";
    json << "  \"isConverged\": " << (isConverged ? "true" : "false") << "\n";
    json << "}";
    return json.str();
}

// SovereignRuntimeBootstrap implementation
SovereignRuntimeBootstrap::SovereignRuntimeBootstrap() : startTime_(0) {}

SovereignRuntimeBootstrap::~SovereignRuntimeBootstrap() {
    if (running_.load()) {
        Shutdown();
    }
}

bool SovereignRuntimeBootstrap::Initialize(const BootstrapConfig& config) {
    config_ = config;
    startTime_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    std::cout << "[SovereignRuntime] Initializing...\n";
    
    // Step 1: Initialize SEG
    if (config_.enableSEG) {
        std::cout << "[SovereignRuntime] Step 1/7: Initializing SEG...\n";
        if (!InitializeSEG()) {
            std::cerr << "[SovereignRuntime] SEG initialization failed\n";
            return false;
        }
        status_.segInitialized = true;
        std::cout << "[SovereignRuntime] ✓ SEG initialized\n";
    }
    
    // Step 2: Initialize Engine
    if (config_.enableEngine) {
        std::cout << "[SovereignRuntime] Step 2/7: Initializing InfinitePerfectionEngine...\n";
        if (!InitializeEngine()) {
            std::cerr << "[SovereignRuntime] Engine initialization failed\n";
            return false;
        }
        status_.engineInitialized = true;
        std::cout << "[SovereignRuntime] ✓ Engine initialized\n";
    }
    
    // Step 3: Initialize Swarm
    if (config_.enableSwarm) {
        std::cout << "[SovereignRuntime] Step 3/7: Initializing SovereignSwarm...\n";
        if (!InitializeSwarm()) {
            std::cerr << "[SovereignRuntime] Swarm initialization failed\n";
            return false;
        }
        status_.swarmInitialized = true;
        std::cout << "[SovereignRuntime] ✓ Swarm initialized\n";
    }
    
    // Step 4: Initialize Telemetry
    if (config_.enableTelemetry) {
        std::cout << "[SovereignRuntime] Step 4/7: Initializing Telemetry...\n";
        if (!InitializeTelemetry()) {
            std::cerr << "[SovereignRuntime] Telemetry initialization failed\n";
            return false;
        }
        status_.telemetryInitialized = true;
        std::cout << "[SovereignRuntime] ✓ Telemetry initialized\n";
    }
    
    // Step 5: Build Execution Graph
    std::cout << "[SovereignRuntime] Step 5/7: Building Execution Graph...\n";
    if (!BuildExecutionGraph()) {
        std::cerr << "[SovereignRuntime] Graph construction failed\n";
        return false;
    }
    status_.graphBuilt = true;
    std::cout << "[SovereignRuntime] ✓ Execution Graph built\n";
    
    // Step 6: Initialize Dashboard
    if (config_.enableDashboard) {
        std::cout << "[SovereignRuntime] Step 6/7: Starting Dashboard Server...\n";
        if (!InitializeDashboard()) {
            std::cerr << "[SovereignRuntime] Dashboard initialization failed\n";
        } else {
            status_.dashboardInitialized = true;
            std::cout << "[SovereignRuntime] ✓ Dashboard started on port " << config_.dashboardPort << "\n";
        }
    }
    
    // Step 7: Start Adaptive Scheduler
    if (config_.enableSwarm) {
        std::cout << "[SovereignRuntime] Step 7/7: Starting Adaptive Scheduler...\n";
        if (!StartAdaptiveScheduler()) {
            std::cerr << "[SovereignRuntime] Scheduler startup failed\n";
            return false;
        }
        status_.schedulerRunning = true;
        std::cout << "[SovereignRuntime] ✓ Scheduler running\n";
    }
    
    // Calculate startup time
    auto endTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    status_.startupTimeMs = endTime - startTime_;
    
    running_.store(true);
    
    std::cout << "\n[SovereignRuntime] ✓✓✓ Initialization Complete ✓✓✓\n";
    std::cout << "  Startup Time: " << status_.startupTimeMs << "ms\n";
    std::cout << "  Status: " << GetStatus().ToJson() << "\n\n";
    
    // Run validation if requested
    if (config_.runValidationOnStartup) {
        std::cout << "[SovereignRuntime] Running startup validation...\n";
        if (!Validate()) {
            std::cerr << "[SovereignRuntime] Validation failed\n";
            if (config_.exitOnValidationFailure) {
                Shutdown();
                return false;
            }
        }
    }
    
    return true;
}

void SovereignRuntimeBootstrap::Shutdown() {
    std::cout << "[SovereignRuntime] Shutting down...\n";
    
    running_.store(false);
    
    if (dashboard_) {
        std::cout << "[SovereignRuntime] Stopping dashboard...\n";
        dashboard_->Stop();
    }
    
    if (engine_) {
        std::cout << "[SovereignRuntime] Shutting down engine...\n";
        engine_->Shutdown();
    }
    
    dashboard_.reset();
    planner_.reset();
    graph_.reset();
    builder_.reset();
    telemetry_.reset();
    swarm_.reset();
    engine_.reset();
    
    std::cout << "[SovereignRuntime] Shutdown complete\n";
}

BootstrapStatus SovereignRuntimeBootstrap::GetStatus() const {
    return status_;
}

bool SovereignRuntimeBootstrap::Validate() {
    std::cout << "[SovereignRuntime] Running validation suite...\n";
    
    SEGValidationSuite suite;
    if (!suite.Initialize(engine_.get(), swarm_.get(), telemetry_.get())) {
        std::cerr << "[SovereignRuntime] Failed to initialize validation suite\n";
        return false;
    }
    
    auto results = suite.RunAllTests();
    
    for (const auto& result : results) {
        if (!result.passed) {
            std::cerr << "[SovereignRuntime] Validation failed: " << result.testName << "\n";
            return false;
        }
    }
    
    std::cout << "[SovereignRuntime] ✓ All validation tests passed\n";
    return true;
}

bool SovereignRuntimeBootstrap::ExecuteWorkflow() {
    if (!running_.load()) {
        std::cerr << "[SovereignRuntime] Runtime not initialized\n";
        return false;
    }
    
    std::cout << "[SovereignRuntime] Executing full workflow...\n";
    
    if (!engine_ || !swarm_) {
        std::cerr << "[SovereignRuntime] Components not available\n";
        return false;
    }
    
    auto result = swarm_->ExecuteUnitySequence(*engine_);
    
    status_.totalCyclesExecuted++;
    
    if (telemetry_) {
        auto snapshot = telemetry_->GetSnapshot();
        status_.currentConvergenceScore = snapshot.averageConvergenceRate;
        status_.isConverged = snapshot.unityCycle.isConverged;
    }
    
    std::cout << "[SovereignRuntime] Workflow execution: " << (result.success ? "SUCCESS" : "FAILED") << "\n";
    std::cout << "  Harmony Index: " << std::fixed << std::setprecision(4) << result.finalHarmonyIndex << "\n";
    
    return result.success;
}

bool SovereignRuntimeBootstrap::RunUntilConvergence(double targetConvergence, int maxIterations) {
    std::cout << "[SovereignRuntime] Running until convergence (target: " << targetConvergence << ")...\n";
    
    for (int i = 0; i < maxIterations; i++) {
        if (!ExecuteWorkflow()) {
            std::cerr << "[SovereignRuntime] Workflow execution failed at iteration " << i << "\n";
            return false;
        }
        
        if (status_.isConverged && status_.currentConvergenceScore >= targetConvergence) {
            std::cout << "[SovereignRuntime] ✓ Convergence achieved after " << (i + 1) << " iterations\n";
            std::cout << "  Final Convergence Score: " << std::fixed << std::setprecision(4)
                      << status_.currentConvergenceScore << "\n";
            return true;
        }
        
        if (swarm_) {
            swarm_->GetScheduler().AdaptExplorationRate(status_.currentConvergenceScore);
        }
    }
    
    std::cout << "[SovereignRuntime] ⚠ Max iterations reached without convergence\n";
    std::cout << "  Final Convergence Score: " << std::fixed << std::setprecision(4)
              << status_.currentConvergenceScore << "\n";
    return false;
}

std::string SovereignRuntimeBootstrap::ExportStateToJson() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"runtime\": " << GetStatus().ToJson() << ",\n";
    json << "  \"config\": {\n";
    json << "    \"enableSEG\": " << (config_.enableSEG ? "true" : "false") << ",\n";
    json << "    \"enableEngine\": " << (config_.enableEngine ? "true" : "false") << ",\n";
    json << "    \"enableSwarm\": " << (config_.enableSwarm ? "true" : "false") << ",\n";
    json << "    \"enableTelemetry\": " << (config_.enableTelemetry ? "true" : "false") << ",\n";
    json << "    \"enableDashboard\": " << (config_.enableDashboard ? "true" : "false") << "\n";
    json << "  }\n";
    json << "}";
    return json.str();
}

// Initialization steps
bool SovereignRuntimeBootstrap::InitializeSEG() {
    builder_ = std::make_unique<SovereignExecutionGraphBuilderEnhanced>();
    return true;
}

bool SovereignRuntimeBootstrap::InitializeEngine() {
    engine_ = std::make_unique<InfinitePerfection::InfinitePerfectionEngine>();
    if (config_.autoInitializeEngine) {
        engine_->Initialize();
    }
    return engine_->IsInitialized();
}

bool SovereignRuntimeBootstrap::InitializeSwarm() {
    if (!engine_) return false;
    
    SwarmAgentContext ctx;
    ctx.engine = engine_.get();
    
    swarm_ = std::make_unique<SovereignSwarm>(ctx);
    
    if (config_.enableAdaptiveScheduling) {
        swarm_->GetScheduler().SetLearnedAssignmentEnabled(true);
        swarm_->GetScheduler().SetTargetConvergenceRate(config_.targetConvergenceRate);
    }
    
    return true;
}

bool SovereignRuntimeBootstrap::InitializeTelemetry() {
    if (!engine_) return false;
    
    telemetry_ = std::make_unique<InfinitePerfectionTelemetry>(engine_.get());
    return true;
}

bool SovereignRuntimeBootstrap::InitializeDashboard() {
    if (!engine_) return false;
    
    DashboardConfig dashboardConfig;
    dashboardConfig.port = config_.dashboardPort;
    dashboardConfig.updateIntervalMs = config_.dashboardUpdateIntervalMs;
    
    dashboard_ = std::make_unique<TelemetryDashboardServer>(engine_.get(), dashboardConfig);
    
    return dashboard_->Start();
}

bool SovereignRuntimeBootstrap::BuildExecutionGraph() {
    if (!builder_ || !engine_ || !swarm_) return false;
    
    builder_->SetEngine(engine_.get());
    builder_->SetSwarm(swarm_.get());
    builder_->SetBatchRange(config_.batchStart, config_.batchEnd);
    
    graph_ = builder_->BuildAuto();
    
    return graph_ != nullptr && graph_->GetNodeCount() > 0;
}

bool SovereignRuntimeBootstrap::StartAdaptiveScheduler() {
    if (!swarm_) return false;
    return true;
}

// CLI Implementation
void SovereignBootstrapCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║           SOVEREIGN RUNTIME - Phase B.5                        ║\n";
    std::cout << "║           Unified Execution Environment                        ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void SovereignBootstrapCLI::PrintUsage() {
    std::cout << "Usage: sovereign-runtime [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --validate              Run validation on startup\n";
    std::cout << "  --no-validation         Skip startup validation\n";
    std::cout << "  --convergence TARGET    Run until convergence (default: 0.85)\n";
    std::cout << "  --max-iterations N      Max iterations for convergence (default: 100)\n";
    std::cout << "  --dashboard-port PORT   Dashboard port (default: 8080)\n";
    std::cout << "  --sqlite-db PATH        SQLite database path\n";
    std::cout << "  --json                  Output status as JSON\n";
    std::cout << "  --help                  Show this help\n\n";
    std::cout << "Examples:\n";
    std::cout << "  sovereign-runtime --validate\n";
    std::cout << "  sovereign-runtime --convergence 0.90 --max-iterations 50\n";
    std::cout << "  sovereign-runtime --dashboard-port 9090\n";
}

BootstrapConfig SovereignBootstrapCLI::ParseArgs(int argc, char* argv[]) {
    BootstrapConfig config;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--validate") {
            config.runValidationOnStartup = true;
        } else if (arg == "--no-validation") {
            config.runValidationOnStartup = false;
        } else if (arg == "--convergence" && i + 1 < argc) {
            config.targetConvergenceRate = std::stod(argv[++i]);
        } else if (arg == "--dashboard-port" && i + 1 < argc) {
            config.dashboardPort = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--sqlite-db" && i + 1 < argc) {
            config.sqliteDbPath = argv[++i];
            config.enableSQLitePersistence = true;
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage();
            exit(0);
        }
    }
    
    return config;
}

int SovereignBootstrapCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    BootstrapConfig config = ParseArgs(argc, argv);
    
    SovereignRuntimeBootstrap runtime;
    
    if (!runtime.Initialize(config)) {
        std::cerr << "[SovereignRuntime] Initialization failed\n";
        return 1;
    }
    
    // Check for convergence target
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--convergence" && i + 1 < argc) {
            double target = std::stod(argv[i + 1]);
            int maxIter = 100;
            
            for (int j = 1; j < argc; j++) {
                if (std::string(argv[j]) == "--max-iterations" && j + 1 < argc) {
                    maxIter = std::stoi(argv[j + 1]);
                }
            }
            
            runtime.RunUntilConvergence(target, maxIter);
            break;
        }
    }
    
    // Output JSON if requested
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--json") {
            std::cout << runtime.ExportStateToJson() << "\n";
        }
    }
    
    std::cout << "[SovereignRuntime] Running... Press Ctrl+C to shutdown\n";
    
    while (runtime.IsRunning()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    return 0;
}

} // namespace Sovereign
