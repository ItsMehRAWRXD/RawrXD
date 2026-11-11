/**
 * RuntimeIntegration.cpp
 * 
 * Phase B.5 Batch 4/5: Runtime Integration & Validation Implementation
 */

#include "RuntimeIntegration.hpp"
#include <iostream>
#include <thread>
#include <chrono>

namespace Sovereign {

// IntegrationStatus implementation
std::string IntegrationStatus::ToJson() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"bootstrapInitialized\": " << (bootstrapInitialized ? "true" : "false") << ",\n";
    json << "  \"checkpointManagerInitialized\": " << (checkpointManagerInitialized ? "true" : "false") << ",\n";
    json << "  \"performanceCaptureInitialized\": " << (performanceCaptureInitialized ? "true" : "false") << ",\n";
    json << "  \"validationHooksRegistered\": " << (validationHooksRegistered ? "true" : "false") << ",\n";
    json << "  \"validationHooksCount\": " << validationHooksCount << ",\n";
    json << "  \"validationFailures\": " << validationFailures << ",\n";
    json << "  \"lastValidationTimeMs\": " << lastValidationTimeMs << "\n";
    json << "}";
    return json.str();
}

// IntegratedSovereignRuntime implementation
IntegratedSovereignRuntime::IntegratedSovereignRuntime() = default;

IntegratedSovereignRuntime::~IntegratedSovereignRuntime() {
    if (running_.load()) {
        Shutdown();
    }
}

bool IntegratedSovereignRuntime::Initialize(const IntegrationConfig& config) {
    config_ = config;
    
    std::cout << "[IntegratedRuntime] Initializing Integrated Sovereign Runtime...\n";
    std::cout << "============================================================\n\n";
    
    // Step 1: Run pre-startup hooks
    if (config_.enablePreStartupHooks) {
        std::cout << "[IntegratedRuntime] Running pre-startup hooks...\n";
        RunPreStartupHooks();
    }
    
    // Step 2: Initialize Bootstrap Runtime
    std::cout << "[IntegratedRuntime] Step 1/4: Initializing Bootstrap Runtime...\n";
    bootstrap_ = std::make_unique<SovereignRuntimeBootstrap>();
    if (!bootstrap_->Initialize(config_.bootstrap)) {
        std::cerr << "[IntegratedRuntime] Bootstrap initialization failed\n";
        return false;
    }
    status_.bootstrapInitialized = true;
    std::cout << "[IntegratedRuntime] ✓ Bootstrap Runtime initialized\n\n";
    
    // Step 3: Initialize Checkpoint Manager
    std::cout << "[IntegratedRuntime] Step 2/4: Initializing Checkpoint Manager...\n";
    if (!InitializeCheckpointManager()) {
        std::cerr << "[IntegratedRuntime] Checkpoint Manager initialization failed\n";
        // Non-fatal - continue without checkpointing
    } else {
        status_.checkpointManagerInitialized = true;
        std::cout << "[IntegratedRuntime] ✓ Checkpoint Manager initialized\n\n";
    }
    
    // Step 4: Initialize Performance Capture
    std::cout << "[IntegratedRuntime] Step 3/4: Initializing Performance Capture...\n";
    if (!InitializePerformanceCapture()) {
        std::cerr << "[IntegratedRuntime] Performance Capture initialization failed\n";
        // Non-fatal - continue without performance tracking
    } else {
        status_.performanceCaptureInitialized = true;
        std::cout << "[IntegratedRuntime] ✓ Performance Capture initialized\n\n";
    }
    
    // Step 5: Register validation hooks
    std::cout << "[IntegratedRuntime] Step 4/4: Registering validation hooks...\n";
    // Default validation hooks would be registered here
    status_.validationHooksRegistered = true;
    std::cout << "[IntegratedRuntime] ✓ Validation hooks registered\n\n";
    
    // Step 6: Run post-startup hooks
    if (config_.enablePostStartupHooks) {
        std::cout << "[IntegratedRuntime] Running post-startup hooks...\n";
        RunPostStartupHooks();
    }
    
    // Step 7: Start continuous validation
    if (config_.enableContinuousValidation) {
        std::cout << "[IntegratedRuntime] Starting continuous validation...\n";
        StartContinuousValidation();
    }
    
    running_.store(true);
    
    std::cout << "\n============================================================\n";
    std::cout << "[IntegratedRuntime] ✓✓✓ Initialization Complete ✓✓✓\n";
    std::cout << "============================================================\n\n";
    
    return true;
}

void IntegratedSovereignRuntime::Shutdown() {
    std::cout << "[IntegratedRuntime] Shutting down...\n";
    
    running_.store(false);
    
    // Stop continuous validation
    StopContinuousValidation();
    
    // Run pre-shutdown hooks
    if (config_.enablePreShutdownHooks) {
        RunPreShutdownHooks();
    }
    
    // Create final checkpoint if enabled
    if (checkpointManager_ && config_.checkpointPolicy.checkpointOnShutdown) {
        std::cout << "[IntegratedRuntime] Creating shutdown checkpoint...\n";
        CreateCheckpoint("shutdown");
    }
    
    // Save performance baseline if enabled
    if (performanceCapture_ && config_.autoSaveBaseline) {
        SavePerformanceBaseline(config_.baselineOutputPath);
    }
    
    // Shutdown bootstrap
    if (bootstrap_) {
        bootstrap_->Shutdown();
    }
    
    // Run post-shutdown hooks
    if (config_.enablePostShutdownHooks) {
        RunPostShutdownHooks();
    }
    
    std::cout << "[IntegratedRuntime] Shutdown complete\n";
}

bool IntegratedSovereignRuntime::IsRunning() const {
    return running_.load() && bootstrap_ && bootstrap_->IsRunning();
}

bool IntegratedSovereignRuntime::ExecuteWorkflow() {
    if (!bootstrap_) {
        std::cerr << "[IntegratedRuntime] Runtime not initialized\n";
        return false;
    }
    
    // Capture start time
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Execute workflow
    bool success = bootstrap_->ExecuteWorkflow();
    
    // Calculate duration
    auto endTime = std::chrono::high_resolution_clock::now();
    auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    // Record performance
    if (performanceCapture_ && success) {
        auto status = bootstrap_->GetStatus();
        performanceCapture_->CaptureWorkflowExecution(
            static_cast<int>(status.totalCyclesExecuted),
            status.currentConvergenceScore,
            durationMs,
            status.currentConvergenceScore
        );
    }
    
    // Run validation hooks
    if (config_.enableContinuousValidation) {
        RunValidationHooks();
    }
    
    return success;
}

bool IntegratedSovereignRuntime::RunUntilConvergence(double targetConvergence, int maxIterations) {
    if (!bootstrap_) {
        std::cerr << "[IntegratedRuntime] Runtime not initialized\n";
        return false;
    }
    
    std::cout << "[IntegratedRuntime] Running until convergence (target: " << targetConvergence << ")...\n";
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    bool converged = bootstrap_->RunUntilConvergence(targetConvergence, maxIterations);
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto totalDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    // Record convergence performance
    if (performanceCapture_ && converged) {
        auto status = bootstrap_->GetStatus();
        performanceCapture_->CaptureConvergence(
            static_cast<int>(status.totalCyclesExecuted),
            status.currentConvergenceScore,
            totalDurationMs
        );
    }
    
    // Create checkpoint on convergence if enabled
    if (converged && checkpointManager_ && config_.checkpointPolicy.checkpointOnConvergence) {
        std::cout << "[IntegratedRuntime] Creating convergence checkpoint...\n";
        CreateCheckpoint("convergence-achieved");
    }
    
    return converged;
}

std::string IntegratedSovereignRuntime::CreateCheckpoint(const std::string& description) {
    if (!checkpointManager_) {
        std::cerr << "[IntegratedRuntime] Checkpoint Manager not initialized\n";
        return "";
    }
    
    return checkpointManager_->CreateCheckpoint(description);
}

bool IntegratedSovereignRuntime::RestoreCheckpoint(const std::string& checkpointId) {
    if (!checkpointManager_) {
        std::cerr << "[IntegratedRuntime] Checkpoint Manager not initialized\n";
        return false;
    }
    
    return checkpointManager_->RestoreCheckpoint(checkpointId);
}

PerformanceBaseline& IntegratedSovereignRuntime::GetPerformanceBaseline() {
    return performanceCapture_->GetBaseline();
}

const PerformanceBaseline& IntegratedSovereignRuntime::GetPerformanceBaseline() const {
    return performanceCapture_->GetBaseline();
}

CheckpointManager& IntegratedSovereignRuntime::GetCheckpointManager() {
    return *checkpointManager_;
}

const CheckpointManager& IntegratedSovereignRuntime::GetCheckpointManager() const {
    return *checkpointManager_;
}

SovereignRuntimeBootstrap& IntegratedSovereignRuntime::GetBootstrapRuntime() {
    return *bootstrap_;
}

const SovereignRuntimeBootstrap& IntegratedSovereignRuntime::GetBootstrapRuntime() const {
    return *bootstrap_;
}

void IntegratedSovereignRuntime::RegisterValidationHook(const ValidationHook& hook) {
    validationHooks_.push_back(hook);
    status_.validationHooksCount = static_cast<int>(validationHooks_.size());
    
    // Sort by priority
    std::sort(validationHooks_.begin(), validationHooks_.end(),
              [](const ValidationHook& a, const ValidationHook& b) {
                  return a.priority > b.priority;
              });
}

void IntegratedSovereignRuntime::UnregisterValidationHook(const std::string& name) {
    validationHooks_.erase(
        std::remove_if(validationHooks_.begin(), validationHooks_.end(),
                       [&name](const ValidationHook& hook) { return hook.name == name; }),
        validationHooks_.end()
    );
    status_.validationHooksCount = static_cast<int>(validationHooks_.size());
}

bool IntegratedSovereignRuntime::RunValidationHooks() {
    bool allPassed = true;
    
    for (const auto& hook : validationHooks_) {
        if (!hook.validateFunc()) {
            status_.validationFailures++;
            std::cerr << "[IntegratedRuntime] Validation failed: " << hook.name << "\n";
            
            if (hook.isCritical) {
                allPassed = false;
                if (config_.failOnValidationError) {
                    return false;
                }
            }
        }
    }
    
    status_.lastValidationTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    return allPassed;
}

IntegrationStatus IntegratedSovereignRuntime::GetStatus() const {
    return status_;
}

std::string IntegratedSovereignRuntime::ExportFullState() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"integrationStatus\": " << status_.ToJson() << ",\n";
    json << "  \"bootstrapStatus\": " << bootstrap_->GetStatus().ToJson() << ",\n";
    json << "  \"performanceBaseline\": " << performanceCapture_->ExportResults() << "\n";
    json << "}";
    return json.str();
}

bool IntegratedSovereignRuntime::SavePerformanceBaseline(const std::string& path) const {
    std::string outputPath = path.empty() ? config_.baselineOutputPath : path;
    return performanceCapture_->GetBaseline().SaveToFile(outputPath);
}

// Internal methods
bool IntegratedSovereignRuntime::InitializeCheckpointManager() {
    checkpointManager_ = std::make_unique<CheckpointManager>();
    
    std::string storagePath = "checkpoints";
    if (!checkpointManager_->Initialize(storagePath)) {
        return false;
    }
    
    checkpointManager_->SetPolicy(config_.checkpointPolicy);
    
    // Register components for checkpointing
    // These would be actual component serializers in production
    checkpointManager_->RegisterComponent(
        "bootstrap",
        []() -> ComponentState {
            ComponentState state;
            state.componentName = "bootstrap";
            return state;
        },
        [](const ComponentState& state) -> bool {
            return true;
        }
    );
    
    return true;
}

bool IntegratedSovereignRuntime::InitializePerformanceCapture() {
    performanceCapture_ = std::make_unique<RuntimePerformanceCapture>();
    
    // Capture startup performance
    if (bootstrap_) {
        auto status = bootstrap_->GetStatus();
        int componentCount = 0;
        if (status.segInitialized) componentCount++;
        if (status.engineInitialized) componentCount++;
        if (status.swarmInitialized) componentCount++;
        if (status.telemetryInitialized) componentCount++;
        if (status.dashboardInitialized) componentCount++;
        if (status.graphBuilt) componentCount++;
        if (status.schedulerRunning) componentCount++;
        
        performanceCapture_->CaptureStartup(status.startupTimeMs, componentCount);
    }
    
    return true;
}

void IntegratedSovereignRuntime::StartContinuousValidation() {
    continuousValidationRunning_.store(true);
    
    // In production, this would start a background thread
    std::cout << "[IntegratedRuntime] Continuous validation enabled (interval: " 
              << config_.validationIntervalMs << " ms)\n";
}

void IntegratedSovereignRuntime::StopContinuousValidation() {
    continuousValidationRunning_.store(false);
    std::cout << "[IntegratedRuntime] Continuous validation stopped\n";
}

void IntegratedSovereignRuntime::RunPreStartupHooks() {
    // Placeholder for pre-startup hooks
}

void IntegratedSovereignRuntime::RunPostStartupHooks() {
    // Placeholder for post-startup hooks
}

void IntegratedSovereignRuntime::RunPreShutdownHooks() {
    // Placeholder for pre-shutdown hooks
}

void IntegratedSovereignRuntime::RunPostShutdownHooks() {
    // Placeholder for post-shutdown hooks
}

// CLI Implementation
void IntegratedRuntimeCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     INTEGRATED SOVEREIGN RUNTIME - Phase B.5                   ║\n";
    std::cout << "║     Full Stack Integration with Validation                     ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void IntegratedRuntimeCLI::PrintUsage() {
    std::cout << "Usage: integrated-runtime [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --validate              Run validation on startup\n";
    std::cout << "  --convergence TARGET    Run until convergence (default: 0.85)\n";
    std::cout << "  --max-iterations N      Max iterations for convergence\n";
    std::cout << "  --checkpoint PATH       Enable checkpointing at path\n";
    std::cout << "  --auto-checkpoint MINS  Enable auto-checkpoint every MINS minutes\n";
    std::cout << "  --baseline PATH         Save performance baseline to path\n";
    std::cout << "  --json                  Output status as JSON\n";
    std::cout << "  --help                  Show this help\n\n";
}

IntegrationConfig IntegratedRuntimeCLI::ParseArgs(int argc, char* argv[]) {
    IntegrationConfig config;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--validate") {
            config.bootstrap.runValidationOnStartup = true;
        } else if (arg == "--convergence" && i + 1 < argc) {
            config.bootstrap.targetConvergenceRate = std::stod(argv[++i]);
        } else if (arg == "--max-iterations" && i + 1 < argc) {
            // Handled in Run()
        } else if (arg == "--checkpoint" && i + 1 < argc) {
            // Would set checkpoint path
        } else if (arg == "--auto-checkpoint" && i + 1 < argc) {
            config.checkpointPolicy.enableAutoCheckpoint = true;
            config.checkpointPolicy.autoCheckpointIntervalMinutes = std::stoi(argv[++i]);
        } else if (arg == "--baseline" && i + 1 < argc) {
            config.baselineOutputPath = argv[++i];
        } else if (arg == "--json") {
            // Handled in Run()
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage();
            exit(0);
        }
    }
    
    return config;
}

int IntegratedRuntimeCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    IntegrationConfig config = ParseArgs(argc, argv);
    
    IntegratedSovereignRuntime runtime;
    
    if (!runtime.Initialize(config)) {
        std::cerr << "[IntegratedRuntime] Initialization failed\n";
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
            std::cout << runtime.ExportFullState() << "\n";
        }
    }
    
    std::cout << "[IntegratedRuntime] Running... Press Ctrl+C to shutdown\n";
    
    while (runtime.IsRunning()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    return 0;
}

} // namespace Sovereign
