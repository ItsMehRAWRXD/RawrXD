#pragma once

/**
 * RuntimeIntegration.hpp
 * 
 * Phase B.5 Batch 4/5: Runtime Integration & Validation
 * 
 * Integrates all runtime components with validation hooks
 */

#include "SovereignRuntimeBootstrap.hpp"
#include "PerformanceBaseline.hpp"
#include "CheckpointManager.hpp"
#include <functional>
#include <vector>

namespace Sovereign {

/**
 * Validation hook for runtime events
 */
struct ValidationHook {
    std::string name;
    std::function<bool()> validateFunc;
    bool isCritical = false;
    int priority = 0;
};

/**
 * Runtime integration configuration
 */
struct IntegrationConfig {
    BootstrapConfig bootstrap;
    CheckpointPolicy checkpointPolicy;
    
    // Validation settings
    bool enableContinuousValidation = true;
    int validationIntervalMs = 5000;
    bool failOnValidationError = false;
    
    // Performance tracking
    bool enablePerformanceTracking = true;
    bool autoSaveBaseline = true;
    std::string baselineOutputPath = "performance_baseline.json";
    
    // Integration hooks
    bool enablePreStartupHooks = true;
    bool enablePostStartupHooks = true;
    bool enablePreShutdownHooks = true;
    bool enablePostShutdownHooks = true;
};

/**
 * Runtime integration status
 */
struct IntegrationStatus {
    bool bootstrapInitialized = false;
    bool checkpointManagerInitialized = false;
    bool performanceCaptureInitialized = false;
    bool validationHooksRegistered = false;
    
    int validationHooksCount = 0;
    int validationFailures = 0;
    int64_t lastValidationTimeMs = 0;
    
    std::string ToJson() const;
};

/**
 * Integrated Sovereign Runtime
 * 
 * Combines Bootstrap, Performance Baseline, and Checkpoint Manager
 * with validation hooks and continuous monitoring
 */
class IntegratedSovereignRuntime {
public:
    IntegratedSovereignRuntime();
    ~IntegratedSovereignRuntime();
    
    // Initialize with full integration
    bool Initialize(const IntegrationConfig& config = IntegrationConfig{});
    
    // Shutdown gracefully
    void Shutdown();
    
    // Check if running
    bool IsRunning() const;
    
    // Execute workflow with full tracking
    bool ExecuteWorkflow();
    
    // Run until convergence with checkpointing
    bool RunUntilConvergence(double targetConvergence = 0.85, int maxIterations = 100);
    
    // Create checkpoint
    std::string CreateCheckpoint(const std::string& description = "");
    
    // Restore from checkpoint
    bool RestoreCheckpoint(const std::string& checkpointId);
    
    // Get performance baseline
    PerformanceBaseline& GetPerformanceBaseline();
    const PerformanceBaseline& GetPerformanceBaseline() const;
    
    // Get checkpoint manager
    CheckpointManager& GetCheckpointManager();
    const CheckpointManager& GetCheckpointManager() const;
    
    // Get bootstrap runtime
    SovereignRuntimeBootstrap& GetBootstrapRuntime();
    const SovereignRuntimeBootstrap& GetBootstrapRuntime() const;
    
    // Validation hooks
    void RegisterValidationHook(const ValidationHook& hook);
    void UnregisterValidationHook(const std::string& name);
    bool RunValidationHooks();
    
    // Get status
    IntegrationStatus GetStatus() const;
    
    // Export full state
    std::string ExportFullState() const;
    
    // Save performance baseline
    bool SavePerformanceBaseline(const std::string& path = "") const;
    
private:
    IntegrationConfig config_;
    IntegrationStatus status_;
    
    std::unique_ptr<SovereignRuntimeBootstrap> bootstrap_;
    std::unique_ptr<CheckpointManager> checkpointManager_;
    std::unique_ptr<RuntimePerformanceCapture> performanceCapture_;
    
    std::vector<ValidationHook> validationHooks_;
    std::atomic<bool> running_{false};
    std::atomic<bool> continuousValidationRunning_{false};
    
    // Internal methods
    bool InitializeCheckpointManager();
    bool InitializePerformanceCapture();
    void StartContinuousValidation();
    void StopContinuousValidation();
    void RunPreStartupHooks();
    void RunPostStartupHooks();
    void RunPreShutdownHooks();
    void RunPostShutdownHooks();
};

/**
 * CLI for integrated runtime
 */
class IntegratedRuntimeCLI {
public:
    static int Run(int argc, char* argv[]);
    
private:
    static void PrintUsage();
    static void PrintBanner();
    static IntegrationConfig ParseArgs(int argc, char* argv[]);
};

} // namespace Sovereign
