/**
 * FaultManager.hpp
 *
 * Phase D.1 Batch 3/5: Failure Containment
 *
 * Detects subsystem failures, isolates failed nodes,
 * restores checkpoint, retries execution path.
 */

#pragma once

#include "SovereignState.hpp"
#include "../runtime/CheckpointManager.hpp"
#include "../seg/ExecutionGraph.hpp"

#include <vector>
#include <queue>
#include <functional>
#include <mutex>

namespace Core {

/**
 * Fault types
 */
enum class FaultType {
    SUBSYSTEM_CRASH,        // Complete subsystem failure
    SUBSYSTEM_HANG,         // Unresponsive subsystem
    EXECUTION_ERROR,        // Runtime execution error
    RESOURCE_EXHAUSTION,    // Out of memory/CPU
    STATE_INCONSISTENCY,    // Data corruption/drift
    NETWORK_FAILURE,        // Communication failure
    TIMEOUT,                // Operation timeout
    UNKNOWN
};

std::string FaultTypeToString(FaultType type);

/**
 * Fault severity
 */
enum class FaultSeverity {
    WARNING,    // Non-critical, logged only
    MINOR,      // Degraded functionality
    MAJOR,      // Significant impact
    CRITICAL    // System halt required
};

/**
 * Fault information
 */
struct Fault {
    std::string faultId;
    FaultType type{FaultType::UNKNOWN};
    FaultSeverity severity{FaultSeverity::WARNING};
    std::string subsystem;
    std::string description;
    std::string errorMessage;
    int64_t timestampMs{0};
    std::map<std::string, std::string> context;
    
    std::string ToJson() const;
};

/**
 * Recovery action
 */
struct RecoveryAction {
    std::string actionId;
    std::string description;
    std::function<bool()> execute;
    int maxRetries{3};
    int retryCount{0};
    int64_t lastAttemptMs{0};
};

/**
 * Recovery result
 */
struct RecoveryResult {
    bool success{false};
    std::string faultId;
    std::string actionId;
    int attempts{0};
    int64_t durationMs{0};
    std::string errorMessage;
    
    std::string ToJson() const;
};

/**
 * Fault manager configuration
 */
struct FaultManagerConfig {
    bool enableAutoRecovery{true};
    int maxConcurrentRecoveries{3};
    int recoveryTimeoutMs{30000};
    int faultHistorySize{1000};
    
    // Thresholds
    int maxFaultsPerMinute{10};
    int maxCriticalFaultsPerHour{5};
    
    std::string ToJson() const;
};

/**
 * Fault Manager
 *
 * Centralized fault detection and recovery coordination.
 */
class FaultManager {
public:
    FaultManager();
    ~FaultManager();

    // Disable copy
    FaultManager(const FaultManager&) = delete;
    FaultManager& operator=(const FaultManager&) = delete;

    /**
     * Initialize fault manager
     */
    bool Initialize(const FaultManagerConfig& config);

    /**
     * Shutdown
     */
    void Shutdown();

    /**
     * Report a fault
     */
    std::string ReportFault(const Fault& fault);

    /**
     * Report fault with automatic type detection
     */
    std::string ReportFault(const std::string& subsystem, 
                           const std::string& error,
                           FaultSeverity severity = FaultSeverity::WARNING);

    /**
     * Check if recovery is in progress
     */
    bool IsRecoveryInProgress() const;

    /**
     * Get active faults
     */
    std::vector<Fault> GetActiveFaults() const;

    /**
     * Get fault history
     */
    std::vector<Fault> GetFaultHistory(int count = 100) const;

    /**
     * Get recovery history
     */
    std::vector<RecoveryResult> GetRecoveryHistory() const;

    /**
     * Clear resolved faults
     */
    void ClearResolvedFaults();

    /**
     * Set checkpoint manager for recovery
     */
    void SetCheckpointManager(std::shared_ptr<Runtime::CheckpointManager> manager);

    /**
     * Set execution graph for mutation recovery
     */
    void SetExecutionGraph(std::shared_ptr<SEG::ExecutionGraph> graph);

    /**
     * Get statistics
     */
    struct Statistics {
        int totalFaults{0};
        int activeFaults{0};
        int recoveredFaults{0};
        int failedRecoveries{0};
        int criticalFaults{0};
        double recoverySuccessRate{0.0};
        
        void Print() const;
    };
    Statistics GetStatistics() const;

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    FaultManagerConfig config_;
    bool initialized_{false};
    
    // Subsystem references
    std::shared_ptr<Runtime::CheckpointManager> checkpointManager_;
    std::shared_ptr<SEG::ExecutionGraph> executionGraph_;
    
    // Fault tracking
    std::vector<Fault> activeFaults_;
    std::vector<Fault> faultHistory_;
    std::vector<RecoveryResult> recoveryHistory_;
    
    // Recovery tracking
    std::map<std::string, RecoveryAction> recoveryActions_;
    std::atomic<bool> recoveryInProgress_{false};
    
    // Threading
    mutable std::mutex mutex_;
    std::unique_ptr<std::thread> recoveryThread_;
    
    // Statistics
    Statistics stats_;
    
    // Recovery methods
    RecoveryResult AttemptRecovery(const Fault& fault);
    RecoveryResult RecoverSubsystemCrash(const Fault& fault);
    RecoveryResult RecoverExecutionError(const Fault& fault);
    RecoveryResult RecoverResourceExhaustion(const Fault& fault);
    RecoveryResult RecoverStateInconsistency(const Fault& fault);
    
    // Helpers
    FaultSeverity AssessSeverity(const Fault& fault) const;
    bool ShouldAttemptRecovery(const Fault& fault) const;
    std::string GenerateFaultId() const;
    void UpdateStatistics(const RecoveryResult& result);
};

/**
 * Fault detection helper
 */
class FaultDetector {
public:
    /**
     * Detect hang by checking responsiveness
     */
    static bool DetectHang(const std::string& subsystem, 
                          std::function<bool()> healthCheck,
                          int timeoutMs = 5000);
    
    /**
     * Detect resource exhaustion
     */
    static bool DetectResourceExhaustion(double memoryUsagePercent,
                                         double cpuUsagePercent,
                                         double threshold = 0.95);
    
    /**
     * Detect state inconsistency
     */
    static bool DetectStateInconsistency(const SovereignState& previous,
                                       const SovereignState& current,
                                       double threshold = 0.5);
};

} // namespace Core
