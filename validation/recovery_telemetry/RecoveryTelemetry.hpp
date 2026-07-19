// ============================================================================
// RecoveryTelemetry.hpp — Structured Recovery Event Stream
// ============================================================================
// Mission 2.2: Recovery Telemetry
//
// Provides structured recovery event tracking with MTTD/MTTR metrics:
//   - Mean Time To Detect (MTTD)
//   - Mean Time To Recover (MTTR)
//   - Recovery success rate
//   - False-positive anomaly rate
//   - Consecutive failure tracking
//   - Recovery latency histograms
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <atomic>
#include <mutex>
#include <queue>
#include <fstream>
#include <sstream>
#include <functional>

#include "nlohmann/json.hpp"

namespace RawrXD {
namespace Validation {

// Forward declarations - FaultManifest defined in FaultInjector.hpp
struct FaultManifest;

// ============================================================================
// Recovery Event Types
// ============================================================================
enum class RecoveryEventType {
    UNKNOWN = 0,
    FAULT_DETECTED,         // Anomaly/fault detected
    RECOVERY_INITIATED,     // Recovery process started
    RECOVERY_STEP_STARTED,  // Individual recovery step started
    RECOVERY_STEP_COMPLETED,// Individual recovery step completed
    RECOVERY_STEP_FAILED,   // Individual recovery step failed
    RECOVERY_COMPLETED,     // Full recovery completed
    RECOVERY_FAILED,        // Recovery failed after retries
    ROLLBACK_INITIATED,     // State rollback started
    ROLLBACK_COMPLETED,     // State rollback completed
    SERVICE_RESTARTED,      // Service successfully restarted
    CACHE_CLEARED,          // Cache cleared as recovery step
    ESCALATION_TRIGGERED    // Escalated to user/operator
};

// ============================================================================
// Recovery Event
// ============================================================================
// Structured event for recovery telemetry
struct RecoveryEvent {
    std::string eventId;
    RecoveryEventType type = RecoveryEventType::UNKNOWN;
    std::string timestamp;              // ISO 8601
    std::string faultId;                // Reference to triggering fault
    std::string strategy;               // Recovery strategy used
    std::string trigger;                // What triggered recovery
    
    // Timing metrics (milliseconds)
    uint64_t detectionLatencyMs = 0;    // Time from fault to detection (MTTD component)
    uint64_t recoveryLatencyMs = 0;     // Time from detection to completion (MTTR component)
    uint64_t totalLatencyMs = 0;        // Total time from fault to recovery
    
    // Status
    bool success = false;
    std::string errorMessage;
    int retryCount = 0;
    int maxRetries = 3;
    
    // Context
    nlohmann::json context;             // Additional context data
    std::string sourceComponent;
    std::string targetComponent;
    
    RecoveryEvent() = default;
    RecoveryEvent(RecoveryEventType t, const std::string& fid, const std::string& strat);
    
    nlohmann::json toJson() const;
    static RecoveryEvent fromJson(const nlohmann::json& j);
};

// ============================================================================
// Recovery Metrics
// ============================================================================
// Aggregated metrics for recovery performance
struct RecoveryMetrics {
    // Counters
    std::atomic<uint64_t> totalFaultsDetected{0};
    std::atomic<uint64_t> totalRecoveriesInitiated{0};
    std::atomic<uint64_t> totalRecoveriesSuccessful{0};
    std::atomic<uint64_t> totalRecoveriesFailed{0};
    std::atomic<uint64_t> totalEscalations{0};
    std::atomic<uint64_t> totalRollbacks{0};
    
    // Latency tracking (milliseconds)
    std::atomic<uint64_t> totalDetectionLatencyMs{0};  // Sum for MTTD calculation
    std::atomic<uint64_t> totalRecoveryLatencyMs{0};  // Sum for MTTR calculation
    std::atomic<uint64_t> minDetectionLatencyMs{UINT64_MAX};
    std::atomic<uint64_t> maxDetectionLatencyMs{0};
    std::atomic<uint64_t> minRecoveryLatencyMs{UINT64_MAX};
    std::atomic<uint64_t> maxRecoveryLatencyMs{0};
    
    // Consecutive failures
    std::atomic<uint64_t> currentConsecutiveFailures{0};
    std::atomic<uint64_t> maxConsecutiveFailures{0};
    
    // False positive tracking
    std::atomic<uint64_t> falsePositiveDetections{0};
    std::atomic<uint64_t> truePositiveDetections{0};
    
    // Strategy-specific metrics
    std::map<std::string, uint64_t> strategySuccessCounts;
    std::map<std::string, uint64_t> strategyFailureCounts;
    mutable std::mutex strategyMutex;
    
    // Computed metrics
    double getMTTD() const;              // Mean Time To Detect (ms)
    double getMTTR() const;              // Mean Time To Recover (ms)
    double getSuccessRate() const;       // 0.0 - 1.0
    double getFalsePositiveRate() const; // 0.0 - 1.0
    
    nlohmann::json toJson() const;
    void reset();
};

// ============================================================================
// Recovery Telemetry Collector
// ============================================================================
class RecoveryTelemetryCollector {
public:
    static RecoveryTelemetryCollector& instance();
    
    // Event recording
    void recordEvent(const RecoveryEvent& event);
    void recordFaultDetected(const std::string& faultId, const std::string& trigger,
                             uint64_t detectionLatencyMs);
    void recordRecoveryInitiated(const std::string& faultId, const std::string& strategy);
    void recordRecoveryCompleted(const std::string& faultId, bool success, 
                                  uint64_t recoveryLatencyMs, int retryCount);
    void recordEscalation(const std::string& faultId, const std::string& reason);
    
    // Query methods
    std::vector<RecoveryEvent> getRecentEvents(size_t count = 100) const;
    std::vector<RecoveryEvent> getEventsByType(RecoveryEventType type) const;
    std::vector<RecoveryEvent> getEventsForFault(const std::string& faultId) const;
    RecoveryEvent getLastEvent() const;
    
    // Metrics access
    const RecoveryMetrics& getMetrics() const { return m_metrics; }
    RecoveryMetrics& getMetrics() { return m_metrics; }
    
    // Export
    nlohmann::json exportEvents() const;
    nlohmann::json exportMetrics() const;
    nlohmann::json exportFullReport() const;
    
    // Persistence
    bool saveToFile(const std::string& filepath) const;
    bool loadFromFile(const std::string& filepath);
    
    // Reset
    void reset();
    
    // Callbacks
    using EventCallback = std::function<void(const RecoveryEvent&)>;
    void setEventCallback(EventCallback cb) { m_eventCallback = std::move(cb); }

private:
    RecoveryTelemetryCollector() = default;
    ~RecoveryTelemetryCollector() = default;
    
    std::deque<RecoveryEvent> m_events;
    mutable std::mutex m_eventsMutex;
    static constexpr size_t MAX_EVENTS = 10000;
    
    RecoveryMetrics m_metrics;
    mutable std::mutex m_metricsMutex;
    
    EventCallback m_eventCallback;
    
    std::string generateEventId();
    void updateMetrics(const RecoveryEvent& event);
};

// ============================================================================
// Recovery Telemetry Logger
// ============================================================================
// Async logger for recovery events
class RecoveryTelemetryLogger {
public:
    static RecoveryTelemetryLogger& instance();
    
    void initialize(const std::string& logDir);
    void shutdown();
    
    void logEvent(const RecoveryEvent& event);
    void logMetrics(const RecoveryMetrics& metrics);
    void logFaultManifest(const FaultManifest& manifest);
    
    // Log rotation
    void rotateLogs();
    std::string getCurrentLogFile() const { return m_currentLogFile; }

private:
    RecoveryTelemetryLogger() = default;
    ~RecoveryTelemetryLogger() { shutdown(); }
    
    std::string m_logDir;
    std::string m_currentLogFile;
    std::ofstream m_logStream;
    std::mutex m_logMutex;
    std::atomic<bool> m_initialized{false};
    
    void ensureLogOpen();
    std::string generateLogFilename();
};

// ============================================================================
// Utility Functions
// ============================================================================
const char* RecoveryEventTypeToString(RecoveryEventType type);
RecoveryEventType RecoveryEventTypeFromString(const std::string& str);

} // namespace Validation
} // namespace RawrXD