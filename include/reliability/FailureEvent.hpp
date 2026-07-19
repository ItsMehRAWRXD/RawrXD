// ============================================================================
// FailureEvent.hpp — Structured Failure Event Types
// ============================================================================
// Mission 2.4: Reliability Interface Layer
//
// Defines the failure event bus contract between:
//   - Fault injectors (test/simulated failures)
//   - Runtime failures (production errors)
//   - HealthMonitor (detection layer)
//   - RecoveryController (orchestration)
//
// This abstraction keeps production code clean while enabling identical
// failure simulation in tests.
// ============================================================================

#pragma once

#include <string>
#include <chrono>
#include <map>
#include <vector>
#include <atomic>
#include <memory>

#include "nlohmann/json.hpp"

namespace RawrXD {
namespace Reliability {

// ============================================================================
// Failure Severity Levels
// ============================================================================
enum class FailureSeverity {
    DEBUG = 0,      // Informational, no action needed
    WARNING = 1,    // Anomaly detected, monitoring
    ERROR = 2,      // Service degradation, recovery may be needed
    CRITICAL = 3,   // Service failure, immediate recovery required
    FATAL = 4       // Process termination likely
};

const char* FailureSeverityToString(FailureSeverity severity);
FailureSeverity FailureSeverityFromString(const std::string& str);

// ============================================================================
// Failure Categories
// ============================================================================
enum class FailureCategory {
    UNKNOWN = 0,
    
    // Process/Thread failures
    THREAD_TERMINATION,
    PROCESS_CRASH,
    DEADLOCK,
    STARVATION,
    
    // Resource failures
    MEMORY_EXHAUSTION,
    MEMORY_CORRUPTION,
    HANDLE_LEAK,
    DISK_FULL,
    
    // Service failures
    SERVICE_UNRESPONSIVE,
    SERVICE_UNAVAILABLE,
    DEPENDENCY_FAILURE,
    TIMEOUT,
    
    // State failures
    STATE_CORRUPTION,
    INVALID_CHECKSUM,
    VERSION_MISMATCH,
    CONFIGURATION_ERROR,
    
    // Execution failures
    EXCEPTION_THROWN,
    ASSERTION_FAILURE,
    INFINITE_LOOP,
    STACK_OVERFLOW,
    
    // External failures
    NETWORK_PARTITION,
    GPU_ERROR,
    DRIVER_FAILURE
};

const char* FailureCategoryToString(FailureCategory category);
FailureCategory FailureCategoryFromString(const std::string& str);

// ============================================================================
// Failure Event
// ============================================================================
// Immutable event representing a failure condition
struct FailureEvent {
    // Event identification
    std::string eventId;
    std::string correlationId;      // Links related events
    std::string parentEventId;    // For cascading failures
    
    // Classification
    FailureCategory category;
    FailureSeverity severity;
    std::string type;               // Specific type within category
    
    // Source information
    std::string sourceComponent;
    std::string sourceLocation;     // file:line or function
    std::string targetResource;     // What was affected
    
    // Timing
    std::chrono::steady_clock::time_point timestamp;
    std::chrono::steady_clock::time_point detectionTime;
    
    // Context
    std::string message;
    std::string stackTrace;
    nlohmann::json context;         // Arbitrary structured data
    
    // State at failure
    uint64_t memoryUsageBytes = 0;
    uint32_t threadCount = 0;
    std::string processState;     // JSON snapshot
    
    // Recovery hints
    std::vector<std::string> suggestedStrategies;
    bool autoRecoverable = false;
    int maxRecoveryAttempts = 3;
    
    FailureEvent();
    FailureEvent(FailureCategory cat, FailureSeverity sev, 
                 const std::string& component, const std::string& msg);
    
    // Serialization
    nlohmann::json toJson() const;
    static FailureEvent fromJson(const nlohmann::json& j);
    
    // Utility
    std::string generateEventId();
    uint64_t detectionLatencyMs() const;
    bool isRecoverable() const;
};

// ============================================================================
// Failure Event Builder
// ============================================================================
class FailureEventBuilder {
public:
    FailureEventBuilder(FailureCategory category, FailureSeverity severity);
    
    FailureEventBuilder& component(const std::string& name);
    FailureEventBuilder& message(const std::string& msg);
    FailureEventBuilder& location(const std::string& file, int line);
    FailureEventBuilder& target(const std::string& resource);
    FailureEventBuilder& context(const nlohmann::json& ctx);
    FailureEventBuilder& suggestedStrategy(const std::string& strategy);
    FailureEventBuilder& autoRecoverable(bool enabled);
    FailureEventBuilder& maxAttempts(int attempts);
    FailureEventBuilder& correlation(const std::string& correlationId);
    FailureEventBuilder& parent(const std::string& parentEventId);
    
    FailureEvent build();

private:
    FailureEvent m_event;
};

// ============================================================================
// Failure Event Filter
// ============================================================================
using FailurePredicate = std::function<bool(const FailureEvent&)>;

struct FailureFilter {
    std::vector<FailureCategory> categories;
    std::vector<FailureSeverity> severities;
    std::vector<std::string> components;
    FailurePredicate customPredicate;
    
    bool matches(const FailureEvent& event) const;
    bool isEmpty() const;
};

} // namespace Reliability
} // namespace RawrXD