// ============================================================================
// FaultInjector.hpp — Base Types for Fault Injection Harness
// ============================================================================
// Mission 2.1: Recovery Validation Harness
//
// Provides deterministic fault injection for validating recovery strategies:
//   - Worker thread crashes
//   - Memory pressure/exhaustion
//   - Service termination
//   - State corruption
//   - Exception storms
//
// Each fault produces a deterministic manifest for validation traceability.
// ============================================================================

#pragma once

#include <string>
#include <chrono>
#include <functional>
#include <atomic>
#include <thread>
#include <memory>
#include <mutex>
#include <map>

#include "nlohmann/json.hpp"

namespace RawrXD {
namespace Validation {

// ============================================================================
// Fault Types
// ============================================================================
enum class FaultType {
    UNKNOWN = 0,
    THREAD_TERMINATION,     // Worker thread crash/kill
    MEMORY_EXHAUSTION,       // Memory pressure simulation
    SERVICE_KILL,           // Background service termination
    STATE_CORRUPTION,       // Internal state corruption
    EXCEPTION_STORM,         // Repeated exception injection
    RESOURCE_LEAK,          // Handle/memory leak simulation
    DEADLOCK,               // Deadlock injection
    NETWORK_PARTITION       // Network isolation
};

// ============================================================================
// Fault Severity
// ============================================================================
enum class FaultSeverity {
    LOW = 0,        // Recoverable without intervention
    MEDIUM = 1,     // Requires automatic recovery
    HIGH = 2,       // Requires escalation
    CRITICAL = 3    // Process termination likely
};

// ============================================================================
// Fault Manifest
// ============================================================================
// Structured record of injected fault for validation traceability
struct FaultManifest {
    std::string faultId;                    // Unique identifier (e.g., "FAULT-WORKER-001")
    FaultType type = FaultType::UNKNOWN;
    FaultSeverity severity = FaultSeverity::LOW;
    std::string timestamp;                  // ISO 8601 timestamp
    std::string targetComponent;            // Component being faulted
    std::string expectedRecovery;         // Expected recovery strategy
    std::string description;                // Human-readable description
    nlohmann::json parameters;              // Fault-specific parameters
    
    FaultManifest() = default;
    FaultManifest(const std::string& id, FaultType t, FaultSeverity s,
                  const std::string& component, const std::string& recovery);
    
    nlohmann::json toJson() const;
    static FaultManifest fromJson(const nlohmann::json& j);
    
    std::string generateFilename() const;
};

// ============================================================================
// Fault Injection Result
// ============================================================================
struct FaultInjectionResult {
    bool success = false;                   // Was fault injected successfully?
    std::string faultId;                  // Reference to manifest
    std::chrono::milliseconds injectionTime{0};
    std::string errorMessage;             // If injection failed
    nlohmann::json telemetry;             // Pre/post injection state
    
    nlohmann::json toJson() const;
};

// ============================================================================
// Base Fault Injector
// ============================================================================
class FaultInjector {
public:
    virtual ~FaultInjector() = default;
    
    // Core interface
    virtual FaultType getType() const = 0;
    virtual std::string getName() const = 0;
    virtual FaultInjectionResult inject() = 0;
    virtual bool isAvailable() const = 0;
    
    // Lifecycle
    virtual bool initialize() { return true; }
    virtual void shutdown() {}
    
    // Configuration
    void setSeverity(FaultSeverity s) { m_severity = s; }
    FaultSeverity getSeverity() const { return m_severity; }
    
    // Manifest access
    const FaultManifest& getLastManifest() const { return m_lastManifest; }
    
    // Callback for pre/post injection
    using PreInjectionCallback = std::function<void(const FaultManifest&)>;
    using PostInjectionCallback = std::function<void(const FaultManifest&, const FaultInjectionResult&)>;
    
    void setPreInjectionCallback(PreInjectionCallback cb) { m_preCallback = std::move(cb); }
    void setPostInjectionCallback(PostInjectionCallback cb) { m_postCallback = std::move(cb); }

protected:
    FaultSeverity m_severity = FaultSeverity::MEDIUM;
    FaultManifest m_lastManifest;
    PreInjectionCallback m_preCallback;
    PostInjectionCallback m_postCallback;
    
    std::string generateFaultId(const std::string& prefix);
    void notifyPreInjection(const FaultManifest& manifest);
    void notifyPostInjection(const FaultManifest& manifest, const FaultInjectionResult& result);
};

// ============================================================================
// Fault Injection Statistics
// ============================================================================
struct FaultInjectionStats {
    std::atomic<uint64_t> totalInjected{0};
    std::atomic<uint64_t> successfulInjections{0};
    std::atomic<uint64_t> failedInjections{0};
    std::atomic<uint64_t> recoveriesDetected{0};
    std::atomic<uint64_t> recoveriesSuccessful{0};
    
    nlohmann::json toJson() const;
    void reset();
};

// ============================================================================
// Fault Injection Registry
// ============================================================================
class FaultInjectionRegistry {
public:
    static FaultInjectionRegistry& instance();
    
    void registerInjector(std::shared_ptr<FaultInjector> injector);
    void unregisterInjector(const std::string& name);
    std::shared_ptr<FaultInjector> getInjector(const std::string& name);
    std::vector<std::shared_ptr<FaultInjector>> getAllInjectors() const;
    std::vector<std::shared_ptr<FaultInjector>> getInjectorsByType(FaultType type) const;
    
    FaultInjectionStats& getStats() { return m_stats; }
    void resetStats() { m_stats.reset(); }
    
private:
    FaultInjectionRegistry() = default;
    ~FaultInjectionRegistry() = default;
    
    std::map<std::string, std::shared_ptr<FaultInjector>> m_injectors;
    FaultInjectionStats m_stats;
    mutable std::mutex m_mutex;
};

// ============================================================================
// Utility Functions
// ============================================================================
const char* FaultTypeToString(FaultType type);
const char* FaultSeverityToString(FaultSeverity severity);
FaultType FaultTypeFromString(const std::string& str);
FaultSeverity FaultSeverityFromString(const std::string& str);

} // namespace Validation
} // namespace RawrXD