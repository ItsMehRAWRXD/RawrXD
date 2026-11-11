#pragma once

/**
 * Failure Mode Firewall (FMF) - Runtime Telemetry Core
 * 
 * Purpose: Distinguish real execution from stub fallback execution
 * Architecture: Non-invasive observation + enforcement layer
 * 
 * This module answers one critical question:
 * "Was this real execution or a fallback illusion?"
 */

#include <cstdint>
#include <atomic>
#include <string>
#include <unordered_map>
#include <mutex>
#include <functional>
#include <chrono>

// Policy modes for stub execution handling
enum class FMFPolicy : uint8_t {
    SILENT = 0,  // Log only, no user notification
    WARN   = 1,  // Log + debug output
    BLOCK  = 2   // Log + assert/halt execution
};

// Event structure for telemetry
struct FMFEvent {
    const char* feature;      // Feature name (e.g., "LSP_Completion")
    const char* file;         // Source file
    const char* function;     // Caller function
    const char* reason;       // Fallback reason (if applicable)
    bool isStub;              // True if stub execution
    uint32_t line;            // Source line
    std::chrono::steady_clock::time_point timestamp;
};

// Runtime state for a feature
struct FeatureRuntimeState {
    bool declared = false;        // Declared in registry
    bool hasRealSymbol = false;  // Has real implementation symbol
    bool stubbed = false;        // Has stub fallback
    mutable std::atomic<uint32_t> stubCallCount{0};
    mutable std::atomic<uint32_t> realCallCount{0};
    std::chrono::steady_clock::time_point lastStubCall;
    std::chrono::steady_clock::time_point lastRealCall;
    
    // Default constructor
    FeatureRuntimeState() = default;
    
    // Copy constructor (needed for unordered_map)
    FeatureRuntimeState(const FeatureRuntimeState& other) {
        declared = other.declared;
        hasRealSymbol = other.hasRealSymbol;
        stubbed = other.stubbed;
        stubCallCount.store(other.stubCallCount.load());
        realCallCount.store(other.realCallCount.load());
        lastStubCall = other.lastStubCall;
        lastRealCall = other.lastRealCall;
    }
    
    // Assignment operator
    FeatureRuntimeState& operator=(const FeatureRuntimeState& other) {
        if (this != &other) {
            declared = other.declared;
            hasRealSymbol = other.hasRealSymbol;
            stubbed = other.stubbed;
            stubCallCount.store(other.stubCallCount.load());
            realCallCount.store(other.realCallCount.load());
            lastStubCall = other.lastStubCall;
            lastRealCall = other.lastRealCall;
        }
        return *this;
    }
};

// Callback types
using FMFEventCallback = std::function<void(const FMFEvent&)>;
using FMFReportCallback = std::function<void(const char* feature, uint32_t stubCount, uint32_t realCount)>;

/**
 * FailureModeFirewall - Core telemetry and enforcement class
 * 
 * Thread-safe singleton for tracking stub vs real execution
 */
class FailureModeFirewall {
public:
    // Singleton access
    static FailureModeFirewall& Instance();

    // Policy control
    void SetPolicy(FMFPolicy policy);
    FMFPolicy GetPolicy() const;

    // Core reporting functions
    void ReportStub(const char* feature, const char* file, const char* function, uint32_t line = 0);
    void ReportFallback(const char* reason, const char* file, uint32_t line);
    void ReportRealExecution(const char* feature, const char* file, const char* function);

    // Feature registry reconciliation
    void RegisterFeature(const char* feature, bool declared, bool hasRealSymbol, bool stubbed);
    bool IsFeatureReal(const char* feature) const;
    const FeatureRuntimeState* GetFeatureState(const char* feature) const;

    // Statistics
    uint32_t GetStubCallCount(const char* feature) const;
    uint32_t GetRealCallCount(const char* feature) const;
    void GetAllFeatureStats(std::unordered_map<std::string, FeatureRuntimeState>& outStats) const;

    // Callbacks for external monitoring
    void SetEventCallback(FMFEventCallback callback);
    void SetReportCallback(FMFReportCallback callback);

    // Diagnostic output
    void DumpReport() const;
    void ExportReport(const char* filepath) const;

    // Reset (for testing)
    void Reset();

private:
    FailureModeFirewall();
    ~FailureModeFirewall() = default;
    FailureModeFirewall(const FailureModeFirewall&) = delete;
    FailureModeFirewall& operator=(const FailureModeFirewall&) = delete;

    void EnforcePolicy(const FMFEvent& event);

    mutable std::mutex m_mutex;
    FMFPolicy m_policy = FMFPolicy::WARN;
    std::unordered_map<std::string, FeatureRuntimeState> m_features;
    FMFEventCallback m_eventCallback;
    FMFReportCallback m_reportCallback;
    std::atomic<uint32_t> m_totalStubCalls{0};
    std::atomic<uint32_t> m_totalRealCalls{0};
};

// Convenience macros for instrumentation
#define FMF_STUB_ENTRY(feature) \
    FailureModeFirewall::Instance().ReportStub(feature, __FILE__, __FUNCTION__, __LINE__)

#define FMF_FALLBACK(reason) \
    FailureModeFirewall::Instance().ReportFallback(reason, __FILE__, __LINE__)

#define FMF_REAL_ENTRY(feature) \
    FailureModeFirewall::Instance().ReportRealExecution(feature, __FILE__, __FUNCTION__)

// Conditional stub entry (for partial implementations)
#define FMF_STUB_IF(condition, feature) \
    if (condition) { FMF_STUB_ENTRY(feature); }

// Feature registration macro (for startup)
#define FMF_REGISTER_FEATURE(name, declared, hasReal, stubbed) \
    FailureModeFirewall::Instance().RegisterFeature(name, declared, hasReal, stubbed)

// Policy guard (temporary policy change)
class FMFPolicyGuard {
public:
    explicit FMFPolicyGuard(FMFPolicy tempPolicy);
    ~FMFPolicyGuard();
private:
    FMFPolicy m_previousPolicy;
};