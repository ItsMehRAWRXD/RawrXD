/**
 * Failure Mode Firewall (FMF) - Implementation
 * 
 * Runtime telemetry core for distinguishing real execution from stub fallbacks.
 */

#include "FailureModeFirewall.h"

// Use minimal logger for standalone builds (FMF_STANDALONE_BUILD defined in CMake)
#ifdef FMF_STANDALONE_BUILD
#include "test/fmf_minimal_logger.h"
#endif

#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>

// Singleton instance
FailureModeFirewall& FailureModeFirewall::Instance() {
    static FailureModeFirewall instance;
    return instance;
}

FailureModeFirewall::FailureModeFirewall() {
    // Initialize with default policy
    m_policy = FMFPolicy::WARN;
}

void FailureModeFirewall::SetPolicy(FMFPolicy policy) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_policy = policy;
}

FMFPolicy FailureModeFirewall::GetPolicy() const {
    return m_policy;
}

void FailureModeFirewall::ReportStub(const char* feature, const char* file, const char* function, uint32_t line) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto now = std::chrono::steady_clock::now();
    
    // Update feature state
    auto& state = m_features[feature];
    state.stubbed = true;
    state.stubCallCount++;
    state.lastStubCall = now;
    
    m_totalStubCalls++;
    
    // Create event
    FMFEvent event;
    event.feature = feature;
    event.file = file;
    event.function = function;
    event.reason = "STUB_EXECUTION";
    event.isStub = true;
    event.line = line;
    event.timestamp = now;
    
    // Invoke callback if set
    if (m_eventCallback) {
        m_eventCallback(event);
    }
    
    // Enforce policy
    EnforcePolicy(event);
    
    // Log based on policy
    if (m_policy != FMFPolicy::SILENT) {
        // Use IDE logger if available (non-standalone builds)
#ifdef IDELOGGER_H
        if (g_ideLogger) {
            char buffer[512];
            snprintf(buffer, sizeof(buffer), "[FMF] STUB: %s in %s (%s:%u)", 
                     feature, function, file, line);
            g_ideLogger->LogWarning(buffer);
        }
#else
        // Standalone build - use stderr
        fprintf(stderr, "[FMF] STUB: %s in %s (%s:%u)\n", 
                feature, function, file, line);
#endif
    }
}

void FailureModeFirewall::ReportFallback(const char* reason, const char* file, uint32_t line) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto now = std::chrono::steady_clock::now();
    
    // Create event
    FMFEvent event;
    event.feature = "FALLBACK";
    event.file = file;
    event.function = "";
    event.reason = reason;
    event.isStub = true;
    event.line = line;
    event.timestamp = now;
    
    // Invoke callback if set
    if (m_eventCallback) {
        m_eventCallback(event);
    }
    
    // Enforce policy
    EnforcePolicy(event);
    
    // Log based on policy
    if (m_policy != FMFPolicy::SILENT) {
#ifdef IDELOGGER_H
        if (g_ideLogger) {
            char buffer[512];
            snprintf(buffer, sizeof(buffer), "[FMF] FALLBACK: %s (%s:%u)", 
                     reason, file, line);
            g_ideLogger->LogWarning(buffer);
        }
#else
        fprintf(stderr, "[FMF] FALLBACK: %s (%s:%u)\n", reason, file, line);
#endif
    }
}

void FailureModeFirewall::ReportRealExecution(const char* feature, const char* file, const char* function) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto now = std::chrono::steady_clock::now();
    
    // Update feature state
    auto& state = m_features[feature];
    state.hasRealSymbol = true;
    state.realCallCount++;
    state.lastRealCall = now;
    
    m_totalRealCalls++;
    
    // Log in debug mode
    if (m_policy == FMFPolicy::WARN) {
#ifdef IDELOGGER_H
        if (g_ideLogger) {
            char buffer[512];
            snprintf(buffer, sizeof(buffer), "[FMF] REAL: %s in %s", feature, function);
            g_ideLogger->LogDebug(buffer);
        }
#else
        fprintf(stderr, "[FMF] REAL: %s in %s\n", feature, function);
#endif
    }
}

void FailureModeFirewall::RegisterFeature(const char* feature, bool declared, bool hasRealSymbol, bool stubbed) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto& state = m_features[feature];
    state.declared = declared;
    state.hasRealSymbol = hasRealSymbol;
    state.stubbed = stubbed;
}

bool FailureModeFirewall::IsFeatureReal(const char* feature) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_features.find(feature);
    if (it == m_features.end()) {
        return false;
    }
    
    // Feature is "real" if it has a real symbol AND has been called at least once
    return it->second.hasRealSymbol && it->second.realCallCount.load() > 0;
}

const FeatureRuntimeState* FailureModeFirewall::GetFeatureState(const char* feature) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_features.find(feature);
    if (it == m_features.end()) {
        return nullptr;
    }
    
    return &it->second;
}

uint32_t FailureModeFirewall::GetStubCallCount(const char* feature) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_features.find(feature);
    if (it == m_features.end()) {
        return 0;
    }
    
    return it->second.stubCallCount.load();
}

uint32_t FailureModeFirewall::GetRealCallCount(const char* feature) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_features.find(feature);
    if (it == m_features.end()) {
        return 0;
    }
    
    return it->second.realCallCount.load();
}

void FailureModeFirewall::GetAllFeatureStats(std::unordered_map<std::string, FeatureRuntimeState>& outStats) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Copy each feature state, converting atomics to regular values
    for (const auto& kv : m_features) {
        const std::string& name = kv.first;
        const FeatureRuntimeState& state = kv.second;
        
        FeatureRuntimeState copy;
        copy.declared = state.declared;
        copy.hasRealSymbol = state.hasRealSymbol;
        copy.stubbed = state.stubbed;
        copy.stubCallCount.store(state.stubCallCount.load());
        copy.realCallCount.store(state.realCallCount.load());
        copy.lastStubCall = state.lastStubCall;
        copy.lastRealCall = state.lastRealCall;
        
        outStats[name] = std::move(copy);
    }
}

void FailureModeFirewall::SetEventCallback(FMFEventCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_eventCallback = std::move(callback);
}

void FailureModeFirewall::SetReportCallback(FMFReportCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_reportCallback = std::move(callback);
}

void FailureModeFirewall::EnforcePolicy(const FMFEvent& event) {
    if (m_policy == FMFPolicy::BLOCK && event.isStub) {
        // In BLOCK mode, halt execution on stub call
        char buffer[512];
        snprintf(buffer, sizeof(buffer), 
                 "[FMF] BLOCKED: Stub execution detected for feature '%s'\n"
                 "File: %s\nFunction: %s\nLine: %u\n"
                 "Change FMF policy to WARN or SILENT to allow stub execution.",
                 event.feature, event.file, event.function, event.line);
        
#ifdef IDELOGGER_H
        if (g_ideLogger) {
            g_ideLogger->LogError(buffer);
        }
#else
        fprintf(stderr, "%s\n", buffer);
#endif
        
        // Trigger debug break in debug builds
        #ifdef _DEBUG
        DebugBreak();
        #else
        // In release, we still halt but more gracefully
        std::terminate();
        #endif
    }
}

void FailureModeFirewall::DumpReport() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::ostringstream oss;
    oss << "\n=== FMF Runtime Report ===\n";
    oss << "Policy: " << (m_policy == FMFPolicy::SILENT ? "SILENT" : 
                        m_policy == FMFPolicy::WARN ? "WARN" : "BLOCK") << "\n";
    oss << "Total Stub Calls: " << m_totalStubCalls.load() << "\n";
    oss << "Total Real Calls: " << m_totalRealCalls.load() << "\n";
    oss << "\nFeature Breakdown:\n";
    oss << std::left << std::setw(30) << "Feature" 
        << std::setw(10) << "Declared" 
        << std::setw(10) << "Real" 
        << std::setw(10) << "Stubbed" 
        << std::setw(12) << "StubCalls" 
        << std::setw(12) << "RealCalls" 
        << "Risk\n";
    oss << std::string(94, '-') << "\n";
    
    for (const auto& [name, state] : m_features) {
        std::string risk = "OK";
        if (state.stubbed && state.stubCallCount.load() > 0 && state.realCallCount.load() == 0) {
            risk = "CRITICAL";
        } else if (state.stubbed && state.stubCallCount.load() > 0) {
            risk = "HIGH";
        } else if (state.stubbed && state.realCallCount.load() > 0) {
            risk = "MEDIUM";
        }
        
        oss << std::left << std::setw(30) << name
            << std::setw(10) << (state.declared ? "YES" : "NO")
            << std::setw(10) << (state.hasRealSymbol ? "YES" : "NO")
            << std::setw(10) << (state.stubbed ? "YES" : "NO")
            << std::setw(12) << state.stubCallCount.load()
            << std::setw(12) << state.realCallCount.load()
            << risk << "\n";
    }
    
    oss << "\n=== End Report ===\n";
    
#ifdef IDELOGGER_H
    if (g_ideLogger) {
        g_ideLogger->LogInfo(oss.str().c_str());
    }
#else
    fprintf(stderr, "%s\n", oss.str().c_str());
#endif
}

void FailureModeFirewall::ExportReport(const char* filepath) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::ofstream file(filepath);
    if (!file.is_open()) {
#ifdef IDELOGGER_H
        if (g_ideLogger) {
            g_ideLogger->LogError("[FMF] Failed to open export file");
        }
#else
        fprintf(stderr, "[FMF] Failed to open export file: %s\n", filepath);
#endif
        return;
    }
    
    // JSON format for machine parsing
    file << "{\n";
    file << "  \"policy\": \"" << (m_policy == FMFPolicy::SILENT ? "SILENT" : 
                                    m_policy == FMFPolicy::WARN ? "WARN" : "BLOCK") << "\",\n";
    file << "  \"totalStubCalls\": " << m_totalStubCalls.load() << ",\n";
    file << "  \"totalRealCalls\": " << m_totalRealCalls.load() << ",\n";
    file << "  \"features\": {\n";
    
    bool first = true;
    for (const auto& [name, state] : m_features) {
        if (!first) file << ",\n";
        first = false;
        
        file << "    \"" << name << "\": {\n";
        file << "      \"declared\": " << (state.declared ? "true" : "false") << ",\n";
        file << "      \"hasRealSymbol\": " << (state.hasRealSymbol ? "true" : "false") << ",\n";
        file << "      \"stubbed\": " << (state.stubbed ? "true" : "false") << ",\n";
        file << "      \"stubCallCount\": " << state.stubCallCount.load() << ",\n";
        file << "      \"realCallCount\": " << state.realCallCount.load() << "\n";
        file << "    }";
    }
    
    file << "\n  }\n";
    file << "}\n";
    
    file.close();
    
#ifdef IDELOGGER_H
    if (g_ideLogger) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "[FMF] Report exported to %s", filepath);
        g_ideLogger->LogInfo(buffer);
    }
#else
    fprintf(stderr, "[FMF] Report exported to %s\n", filepath);
#endif
}

void FailureModeFirewall::Reset() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_features.clear();
    m_totalStubCalls = 0;
    m_totalRealCalls = 0;
}

// Policy guard implementation
FMFPolicyGuard::FMFPolicyGuard(FMFPolicy tempPolicy) 
    : m_previousPolicy(FailureModeFirewall::Instance().GetPolicy()) {
    FailureModeFirewall::Instance().SetPolicy(tempPolicy);
}

FMFPolicyGuard::~FMFPolicyGuard() {
    FailureModeFirewall::Instance().SetPolicy(m_previousPolicy);
}