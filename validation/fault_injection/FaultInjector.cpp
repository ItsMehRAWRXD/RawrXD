// ============================================================================
// FaultInjector.cpp — Base Fault Injection Implementation
// ============================================================================

#include "FaultInjector.hpp"
#include <iomanip>
#include <sstream>
#include <random>

namespace RawrXD {
namespace Validation {

// ============================================================================
// FaultManifest Implementation
// ============================================================================
FaultManifest::FaultManifest(const std::string& id, FaultType t, FaultSeverity s,
                               const std::string& component, const std::string& recovery)
    : faultId(id), type(t), severity(s), targetComponent(component), expectedRecovery(recovery) {
    
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");
    timestamp = ss.str();
}

nlohmann::json FaultManifest::toJson() const {
    nlohmann::json j;
    j["fault_id"] = faultId;
    j["type"] = FaultTypeToString(type);
    j["severity"] = FaultSeverityToString(severity);
    j["timestamp"] = timestamp;
    j["target_component"] = targetComponent;
    j["expected_recovery"] = expectedRecovery;
    j["description"] = description;
    j["parameters"] = parameters;
    return j;
}

FaultManifest FaultManifest::fromJson(const nlohmann::json& j) {
    FaultManifest manifest;
    manifest.faultId = j.value("fault_id", "");
    manifest.type = FaultTypeFromString(j.value("type", "UNKNOWN"));
    manifest.severity = FaultSeverityFromString(j.value("severity", "LOW"));
    manifest.timestamp = j.value("timestamp", "");
    manifest.targetComponent = j.value("target_component", "");
    manifest.expectedRecovery = j.value("expected_recovery", "");
    manifest.description = j.value("description", "");
    manifest.parameters = j.value("parameters", nlohmann::json::object());
    return manifest;
}

std::string FaultManifest::generateFilename() const {
    std::string safeId = faultId;
    // Replace special characters
    for (auto& c : safeId) {
        if (c == ':' || c == '/' || c == '\\') c = '_';
    }
    return "fault_" + safeId + "_" + timestamp.substr(0, 10) + ".json";
}

// ============================================================================
// FaultInjectionResult Implementation
// ============================================================================
nlohmann::json FaultInjectionResult::toJson() const {
    nlohmann::json j;
    j["success"] = success;
    j["fault_id"] = faultId;
    j["injection_time_ms"] = injectionTime.count();
    j["error_message"] = errorMessage;
    j["telemetry"] = telemetry;
    return j;
}

// ============================================================================
// FaultInjector Base Implementation
// ============================================================================
std::string FaultInjector::generateFaultId(const std::string& prefix) {
    static std::atomic<uint64_t> counter{0};
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    static thread_local std::uniform_int_distribution<> dis(1000, 9999);
    
    std::stringstream ss;
    ss << "FAULT-" << prefix << "-" << std::setfill('0') << std::setw(4) << (++counter)
       << "-" << dis(gen);
    return ss.str();
}

void FaultInjector::notifyPreInjection(const FaultManifest& manifest) {
    if (m_preCallback) {
        m_preCallback(manifest);
    }
}

void FaultInjector::notifyPostInjection(const FaultManifest& manifest, const FaultInjectionResult& result) {
    if (m_postCallback) {
        m_postCallback(manifest, result);
    }
}

// ============================================================================
// FaultInjectionStats Implementation
// ============================================================================
nlohmann::json FaultInjectionStats::toJson() const {
    nlohmann::json j;
    j["total_injected"] = totalInjected.load();
    j["successful_injections"] = successfulInjections.load();
    j["failed_injections"] = failedInjections.load();
    j["recoveries_detected"] = recoveriesDetected.load();
    j["recoveries_successful"] = recoveriesSuccessful.load();
    return j;
}

void FaultInjectionStats::reset() {
    totalInjected.store(0);
    successfulInjections.store(0);
    failedInjections.store(0);
    recoveriesDetected.store(0);
    recoveriesSuccessful.store(0);
}

// ============================================================================
// FaultInjectionRegistry Implementation
// ============================================================================
FaultInjectionRegistry& FaultInjectionRegistry::instance() {
    static FaultInjectionRegistry instance;
    return instance;
}

void FaultInjectionRegistry::registerInjector(std::shared_ptr<FaultInjector> injector) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (injector) {
        m_injectors[injector->getName()] = injector;
    }
}

void FaultInjectionRegistry::unregisterInjector(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_injectors.erase(name);
}

std::shared_ptr<FaultInjector> FaultInjectionRegistry::getInjector(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_injectors.find(name);
    if (it != m_injectors.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::shared_ptr<FaultInjector>> FaultInjectionRegistry::getAllInjectors() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::shared_ptr<FaultInjector>> result;
    for (const auto& pair : m_injectors) {
        result.push_back(pair.second);
    }
    return result;
}

std::vector<std::shared_ptr<FaultInjector>> FaultInjectionRegistry::getInjectorsByType(FaultType type) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::shared_ptr<FaultInjector>> result;
    for (const auto& pair : m_injectors) {
        if (pair.second->getType() == type) {
            result.push_back(pair.second);
        }
    }
    return result;
}

// ============================================================================
// Utility Functions
// ============================================================================
const char* FaultTypeToString(FaultType type) {
    switch (type) {
        case FaultType::THREAD_TERMINATION: return "THREAD_TERMINATION";
        case FaultType::MEMORY_EXHAUSTION: return "MEMORY_EXHAUSTION";
        case FaultType::SERVICE_KILL: return "SERVICE_KILL";
        case FaultType::STATE_CORRUPTION: return "STATE_CORRUPTION";
        case FaultType::EXCEPTION_STORM: return "EXCEPTION_STORM";
        case FaultType::RESOURCE_LEAK: return "RESOURCE_LEAK";
        case FaultType::DEADLOCK: return "DEADLOCK";
        case FaultType::NETWORK_PARTITION: return "NETWORK_PARTITION";
        default: return "UNKNOWN";
    }
}

const char* FaultSeverityToString(FaultSeverity severity) {
    switch (severity) {
        case FaultSeverity::LOW: return "LOW";
        case FaultSeverity::MEDIUM: return "MEDIUM";
        case FaultSeverity::HIGH: return "HIGH";
        case FaultSeverity::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

FaultType FaultTypeFromString(const std::string& str) {
    if (str == "THREAD_TERMINATION") return FaultType::THREAD_TERMINATION;
    if (str == "MEMORY_EXHAUSTION") return FaultType::MEMORY_EXHAUSTION;
    if (str == "SERVICE_KILL") return FaultType::SERVICE_KILL;
    if (str == "STATE_CORRUPTION") return FaultType::STATE_CORRUPTION;
    if (str == "EXCEPTION_STORM") return FaultType::EXCEPTION_STORM;
    if (str == "RESOURCE_LEAK") return FaultType::RESOURCE_LEAK;
    if (str == "DEADLOCK") return FaultType::DEADLOCK;
    if (str == "NETWORK_PARTITION") return FaultType::NETWORK_PARTITION;
    return FaultType::UNKNOWN;
}

FaultSeverity FaultSeverityFromString(const std::string& str) {
    if (str == "LOW") return FaultSeverity::LOW;
    if (str == "MEDIUM") return FaultSeverity::MEDIUM;
    if (str == "HIGH") return FaultSeverity::HIGH;
    if (str == "CRITICAL") return FaultSeverity::CRITICAL;
    return FaultSeverity::LOW;
}

} // namespace Validation
} // namespace RawrXD