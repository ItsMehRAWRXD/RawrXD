// ============================================================================
// FailureEvent.cpp — Failure Event Implementation
// ============================================================================

#include "reliability/FailureEvent.hpp"
#include <sstream>
#include <iomanip>
#include <random>

namespace RawrXD {
namespace Reliability {

// ============================================================================
// Failure Severity Conversions
// ============================================================================
const char* FailureSeverityToString(FailureSeverity severity) {
    switch (severity) {
        case FailureSeverity::DEBUG: return "DEBUG";
        case FailureSeverity::WARNING: return "WARNING";
        case FailureSeverity::ERROR: return "ERROR";
        case FailureSeverity::CRITICAL: return "CRITICAL";
        case FailureSeverity::FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

FailureSeverity FailureSeverityFromString(const std::string& str) {
    if (str == "DEBUG") return FailureSeverity::DEBUG;
    if (str == "WARNING") return FailureSeverity::WARNING;
    if (str == "ERROR") return FailureSeverity::ERROR;
    if (str == "CRITICAL") return FailureSeverity::CRITICAL;
    if (str == "FATAL") return FailureSeverity::FATAL;
    return FailureSeverity::DEBUG;
}

// ============================================================================
// Failure Category Conversions
// ============================================================================
const char* FailureCategoryToString(FailureCategory category) {
    switch (category) {
        case FailureCategory::THREAD_TERMINATION: return "THREAD_TERMINATION";
        case FailureCategory::PROCESS_CRASH: return "PROCESS_CRASH";
        case FailureCategory::DEADLOCK: return "DEADLOCK";
        case FailureCategory::STARVATION: return "STARVATION";
        case FailureCategory::MEMORY_EXHAUSTION: return "MEMORY_EXHAUSTION";
        case FailureCategory::MEMORY_CORRUPTION: return "MEMORY_CORRUPTION";
        case FailureCategory::HANDLE_LEAK: return "HANDLE_LEAK";
        case FailureCategory::DISK_FULL: return "DISK_FULL";
        case FailureCategory::SERVICE_UNRESPONSIVE: return "SERVICE_UNRESPONSIVE";
        case FailureCategory::SERVICE_UNAVAILABLE: return "SERVICE_UNAVAILABLE";
        case FailureCategory::DEPENDENCY_FAILURE: return "DEPENDENCY_FAILURE";
        case FailureCategory::TIMEOUT: return "TIMEOUT";
        case FailureCategory::STATE_CORRUPTION: return "STATE_CORRUPTION";
        case FailureCategory::INVALID_CHECKSUM: return "INVALID_CHECKSUM";
        case FailureCategory::VERSION_MISMATCH: return "VERSION_MISMATCH";
        case FailureCategory::CONFIGURATION_ERROR: return "CONFIGURATION_ERROR";
        case FailureCategory::EXCEPTION_THROWN: return "EXCEPTION_THROWN";
        case FailureCategory::ASSERTION_FAILURE: return "ASSERTION_FAILURE";
        case FailureCategory::INFINITE_LOOP: return "INFINITE_LOOP";
        case FailureCategory::STACK_OVERFLOW: return "STACK_OVERFLOW";
        case FailureCategory::NETWORK_PARTITION: return "NETWORK_PARTITION";
        case FailureCategory::GPU_ERROR: return "GPU_ERROR";
        case FailureCategory::DRIVER_FAILURE: return "DRIVER_FAILURE";
        default: return "UNKNOWN";
    }
}

FailureCategory FailureCategoryFromString(const std::string& str) {
    if (str == "THREAD_TERMINATION") return FailureCategory::THREAD_TERMINATION;
    if (str == "PROCESS_CRASH") return FailureCategory::PROCESS_CRASH;
    if (str == "DEADLOCK") return FailureCategory::DEADLOCK;
    if (str == "STARVATION") return FailureCategory::STARVATION;
    if (str == "MEMORY_EXHAUSTION") return FailureCategory::MEMORY_EXHAUSTION;
    if (str == "MEMORY_CORRUPTION") return FailureCategory::MEMORY_CORRUPTION;
    if (str == "HANDLE_LEAK") return FailureCategory::HANDLE_LEAK;
    if (str == "DISK_FULL") return FailureCategory::DISK_FULL;
    if (str == "SERVICE_UNRESPONSIVE") return FailureCategory::SERVICE_UNRESPONSIVE;
    if (str == "SERVICE_UNAVAILABLE") return FailureCategory::SERVICE_UNAVAILABLE;
    if (str == "DEPENDENCY_FAILURE") return FailureCategory::DEPENDENCY_FAILURE;
    if (str == "TIMEOUT") return FailureCategory::TIMEOUT;
    if (str == "STATE_CORRUPTION") return FailureCategory::STATE_CORRUPTION;
    if (str == "INVALID_CHECKSUM") return FailureCategory::INVALID_CHECKSUM;
    if (str == "VERSION_MISMATCH") return FailureCategory::VERSION_MISMATCH;
    if (str == "CONFIGURATION_ERROR") return FailureCategory::CONFIGURATION_ERROR;
    if (str == "EXCEPTION_THROWN") return FailureCategory::EXCEPTION_THROWN;
    if (str == "ASSERTION_FAILURE") return FailureCategory::ASSERTION_FAILURE;
    if (str == "INFINITE_LOOP") return FailureCategory::INFINITE_LOOP;
    if (str == "STACK_OVERFLOW") return FailureCategory::STACK_OVERFLOW;
    if (str == "NETWORK_PARTITION") return FailureCategory::NETWORK_PARTITION;
    if (str == "GPU_ERROR") return FailureCategory::GPU_ERROR;
    if (str == "DRIVER_FAILURE") return FailureCategory::DRIVER_FAILURE;
    return FailureCategory::UNKNOWN;
}

// ============================================================================
// Failure Event Implementation
// ============================================================================
FailureEvent::FailureEvent() 
    : category(FailureCategory::UNKNOWN)
    , severity(FailureSeverity::DEBUG)
    , timestamp(std::chrono::steady_clock::now())
    , detectionTime(std::chrono::steady_clock::now()) {
    eventId = generateEventId();
}

FailureEvent::FailureEvent(FailureCategory cat, FailureSeverity sev,
                            const std::string& component, const std::string& msg)
    : category(cat)
    , severity(sev)
    , sourceComponent(component)
    , message(msg)
    , timestamp(std::chrono::steady_clock::now())
    , detectionTime(std::chrono::steady_clock::now()) {
    eventId = generateEventId();
}

std::string FailureEvent::generateEventId() {
    static std::atomic<uint64_t> counter{0};
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    static thread_local std::uniform_int_distribution<> dis(1000, 9999);
    
    std::stringstream ss;
    ss << "FAIL-" << std::setfill('0') << std::setw(8) << (++counter)
       << "-" << dis(gen);
    return ss.str();
}

uint64_t FailureEvent::detectionLatencyMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        detectionTime - timestamp).count();
}

bool FailureEvent::isRecoverable() const {
    return autoRecoverable && severity < FailureSeverity::FATAL;
}

nlohmann::json FailureEvent::toJson() const {
    nlohmann::json j;
    j["event_id"] = eventId;
    j["correlation_id"] = correlationId;
    j["parent_event_id"] = parentEventId;
    j["category"] = FailureCategoryToString(category);
    j["severity"] = FailureSeverityToString(severity);
    j["type"] = type;
    j["source_component"] = sourceComponent;
    j["source_location"] = sourceLocation;
    j["target_resource"] = targetResource;
    j["message"] = message;
    j["stack_trace"] = stackTrace;
    j["context"] = context;
    j["memory_usage_bytes"] = memoryUsageBytes;
    j["thread_count"] = threadCount;
    j["process_state"] = processState;
    j["suggested_strategies"] = suggestedStrategies;
    j["auto_recoverable"] = autoRecoverable;
    j["max_recovery_attempts"] = maxRecoveryAttempts;
    return j;
}

FailureEvent FailureEvent::fromJson(const nlohmann::json& j) {
    FailureEvent event;
    event.eventId = j.value("event_id", "");
    event.correlationId = j.value("correlation_id", "");
    event.parentEventId = j.value("parent_event_id", "");
    event.category = FailureCategoryFromString(j.value("category", "UNKNOWN"));
    event.severity = FailureSeverityFromString(j.value("severity", "DEBUG"));
    event.type = j.value("type", "");
    event.sourceComponent = j.value("source_component", "");
    event.sourceLocation = j.value("source_location", "");
    event.targetResource = j.value("target_resource", "");
    event.message = j.value("message", "");
    event.stackTrace = j.value("stack_trace", "");
    event.context = j.value("context", nlohmann::json::object());
    event.memoryUsageBytes = j.value("memory_usage_bytes", 0);
    event.threadCount = j.value("thread_count", 0);
    event.processState = j.value("process_state", "");
    event.suggestedStrategies = j.value("suggested_strategies", nlohmann::json::array()).get<std::vector<std::string>>();
    event.autoRecoverable = j.value("auto_recoverable", false);
    event.maxRecoveryAttempts = j.value("max_recovery_attempts", 3);
    return event;
}

// ============================================================================
// Failure Event Builder
// ============================================================================
FailureEventBuilder::FailureEventBuilder(FailureCategory category, FailureSeverity severity) {
    m_event.category = category;
    m_event.severity = severity;
    m_event.timestamp = std::chrono::steady_clock::now();
    m_event.detectionTime = std::chrono::steady_clock::now();
}

FailureEventBuilder& FailureEventBuilder::component(const std::string& name) {
    m_event.sourceComponent = name;
    return *this;
}

FailureEventBuilder& FailureEventBuilder::message(const std::string& msg) {
    m_event.message = msg;
    return *this;
}

FailureEventBuilder& FailureEventBuilder::location(const std::string& file, int line) {
    m_event.sourceLocation = file + ":" + std::to_string(line);
    return *this;
}

FailureEventBuilder& FailureEventBuilder::target(const std::string& resource) {
    m_event.targetResource = resource;
    return *this;
}

FailureEventBuilder& FailureEventBuilder::context(const nlohmann::json& ctx) {
    m_event.context = ctx;
    return *this;
}

FailureEventBuilder& FailureEventBuilder::suggestedStrategy(const std::string& strategy) {
    m_event.suggestedStrategies.push_back(strategy);
    return *this;
}

FailureEventBuilder& FailureEventBuilder::autoRecoverable(bool enabled) {
    m_event.autoRecoverable = enabled;
    return *this;
}

FailureEventBuilder& FailureEventBuilder::maxAttempts(int attempts) {
    m_event.maxRecoveryAttempts = attempts;
    return *this;
}

FailureEventBuilder& FailureEventBuilder::correlation(const std::string& correlationId) {
    m_event.correlationId = correlationId;
    return *this;
}

FailureEventBuilder& FailureEventBuilder::parent(const std::string& parentEventId) {
    m_event.parentEventId = parentEventId;
    return *this;
}

FailureEvent FailureEventBuilder::build() {
    m_event.eventId = m_event.generateEventId();
    return m_event;
}

// ============================================================================
// Failure Filter
// ============================================================================
bool FailureFilter::matches(const FailureEvent& event) const {
    if (!categories.empty()) {
        bool catMatch = false;
        for (const auto& cat : categories) {
            if (cat == event.category) {
                catMatch = true;
                break;
            }
        }
        if (!catMatch) return false;
    }
    
    if (!severities.empty()) {
        bool sevMatch = false;
        for (const auto& sev : severities) {
            if (sev == event.severity) {
                sevMatch = true;
                break;
            }
        }
        if (!sevMatch) return false;
    }
    
    if (!components.empty()) {
        bool compMatch = false;
        for (const auto& comp : components) {
            if (event.sourceComponent.find(comp) != std::string::npos) {
                compMatch = true;
                break;
            }
        }
        if (!compMatch) return false;
    }
    
    if (customPredicate && !customPredicate(event)) {
        return false;
    }
    
    return true;
}

bool FailureFilter::isEmpty() const {
    return categories.empty() && severities.empty() && components.empty() && !customPredicate;
}

} // namespace Reliability
} // namespace RawrXD
