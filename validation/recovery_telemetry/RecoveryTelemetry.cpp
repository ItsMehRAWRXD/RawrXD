// ============================================================================
// RecoveryTelemetry.cpp — Recovery Telemetry Implementation
// ============================================================================

#include "RecoveryTelemetry.hpp"
#include "../fault_injection/FaultInjector.hpp"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <random>

namespace RawrXD {
namespace Validation {

// ============================================================================
// Recovery Event Implementation
// ============================================================================
RecoveryEvent::RecoveryEvent(RecoveryEventType t, const std::string& fid, const std::string& strat)
    : type(t), faultId(fid), strategy(strat) {
    
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");
    timestamp = ss.str();
}

nlohmann::json RecoveryEvent::toJson() const {
    nlohmann::json j;
    j["event_id"] = eventId;
    j["type"] = RecoveryEventTypeToString(type);
    j["timestamp"] = timestamp;
    j["fault_id"] = faultId;
    j["strategy"] = strategy;
    j["trigger"] = trigger;
    j["detection_latency_ms"] = detectionLatencyMs;
    j["recovery_latency_ms"] = recoveryLatencyMs;
    j["total_latency_ms"] = totalLatencyMs;
    j["success"] = success;
    j["error_message"] = errorMessage;
    j["retry_count"] = retryCount;
    j["max_retries"] = maxRetries;
    j["context"] = context;
    j["source_component"] = sourceComponent;
    j["target_component"] = targetComponent;
    return j;
}

RecoveryEvent RecoveryEvent::fromJson(const nlohmann::json& j) {
    RecoveryEvent event;
    event.eventId = j.value("event_id", "");
    event.type = RecoveryEventTypeFromString(j.value("type", "UNKNOWN"));
    event.timestamp = j.value("timestamp", "");
    event.faultId = j.value("fault_id", "");
    event.strategy = j.value("strategy", "");
    event.trigger = j.value("trigger", "");
    event.detectionLatencyMs = j.value("detection_latency_ms", 0);
    event.recoveryLatencyMs = j.value("recovery_latency_ms", 0);
    event.totalLatencyMs = j.value("total_latency_ms", 0);
    event.success = j.value("success", false);
    event.errorMessage = j.value("error_message", "");
    event.retryCount = j.value("retry_count", 0);
    event.maxRetries = j.value("max_retries", 3);
    event.context = j.value("context", nlohmann::json::object());
    event.sourceComponent = j.value("source_component", "");
    event.targetComponent = j.value("target_component", "");
    return event;
}

// ============================================================================
// Recovery Metrics Implementation
// ============================================================================
double RecoveryMetrics::getMTTD() const {
    uint64_t total = totalFaultsDetected.load();
    if (total == 0) return 0.0;
    return static_cast<double>(totalDetectionLatencyMs.load()) / static_cast<double>(total);
}

double RecoveryMetrics::getMTTR() const {
    uint64_t total = totalRecoveriesInitiated.load();
    if (total == 0) return 0.0;
    return static_cast<double>(totalRecoveryLatencyMs.load()) / static_cast<double>(total);
}

double RecoveryMetrics::getSuccessRate() const {
    uint64_t total = totalRecoveriesInitiated.load();
    if (total == 0) return 0.0;
    return static_cast<double>(totalRecoveriesSuccessful.load()) / static_cast<double>(total);
}

double RecoveryMetrics::getFalsePositiveRate() const {
    uint64_t total = truePositiveDetections.load() + falsePositiveDetections.load();
    if (total == 0) return 0.0;
    return static_cast<double>(falsePositiveDetections.load()) / static_cast<double>(total);
}

nlohmann::json RecoveryMetrics::toJson() const {
    nlohmann::json j;
    
    // Counters
    j["total_faults_detected"] = totalFaultsDetected.load();
    j["total_recoveries_initiated"] = totalRecoveriesInitiated.load();
    j["total_recoveries_successful"] = totalRecoveriesSuccessful.load();
    j["total_recoveries_failed"] = totalRecoveriesFailed.load();
    j["total_escalations"] = totalEscalations.load();
    j["total_rollbacks"] = totalRollbacks.load();
    
    // Latency metrics
    j["mttd_ms"] = getMTTD();
    j["mttr_ms"] = getMTTR();
    j["min_detection_latency_ms"] = minDetectionLatencyMs.load();
    j["max_detection_latency_ms"] = maxDetectionLatencyMs.load();
    j["min_recovery_latency_ms"] = minRecoveryLatencyMs.load();
    j["max_recovery_latency_ms"] = maxRecoveryLatencyMs.load();
    
    // Consecutive failures
    j["current_consecutive_failures"] = currentConsecutiveFailures.load();
    j["max_consecutive_failures"] = maxConsecutiveFailures.load();
    
    // False positive tracking
    j["false_positive_detections"] = falsePositiveDetections.load();
    j["true_positive_detections"] = truePositiveDetections.load();
    j["false_positive_rate"] = getFalsePositiveRate();
    
    // Success rate
    j["success_rate"] = getSuccessRate();
    
    // Strategy-specific metrics
    {
        std::lock_guard<std::mutex> lock(strategyMutex);
        nlohmann::json strategies;
        for (const auto& pair : strategySuccessCounts) {
            nlohmann::json strat;
            strat["success_count"] = pair.second;
            auto failIt = strategyFailureCounts.find(pair.first);
            strat["failure_count"] = (failIt != strategyFailureCounts.end()) ? failIt->second : 0;
            strategies[pair.first] = strat;
        }
        j["strategy_metrics"] = strategies;
    }
    
    return j;
}

void RecoveryMetrics::reset() {
    totalFaultsDetected.store(0);
    totalRecoveriesInitiated.store(0);
    totalRecoveriesSuccessful.store(0);
    totalRecoveriesFailed.store(0);
    totalEscalations.store(0);
    totalRollbacks.store(0);
    totalDetectionLatencyMs.store(0);
    totalRecoveryLatencyMs.store(0);
    minDetectionLatencyMs.store(UINT64_MAX);
    maxDetectionLatencyMs.store(0);
    minRecoveryLatencyMs.store(UINT64_MAX);
    maxRecoveryLatencyMs.store(0);
    currentConsecutiveFailures.store(0);
    maxConsecutiveFailures.store(0);
    falsePositiveDetections.store(0);
    truePositiveDetections.store(0);
    
    std::lock_guard<std::mutex> lock(strategyMutex);
    strategySuccessCounts.clear();
    strategyFailureCounts.clear();
}

// ============================================================================
// Recovery Telemetry Collector Implementation
// ============================================================================
RecoveryTelemetryCollector& RecoveryTelemetryCollector::instance() {
    static RecoveryTelemetryCollector instance;
    return instance;
}

void RecoveryTelemetryCollector::recordEvent(const RecoveryEvent& event) {
    RecoveryEvent eventWithId = event;
    if (eventWithId.eventId.empty()) {
        eventWithId.eventId = generateEventId();
    }
    
    {
        std::lock_guard<std::mutex> lock(m_eventsMutex);
        m_events.push_back(eventWithId);
        if (m_events.size() > MAX_EVENTS) {
            m_events.pop_front();
        }
    }
    
    updateMetrics(eventWithId);
    
    if (m_eventCallback) {
        m_eventCallback(eventWithId);
    }
    
    // Also log to file
    RecoveryTelemetryLogger::instance().logEvent(eventWithId);
}

void RecoveryTelemetryCollector::recordFaultDetected(const std::string& faultId, 
                                                      const std::string& trigger,
                                                      uint64_t detectionLatencyMs) {
    RecoveryEvent event(RecoveryEventType::FAULT_DETECTED, faultId, "");
    event.trigger = trigger;
    event.detectionLatencyMs = detectionLatencyMs;
    event.success = true;
    recordEvent(event);
}

void RecoveryTelemetryCollector::recordRecoveryInitiated(const std::string& faultId,
                                                          const std::string& strategy) {
    RecoveryEvent event(RecoveryEventType::RECOVERY_INITIATED, faultId, strategy);
    recordEvent(event);
}

void RecoveryTelemetryCollector::recordRecoveryCompleted(const std::string& faultId,
                                                          bool success,
                                                          uint64_t recoveryLatencyMs,
                                                          int retryCount) {
    RecoveryEvent event(RecoveryEventType::RECOVERY_COMPLETED, faultId, "");
    event.success = success;
    event.recoveryLatencyMs = recoveryLatencyMs;
    event.retryCount = retryCount;
    event.totalLatencyMs = event.detectionLatencyMs + recoveryLatencyMs;
    recordEvent(event);
}

void RecoveryTelemetryCollector::recordEscalation(const std::string& faultId,
                                                     const std::string& reason) {
    RecoveryEvent event(RecoveryEventType::ESCALATION_TRIGGERED, faultId, "");
    event.errorMessage = reason;
    recordEvent(event);
}

std::vector<RecoveryEvent> RecoveryTelemetryCollector::getRecentEvents(size_t count) const {
    std::lock_guard<std::mutex> lock(m_eventsMutex);
    std::vector<RecoveryEvent> result;
    size_t start = (m_events.size() > count) ? m_events.size() - count : 0;
    for (size_t i = start; i < m_events.size(); ++i) {
        result.push_back(m_events[i]);
    }
    return result;
}

std::vector<RecoveryEvent> RecoveryTelemetryCollector::getEventsByType(RecoveryEventType type) const {
    std::lock_guard<std::mutex> lock(m_eventsMutex);
    std::vector<RecoveryEvent> result;
    for (const auto& event : m_events) {
        if (event.type == type) {
            result.push_back(event);
        }
    }
    return result;
}

std::vector<RecoveryEvent> RecoveryTelemetryCollector::getEventsForFault(const std::string& faultId) const {
    std::lock_guard<std::mutex> lock(m_eventsMutex);
    std::vector<RecoveryEvent> result;
    for (const auto& event : m_events) {
        if (event.faultId == faultId) {
            result.push_back(event);
        }
    }
    return result;
}

RecoveryEvent RecoveryTelemetryCollector::getLastEvent() const {
    std::lock_guard<std::mutex> lock(m_eventsMutex);
    if (m_events.empty()) {
        return RecoveryEvent();
    }
    return m_events.back();
}

nlohmann::json RecoveryTelemetryCollector::exportEvents() const {
    std::lock_guard<std::mutex> lock(m_eventsMutex);
    nlohmann::json j = nlohmann::json::array();
    for (const auto& event : m_events) {
        j.push_back(event.toJson());
    }
    return j;
}

nlohmann::json RecoveryTelemetryCollector::exportMetrics() const {
    std::lock_guard<std::mutex> lock(m_metricsMutex);
    return m_metrics.toJson();
}

nlohmann::json RecoveryTelemetryCollector::exportFullReport() const {
    nlohmann::json report;
    report["timestamp"] = []() {
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");
        return ss.str();
    }();
    report["metrics"] = exportMetrics();
    report["events"] = exportEvents();
    return report;
}

bool RecoveryTelemetryCollector::saveToFile(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        return false;
    }
    file << exportFullReport().dump(2);
    return file.good();
}

bool RecoveryTelemetryCollector::loadFromFile(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return false;
    }
    
    try {
        nlohmann::json j;
        file >> j;
        
        // Load events
        if (j.contains("events")) {
            std::lock_guard<std::mutex> lock(m_eventsMutex);
            m_events.clear();
            for (const auto& eventJson : j["events"]) {
                m_events.push_back(RecoveryEvent::fromJson(eventJson));
            }
        }
        
        // Metrics would need to be recalculated from events
        return true;
    } catch (...) {
        return false;
    }
}

void RecoveryTelemetryCollector::reset() {
    {
        std::lock_guard<std::mutex> lock(m_eventsMutex);
        m_events.clear();
    }
    {
        std::lock_guard<std::mutex> lock(m_metricsMutex);
        m_metrics.reset();
    }
}

std::string RecoveryTelemetryCollector::generateEventId() {
    static std::atomic<uint64_t> counter{0};
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    static thread_local std::uniform_int_distribution<> dis(1000, 9999);
    
    std::stringstream ss;
    ss << "EVT-" << std::setfill('0') << std::setw(6) << (++counter)
       << "-" << dis(gen);
    return ss.str();
}

void RecoveryTelemetryCollector::updateMetrics(const RecoveryEvent& event) {
    std::lock_guard<std::mutex> lock(m_metricsMutex);
    
    switch (event.type) {
        case RecoveryEventType::FAULT_DETECTED:
            m_metrics.totalFaultsDetected++;
            m_metrics.totalDetectionLatencyMs += event.detectionLatencyMs;
            m_metrics.minDetectionLatencyMs.store(
                std::min(m_metrics.minDetectionLatencyMs.load(), event.detectionLatencyMs));
            m_metrics.maxDetectionLatencyMs.store(
                std::max(m_metrics.maxDetectionLatencyMs.load(), event.detectionLatencyMs));
            break;
            
        case RecoveryEventType::RECOVERY_INITIATED:
            m_metrics.totalRecoveriesInitiated++;
            break;
            
        case RecoveryEventType::RECOVERY_COMPLETED:
            if (event.success) {
                m_metrics.totalRecoveriesSuccessful++;
                m_metrics.currentConsecutiveFailures.store(0);
            } else {
                m_metrics.totalRecoveriesFailed++;
                m_metrics.currentConsecutiveFailures++;
                m_metrics.maxConsecutiveFailures.store(
                    std::max(m_metrics.maxConsecutiveFailures.load(), 
                            m_metrics.currentConsecutiveFailures.load()));
            }
            m_metrics.totalRecoveryLatencyMs += event.recoveryLatencyMs;
            m_metrics.minRecoveryLatencyMs.store(
                std::min(m_metrics.minRecoveryLatencyMs.load(), event.recoveryLatencyMs));
            m_metrics.maxRecoveryLatencyMs.store(
                std::max(m_metrics.maxRecoveryLatencyMs.load(), event.recoveryLatencyMs));
            
            // Update strategy metrics
            if (!event.strategy.empty()) {
                if (event.success) {
                    m_metrics.strategySuccessCounts[event.strategy]++;
                } else {
                    m_metrics.strategyFailureCounts[event.strategy]++;
                }
            }
            break;
            
        case RecoveryEventType::ESCALATION_TRIGGERED:
            m_metrics.totalEscalations++;
            break;
            
        case RecoveryEventType::ROLLBACK_COMPLETED:
            m_metrics.totalRollbacks++;
            break;
            
        default:
            break;
    }
}

// ============================================================================
// Recovery Telemetry Logger Implementation
// ============================================================================
RecoveryTelemetryLogger& RecoveryTelemetryLogger::instance() {
    static RecoveryTelemetryLogger instance;
    return instance;
}

void RecoveryTelemetryLogger::initialize(const std::string& logDir) {
    m_logDir = logDir;
    m_currentLogFile = generateLogFilename();
    ensureLogOpen();
    m_initialized.store(true);
}

void RecoveryTelemetryLogger::shutdown() {
    std::lock_guard<std::mutex> lock(m_logMutex);
    if (m_logStream.is_open()) {
        m_logStream.close();
    }
    m_initialized.store(false);
}

void RecoveryTelemetryLogger::logEvent(const RecoveryEvent& event) {
    if (!m_initialized.load()) return;
    
    std::lock_guard<std::mutex> lock(m_logMutex);
    ensureLogOpen();
    
    if (m_logStream.is_open()) {
        m_logStream << event.toJson().dump() << std::endl;
    }
}

void RecoveryTelemetryLogger::logMetrics(const RecoveryMetrics& metrics) {
    if (!m_initialized.load()) return;
    
    std::lock_guard<std::mutex> lock(m_logMutex);
    ensureLogOpen();
    
    if (m_logStream.is_open()) {
        m_logStream << "{\"type\":\"METRICS\",\"data\":" << metrics.toJson().dump() << "}" << std::endl;
    }
}

void RecoveryTelemetryLogger::logFaultManifest(const FaultManifest& manifest) {
    if (!m_initialized.load()) return;
    
    std::lock_guard<std::mutex> lock(m_logMutex);
    ensureLogOpen();
    
    if (m_logStream.is_open()) {
        m_logStream << "{\"type\":\"FAULT_MANIFEST\",\"data\":" << manifest.toJson().dump() << "}" << std::endl;
    }
}

void RecoveryTelemetryLogger::rotateLogs() {
    std::lock_guard<std::mutex> lock(m_logMutex);
    if (m_logStream.is_open()) {
        m_logStream.close();
    }
    m_currentLogFile = generateLogFilename();
    ensureLogOpen();
}

void RecoveryTelemetryLogger::ensureLogOpen() {
    if (!m_logStream.is_open()) {
        m_logStream.open(m_currentLogFile, std::ios::app);
    }
}

std::string RecoveryTelemetryLogger::generateLogFilename() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << m_logDir << "/recovery_telemetry_"
       << std::put_time(std::gmtime(&time_t_now), "%Y%m%d_%H%M%S")
       << ".jsonl";
    return ss.str();
}

// ============================================================================
// Utility Functions
// ============================================================================
const char* RecoveryEventTypeToString(RecoveryEventType type) {
    switch (type) {
        case RecoveryEventType::FAULT_DETECTED: return "FAULT_DETECTED";
        case RecoveryEventType::RECOVERY_INITIATED: return "RECOVERY_INITIATED";
        case RecoveryEventType::RECOVERY_STEP_STARTED: return "RECOVERY_STEP_STARTED";
        case RecoveryEventType::RECOVERY_STEP_COMPLETED: return "RECOVERY_STEP_COMPLETED";
        case RecoveryEventType::RECOVERY_STEP_FAILED: return "RECOVERY_STEP_FAILED";
        case RecoveryEventType::RECOVERY_COMPLETED: return "RECOVERY_COMPLETED";
        case RecoveryEventType::RECOVERY_FAILED: return "RECOVERY_FAILED";
        case RecoveryEventType::ROLLBACK_INITIATED: return "ROLLBACK_INITIATED";
        case RecoveryEventType::ROLLBACK_COMPLETED: return "ROLLBACK_COMPLETED";
        case RecoveryEventType::SERVICE_RESTARTED: return "SERVICE_RESTARTED";
        case RecoveryEventType::CACHE_CLEARED: return "CACHE_CLEARED";
        case RecoveryEventType::ESCALATION_TRIGGERED: return "ESCALATION_TRIGGERED";
        default: return "UNKNOWN";
    }
}

RecoveryEventType RecoveryEventTypeFromString(const std::string& str) {
    if (str == "FAULT_DETECTED") return RecoveryEventType::FAULT_DETECTED;
    if (str == "RECOVERY_INITIATED") return RecoveryEventType::RECOVERY_INITIATED;
    if (str == "RECOVERY_STEP_STARTED") return RecoveryEventType::RECOVERY_STEP_STARTED;
    if (str == "RECOVERY_STEP_COMPLETED") return RecoveryEventType::RECOVERY_STEP_COMPLETED;
    if (str == "RECOVERY_STEP_FAILED") return RecoveryEventType::RECOVERY_STEP_FAILED;
    if (str == "RECOVERY_COMPLETED") return RecoveryEventType::RECOVERY_COMPLETED;
    if (str == "RECOVERY_FAILED") return RecoveryEventType::RECOVERY_FAILED;
    if (str == "ROLLBACK_INITIATED") return RecoveryEventType::ROLLBACK_INITIATED;
    if (str == "ROLLBACK_COMPLETED") return RecoveryEventType::ROLLBACK_COMPLETED;
    if (str == "SERVICE_RESTARTED") return RecoveryEventType::SERVICE_RESTARTED;
    if (str == "CACHE_CLEARED") return RecoveryEventType::CACHE_CLEARED;
    if (str == "ESCALATION_TRIGGERED") return RecoveryEventType::ESCALATION_TRIGGERED;
    return RecoveryEventType::UNKNOWN;
}

} // namespace Validation
} // namespace RawrXD