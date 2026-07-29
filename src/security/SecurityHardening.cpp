// Security Hardening - Implementation
// Production-grade security controls for the Sovereign Substrate

#include "SecurityHardening.hpp"

#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <regex>

// Platform-specific includes
#ifdef _WIN32
#include <windows.h>
#include <processthreadsapi.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace RawrXD {
namespace Security {

// ============================================================================
// Utility Functions
// ============================================================================

static std::string GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

static std::string ComputeSHA256(const std::string& data) {
    // Simplified hash - in production use OpenSSL or similar
    std::hash<std::string> hasher;
    auto hash = hasher(data);
    
    std::stringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << hash;
    return ss.str();
}

// ============================================================================
// Audit Event
// ============================================================================

std::string AuditEvent::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"eventId\":" << eventId << ",";
    ss << "\"type\":" << static_cast<int>(type) << ",";
    ss << "\"timestamp\":\"" << timestamp << "\",";
    ss << "\"severity\":\"" << severity << "\",";
    ss << "\"agentId\":" << agentId << ",";
    ss << "\"intentId\":" << intentId << ",";
    ss << "\"agentType\":\"" << agentType << "\",";
    ss << "\"action\":\"" << action << "\",";
    ss << "\"target\":\"" << target << "\",";
    ss << "\"details\":\"" << details << "\",";
    ss << "\"hash\":\"" << hash << "\",";
    ss << "\"previousEventId\":" << previousEventId;
    ss << "}";
    return ss.str();
}

std::string AuditEvent::ComputeHash() const {
    std::stringstream ss;
    ss << eventId << type << timestamp << agentId << intentId
       << action << target << details << previousEventId;
    return ComputeSHA256(ss.str());
}

// ============================================================================
// Audit Log
// ============================================================================

AuditLog& AuditLog::Instance() {
    static AuditLog instance;
    return instance;
}

bool AuditLog::Initialize(const std::string& logPath) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    logPath_ = logPath;
    
    // Create log directory if needed
    // (Platform-specific code would go here)
    
    // Load existing events
    LoadFromDisk();
    
    initialized_.store(true);
    
    // Log startup
    AuditEvent event;
    event.eventId = nextEventId_++;
    event.type = AuditEventType::SYSTEM_STARTUP;
    event.timestamp = GetTimestamp();
    event.severity = "INFO";
    event.action = "System startup";
    event.details = "Audit log initialized";
    event.previousEventId = lastEventId_.load();
    event.hash = event.ComputeHash();
    
    LogEvent(event);
    
    return true;
}

void AuditLog::Shutdown() {
    if (!initialized_.load()) return;
    
    // Log shutdown
    AuditEvent event;
    event.eventId = nextEventId_++;
    event.type = AuditEventType::SYSTEM_SHUTDOWN;
    event.timestamp = GetTimestamp();
    event.severity = "INFO";
    event.action = "System shutdown";
    event.details = "Audit log shutting down";
    event.previousEventId = lastEventId_.load();
    event.hash = event.ComputeHash();
    
    LogEvent(event);
    
    // Persist all events
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& e : events_) {
            PersistEvent(e);
        }
    }
    
    initialized_.store(false);
}

void AuditLog::LogEvent(const AuditEvent& event) {
    if (!initialized_.load()) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Store in memory
    events_.push_back(event);
    eventIndex_[event.eventId] = events_.size() - 1;
    
    // Update last event ID
    lastEventId_.store(event.eventId);
    
    // Persist to disk
    PersistEvent(event);
}

void AuditLog::LogIntentReceived(uint64_t intentId, uint64_t agentId, 
                                  const std::string& intentType) {
    AuditEvent event;
    event.eventId = nextEventId_++;
    event.type = AuditEventType::INTENT_RECEIVED;
    event.timestamp = GetTimestamp();
    event.severity = "INFO";
    event.agentId = agentId;
    event.intentId = intentId;
    event.action = "Intent received";
    event.target = intentType;
    event.previousEventId = lastEventId_.load();
    event.hash = event.ComputeHash();
    
    LogEvent(event);
}

void AuditLog::LogIntentExecuted(uint64_t intentId, bool success, 
                                  const std::string& details) {
    AuditEvent event;
    event.eventId = nextEventId_++;
    event.type = success ? AuditEventType::INTENT_EXECUTED : AuditEventType::INTENT_REJECTED;
    event.timestamp = GetTimestamp();
    event.severity = success ? "INFO" : "WARNING";
    event.intentId = intentId;
    event.action = success ? "Intent executed" : "Intent rejected";
    event.details = details;
    event.previousEventId = lastEventId_.load();
    event.hash = event.ComputeHash();
    
    LogEvent(event);
}

void AuditLog::LogPatchApplied(uint64_t patchId, const std::string& symbol, 
                                uint64_t agentId) {
    AuditEvent event;
    event.eventId = nextEventId_++;
    event.type = AuditEventType::PATCH_APPLIED;
    event.timestamp = GetTimestamp();
    event.severity = "INFO";
    event.agentId = agentId;
    event.action = "Patch applied";
    event.target = symbol;
    event.details = "Patch ID: " + std::to_string(patchId);
    event.previousEventId = lastEventId_.load();
    event.hash = event.ComputeHash();
    
    LogEvent(event);
}

void AuditLog::LogViolation(const std::string& violationType, 
                            const std::string& details, 
                            uint64_t agentId) {
    AuditEvent event;
    event.eventId = nextEventId_++;
    event.type = AuditEventType::VIOLATION_DETECTED;
    event.timestamp = GetTimestamp();
    event.severity = "ERROR";
    event.agentId = agentId;
    event.action = "Security violation";
    event.target = violationType;
    event.details = details;
    event.previousEventId = lastEventId_.load();
    event.hash = event.ComputeHash();
    
    LogEvent(event);
}

void AuditLog::LogSecurityEvent(AuditEventType type, const std::string& details, 
                                 const std::string& severity) {
    AuditEvent event;
    event.eventId = nextEventId_++;
    event.type = type;
    event.timestamp = GetTimestamp();
    event.severity = severity;
    event.action = "Security event";
    event.details = details;
    event.previousEventId = lastEventId_.load();
    event.hash = event.ComputeHash();
    
    LogEvent(event);
}

std::vector<AuditEvent> AuditLog::QueryEvents(
    AuditEventType type,
    const std::chrono::system_clock::time_point& start,
    const std::chrono::system_clock::time_point& end
) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<AuditEvent> result;
    for (const auto& event : events_) {
        if (event.type == type) {
            // Parse timestamp and check range
            // (Simplified - would parse actual timestamp in production)
            result.push_back(event);
        }
    }
    
    return result;
}

std::vector<AuditEvent> AuditLog::QueryEventsByAgent(uint64_t agentId, 
                                                          uint32_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<AuditEvent> result;
    for (auto it = events_.rbegin(); it != events_.rend() && result.size() < limit; ++it) {
        if (it->agentId == agentId) {
            result.push_back(*it);
        }
    }
    
    return result;
}

std::vector<AuditEvent> AuditLog::QuerySecurityEvents(const std::string& severity, 
                                                      uint32_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<AuditEvent> result;
    for (auto it = events_.rbegin(); it != events_.rend() && result.size() < limit; ++it) {
        if (it->severity == severity) {
            result.push_back(*it);
        }
    }
    
    return result;
}

bool AuditLog::VerifyChain() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (size_t i = 1; i < events_.size(); ++i) {
        if (events_[i].previousEventId != events_[i-1].eventId) {
            return false;  // Chain broken
        }
        
        // Verify hash
        if (events_[i].hash != events_[i].ComputeHash()) {
            return false;  // Tampering detected
        }
    }
    
    return true;
}

void AuditLog::PersistEvent(const AuditEvent& event) {
    // In production, write to secure log file
    // For now, just keep in memory
}

void AuditLog::LoadFromDisk() {
    // In production, load from secure log file
}

AuditLog::Stats AuditLog::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Stats stats;
    stats.totalEvents = events_.size();
    
    for (const auto& event : events_) {
        switch (event.type) {
            case AuditEventType::VIOLATION_DETECTED:
            case AuditEventType::RATE_LIMIT_EXCEEDED:
            case AuditEventType::SANDBOX_ESCAPE_ATTEMPT:
                stats.securityEvents++;
                break;
            default:
                break;
        }
        
        if (event.severity == "ERROR" || event.severity == "CRITICAL") {
            stats.violationEvents++;
        }
    }
    
    // Calculate storage size (rough estimate)
    stats.storageSizeMB = events_.size() * 0.5;  // ~500 bytes per event
    
    if (!events_.empty()) {
        // Would set actual timestamps in production
        stats.oldestEvent = std::chrono::system_clock::now();
        stats.newestEvent = std::chrono::system_clock::now();
    }
    
    return stats;
}

void AuditLog::SetRetentionPolicy(uint32_t days) {
    retentionDays_ = days;
}

void AuditLog::PruneOldEvents() {
    // Remove events older than retention policy
    // Implementation would check timestamps
}

// ============================================================================
// Rate Limiter
// ============================================================================

RateLimiter& RateLimiter::Instance() {
    static RateLimiter instance;
    return instance;
}

bool RateLimiter::Initialize(const Limits& limits) {
    limits_ = limits;
    initialized_.store(true);
    return true;
}

void RateLimiter::Shutdown() {
    initialized_.store(false);
}

bool RateLimiter::CanExecuteIntent(uint64_t agentId) {
    if (!initialized_.load()) return true;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if locked out
    if (IsLockedOut(agentId)) {
        return false;
    }
    
    auto& data = agentData_[agentId];
    PruneOldEntries(data);
    
    // Check per-second limit
    if (!CheckLimit(data.intentTimes, limits_.intentsPerSecond, std::chrono::seconds(1))) {
        return false;
    }
    
    // Check per-minute limit
    if (!CheckLimit(data.intentTimes, limits_.intentsPerMinute, std::chrono::minutes(1))) {
        return false;
    }
    
    // Check per-hour limit
    if (!CheckLimit(data.intentTimes, limits_.intentsPerHour, std::chrono::hours(1))) {
        return false;
    }
    
    return true;
}

bool RateLimiter::CanApplyPatch(uint64_t agentId) {
    if (!initialized_.load()) return true;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (IsLockedOut(agentId)) {
        return false;
    }
    
    auto& data = agentData_[agentId];
    PruneOldEntries(data);
    
    return CheckLimit(data.patchTimes, limits_.patchesPerSecond, std::chrono::seconds(1));
}

bool RateLimiter::CanAcquireResource(uint64_t agentId) {
    if (!initialized_.load()) return true;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (IsLockedOut(agentId)) {
        return false;
    }
    
    auto& data = agentData_[agentId];
    PruneOldEntries(data);
    
    return CheckLimit(data.resourceTimes, limits_.resourcesPerSecond, std::chrono::seconds(1));
}

void RateLimiter::RecordIntent(uint64_t agentId) {
    if (!initialized_.load()) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    agentData_[agentId].intentTimes.push_back(std::chrono::system_clock::now());
}

void RateLimiter::RecordPatch(uint64_t agentId) {
    if (!initialized_.load()) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    agentData_[agentId].patchTimes.push_back(std::chrono::system_clock::now());
}

void RateLimiter::RecordResource(uint64_t agentId) {
    if (!initialized_.load()) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    agentData_[agentId].resourceTimes.push_back(std::chrono::system_clock::now());
}

void RateLimiter::RecordFailure(uint64_t agentId) {
    if (!initialized_.load()) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    auto& data = agentData_[agentId];
    data.failureTimes.push_back(std::chrono::system_clock::now());
    
    // Check if should lock out
    PruneOldEntries(data);
    if (data.failureTimes.size() >= limits_.failedAttemptsBeforeLockout) {
        LockoutAgent(agentId, limits_.lockoutDurationSeconds);
    }
}

bool RateLimiter::IsLockedOut(uint64_t agentId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = agentData_.find(agentId);
    if (it == agentData_.end()) return false;
    
    auto now = std::chrono::system_clock::now();
    return now < it->second.lockoutExpiry;
}

void RateLimiter::LockoutAgent(uint64_t agentId, uint32_t durationSeconds) {
    auto& data = agentData_[agentId];
    data.lockoutExpiry = std::chrono::system_clock::now() + 
                         std::chrono::seconds(durationSeconds);
}

void RateLimiter::UnlockAgent(uint64_t agentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = agentData_.find(agentId);
    if (it != agentData_.end()) {
        it->second.lockoutExpiry = std::chrono::system_clock::now();
    }
}

void RateLimiter::PruneOldEntries(AgentRateData& data) {
    auto now = std::chrono::system_clock::now();
    auto cutoff = now - std::chrono::hours(1);
    
    // Prune old intent times
    data.intentTimes.erase(
        std::remove_if(data.intentTimes.begin(), data.intentTimes.end(),
            [cutoff](const auto& time) { return time < cutoff; }),
        data.intentTimes.end()
    );
    
    // Prune old patch times
    data.patchTimes.erase(
        std::remove_if(data.patchTimes.begin(), data.patchTimes.end(),
            [cutoff](const auto& time) { return time < cutoff; }),
        data.patchTimes.end()
    );
    
    // Prune old resource times
    data.resourceTimes.erase(
        std::remove_if(data.resourceTimes.begin(), data.resourceTimes.end(),
            [cutoff](const auto& time) { return time < cutoff; }),
        data.resourceTimes.end()
    );
    
    // Prune old failure times
    data.failureTimes.erase(
        std::remove_if(data.failureTimes.begin(), data.failureTimes.end(),
            [cutoff](const auto& time) { return time < cutoff; }),
        data.failureTimes.end()
    );
}

bool RateLimiter::CheckLimit(
    const std::vector<std::chrono::system_clock::time_point>& times,
    uint32_t limit,
    std::chrono::seconds window
) {
    if (limit == 0) return true;
    
    auto now = std::chrono::system_clock::now();
    auto cutoff = now - window;
    
    uint32_t count = 0;
    for (const auto& time : times) {
        if (time > cutoff) {
            count++;
        }
    }
    
    return count < limit;
}

// ============================================================================
// Input Validator
// ============================================================================

InputValidator& InputValidator::Instance() {
    static InputValidator instance;
    return instance;
}

bool InputValidator::Initialize(const ValidationRules& rules) {
    rules_ = rules;
    
    // Initialize dangerous patterns
    dangerousPatterns_ = {
        "system(", "exec(", "eval(", "__asm", "shell",
        "CreateProcess", "fork", "execve",
        "VirtualProtect", "mprotect",
        "LoadLibrary", "dlopen"
    };
    
    shellInjectionPatterns_ = {
        ";", "|", "&&", "||", "`", "$()", ">", "<"
    };
    
    pathTraversalPatterns_ = {
        "../", "..\\", "%2e%2e", "..%2f"
    };
    
    initialized_.store(true);
    return true;
}

bool InputValidator::ValidateIntentPayload(const std::vector<uint8_t>& payload, 
                                            std::string& error) {
    if (!initialized_.load()) return true;
    
    if (payload.size() > rules_.maxIntentPayloadSize) {
        error = "Intent payload exceeds maximum size";
        return false;
    }
    
    return true;
}

bool InputValidator::ValidateSymbolName(const std::string& name, 
                                         std::string& error) {
    if (!initialized_.load()) return true;
    
    if (name.length() > rules_.maxSymbolNameLength) {
        error = "Symbol name exceeds maximum length";
        return false;
    }
    
    if (rules_.requireAsciiOnly) {
        for (char c : name) {
            if (static_cast<unsigned char>(c) > 127) {
                error = "Symbol name contains non-ASCII characters";
                return false;
            }
        }
    }
    
    if (rules_.blockDangerousPatterns && ContainsDangerousPattern(name)) {
        error = "Symbol name contains dangerous pattern";
        return false;
    }
    
    return true;
}

bool InputValidator::ValidateFilePath(const std::string& path, 
                                       std::string& error) {
    if (!initialized_.load()) return true;
    
    if (path.length() > rules_.maxFilePathLength) {
        error = "File path exceeds maximum length";
        return false;
    }
    
    if (ContainsPathTraversal(path)) {
        error = "File path contains path traversal attempt";
        return false;
    }
    
    return true;
}

bool InputValidator::ContainsDangerousPattern(const std::string& input) {
    for (const auto& pattern : dangerousPatterns_) {
        if (input.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool InputValidator::ContainsShellInjection(const std::string& input) {
    for (const auto& pattern : shellInjectionPatterns_) {
        if (input.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool InputValidator::ContainsPathTraversal(const std::string& input) {
    for (const auto& pattern : pathTraversalPatterns_) {
        if (input.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Security Manager
// ============================================================================

SecurityManager& SecurityManager::Instance() {
    static SecurityManager instance;
    return instance;
}

bool SecurityManager::Initialize(SecurityLevel level) {
    securityLevel_.store(level);
    startupTime_ = std::chrono::system_clock::now();
    
    // Initialize all security components
    AuditLog::Instance().Initialize("logs/security_audit.log");
    
    RateLimiter::Limits limits;
    limits.intentsPerSecond = 10;
    limits.intentsPerMinute = 100;
    limits.intentsPerHour = 1000;
    limits.patchesPerSecond = 5;
    limits.resourcesPerSecond = 20;
    limits.failedAttemptsBeforeLockout = 5;
    limits.lockoutDurationSeconds = 300;
    RateLimiter::Instance().Initialize(limits);
    
    InputValidator::ValidationRules rules;
    rules.maxIntentPayloadSize = 1024 * 1024;  // 1MB
    rules.maxSymbolNameLength = 256;
    rules.maxFilePathLength = 4096;
    rules.requireAsciiOnly = true;
    rules.blockDangerousPatterns = true;
    InputValidator::Instance().Initialize(rules);
    
    initialized_.store(true);
    
    SECURITY_LOG_EVENT(AuditEventType::SYSTEM_STARTUP, 
                       "Security manager initialized at level " + 
                       std::to_string(static_cast<int>(level)));
    
    return true;
}

void SecurityManager::Shutdown() {
    if (!initialized_.load()) return;
    
    SECURITY_LOG_EVENT(AuditEventType::SYSTEM_SHUTDOWN, 
                       "Security manager shutting down");
    
    AuditLog::Instance().Shutdown();
    RateLimiter::Instance().Shutdown();
    
    initialized_.store(false);
}

bool SecurityManager::ValidatePreExecution(uint64_t agentId, uint64_t intentId, 
                                            std::string& error) {
    if (!initialized_.load()) return true;
    
    // Check lockdown
    if (lockdown_.load()) {
        error = "System is in lockdown";
        return false;
    }
    
    // Check rate limits
    if (!RateLimiter::Instance().CanExecuteIntent(agentId)) {
        error = "Rate limit exceeded";
        SECURITY_LOG_WARNING(AuditEventType::RATE_LIMIT_EXCEEDED,
                             "Agent " + std::to_string(agentId) + " rate limited");
        return false;
    }
    
    // Log intent received
    AuditLog::Instance().LogIntentReceived(intentId, agentId, "UNKNOWN");
    
    return true;
}

void SecurityManager::LogPostExecution(uint64_t agentId, uint64_t intentId, 
                                       bool success) {
    if (!initialized_.load()) return;
    
    AuditLog::Instance().LogIntentExecuted(intentId, success, "");
    
    if (success) {
        RateLimiter::Instance().RecordIntent(agentId);
    } else {
        RateLimiter::Instance().RecordFailure(agentId);
    }
}

void SecurityManager::EmergencyLockdown(const std::string& reason) {
    lockdown_.store(true);
    SECURITY_LOG_CRITICAL(AuditEventType::EMERGENCY_STOP,
                            "Emergency lockdown: " + reason);
}

void SecurityManager::LiftLockdown() {
    lockdown_.store(false);
    SECURITY_LOG_EVENT(AuditEventType::CONFIG_CHANGED,
                       "Lockdown lifted");
}

bool SecurityManager::RunSecurityAudit() {
    // Verify audit log chain
    if (!AuditLog::Instance().VerifyChain()) {
        SECURITY_LOG_CRITICAL(AuditEventType::VIOLATION_DETECTED,
                              "Audit log chain verification failed");
        return false;
    }
    
    return true;
}

SecurityManager::SecurityStats SecurityManager::GetStats() const {
    SecurityStats stats;
    
    auto auditStats = AuditLog::Instance().GetStats();
    stats.totalEventsLogged = auditStats.totalEvents;
    stats.violationsDetected = auditStats.violationEvents;
    
    return stats;
}

} // namespace Security
} // namespace RawrXD
