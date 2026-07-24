// Security Hardening - Production-Grade Security Controls
//
// Critical protections for a self-modifying system:
// - Sandboxing: Isolate agent execution
// - Audit Logging: Complete trace of all actions
// - Rate Limiting: Prevent abuse
// - Input Validation: Sanitize all inputs
// - Memory Protection: Secure memory handling
// - Privilege Separation: Least-privilege execution

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>

namespace RawrXD {
namespace Security {

// Forward declarations
class Sandbox;
class AuditLog;
class RateLimiter;
class InputValidator;
class MemoryGuard;
class PrivilegeManager;

// ============================================================================
// Security Levels - Defense in depth
// ============================================================================

enum class SecurityLevel : uint32_t {
    NONE = 0,           // No security (emergency only)
    MINIMAL = 1,        // Basic checks
    STANDARD = 2,       // Production default
    HIGH = 3,           // Enhanced security
    MAXIMUM = 4         // Maximum protection
};

// ============================================================================
// Audit Event - Complete trace of system actions
// ============================================================================

enum class AuditEventType : uint32_t {
    // Intent events
    INTENT_RECEIVED = 0,
    INTENT_VALIDATED = 1,
    INTENT_REJECTED = 2,
    INTENT_EXECUTED = 3,
    INTENT_ROLLED_BACK = 4,
    
    // Patch events
    PATCH_CREATED = 10,
    PATCH_VALIDATED = 11,
    PATCH_APPLIED = 12,
    PATCH_ROLLED_BACK = 13,
    PATCH_BLOCKED = 14,
    
    // Resource events
    RESOURCE_ACQUIRED = 20,
    RESOURCE_RELEASED = 21,
    RESOURCE_REVOKED = 22,
    RESOURCE_CONTENTION = 23,
    
    // Security events
    VIOLATION_DETECTED = 30,
    RATE_LIMIT_EXCEEDED = 31,
    SANDBOX_ESCAPE_ATTEMPT = 32,
    PRIVILEGE_ESCALATION = 33,
    MEMORY_VIOLATION = 34,
    
    // System events
    SYSTEM_STARTUP = 40,
    SYSTEM_SHUTDOWN = 41,
    EMERGENCY_STOP = 42,
    CONFIG_CHANGED = 43,
    
    // Authentication events
    AGENT_REGISTERED = 50,
    AGENT_REVOKED = 51,
    TOKEN_ISSUED = 52,
    TOKEN_REVOKED = 53,
    
    // Custom
    CUSTOM = 100
};

struct AuditEvent {
    uint64_t eventId;
    AuditEventType type;
    std::string timestamp;
    std::string severity;       // "INFO", "WARNING", "ERROR", "CRITICAL"
    
    // Actor
    uint64_t agentId;
    uint64_t intentId;
    std::string agentType;
    
    // Action details
    std::string action;
    std::string target;
    std::string details;
    
    // Context
    std::string sourceIp;       // For remote agents
    std::string sessionId;
    std::unordered_map<std::string, std::string> metadata;
    
    // Integrity
    std::string hash;           // SHA256 of event data
    uint64_t previousEventId;   // Chain for tamper detection
    
    std::string ToJson() const;
    std::string ComputeHash() const;
};

// ============================================================================
// Audit Log - Tamper-evident logging
// ============================================================================

class AuditLog {
public:
    static AuditLog& Instance();
    
    // Lifecycle
    bool Initialize(const std::string& logPath);
    void Shutdown();
    bool IsInitialized() const { return initialized_.load(); }
    
    // Logging
    void LogEvent(const AuditEvent& event);
    void LogIntentReceived(uint64_t intentId, uint64_t agentId, const std::string& intentType);
    void LogIntentExecuted(uint64_t intentId, bool success, const std::string& details);
    void LogPatchApplied(uint64_t patchId, const std::string& symbol, uint64_t agentId);
    void LogViolation(const std::string& violationType, const std::string& details, uint64_t agentId);
    void LogSecurityEvent(AuditEventType type, const std::string& details, const std::string& severity);
    
    // Query
    std::vector<AuditEvent> QueryEvents(
        AuditEventType type,
        const std::chrono::system_clock::time_point& start,
        const std::chrono::system_clock::time_point& end
    ) const;
    std::vector<AuditEvent> QueryEventsByAgent(uint64_t agentId, uint32_t limit = 100) const;
    std::vector<AuditEvent> QuerySecurityEvents(const std::string& severity, uint32_t limit = 100) const;
    
    // Integrity
    bool VerifyChain() const;           // Verify hash chain integrity
    bool ExportToFile(const std::string& path) const;
    bool ImportFromFile(const std::string& path);
    
    // Statistics
    struct Stats {
        uint64_t totalEvents;
        uint64_t securityEvents;
        uint64_t violationEvents;
        uint64_t intentEvents;
        uint64_t patchEvents;
        double storageSizeMB;
        std::chrono::system_clock::time_point oldestEvent;
        std::chrono::system_clock::time_point newestEvent;
    };
    Stats GetStats() const;
    
    // Retention
    void SetRetentionPolicy(uint32_t days);
    void PruneOldEvents();

private:
    AuditLog() = default;
    
    std::atomic<bool> initialized_{false};
    std::string logPath_;
    std::atomic<uint64_t> nextEventId_{1};
    std::atomic<uint64_t> lastEventId_{0};
    
    mutable std::mutex mutex_;
    std::vector<AuditEvent> events_;        // In-memory cache
    std::unordered_map<uint64_t, size_t> eventIndex_;  // eventId -> index
    
    uint32_t retentionDays_{90};
    
    void PersistEvent(const AuditEvent& event);
    void LoadFromDisk();
};

// ============================================================================
// Rate Limiter - Prevent abuse
// ============================================================================

class RateLimiter {
public:
    static RateLimiter& Instance();
    
    // Configuration
    struct Limits {
        uint32_t intentsPerSecond;
        uint32_t intentsPerMinute;
        uint32_t intentsPerHour;
        uint32_t patchesPerSecond;
        uint32_t resourcesPerSecond;
        uint32_t failedAttemptsBeforeLockout;
        uint32_t lockoutDurationSeconds;
    };
    
    bool Initialize(const Limits& limits);
    void Shutdown();
    
    // Check limits
    bool CanExecuteIntent(uint64_t agentId);
    bool CanApplyPatch(uint64_t agentId);
    bool CanAcquireResource(uint64_t agentId);
    
    // Record usage
    void RecordIntent(uint64_t agentId);
    void RecordPatch(uint64_t agentId);
    void RecordResource(uint64_t agentId);
    void RecordFailure(uint64_t agentId);
    
    // Lockout
    bool IsLockedOut(uint64_t agentId) const;
    void LockoutAgent(uint64_t agentId, uint32_t durationSeconds);
    void UnlockAgent(uint64_t agentId);
    
    // Statistics
    struct AgentStats {
        uint32_t intentsLastSecond;
        uint32_t intentsLastMinute;
        uint32_t intentsLastHour;
        uint32_t totalFailures;
        bool isLockedOut;
        std::chrono::system_clock::time_point lockoutExpiry;
    };
    AgentStats GetAgentStats(uint64_t agentId) const;

private:
    RateLimiter() = default;
    
    struct AgentRateData {
        std::vector<std::chrono::system_clock::time_point> intentTimes;
        std::vector<std::chrono::system_clock::time_point> patchTimes;
        std::vector<std::chrono::system_clock::time_point> resourceTimes;
        std::vector<std::chrono::system_clock::time_point> failureTimes;
        std::chrono::system_clock::time_point lockoutExpiry;
    };
    
    std::atomic<bool> initialized_{false};
    Limits limits_;
    
    mutable std::mutex mutex_;
    std::unordered_map<uint64_t, AgentRateData> agentData_;
    
    void PruneOldEntries(AgentRateData& data);
    bool CheckLimit(const std::vector<std::chrono::system_clock::time_point>& times, 
                    uint32_t limit, 
                    std::chrono::seconds window);
};

// ============================================================================
// Input Validator - Sanitize all inputs
// ============================================================================

class InputValidator {
public:
    static InputValidator& Instance();
    
    // Validation rules
    struct ValidationRules {
        uint32_t maxIntentPayloadSize;
        uint32_t maxSymbolNameLength;
        uint32_t maxFilePathLength;
        bool requireAsciiOnly;
        bool blockDangerousPatterns;
        std::unordered_set<std::string> blockedPatterns;
    };
    
    bool Initialize(const ValidationRules& rules);
    
    // Validation methods
    bool ValidateIntentPayload(const std::vector<uint8_t>& payload, std::string& error);
    bool ValidateSymbolName(const std::string& name, std::string& error);
    bool ValidateFilePath(const std::string& path, std::string& error);
    bool ValidatePatchData(const std::vector<uint8_t>& data, std::string& error);
    bool ValidateModelOutput(const std::string& output, std::string& error);
    
    // Sanitization
    std::string SanitizeSymbolName(const std::string& name);
    std::string SanitizeFilePath(const std::string& path);
    std::vector<uint8_t> SanitizePatchData(const std::vector<uint8_t>& data);
    
    // Dangerous pattern detection
    bool ContainsDangerousPattern(const std::string& input);
    bool ContainsShellInjection(const std::string& input);
    bool ContainsPathTraversal(const std::string& input);
    bool ContainsMemoryUnsafeCode(const std::vector<uint8_t>& code);

private:
    InputValidator() = default;
    
    std::atomic<bool> initialized_{false};
    ValidationRules rules_;
    
    std::unordered_set<std::string> dangerousPatterns_;
    std::unordered_set<std::string> shellInjectionPatterns_;
    std::unordered_set<std::string> pathTraversalPatterns_;
};

// ============================================================================
// Memory Guard - Secure memory handling
// ============================================================================

class MemoryGuard {
public:
    static MemoryGuard& Instance();
    
    // Memory protection
    bool ProtectRegion(void* address, size_t size, uint32_t protection);
    bool UnprotectRegion(void* address, size_t size);
    bool IsRegionProtected(void* address) const;
    
    // Secure allocation
    void* SecureAllocate(size_t size);
    void SecureFree(void* address, size_t size);
    void SecureZero(void* address, size_t size);
    
    // Stack protection
    bool EnableStackProtection();
    bool EnableHeapProtection();
    
    // ASLR (Address Space Layout Randomization)
    bool EnableASLR();
    
    // DEP (Data Execution Prevention)
    bool EnableDEP();
    
    // Canary values
    bool VerifyStackCanary();
    void SetStackCanary();
    
    // Statistics
    struct Stats {
        size_t protectedRegions;
        size_t secureAllocations;
        size_t totalProtectedMemory;
        size_t violationsDetected;
    };
    Stats GetStats() const;

private:
    MemoryGuard() = default;
    
    struct ProtectedRegion {
        void* address;
        size_t size;
        uint32_t originalProtection;
    };
    
    mutable std::mutex mutex_;
    std::unordered_map<void*, ProtectedRegion> protectedRegions_;
    
    std::atomic<size_t> secureAllocations_{0};
    std::atomic<size_t> violationsDetected_{0};
};

// ============================================================================
// Privilege Manager - Least-privilege execution
// ============================================================================

class PrivilegeManager {
public:
    static PrivilegeManager& Instance();
    
    // Privilege levels
    enum class PrivilegeLevel : uint32_t {
        UNTRUSTED = 0,      // Unknown/untrusted code
        RESTRICTED = 1,     // Sandboxed agent
        STANDARD = 2,       // Normal agent
        ELEVATED = 3,       // Trusted agent
        SYSTEM = 4          // System/core
    };
    
    // Capabilities per level
    struct Capabilities {
        bool canModifyCode;
        bool canAccessFilesystem;
        bool canAccessNetwork;
        bool canExecuteSystemCalls;
        bool canAccessKernelMemory;
        bool canModifyPermissions;
    };
    
    bool Initialize();
    
    // Privilege management
    bool SetAgentPrivilege(uint64_t agentId, PrivilegeLevel level);
    PrivilegeLevel GetAgentPrivilege(uint64_t agentId) const;
    Capabilities GetCapabilities(PrivilegeLevel level) const;
    
    // Capability checks
    bool CanModifyCode(uint64_t agentId);
    bool CanAccessFilesystem(uint64_t agentId);
    bool CanAccessNetwork(uint64_t agentId);
    bool CanExecuteSystemCalls(uint64_t agentId);
    
    // Temporary elevation
    bool ElevateTemporarily(uint64_t agentId, std::function<void()> callback);
    
    // Sandboxing
    bool EnterSandbox(uint64_t agentId);
    bool ExitSandbox(uint64_t agentId);
    bool IsInSandbox(uint64_t agentId) const;

private:
    PrivilegeManager() = default;
    
    mutable std::mutex mutex_;
    std::unordered_map<uint64_t, PrivilegeLevel> agentPrivileges_;
    std::unordered_set<uint64_t> sandboxedAgents_;
};

// ============================================================================
// Security Manager - Main security interface
// ============================================================================

class SecurityManager {
public:
    static SecurityManager& Instance();
    
    // Lifecycle
    bool Initialize(SecurityLevel level = SecurityLevel::STANDARD);
    void Shutdown();
    bool IsInitialized() const { return initialized_.load(); }
    
    // Security level
    void SetSecurityLevel(SecurityLevel level);
    SecurityLevel GetSecurityLevel() const { return securityLevel_.load(); }
    
    // Pre-execution checks
    bool ValidatePreExecution(uint64_t agentId, uint64_t intentId, std::string& error);
    
    // Post-execution logging
    void LogPostExecution(uint64_t agentId, uint64_t intentId, bool success);
    
    // Emergency
    void EmergencyLockdown(const std::string& reason);
    bool IsInLockdown() const { return lockdown_.load(); }
    void LiftLockdown();
    
    // Health check
    bool RunSecurityAudit();
    std::vector<std::string> GetSecurityRecommendations() const;
    
    // Statistics
    struct SecurityStats {
        uint64_t totalEventsLogged;
        uint64_t violationsDetected;
        uint64_t rateLimitHits;
        uint64_t invalidInputsBlocked;
        uint64_t memoryViolations;
        uint64_t privilegeEscalationsAttempted;
        uint64_t privilegeEscalationsBlocked;
        double averageValidationTimeMs;
    };
    SecurityStats GetStats() const;

private:
    SecurityManager() = default;
    
    std::atomic<bool> initialized_{false};
    std::atomic<SecurityLevel> securityLevel_{SecurityLevel::STANDARD};
    std::atomic<bool> lockdown_{false};
    
    std::chrono::system_clock::time_point startupTime_;
};

// ============================================================================
// Security Macros
// ============================================================================

// Audit logging macros
#define SECURITY_LOG_EVENT(type, details) \
    Security::AuditLog::Instance().LogSecurityEvent(type, details, "INFO")

#define SECURITY_LOG_WARNING(type, details) \
    Security::AuditLog::Instance().LogSecurityEvent(type, details, "WARNING")

#define SECURITY_LOG_ERROR(type, details) \
    Security::AuditLog::Instance().LogSecurityEvent(type, details, "ERROR")

#define SECURITY_LOG_CRITICAL(type, details) \
    Security::AuditLog::Instance().LogSecurityEvent(type, details, "CRITICAL")

// Validation macros
#define SECURITY_VALIDATE_INPUT(input, error) \
    if (!Security::InputValidator::Instance().Validate##input) { \
        SECURITY_LOG_ERROR(Security::AuditEventType::VIOLATION_DETECTED, error); \
        return false; \
    }

// Rate limiting macros
#define SECURITY_CHECK_RATE_LIMIT(agentId, action) \
    if (!Security::RateLimiter::Instance().Can##action(agentId)) { \
        SECURITY_LOG_WARNING(Security::AuditEventType::RATE_LIMIT_EXCEEDED, \
            "Rate limit exceeded for agent " + std::to_string(agentId)); \
        return false; \
    }

} // namespace Security
} // namespace RawrXD
