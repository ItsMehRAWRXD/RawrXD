// Phase N.2/5: Audit Logging System
// RawrXD Audit Logger - Comprehensive audit trail

#pragma once

#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <variant>
#include <functional>
#include <queue>
#include <thread>
#include <atomic>

namespace RawrXD {
namespace Enterprise {

// Audit event severity
enum class AuditSeverity {
    DEBUG,
    INFO,
    NOTICE,
    WARNING,
    ERROR,
    CRITICAL,
    ALERT,
    EMERGENCY
};

// Audit event categories
enum class AuditCategory {
    AUTHENTICATION,      // Login, logout, token refresh
    AUTHORIZATION,       // Permission checks, access denied
    DATA_ACCESS,         // Data read/write operations
    CONFIGURATION,       // Config changes
    ADMINISTRATIVE,      // Admin operations
    INFERENCE,           // Model inference requests
    SYSTEM,              // System events
    SECURITY,            // Security-related events
    COMPLIANCE           // Compliance-specific events
};

// Audit event structure
struct AuditEvent {
    // Event identification
    std::string event_id;                    // Unique event ID (UUID)
    std::string correlation_id;              // Request correlation ID
    AuditCategory category;
    AuditSeverity severity;
    std::string event_type;                  // Specific event type
    
    // Timestamp
    std::chrono::system_clock::time_point timestamp;
    uint64_t timestamp_ns;                   // Nanosecond precision
    
    // Actor information
    struct Actor {
        std::string tenant_id;
        std::string user_id;
        std::string session_id;
        std::string api_key_id;
        std::string ip_address;
        std::string user_agent;
        std::vector<std::string> roles;
    } actor;
    
    // Resource information
    struct Resource {
        std::string resource_type;           // e.g., "model", "api_endpoint"
        std::string resource_id;
        std::string resource_name;
        std::string action;                  // e.g., "read", "write", "delete"
    } resource;
    
    // Event details
    struct Details {
        bool success;
        std::string status_code;
        std::string error_message;
        uint64_t duration_ms;
        std::unordered_map<std::string, std::variant<
            std::string, int64_t, double, bool
        >> metadata;
    } details;
    
    // For inference events
    struct InferenceDetails {
        std::string model_id;
        std::string model_version;
        uint32_t input_tokens;
        uint32_t output_tokens;
        uint32_t total_tokens;
        float temperature;
        float top_p;
        uint32_t top_k;
        std::string prompt_hash;             // Hash of input (for privacy)
        std::string completion_hash;         // Hash of output
        std::vector<std::string> tools_used;
    } inference_details;
    
    // Integrity
    std::string previous_hash;               // Hash chain for tamper detection
    std::string event_hash;                  // Hash of this event
    
    // Serialization
    std::string ToJSON() const;
    static std::optional<AuditEvent> FromJSON(const std::string& json);
};

// Audit log storage interface
class IAuditStorage {
public:
    virtual ~IAuditStorage() = default;
    
    virtual bool Initialize(const std::string& config) = 0;
    virtual void Shutdown() = 0;
    
    // Write operations
    virtual bool WriteEvent(const AuditEvent& event) = 0;
    virtual bool WriteEvents(const std::vector<AuditEvent>& events) = 0;
    
    // Read operations
    virtual std::vector<AuditEvent> QueryEvents(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        const std::vector<AuditCategory>& categories = {},
        const std::vector<AuditSeverity>& severities = {},
        const std::string& tenant_id = "",
        const std::string& user_id = "",
        uint32_t limit = 1000) = 0;
    
    // Aggregation
    virtual std::unordered_map<std::string, uint64_t> GetEventCounts(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        AuditCategory category) = 0;
    
    // Integrity verification
    virtual bool VerifyIntegrity(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end) = 0;
    
    // Retention
    virtual bool ArchiveEvents(
        std::chrono::system_clock::time_point before) = 0;
    virtual bool DeleteEvents(
        std::chrono::system_clock::time_point before) = 0;
    
    // Health
    virtual bool IsHealthy() const = 0;
    virtual std::string GetStatus() const = 0;
};

// File-based audit storage
class FileAuditStorage : public IAuditStorage {
public:
    FileAuditStorage();
    ~FileAuditStorage() override;
    
    bool Initialize(const std::string& config) override;
    void Shutdown() override;
    
    bool WriteEvent(const AuditEvent& event) override;
    bool WriteEvents(const std::vector<AuditEvent>& events) override;
    
    std::vector<AuditEvent> QueryEvents(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        const std::vector<AuditCategory>& categories = {},
        const std::vector<AuditSeverity>& severities = {},
        const std::string& tenant_id = "",
        const std::string& user_id = "",
        uint32_t limit = 1000) override;
    
    std::unordered_map<std::string, uint64_t> GetEventCounts(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        AuditCategory category) override;
    
    bool VerifyIntegrity(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end) override;
    
    bool ArchiveEvents(std::chrono::system_clock::time_point before) override;
    bool DeleteEvents(std::chrono::system_clock::time_point before) override;
    
    bool IsHealthy() const override;
    std::string GetStatus() const override;
    
private:
    std::string base_path_;
    std::atomic<bool> initialized_{false};
    std::mutex write_mutex_;
    std::string current_hash_;
    
    std::string GetFilePath(const std::chrono::system_clock::time_point& timestamp);
    std::string CalculateHash(const AuditEvent& event);
    bool RotateLogIfNeeded();
};

// Database audit storage (PostgreSQL/MySQL)
class DatabaseAuditStorage : public IAuditStorage {
public:
    DatabaseAuditStorage();
    ~DatabaseAuditStorage() override;
    
    bool Initialize(const std::string& config) override;
    void Shutdown() override;
    
    bool WriteEvent(const AuditEvent& event) override;
    bool WriteEvents(const std::vector<AuditEvent>& events) override;
    
    std::vector<AuditEvent> QueryEvents(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        const std::vector<AuditCategory>& categories = {},
        const std::vector<AuditSeverity>& severities = {},
        const std::string& tenant_id = "",
        const std::string& user_id = "",
        uint32_t limit = 1000) override;
    
    std::unordered_map<std::string, uint64_t> GetEventCounts(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        AuditCategory category) override;
    
    bool VerifyIntegrity(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end) override;
    
    bool ArchiveEvents(std::chrono::system_clock::time_point before) override;
    bool DeleteEvents(std::chrono::system_clock::time_point before) override;
    
    bool IsHealthy() const override;
    std::string GetStatus() const override;
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// SIEM integration (Splunk, ELK, etc.)
class SIEMAuditStorage : public IAuditStorage {
public:
    SIEMAuditStorage();
    ~SIEMAuditStorage() override;
    
    bool Initialize(const std::string& config) override;
    void Shutdown() override;
    
    bool WriteEvent(const AuditEvent& event) override;
    bool WriteEvents(const std::vector<AuditEvent>& events) override;
    
    std::vector<AuditEvent> QueryEvents(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        const std::vector<AuditCategory>& categories = {},
        const std::vector<AuditSeverity>& severities = {},
        const std::string& tenant_id = "",
        const std::string& user_id = "",
        uint32_t limit = 1000) override;
    
    std::unordered_map<std::string, uint64_t> GetEventCounts(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        AuditCategory category) override;
    
    bool VerifyIntegrity(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end) override;
    
    bool ArchiveEvents(std::chrono::system_clock::time_point before) override;
    bool DeleteEvents(std::chrono::system_clock::time_point before) override;
    
    bool IsHealthy() const override;
    std::string GetStatus() const override;
    
private:
    std::string endpoint_;
    std::string api_key_;
    std::atomic<bool> initialized_{false};
};

// Main audit logger
class AuditLogger {
public:
    AuditLogger();
    ~AuditLogger();
    
    // Initialization
    bool Initialize(const std::string& config);
    void Shutdown();
    
    // Configuration
    struct Config {
        std::string storage_type = "file";  // file, database, siem
        std::string storage_config;
        AuditSeverity min_severity = AuditSeverity::INFO;
        std::vector<AuditCategory> enabled_categories;
        bool async_logging = true;
        uint32_t batch_size = 100;
        uint32_t flush_interval_ms = 1000;
        bool enable_hash_chain = true;
        bool enable_tamper_detection = true;
        uint32_t retention_days = 90;
        uint32_t archive_after_days = 30;
    };
    
    bool Configure(const Config& config);
    const Config& GetConfig() const { return config_; }
    
    // Event logging
    void LogEvent(const AuditEvent& event);
    void LogEvent(AuditCategory category, AuditSeverity severity,
                  const std::string& event_type, const std::string& tenant_id,
                  const std::string& user_id, bool success,
                  const std::unordered_map<std::string, std::variant<
                      std::string, int64_t, double, bool
                  >>& metadata = {});
    
    // Convenience methods
    void LogAuthentication(const std::string& tenant_id, const std::string& user_id,
                           const std::string& ip_address, bool success,
                           const std::string& method);
    void LogInference(const std::string& tenant_id, const std::string& user_id,
                      const std::string& model_id, uint32_t input_tokens,
                      uint32_t output_tokens, uint64_t duration_ms, bool success);
    void LogDataAccess(const std::string& tenant_id, const std::string& user_id,
                       const std::string& resource_type, const std::string& resource_id,
                       const std::string& action, bool success);
    void LogConfiguration(const std::string& tenant_id, const std::string& user_id,
                          const std::string& config_key, const std::string& old_value,
                          const std::string& new_value);
    
    // Query interface
    std::vector<AuditEvent> QueryEvents(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end,
        const std::vector<AuditCategory>& categories = {},
        const std::vector<AuditSeverity>& severities = {},
        const std::string& tenant_id = "",
        const std::string& user_id = "",
        uint32_t limit = 1000);
    
    // Reporting
    struct AuditReport {
        std::chrono::system_clock::time_point period_start;
        std::chrono::system_clock::time_point period_end;
        uint64_t total_events;
        std::unordered_map<AuditCategory, uint64_t> events_by_category;
        std::unordered_map<AuditSeverity, uint64_t> events_by_severity;
        std::unordered_map<std::string, uint64_t> events_by_tenant;
        std::unordered_map<std::string, uint64_t> events_by_user;
        uint64_t failed_authentications;
        uint64_t unauthorized_access_attempts;
        uint64_t inference_requests;
        uint64_t total_tokens_processed;
    };
    AuditReport GenerateReport(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end);
    
    // Integrity
    bool VerifyLogIntegrity(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end);
    
    // Health
    bool IsHealthy() const;
    std::string GetStatus() const;
    
    // Statistics
    struct Statistics {
        uint64_t events_logged;
        uint64_t events_dropped;
        uint64_t events_queued;
        uint64_t storage_errors;
        double average_write_latency_ms;
        std::chrono::system_clock::time_point last_flush;
    };
    Statistics GetStatistics() const;
    void ResetStatistics();
    
private:
    Config config_;
    std::unique_ptr<IAuditStorage> storage_;
    
    // Async logging
    std::queue<AuditEvent> event_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::thread flush_thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> shutdown_{false};
    
    // Statistics
    Statistics stats_;
    mutable std::mutex stats_mutex_;
    
    // Hash chain
    std::string last_hash_;
    std::mutex hash_mutex_;
    
    void FlushThread();
    void FlushBatch();
    std::string CalculateEventHash(const AuditEvent& event);
};

// Global audit logger instance
extern std::unique_ptr<AuditLogger> g_audit_logger;

// Initialize audit logging
bool InitializeAuditLogging(const AuditLogger::Config& config);
void ShutdownAuditLogging();
bool IsAuditLoggingEnabled();

// Convenience macros
#define AUDIT_LOG_EVENT(category, severity, type, tenant, user, success, ...) \
    do { if (g_audit_logger) g_audit_logger->LogEvent(category, severity, type, tenant, user, success, ##__VA_ARGS__); } while(0)

#define AUDIT_LOG_AUTH(tenant, user, ip, success, method) \
    do { if (g_audit_logger) g_audit_logger->LogAuthentication(tenant, user, ip, success, method); } while(0)

#define AUDIT_LOG_INFERENCE(tenant, user, model, in_tokens, out_tokens, duration, success) \
    do { if (g_audit_logger) g_audit_logger->LogInference(tenant, user, model, in_tokens, out_tokens, duration, success); } while(0)

} // namespace Enterprise
} // namespace RawrXD
