#pragma once
/**
 * @file audit_logger.hpp
 * @brief Audit logging for compliance and security
 * @copyright 2026 RawrXD Team
 */

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <map>
#include <functional>
#include <fstream>
#include <mutex>

namespace rawrxd {
namespace audit {

/**
 * @brief Audit event severity
 */
enum class AuditSeverity {
    DEBUG = 0,
    INFO = 1,
    NOTICE = 2,
    WARNING = 3,
    ERROR = 4,
    CRITICAL = 5,
    ALERT = 6,
    EMERGENCY = 7
};

/**
 * @brief Audit event categories
 */
enum class AuditCategory {
    AUTHENTICATION,
    AUTHORIZATION,
    DATA_ACCESS,
    DATA_MODIFICATION,
    SYSTEM_CHANGE,
    SECURITY_EVENT,
    COMPLIANCE,
    BENCHMARK_EXECUTION,
    CONFIGURATION,
    USER_MANAGEMENT
};

/**
 * @brief Audit event structure
 */
struct AuditEvent {
    std::string id;
    std::chrono::system_clock::time_point timestamp;
    AuditSeverity severity;
    AuditCategory category;
    std::string action;
    std::string actor_id;
    std::string actor_type;
    std::string target_id;
    std::string target_type;
    std::string resource;
    std::string details;
    std::string client_ip;
    std::string session_id;
    bool success;
    std::map<std::string, std::string> metadata;
    
    AuditEvent();
    
    /**
     * @brief Convert to JSON string
     */
    std::string ToJson() const;
    
    /**
     * @brief Convert to syslog format
     */
    std::string ToSyslog() const;
    
    /**
     * @brief Convert to CEF format
     */
    std::string ToCEF() const;
};

/**
 * @brief Audit log filter
 */
struct AuditFilter {
    std::vector<AuditSeverity> severities;
    std::vector<AuditCategory> categories;
    std::vector<std::string> actors;
    std::vector<std::string> actions;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    std::string search_text;
    int limit;
    int offset;
    
    AuditFilter();
};

/**
 * @brief Audit log entry with storage info
 */
struct AuditLogEntry {
    AuditEvent event;
    std::string storage_location;
    std::string integrity_hash;
    bool tamper_detected;
};

/**
 * @brief Audit log retention policy
 */
struct RetentionPolicy {
    int debug_days;
    int info_days;
    int notice_days;
    int warning_days;
    int error_days;
    int critical_days;
    int alert_days;
    int emergency_days;
    bool archive_before_delete;
    std::string archive_location;
};

/**
 * @brief Audit logger interface
 */
class IAuditLogger {
public:
    virtual ~IAuditLogger() = default;
    
    /**
     * @brief Log an audit event
     */
    virtual bool LogEvent(const AuditEvent& event) = 0;
    
    /**
     * @brief Query audit log
     */
    virtual std::vector<AuditLogEntry> Query(
        const AuditFilter& filter
    ) = 0;
    
    /**
     * @brief Export audit log
     */
    virtual bool Export(
        const AuditFilter& filter,
        const std::string& format,
        const std::string& output_path
    ) = 0;
    
    /**
     * @brief Verify log integrity
     */
    virtual bool VerifyIntegrity(
        const std::chrono::system_clock::time_point& start,
        const std::chrono::system_clock::time_point& end
    ) = 0;
    
    /**
     * @brief Archive old logs
     */
    virtual bool ArchiveOldLogs(const RetentionPolicy& policy) = 0;
};

/**
 * @brief File-based audit logger
 */
class FileAuditLogger : public IAuditLogger {
public:
    FileAuditLogger();
    ~FileAuditLogger() override;
    
    /**
     * @brief Initialize logger
     */
    bool Initialize(
        const std::string& log_directory,
        const std::string& integrity_key
    );
    
    bool LogEvent(const AuditEvent& event) override;
    std::vector<AuditLogEntry> Query(const AuditFilter& filter) override;
    bool Export(
        const AuditFilter& filter,
        const std::string& format,
        const std::string& output_path
    ) override;
    bool VerifyIntegrity(
        const std::chrono::system_clock::time_point& start,
        const std::chrono::system_clock::time_point& end
    ) override;
    bool ArchiveOldLogs(const RetentionPolicy& policy) override;
    
    /**
     * @brief Get current log file
     */
    std::string GetCurrentLogFile() const;
    
    /**
     * @brief Rotate log file
     */
    bool RotateLog();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

/**
 * @brief Syslog audit logger
 */
class SyslogAuditLogger : public IAuditLogger {
public:
    SyslogAuditLogger();
    ~SyslogAuditLogger() override;
    
    /**
     * @brief Initialize syslog logger
     */
    bool Initialize(
        const std::string& facility,
        const std::string& tag
    );
    
    bool LogEvent(const AuditEvent& event) override;
    std::vector<AuditLogEntry> Query(const AuditFilter& filter) override;
    bool Export(
        const AuditFilter& filter,
        const std::string& format,
        const std::string& output_path
    ) override;
    bool VerifyIntegrity(
        const std::chrono::system_clock::time_point& start,
        const std::chrono::system_clock::time_point& end
    ) override;
    bool ArchiveOldLogs(const RetentionPolicy& policy) override;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

/**
 * @brief Audit log manager
 */
class AuditLogManager {
public:
    AuditLogManager();
    ~AuditLogManager();
    
    /**
     * @brief Initialize audit log manager
     */
    bool Initialize(const std::string& config_path);
    
    /**
     * @brief Shutdown audit log manager
     */
    void Shutdown();
    
    /**
     * @brief Add logger
     */
    void AddLogger(std::shared_ptr<IAuditLogger> logger);
    
    /**
     * @brief Log event to all loggers
     */
    bool LogEvent(const AuditEvent& event);
    
    /**
     * @brief Create audit event builder
     */
    class EventBuilder {
    public:
        EventBuilder();
        
        EventBuilder& SetSeverity(AuditSeverity severity);
        EventBuilder& SetCategory(AuditCategory category);
        EventBuilder& SetAction(const std::string& action);
        EventBuilder& SetActor(const std::string& id, const std::string& type);
        EventBuilder& SetTarget(const std::string& id, const std::string& type);
        EventBuilder& SetResource(const std::string& resource);
        EventBuilder& SetDetails(const std::string& details);
        EventBuilder& SetClientIp(const std::string& ip);
        EventBuilder& SetSessionId(const std::string& session);
        EventBuilder& SetSuccess(bool success);
        EventBuilder& AddMetadata(
            const std::string& key,
            const std::string& value
        );
        
        AuditEvent Build();
        
    private:
        AuditEvent event_;
    };
    
    /**
     * @brief Create builder for convenience
     */
    static EventBuilder CreateEvent();
    
    /**
     * @brief Get singleton instance
     */
    static AuditLogManager& Instance();
    
    // Convenience methods for common events
    void LogAuthentication(
        const std::string& user_id,
        bool success,
        const std::string& details
    );
    
    void LogAuthorization(
        const std::string& user_id,
        const std::string& resource,
        const std::string& action,
        bool success
    );
    
    void LogDataAccess(
        const std::string& user_id,
        const std::string& data_type,
        const std::string& data_id,
        const std::string& action
    );
    
    void LogBenchmarkExecution(
        const std::string& user_id,
        const std::string& benchmark_id,
        const std::string& backend,
        bool success,
        const std::string& details
    );
    
    void LogConfigurationChange(
        const std::string& user_id,
        const std::string& config_key,
        const std::string& old_value,
        const std::string& new_value
    );
    
    void LogSecurityEvent(
        AuditSeverity severity,
        const std::string& event_type,
        const std::string& details,
        const std::string& source_ip
    );

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

/**
 * @brief Audit log viewer
 */
class AuditLogViewer {
public:
    AuditLogViewer();
    ~AuditLogViewer();
    
    /**
     * @brief Load logs from file
     */
    bool LoadFromFile(const std::string& path);
    
    /**
     * @brief Filter loaded logs
     */
    std::vector<AuditEvent> Filter(const AuditFilter& filter);
    
    /**
     * @brief Generate summary statistics
     */
    std::map<std::string, int> GetStatistics() const;
    
    /**
     * @brief Export to different formats
     */
    bool ExportToJson(const std::string& output_path);
    bool ExportToCsv(const std::string& output_path);
    bool ExportToHtml(const std::string& output_path);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

/**
 * @brief Compliance report generator
 */
class ComplianceReportGenerator {
public:
    ComplianceReportGenerator();
    ~ComplianceReportGenerator();
    
    /**
     * @brief Generate SOC2 report
     */
    bool GenerateSOC2Report(
        const std::chrono::system_clock::time_point& start,
        const std::chrono::system_clock::time_point& end,
        const std::string& output_path
    );
    
    /**
     * @brief Generate ISO27001 report
     */
    bool GenerateISO27001Report(
        const std::chrono::system_clock::time_point& start,
        const std::chrono::system_clock::time_point& end,
        const std::string& output_path
    );
    
    /**
     * @brief Generate GDPR report
     */
    bool GenerateGDPRReport(
        const std::chrono::system_clock::time_point& start,
        const std::chrono::system_clock::time_point& end,
        const std::string& output_path
    );
    
    /**
     * @brief Generate custom compliance report
     */
    bool GenerateCustomReport(
        const std::vector<std::string>& requirements,
        const std::chrono::system_clock::time_point& start,
        const std::chrono::system_clock::time_point& end,
        const std::string& output_path
    );

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace audit
} // namespace rawrxd
