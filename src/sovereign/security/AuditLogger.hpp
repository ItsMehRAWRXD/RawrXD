// ============================================================================
// AuditLogger.hpp - Comprehensive Audit Logging System
// ============================================================================

#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <mutex>
#include <chrono>

namespace Sovereign {

enum class AuditSeverity { DEBUG, INFO, WARNING, ERROR, CRITICAL };

struct AuditEntry {
    uint64_t id;
    uint64_t timestamp;
    AuditSeverity severity;
    std::string source;
    std::string action;
    std::string details;
    std::string agentId;
    std::string sessionId;
};

class AuditLogger {
public:
    AuditLogger();
    ~AuditLogger();

    bool Initialize(const std::string& logPath);
    void Shutdown();

    void Log(AuditSeverity severity, const std::string& source, const std::string& action, const std::string& details = "");
    void Info(const std::string& source, const std::string& action, const std::string& details = "");
    void Warn(const std::string& source, const std::string& action, const std::string& details = "");
    void Error(const std::string& source, const std::string& action, const std::string& details = "");

    std::vector<AuditEntry> Query(uint64_t since, uint64_t until, AuditSeverity minSeverity = AuditSeverity::DEBUG);
    std::vector<AuditEntry> GetBySource(const std::string& source, size_t limit = 100);
    std::vector<AuditEntry> GetByAgent(const std::string& agentId, size_t limit = 100);

    void Flush();
    void SetMaxEntries(size_t max) { maxEntries_ = max; }
    size_t GetEntryCount() const { return entries_.size(); }

private:
    std::string logPath_;
    std::vector<AuditEntry> entries_;
    size_t maxEntries_ = 10000;
    uint64_t nextId_ = 1;
    mutable std::mutex mutex_;
    std::ofstream logFile_;
    
    void WriteToFile(const AuditEntry& entry);
};

} // namespace Sovereign
