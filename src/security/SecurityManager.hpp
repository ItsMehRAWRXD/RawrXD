// ============================================================================
// SecurityManager.hpp — Production Security Layer for RawrXD CEO Agent
// Sandbox, permissions, audit logging, secret scanning
// ============================================================================
#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <functional>
#include <chrono>
#include <memory>
#include <fstream>
#include <filesystem>

namespace RawrXD {
namespace Security {

using json = nlohmann::json;

// ============================================================================
// Permission Levels
// ============================================================================
enum class PermissionLevel {
    None = 0,
    Read = 1,
    Write = 2,
    Execute = 3,
    Admin = 4
};

// ============================================================================
// Permission Scope
// ============================================================================
struct PermissionScope {
    std::string resource;       // File path, directory, or pattern
    PermissionLevel level = PermissionLevel::None;
    bool recursive = false;
    std::string reason;         // Why this permission was granted
    std::chrono::system_clock::time_point grantedAt;
    std::chrono::system_clock::time_point expiresAt;
};

// ============================================================================
// Audit Entry
// ============================================================================
struct AuditEntry {
    std::string id;
    std::string agentName;
    std::string action;         // read_file, write_file, execute, etc.
    std::string resource;
    json params;
    bool allowed = false;
    bool success = false;
    std::string result;
    std::string reason;
    std::chrono::system_clock::time_point timestamp;
    double durationMs = 0.0;
};

// ============================================================================
// Sandbox Configuration
// ============================================================================
struct SandboxConfig {
    bool enabled = true;
    std::vector<std::string> allowedPaths;
    std::vector<std::string> deniedPaths;
    std::vector<std::string> allowedCommands;
    std::vector<std::string> deniedCommands;
    std::vector<std::string> allowedExtensions;
    std::vector<std::string> deniedExtensions;
    int maxFileSizeMB = 100;
    int maxCommandTimeoutSec = 300;
    bool requireApprovalForWrite = true;
    bool requireApprovalForExecute = true;
    bool requireApprovalForNetwork = true;
    bool enableAuditLog = true;
    std::string auditLogPath = ".rawrxd/audit.log";
};

// ============================================================================
// Secret Pattern
// ============================================================================
struct SecretPattern {
    std::string name;
    std::string pattern;        // Regex pattern
    std::string description;
    Severity severity = Severity::High;
};

enum class Severity {
    Low,
    Medium,
    High,
    Critical
};

// ============================================================================
// Security Manager
// ============================================================================
class SecurityManager {
public:
    SecurityManager();
    ~SecurityManager();

    // Initialization
    bool Initialize(const SandboxConfig& config);
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }

    // Permission Management
    bool GrantPermission(const PermissionScope& scope);
    bool RevokePermission(const std::string& resource);
    bool CheckPermission(const std::string& resource, PermissionLevel level) const;
    std::vector<PermissionScope> GetPermissions() const;
    void ClearPermissions();

    // Sandbox Enforcement
    bool IsPathAllowed(const std::string& path) const;
    bool IsCommandAllowed(const std::string& command) const;
    bool IsFileTypeAllowed(const std::string& extension) const;
    std::string SanitizePath(const std::string& path) const;

    // Audit Logging
    void LogAction(const AuditEntry& entry);
    std::vector<AuditEntry> GetAuditLog(int maxEntries = 1000) const;
    std::vector<AuditEntry> SearchAuditLog(const std::string& query) const;
    bool ExportAuditLog(const std::string& path) const;
    void ClearAuditLog();

    // Secret Scanning
    bool ScanForSecrets(const std::string& content, std::vector<std::string>& found) const;
    bool ScanFileForSecrets(const std::string& filePath) const;
    void RegisterSecretPattern(const SecretPattern& pattern);
    std::vector<SecretPattern> GetSecretPatterns() const;

    // Tool Call Validation
    bool ValidateToolCall(const std::string& toolName, const json& params, std::string& error) const;
    bool RequiresApproval(const std::string& toolName, const json& params) const;

    // Statistics
    json GetStats() const;
    int GetAuditCount() const { return m_auditLog.size(); }
    int GetPermissionCount() const { return m_permissions.size(); }

private:
    bool IsPathInAllowedList(const std::string& path) const;
    bool IsPathInDeniedList(const std::string& path) const;
    std::string ResolvePath(const std::string& path) const;
    void FlushAuditLog();

private:
    SandboxConfig m_config;
    std::vector<PermissionScope> m_permissions;
    std::vector<AuditEntry> m_auditLog;
    std::vector<SecretPattern> m_secretPatterns;
    mutable std::mutex m_mutex;
    bool m_initialized = false;
    std::ofstream m_auditStream;
};

} // namespace Security
} // namespace RawrXD
