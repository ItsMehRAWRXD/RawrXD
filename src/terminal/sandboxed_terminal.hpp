#pragma once
<<<<<<< HEAD
// sandboxed_terminal.hpp – Qt-free sandboxed terminal (C++20 / Win32)
=======


>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

struct JsonValue;
using JsonObject = std::unordered_map<std::string, JsonValue>;

/**
 * Production-ready terminal with security isolation and command filtering.
 *   - Process isolation with resource limits
 *   - Command filtering (whitelist/blacklist)
 *   - Output sanitization
 *   - Structured logging + audit trail
 *   - Win32 CreateProcess backend
 */
<<<<<<< HEAD
class SandboxedTerminal {
public:
    SandboxedTerminal();
    ~SandboxedTerminal();
=======
class SandboxedTerminal : public void {

public:
    explicit SandboxedTerminal(void* parent = nullptr);
    ~SandboxedTerminal() override;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    // ---------- Configuration ----------
    struct Config {
<<<<<<< HEAD
        std::vector<std::string> commandWhitelist;
        std::vector<std::string> commandBlacklist;
        bool        useWhitelistMode      = true;
        int         maxExecutionTimeMs    = 30000;
        int         maxOutputSize         = 1048576; // 1 MB
        bool        enableOutputFiltering = true;
        bool        enableAuditLog        = true;
        std::string auditLogPath;
        std::string workingDirectory;
        std::vector<std::string> allowedEnvironmentVars;
        bool        enableResourceLimits  = true;
        int64_t     maxMemoryBytes        = 536870912; // 512 MB
        int         maxCpuPercent         = 80;
        bool        enableMetrics         = true;
=======
        std::vector<std::string> commandWhitelist;        // Allowed commands
        std::vector<std::string> commandBlacklist;        // Explicitly forbidden commands
        bool useWhitelistMode = true;        // If true, only whitelist allowed; if false, blacklist forbidden
        int maxExecutionTimeMs = 30000;      // Command timeout
        int maxOutputSize = 1048576;         // 1MB max output
        bool enableOutputFiltering = true;   // Filter sensitive data from output
        bool enableAuditLog = true;
        std::string auditLogPath;
        std::string workingDirectory;
        std::vector<std::string> allowedEnvironmentVars;  // Environment variables to preserve
        bool enableResourceLimits = true;
        int64_t maxMemoryBytes = 536870912;   // 512MB
        int maxCpuPercent = 80;
        bool enableMetrics = true;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    };

    void   setConfig(const Config& config);
    Config getConfig() const;

    // ---------- Command execution ----------
    struct CommandResult {
        std::string output;
        std::string error;
<<<<<<< HEAD
        int         exitCode        = -1;
        bool        timedOut        = false;
        bool        wasBlocked      = false;
        std::string blockReason;
        int64_t     executionTimeMs = 0;
    };

    CommandResult executeCommand(const std::string& command,
                                 const std::vector<std::string>& args = {});
    bool        isCommandAllowed(const std::string& command) const;
    std::string sanitizeOutput(const std::string& output) const;

=======
        int exitCode;
        bool timedOut;
        bool wasBlocked;
        std::string blockReason;
        int64_t executionTimeMs;
    };

    CommandResult executeCommand(const std::string& command, const std::vector<std::string>& args = std::vector<std::string>());
    bool isCommandAllowed(const std::string& command) const;
    std::string sanitizeOutput(const std::string& output) const;
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    // Process management
    bool isRunning() const;
    void terminate();
    void kill();

    // ---------- Metrics ----------
    struct Metrics {
<<<<<<< HEAD
        int64_t commandsExecuted     = 0;
        int64_t commandsBlocked      = 0;
        int64_t commandsTimedOut     = 0;
        int64_t outputBytesFiltered  = 0;
        int64_t securityViolations   = 0;
        int64_t errorCount           = 0;
        double  avgExecutionTimeMs   = 0.0;
=======
        int64_t commandsExecuted = 0;
        int64_t commandsBlocked = 0;
        int64_t commandsTimedOut = 0;
        int64_t outputBytesFiltered = 0;
        int64_t securityViolations = 0;
        int64_t errorCount = 0;
        double avgExecutionTimeMs = 0.0;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    };

    Metrics getMetrics() const;
    void    resetMetrics();

<<<<<<< HEAD
    // ---------- Callbacks (replaces Qt signals) ----------
    using CmdStringCb   = void(*)(void* ctx, const char* command);
    using CmdResultCb   = void(*)(void* ctx, const CommandResult* result);
    using CmdBlockCb    = void(*)(void* ctx, const char* command, const char* reason);
    using StringCb      = void(*)(void* ctx, const char* msg);
    using MetricsCb     = void(*)(void* ctx, const Metrics* m);

    void setCommandStartedCb(CmdStringCb cb, void* ctx)    { m_startCb  = cb; m_startCtx  = ctx; }
    void setCommandFinishedCb(CmdResultCb cb, void* ctx)    { m_finishCb = cb; m_finishCtx = ctx; }
    void setCommandBlockedCb(CmdBlockCb cb, void* ctx)      { m_blockCb  = cb; m_blockCtx  = ctx; }
    void setSecurityViolationCb(StringCb cb, void* ctx)     { m_secCb    = cb; m_secCtx    = ctx; }
    void setErrorCb(StringCb cb, void* ctx)                  { m_errCb    = cb; m_errCtx    = ctx; }
    void setMetricsUpdatedCb(MetricsCb cb, void* ctx)        { m_metCb    = cb; m_metCtx    = ctx; }

private:
    // State
    Config          m_config;
    mutable std::mutex m_configMutex;

    void*           m_processHandle = nullptr; // Win32 HANDLE
    mutable std::mutex m_processMutex;

    Metrics         m_metrics;
    mutable std::mutex m_metricsMutex;

    // Helpers
    void logStructured(const std::string& level, const std::string& message,
                       const JsonObject& context = {});
    void recordLatency(const std::string& operation, std::chrono::milliseconds duration);
    void logAudit(const std::string& action, const JsonObject& details);
    bool validateCommand(const std::string& command, std::string& blockReason) const;
    std::vector<std::string> buildSanitizedEnvironment() const;
    bool enforceResourceLimits();
    std::string filterSensitiveData(const std::string& data) const;

    // Callback state
    CmdStringCb m_startCb  = nullptr;  void* m_startCtx  = nullptr;
    CmdResultCb m_finishCb = nullptr;  void* m_finishCtx = nullptr;
    CmdBlockCb  m_blockCb  = nullptr;  void* m_blockCtx  = nullptr;
    StringCb    m_secCb    = nullptr;  void* m_secCtx    = nullptr;
    StringCb    m_errCb    = nullptr;  void* m_errCtx    = nullptr;
    MetricsCb   m_metCb    = nullptr;  void* m_metCtx    = nullptr;
=======
    void commandStarted(const std::string& command);
    void commandFinished(const CommandResult& result);
    void commandBlocked(const std::string& command, const std::string& reason);
    void securityViolation(const std::string& violation);
    void errorOccurred(const std::string& error);
    void metricsUpdated(const Metrics& metrics);

private:
    // Configuration
    Config m_config;
    mutable std::mutex m_configMutex;

    // Process
    void** m_process;
    mutable std::mutex m_processMutex;

    // Metrics
    Metrics m_metrics;
    mutable std::mutex m_metricsMutex;

    // Helper methods
    void logStructured(const std::string& level, const std::string& message, const void*& context = void*());
    void recordLatency(const std::string& operation, const std::chrono::milliseconds& duration);
    void logAudit(const std::string& action, const void*& details);
    bool validateCommand(const std::string& command, std::string& blockReason);
    bool validateCommand(const std::string& command, std::string& blockReason) const;  // const overload
    std::vector<std::string> buildSanitizedEnvironment() const;
    bool enforceResourceLimits();
    std::string filterSensitiveData(const std::string& data) const;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};


