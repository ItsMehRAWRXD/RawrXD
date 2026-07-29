// error_recovery_system.h - Enterprise Error Recovery and Auto-Healing (Qt-free)
// FULLY SYNCHRONIZED WITH error_recovery_system.cpp
#ifndef ERROR_RECOVERY_SYSTEM_H
#define ERROR_RECOVERY_SYSTEM_H

<<<<<<< HEAD
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <nlohmann/json.hpp>
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

// Error severity levels
enum class ErrorSeverity {
    Info,
    Warning,
    Error,
    Critical,
    Fatal
};

// Error categories
enum class ErrorCategory {
    System,
    Network,
    FileIO,
    Database,
    AIModel,
    CloudProvider,
    Security,
    Performance,
    UserInput,
    Configuration
};

// Error record - matches cpp usage
<<<<<<< HEAD
struct ErrorRecord_ERS {
=======
struct ErrorRecord {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::string errorId;
    std::string component;
    ErrorSeverity severity;
    ErrorCategory category;
    std::string message;
    std::string stackTrace;
<<<<<<< HEAD
    nlohmann::json context;
=======
    void* context;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point recoveredAt;
    int retryCount = 0;
    bool wasRecovered = false;
    std::string recoveryAction;
};

// Recovery strategy - uses std::vector<ErrorCategory> for applicableCategories
struct RecoveryStrategy {
    std::string strategyId;
    std::string name;
    std::string description;
    std::vector<ErrorCategory> applicableCategories;
    std::vector<std::string> recoverySteps;
    int maxRetries = 3;
    int retryDelayMs = 1000;
    double successRate = 0.5;
    bool isAutomatic = true;
};

// Recovery execution result
struct RecoveryResult {
    std::string errorId;
    std::string strategyId;
    bool success;
    std::string resultMessage;
    std::chrono::system_clock::time_point executedAt;
    int attemptsUsed;
<<<<<<< HEAD
    nlohmann::json details;
=======
    void* details;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};

// System health status - matches cpp member name currentSystemHealth
struct SystemHealth {
    bool isHealthy = true;
    double healthScore = 100.0;
    int activeErrors = 0;
    int criticalErrors = 0;
    int errorsRecovered = 0;
    int errorsPending = 0;
    std::unordered_map<std::string, int> errorsByComponent;
    std::unordered_map<std::string, int> errorsByCategory;
    std::chrono::system_clock::time_point lastCheckTime;
};

<<<<<<< HEAD
// Callback types (replaces Qt signals)
using ErrorRecordedERS_Cb       = void(*)(const ErrorRecord_ERS& error, void* ud);
using ErrorRecoveredERS_Cb      = void(*)(const std::string& errorId, bool success, void* ud);
using ErrorRecoveredRecordCb    = void(*)(const ErrorRecord_ERS& error, void* ud);
using RecoveryFailedCb_ERS      = void(*)(const ErrorRecord_ERS& error, void* ud);
using SystemHealthUpdatedCb     = void(*)(const SystemHealth& health, void* ud);
using ComponentRequestCb        = void(*)(const std::string& component, void* ud);
using SimpleRequestCb           = void(*)(void* ud);
using AdminEscalationCb         = void(*)(const ErrorRecord_ERS& error, void* ud);
=======
class ErrorRecoverySystem : public void {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

class ErrorRecoverySystem {
public:
<<<<<<< HEAD
    ErrorRecoverySystem();
=======
    explicit ErrorRecoverySystem(void* parent = nullptr);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    ~ErrorRecoverySystem();

    // Error recording - returns errorId as std::string
    std::string recordError(const std::string& component,
                       ErrorSeverity severity,
                       ErrorCategory category,
                       const std::string& message,
<<<<<<< HEAD
                       const std::string& stackTrace = "",
                       const nlohmann::json& context = nlohmann::json::object());
    
    // Error retrieval
    std::vector<ErrorRecord_ERS> getActiveErrors() const;
    std::vector<ErrorRecord_ERS> getErrorsByComponent(const std::string& component) const;
    std::vector<ErrorRecord_ERS> getErrorsBySeverity(ErrorSeverity severity) const;
    ErrorRecord_ERS getError(const std::string& errorId) const;
    
    // Recovery operations
    bool attemptRecovery(const std::string& errorId);
    RecoveryStrategy selectBestStrategy(const ErrorRecord_ERS& error);
=======
                       const std::string& stackTrace = std::string(),
                       const void*& context = void*());
    
    // Error retrieval
    std::vector<ErrorRecord> getActiveErrors() const;
    std::vector<ErrorRecord> getErrorsByComponent(const std::string& component) const;
    std::vector<ErrorRecord> getErrorsBySeverity(ErrorSeverity severity) const;
    ErrorRecord getError(const std::string& errorId) const;
    
    // Recovery operations
    bool attemptRecovery(const std::string& errorId);
    RecoveryStrategy selectBestStrategy(const ErrorRecord& error);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    
    // Auto-recovery configuration
    void enableAutoRecovery(bool enable);
    void setMaxRetries(int retries);
    void setRetryDelay(int milliseconds);
    bool isAutoRecoveryEnabled() const { return autoRecoveryEnabled; }
    
    // Poll-based tick (replaces QTimer — call periodically from main loop)
    void tick();
    
    // System health
    SystemHealth getSystemHealth() const;
    
    // Error management
    void clearErrorHistory();
    void clearRecoveredErrors();
    void resolveError(const std::string& errorId);
    
    // Statistics
<<<<<<< HEAD
    nlohmann::json getErrorStatistics() const;
=======
    void* getErrorStatistics() const;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    
    // Utility - member functions (const)
    std::string errorSeverityToString(ErrorSeverity severity) const;
    std::string errorCategoryToString(ErrorCategory category) const;
<<<<<<< HEAD

    // ===== CALLBACKS (replaces Qt signals) =====
    void setErrorRecordedCb(ErrorRecordedERS_Cb cb, void* ud = nullptr)       { m_errorRecordedCb = cb; m_errorRecordedUd = ud; }
    void setErrorRecoveredCb(ErrorRecoveredERS_Cb cb, void* ud = nullptr)     { m_errorRecoveredCb = cb; m_errorRecoveredUd = ud; }
    void setErrorRecoveredRecordCb(ErrorRecoveredRecordCb cb, void* ud = nullptr) { m_errorRecoveredRecordCb = cb; m_errorRecoveredRecordUd = ud; }
    void setRecoveryFailedCb(RecoveryFailedCb_ERS cb, void* ud = nullptr)     { m_recoveryFailedCb = cb; m_recoveryFailedUd = ud; }
    void setSystemHealthUpdatedCb(SystemHealthUpdatedCb cb, void* ud = nullptr) { m_systemHealthUpdatedCb = cb; m_systemHealthUpdatedUd = ud; }
    void setFallbackToLocalCb(ComponentRequestCb cb, void* ud = nullptr)      { m_fallbackToLocalCb = cb; m_fallbackToLocalUd = ud; }
    void setCacheClearCb(ComponentRequestCb cb, void* ud = nullptr)           { m_cacheClearCb = cb; m_cacheClearUd = ud; }
    void setComponentRestartCb(ComponentRequestCb cb, void* ud = nullptr)     { m_componentRestartCb = cb; m_componentRestartUd = ud; }
    void setNetworkReconnectCb(SimpleRequestCb cb, void* ud = nullptr)        { m_networkReconnectCb = cb; m_networkReconnectUd = ud; }
    void setDataReloadCb(ComponentRequestCb cb, void* ud = nullptr)           { m_dataReloadCb = cb; m_dataReloadUd = ud; }
    void setResourceReductionCb(SimpleRequestCb cb, void* ud = nullptr)       { m_resourceReductionCb = cb; m_resourceReductionUd = ud; }
    void setEndpointSwitchCb(ComponentRequestCb cb, void* ud = nullptr)       { m_endpointSwitchCb = cb; m_endpointSwitchUd = ud; }
    void setGracefulDegradationCb(SimpleRequestCb cb, void* ud = nullptr)     { m_gracefulDegradationCb = cb; m_gracefulDegradationUd = ud; }
    void setReauthenticationCb(ComponentRequestCb cb, void* ud = nullptr)     { m_reauthenticationCb = cb; m_reauthenticationUd = ud; }
    void setAdminEscalationCb(AdminEscalationCb cb, void* ud = nullptr)       { m_adminEscalationCb = cb; m_adminEscalationUd = ud; }
=======


    void errorRecorded(const ErrorRecord& error);
    void errorRecovered(const std::string& errorId, bool success);
    void errorRecoveredRecord(const ErrorRecord& error);
    void recoveryFailed(const ErrorRecord& error);
    void systemHealthUpdated(const SystemHealth& health);
    
    // Recovery action signals
    void fallbackToLocalRequested(const std::string& component);
    void cacheClearRequested(const std::string& component);
    void componentRestartRequested(const std::string& component);
    void networkReconnectRequested();
    void dataReloadRequested(const std::string& component);
    void resourceReductionRequested();
    void endpointSwitchRequested(const std::string& component);
    void gracefulDegradationEnabled();
    void reauthenticationRequested(const std::string& component);
    void adminEscalationRequired(const ErrorRecord& error);

private:
    void processAutoRecovery();
    void updateSystemHealth();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

private:
    // Setup
    void setupDefaultStrategies();
    
    // Recovery execution
    bool executeRecoveryStrategy(ErrorRecord_ERS& error, const RecoveryStrategy& strategy);
    
    // Built-in recovery methods
    bool recoverWithRetry(ErrorRecord_ERS& error);
    bool recoverFallbackLocal(ErrorRecord_ERS& error);
    bool recoverClearCache(ErrorRecord_ERS& error);
    bool recoverRestartComponent(ErrorRecord_ERS& error);
    bool recoverReconnectNetwork(ErrorRecord_ERS& error);
    bool recoverReloadData(ErrorRecord_ERS& error);
    bool recoverReduceResources(ErrorRecord_ERS& error);
    bool recoverSwitchEndpoint(ErrorRecord_ERS& error);
    bool recoverGracefulDegradation(ErrorRecord_ERS& error);
    bool recoverReauthenticate(ErrorRecord_ERS& error);
    bool recoverEscalateAdmin(ErrorRecord_ERS& error);
    
    // ID generation
    std::string generateErrorId();
<<<<<<< HEAD

    // Poll-based periodic handlers (replace QTimer slots)
    void processAutoRecovery();
    void updateSystemHealth();
    
    // Data members
    std::unordered_map<std::string, ErrorRecord_ERS> activeErrors;
    std::vector<ErrorRecord_ERS> recoveredErrors;
    std::vector<ErrorRecord_ERS> errorHistory;
=======
    
    // Data members - exact names from cpp
    std::unordered_map<std::string, ErrorRecord> activeErrors;
    std::vector<ErrorRecord> recoveredErrors;
    std::vector<ErrorRecord> errorHistory;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::unordered_map<std::string, RecoveryStrategy> strategies;
    
    SystemHealth currentSystemHealth;
    
<<<<<<< HEAD
    // Timing for poll-based tick (replaces QTimer)
    std::chrono::steady_clock::time_point m_lastAutoRecoveryTick;
    std::chrono::steady_clock::time_point m_lastHealthCheckTick;
=======
    void** autoRecoveryTimer;
    void** healthCheckTimer;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    
    bool autoRecoveryEnabled;
    int maxRetries;
    int retryDelayMs;
    int healthCheckIntervalMs;

    // Deferred recovery queue (replaces QTimer::singleShot)
    struct DeferredRecovery {
        std::string errorId;
        std::chrono::steady_clock::time_point triggerTime;
    };
    std::vector<DeferredRecovery> m_deferredRecoveries;

    // Callbacks (function pointers, per project rules)
    ErrorRecordedERS_Cb    m_errorRecordedCb = nullptr;        void* m_errorRecordedUd = nullptr;
    ErrorRecoveredERS_Cb   m_errorRecoveredCb = nullptr;       void* m_errorRecoveredUd = nullptr;
    ErrorRecoveredRecordCb m_errorRecoveredRecordCb = nullptr;  void* m_errorRecoveredRecordUd = nullptr;
    RecoveryFailedCb_ERS   m_recoveryFailedCb = nullptr;       void* m_recoveryFailedUd = nullptr;
    SystemHealthUpdatedCb  m_systemHealthUpdatedCb = nullptr;   void* m_systemHealthUpdatedUd = nullptr;
    ComponentRequestCb     m_fallbackToLocalCb = nullptr;       void* m_fallbackToLocalUd = nullptr;
    ComponentRequestCb     m_cacheClearCb = nullptr;            void* m_cacheClearUd = nullptr;
    ComponentRequestCb     m_componentRestartCb = nullptr;      void* m_componentRestartUd = nullptr;
    SimpleRequestCb        m_networkReconnectCb = nullptr;      void* m_networkReconnectUd = nullptr;
    ComponentRequestCb     m_dataReloadCb = nullptr;            void* m_dataReloadUd = nullptr;
    SimpleRequestCb        m_resourceReductionCb = nullptr;     void* m_resourceReductionUd = nullptr;
    ComponentRequestCb     m_endpointSwitchCb = nullptr;        void* m_endpointSwitchUd = nullptr;
    SimpleRequestCb        m_gracefulDegradationCb = nullptr;   void* m_gracefulDegradationUd = nullptr;
    ComponentRequestCb     m_reauthenticationCb = nullptr;      void* m_reauthenticationUd = nullptr;
    AdminEscalationCb      m_adminEscalationCb = nullptr;       void* m_adminEscalationUd = nullptr;
};

#endif // ERROR_RECOVERY_SYSTEM_H

