#pragma once
// sentry_integration.hpp – Qt-free Sentry crash reporting (C++20 / Win32)
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

<<<<<<< HEAD
// Forward-declare JSON helpers from project-wide header
struct JsonValue;
using JsonObject = std::unordered_map<std::string, JsonValue>;

/**
 * Sentry crash reporting integration for production error tracking.
 *   - Centralized error capture
 *   - Performance monitoring (latency tracking)
 *   - Breadcrumb logging for debugging context
 *   - Environment-based configuration (DSN from env var)
 *   - Privacy-respecting (no PII collection)
 */
class SentryIntegration {
public:
    static SentryIntegration* instance();

    bool initialize();

    void captureException(const std::string& exception, const JsonObject& context = {});
    void captureMessage(const std::string& message, const std::string& level = "info");
    void addBreadcrumb(const std::string& message, const std::string& category = "default");

    std::string startTransaction(const std::string& operation);
    void        finishTransaction(const std::string& transactionId);
    void        setUser(const std::string& userId);

    // --- Callbacks (replaces Qt signals) ---
    using ErrorReportedCb      = void(*)(void* ctx, const char* errorId);
    using TransactionDoneCb    = void(*)(void* ctx, const char* txId, int64_t durationMs);

    void setErrorReportedCb(ErrorReportedCb cb, void* ctx)      { m_errCb = cb; m_errCtx = ctx; }
    void setTransactionDoneCb(TransactionDoneCb cb, void* ctx)  { m_txCb = cb; m_txCtx = ctx; }

=======
#include <string>
#include <vector>
#include <mutex>
#include <nlohmann/json.hpp>

class SentryIntegration
{
public:
    static SentryIntegration* instance();
    
    bool initialize();
    
    void captureException(const std::string& exception, const nlohmann::json& context = nlohmann::json::object());
    void captureMessage(const std::string& message, const std::string& level = "info");
    
    void addBreadcrumb(const std::string& message, const std::string& category = "default", const std::string& level = "info");
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
private:
    SentryIntegration();
    ~SentryIntegration();

<<<<<<< HEAD
    static SentryIntegration* s_instance;

    bool        m_initialized = false;
    std::string m_dsn;

    std::mutex                                m_mutex;
    std::unordered_map<std::string, int64_t>  m_activeTransactions;  // txId → start ms
    std::vector<JsonObject>                   m_breadcrumbs;

    void sendEvent(const JsonObject& event);

    // Callback state
    ErrorReportedCb   m_errCb  = nullptr;  void* m_errCtx = nullptr;
    TransactionDoneCb m_txCb   = nullptr;  void* m_txCtx  = nullptr;
=======
    // No copy
    SentryIntegration(const SentryIntegration&) = delete;
    SentryIntegration& operator=(const SentryIntegration&) = delete;

    void sendEvent(const nlohmann::json& event);

    static SentryIntegration* s_instance;
    bool m_initialized = false;
    std::string m_dsn;
    std::string m_projectId;
    std::string m_publicKey;
    std::string m_sentryEndpoint;
    
    mutable std::mutex m_mutex;
    std::vector<nlohmann::json> m_breadcrumbs;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};
