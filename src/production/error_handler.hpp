#pragma once

#include "../core/common.hpp"
#include <functional>
#include <exception>
#include <stacktrace>

namespace rawrxd::production {

// Error severity levels
enum class ErrorSeverity {
    DEBUG = 0,      // Debug information
    INFO = 1,       // Informational
    WARNING = 2,    // Warning
    ERROR = 3,      // Recoverable error
    CRITICAL = 4,   // Critical error
    FATAL = 5       // Fatal error, cannot continue
};

// Error category
enum class ErrorCategory {
    SYSTEM,         // System-level errors
    NETWORK,        // Network errors
    DATABASE,       // Database errors
    INFERENCE,      // Model inference errors
    MEMORY,         // Memory errors
    DISK,           // Disk I/O errors
    CONFIGURATION,  // Configuration errors
    VALIDATION,     // Input validation errors
    AUTHENTICATION, // Auth errors
    AUTHORIZATION,  // Permission errors
    TIMEOUT,        // Timeout errors
    UNKNOWN         // Unknown errors
};

// Error context
struct ErrorContext {
    std::string operation;
    std::string component;
    std::string user_id;
    std::string request_id;
    std::chrono::system_clock::time_point timestamp;
    std::optional<std::stacktrace> stack_trace;
    std::unordered_map<std::string, std::string> metadata;

    ErrorContext() : timestamp(std::chrono::system_clock::now()) {}
};

// Production error
class ProductionError : public std::exception {
public:
    ProductionError(const std::string& message,
                    ErrorSeverity severity,
                    ErrorCategory category,
                    const ErrorContext& context);

    const char* what() const noexcept override { return message_.c_str(); }

    ErrorSeverity getSeverity() const { return severity_; }
    ErrorCategory getCategory() const { return category_; }
    const ErrorContext& getContext() const { return context_; }
    const std::string& getMessage() const { return message_; }

private:
    std::string message_;
    ErrorSeverity severity_;
    ErrorCategory category_;
    ErrorContext context_;
};

// Error handler
class ErrorHandler {
public:
    using ErrorCallback = std::function<void(const ProductionError&)>;
    using RecoveryFunction = std::function<bool(const ProductionError&)>;

    static ErrorHandler& getInstance();

    // Register error callback
    void registerCallback(ErrorSeverity min_severity, ErrorCallback callback);

    // Register recovery strategy
    void registerRecovery(ErrorCategory category, RecoveryFunction recovery);

    // Handle error
    void handleError(const ProductionError& error);
    void handleError(const std::exception& e,
                     ErrorSeverity severity = ErrorSeverity::ERROR,
                     ErrorCategory category = ErrorCategory::UNKNOWN);

    // Try operation with recovery
    template<typename Func>
    auto tryWithRecovery(Func&& operation, ErrorCategory category)
        -> std::optional<std::invoke_result_t<Func>> {
        try {
            return operation();
        } catch (const ProductionError& e) {
            handleError(e);
            if (auto recovered = attemptRecovery(e)) {
                return recovered;
            }
            return std::nullopt;
        } catch (const std::exception& e) {
            ProductionError pe(e.what(), ErrorSeverity::ERROR, category, ErrorContext{});
            handleError(pe);
            return std::nullopt;
        }
    }

    // Get error statistics
    struct ErrorStats {
        std::unordered_map<ErrorSeverity, uint64_t> severity_counts;
        std::unordered_map<ErrorCategory, uint64_t> category_counts;
        uint64_t total_errors = 0;
        uint64_t recovered_errors = 0;
        uint64_t unrecovered_errors = 0;
    };

    ErrorStats getStats() const;
    void resetStats();

private:
    ErrorHandler() = default;

    std::vector<std::pair<ErrorSeverity, ErrorCallback>> callbacks_;
    std::unordered_map<ErrorCategory, std::vector<RecoveryFunction>> recovery_strategies_;

    ErrorStats stats_;
    mutable std::mutex stats_mutex_;
    mutable std::shared_mutex callback_mutex_;

    void notifyCallbacks(const ProductionError& error);
    std::optional<std::any> attemptRecovery(const ProductionError& error);
};

// Scoped error context
class ScopedErrorContext {
public:
    explicit ScopedErrorContext(const std::string& operation);
    ~ScopedErrorContext();

    void setComponent(const std::string& component);
    void setUserId(const std::string& user_id);
    void setRequestId(const std::string& request_id);
    void addMetadata(const std::string& key, const std::string& value);

private:
    ErrorContext context_;
};

// Error logging macros
#define RAWRXD_TRY(operation, category) \
    rawrxd::production::ErrorHandler::getInstance().tryWithRecovery((operation), (category))

#define RAWRXD_THROW(message, severity, category) \
    throw rawrxd::production::ProductionError((message), (severity), (category), \
        rawrxd::production::ErrorContext{})

} // namespace rawrxd::production
