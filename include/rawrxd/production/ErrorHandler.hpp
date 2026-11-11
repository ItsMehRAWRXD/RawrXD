#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <unordered_map>

namespace rawrxd {
namespace production {

// Error severity levels
enum class ErrorSeverity {
    DEBUG,      // Diagnostic information
    INFO,       // General information
    WARNING,    // Non-critical issue
    ERROR,      // Recoverable error
    CRITICAL    // Unrecoverable error
};

// Error category
enum class ErrorCategory {
    NONE,
    MODEL_LOAD,         // Model loading errors
    INFERENCE,          // Inference errors
    MEMORY,             // Memory errors
    QUANTIZATION,       // Quantization errors
    VISION,             // Vision processing errors
    NETWORK,            // Network errors
    FILE_IO,            // File I/O errors
    CONFIGURATION,      // Configuration errors
    HARDWARE,           // Hardware errors
    UNKNOWN
};

// Error context information
struct ErrorContext {
    std::string function;
    std::string file;
    int line = 0;
    std::string timestamp;
    std::unordered_map<std::string, std::string> extraInfo;
};

// Error record
struct ErrorRecord {
    ErrorSeverity severity;
    ErrorCategory category;
    std::string message;
    std::string details;
    ErrorContext context;
    std::string stackTrace;
    bool recovered = false;
    std::string recoveryAction;
};

// Error handler interface
class ErrorHandler {
public:
    ErrorHandler();
    ~ErrorHandler() = default;

    // Report an error
    void ReportError(ErrorSeverity severity,
                     ErrorCategory category,
                     const std::string& message,
                     const std::string& details = "",
                     const ErrorContext& context = ErrorContext());

    // Convenience methods
    void Debug(ErrorCategory category, const std::string& message);
    void Info(ErrorCategory category, const std::string& message);
    void Warning(ErrorCategory category, const std::string& message);
    void Error(ErrorCategory category, const std::string& message);
    void Critical(ErrorCategory category, const std::string& message);

    // Set error callback
    using ErrorCallback = std::function<void(const ErrorRecord&)>;
    void SetCallback(ErrorCallback callback);

    // Set minimum severity for reporting
    void SetMinSeverity(ErrorSeverity severity) { minSeverity_ = severity; }

    // Recovery strategies
    using RecoveryStrategy = std::function<bool(const ErrorRecord&)>;
    void RegisterRecoveryStrategy(ErrorCategory category, RecoveryStrategy strategy);
    bool AttemptRecovery(const ErrorRecord& error);

    // Get error history
    std::vector<ErrorRecord> GetErrorHistory() const { return errorHistory_; }
    std::vector<ErrorRecord> GetErrorsByCategory(ErrorCategory category) const;
    std::vector<ErrorRecord> GetErrorsBySeverity(ErrorSeverity severity) const;

    // Clear history
    void ClearHistory() { errorHistory_.clear(); }

    // Export error report
    std::string ExportToJSON() const;
    std::string ExportToMarkdown() const;

    // Global instance
    static ErrorHandler& GetInstance();

private:
    ErrorCallback callback_;
    ErrorSeverity minSeverity_ = ErrorSeverity::DEBUG;
    std::vector<ErrorRecord> errorHistory_;
    std::unordered_map<ErrorCategory, RecoveryStrategy> recoveryStrategies_;
    size_t maxHistorySize_ = 1000;

    void AddToHistory(const ErrorRecord& record);
    std::string GenerateStackTrace();
    std::string SeverityToString(ErrorSeverity severity) const;
    std::string CategoryToString(ErrorCategory category) const;
};

// Scoped error context
class ScopedErrorContext {
public:
    explicit ScopedErrorContext(const std::string& function,
                                const std::string& file,
                                int line);
    ~ScopedErrorContext() = default;

    void AddInfo(const std::string& key, const std::string& value);
    ErrorContext GetContext() const { return context_; }

private:
    ErrorContext context_;
};

// Error macros for easy context capture
#define RAWRXD_ERROR_CONTEXT() \
    ScopedErrorContext errorContext(__FUNCTION__, __FILE__, __LINE__)

#define RAWRXD_REPORT_ERROR(severity, category, message) \
    ErrorHandler::GetInstance().ReportError(severity, category, message, "", \
        ScopedErrorContext(__FUNCTION__, __FILE__, __LINE__).GetContext())

#define RAWRXD_REPORT_ERROR_WITH_DETAILS(severity, category, message, details) \
    ErrorHandler::GetInstance().ReportError(severity, category, message, details, \
        ScopedErrorContext(__FUNCTION__, __FILE__, __LINE__).GetContext())

} // namespace production
} // namespace rawrxd
