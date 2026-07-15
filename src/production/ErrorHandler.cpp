#include "rawrxd/production/ErrorHandler.hpp"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>

namespace rawrxd {
namespace production {

// Global instance
ErrorHandler& ErrorHandler::GetInstance() {
    static ErrorHandler instance;
    return instance;
}

ErrorHandler::ErrorHandler() = default;

void ErrorHandler::ReportError(ErrorSeverity severity,
                               ErrorCategory category,
                               const std::string& message,
                               const std::string& details,
                               const ErrorContext& context) {
    // Filter by severity
    if (static_cast<int>(severity) < static_cast<int>(minSeverity_)) {
        return;
    }

    ErrorRecord record;
    record.severity = severity;
    record.category = category;
    record.message = message;
    record.details = details;
    record.context = context;
    record.stackTrace = GenerateStackTrace();

    // Attempt recovery for errors
    if (severity == ErrorSeverity::ERROR || severity == ErrorSeverity::CRITICAL) {
        record.recovered = AttemptRecovery(record);
    }

    // Add to history
    AddToHistory(record);

    // Call callback if set
    if (callback_) {
        callback_(record);
    }
}

void ErrorHandler::Debug(ErrorCategory category, const std::string& message) {
    ReportError(ErrorSeverity::DEBUG, category, message);
}

void ErrorHandler::Info(ErrorCategory category, const std::string& message) {
    ReportError(ErrorSeverity::INFO, category, message);
}

void ErrorHandler::Warning(ErrorCategory category, const std::string& message) {
    ReportError(ErrorSeverity::WARNING, category, message);
}

void ErrorHandler::Error(ErrorCategory category, const std::string& message) {
    ReportError(ErrorSeverity::ERROR, category, message);
}

void ErrorHandler::Critical(ErrorCategory category, const std::string& message) {
    ReportError(ErrorSeverity::CRITICAL, category, message);
}

void ErrorHandler::SetCallback(ErrorCallback callback) {
    callback_ = callback;
}

void ErrorHandler::RegisterRecoveryStrategy(ErrorCategory category, RecoveryStrategy strategy) {
    recoveryStrategies_[category] = strategy;
}

bool ErrorHandler::AttemptRecovery(const ErrorRecord& error) {
    auto it = recoveryStrategies_.find(error.category);
    if (it != recoveryStrategies_.end()) {
        return it->second(error);
    }
    return false;
}

std::vector<ErrorRecord> ErrorHandler::GetErrorsByCategory(ErrorCategory category) const {
    std::vector<ErrorRecord> result;
    for (const auto& record : errorHistory_) {
        if (record.category == category) {
            result.push_back(record);
        }
    }
    return result;
}

std::vector<ErrorRecord> ErrorHandler::GetErrorsBySeverity(ErrorSeverity severity) const {
    std::vector<ErrorRecord> result;
    for (const auto& record : errorHistory_) {
        if (record.severity == severity) {
            result.push_back(record);
        }
    }
    return result;
}

std::string ErrorHandler::ExportToJSON() const {
    std::stringstream json;
    json << "{\n";
    json << "  \"errors\": [\n";

    for (size_t i = 0; i < errorHistory_.size(); ++i) {
        const auto& record = errorHistory_[i];
        json << "    {\n";
        json << "      \"severity\": \"" << SeverityToString(record.severity) << "\",\n";
        json << "      \"category\": \"" << CategoryToString(record.category) << "\",\n";
        json << "      \"message\": \"" << record.message << "\",\n";
        json << "      \"details\": \"" << record.details << "\",\n";
        json << "      \"recovered\": " << (record.recovered ? "true" : "false") << "\n";
        json << "    }";
        if (i < errorHistory_.size() - 1) json << ",";
        json << "\n";
    }

    json << "  ]\n";
    json << "}";
    return json.str();
}

std::string ErrorHandler::ExportToMarkdown() const {
    std::stringstream md;
    md << "# Error Report\n\n";
    md << "| Severity | Category | Message | Recovered |\n";
    md << "|----------|----------|---------|-----------|\n";

    for (const auto& record : errorHistory_) {
        md << "| " << SeverityToString(record.severity)
           << " | " << CategoryToString(record.category)
           << " | " << record.message
           << " | " << (record.recovered ? "Yes" : "No") << " |\n";
    }

    return md.str();
}

void ErrorHandler::AddToHistory(const ErrorRecord& record) {
    errorHistory_.push_back(record);
    if (errorHistory_.size() > maxHistorySize_) {
        errorHistory_.erase(errorHistory_.begin());
    }
}

std::string ErrorHandler::GenerateStackTrace() {
    // Platform-specific stack trace generation would go here
    // For now, return empty string
    return "";
}

std::string ErrorHandler::SeverityToString(ErrorSeverity severity) const {
    switch (severity) {
        case ErrorSeverity::DEBUG: return "DEBUG";
        case ErrorSeverity::INFO: return "INFO";
        case ErrorSeverity::WARNING: return "WARNING";
        case ErrorSeverity::ERROR: return "ERROR";
        case ErrorSeverity::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

std::string ErrorHandler::CategoryToString(ErrorCategory category) const {
    switch (category) {
        case ErrorCategory::MODEL_LOAD: return "MODEL_LOAD";
        case ErrorCategory::INFERENCE: return "INFERENCE";
        case ErrorCategory::MEMORY: return "MEMORY";
        case ErrorCategory::QUANTIZATION: return "QUANTIZATION";
        case ErrorCategory::VISION: return "VISION";
        case ErrorCategory::NETWORK: return "NETWORK";
        case ErrorCategory::FILE_IO: return "FILE_IO";
        case ErrorCategory::CONFIGURATION: return "CONFIGURATION";
        case ErrorCategory::HARDWARE: return "HARDWARE";
        case ErrorCategory::UNKNOWN: return "UNKNOWN";
        default: return "NONE";
    }
}

// ScopedErrorContext implementation
ScopedErrorContext::ScopedErrorContext(const std::string& function,
                                       const std::string& file,
                                       int line) {
    context_.function = function;
    context_.file = file;
    context_.line = line;

    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    context_.timestamp = ss.str();
}

void ScopedErrorContext::AddInfo(const std::string& key, const std::string& value) {
    context_.extraInfo[key] = value;
}

} // namespace production
} // namespace rawrxd
