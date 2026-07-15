#include "error_handler.hpp"
#include "../core/logger.hpp"
#include <iostream>

namespace rawrxd::production {

// ============================================================================
// Production Error
// ============================================================================

ProductionError::ProductionError(const std::string& message,
                                  ErrorSeverity severity,
                                  ErrorCategory category,
                                  const ErrorContext& context)
    : message_(message), severity_(severity), category_(category), context_(context) {
}

// ============================================================================
// Error Handler
// ============================================================================

ErrorHandler& ErrorHandler::getInstance() {
    static ErrorHandler instance;
    return instance;
}

void ErrorHandler::registerCallback(ErrorSeverity min_severity, ErrorCallback callback) {
    std::unique_lock<std::shared_mutex> lock(callback_mutex_);
    callbacks_.push_back({min_severity, callback});
}

void ErrorHandler::registerRecovery(ErrorCategory category, RecoveryFunction recovery) {
    std::unique_lock<std::shared_mutex> lock(callback_mutex_);
    recovery_strategies_[category].push_back(recovery);
}

void ErrorHandler::handleError(const ProductionError& error) {
    // Log error
    logError(error);

    // Update stats
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_errors++;
        stats_.severity_counts[error.getSeverity()]++;
        stats_.category_counts[error.getCategory()]++;
    }

    // Notify callbacks
    notifyCallbacks(error);

    // Attempt recovery
    if (auto recovered = attemptRecovery(error)) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.recovered_errors++;
    } else {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.unrecovered_errors++;
    }
}

void ErrorHandler::handleError(const std::exception& e,
                               ErrorSeverity severity,
                               ErrorCategory category) {
    ErrorContext context;
    context.operation = "unknown";
    context.component = "unknown";

    ProductionError error(e.what(), severity, category, context);
    handleError(error);
}

void ErrorHandler::notifyCallbacks(const ProductionError& error) {
    std::shared_lock<std::shared_mutex> lock(callback_mutex_);

    for (const auto& [min_severity, callback] : callbacks_) {
        if (static_cast<int>(error.getSeverity()) >= static_cast<int>(min_severity)) {
            try {
                callback(error);
            } catch (...) {
                // Don't let callback errors propagate
            }
        }
    }
}

std::optional<std::any> ErrorHandler::attemptRecovery(const ProductionError& error) {
    std::shared_lock<std::shared_mutex> lock(callback_mutex_);

    auto it = recovery_strategies_.find(error.getCategory());
    if (it == recovery_strategies_.end()) {
        return std::nullopt;
    }

    for (const auto& recovery : it->second) {
        try {
            if (recovery(error)) {
                return std::any{};  // Recovery succeeded
            }
        } catch (...) {
            // Try next recovery strategy
        }
    }

    return std::nullopt;
}

void ErrorHandler::logError(const ProductionError& error) {
    const auto& ctx = error.getContext();

    std::string severity_str;
    switch (error.getSeverity()) {
        case ErrorSeverity::DEBUG: severity_str = "DEBUG"; break;
        case ErrorSeverity::INFO: severity_str = "INFO"; break;
        case ErrorSeverity::WARNING: severity_str = "WARNING"; break;
        case ErrorSeverity::ERROR: severity_str = "ERROR"; break;
        case ErrorSeverity::CRITICAL: severity_str = "CRITICAL"; break;
        case ErrorSeverity::FATAL: severity_str = "FATAL"; break;
    }

    RAWRXD_LOG_ERROR("ProductionError",
                     "[{}] {}: {} | Operation: {} | Component: {} | Request: {}",
                     severity_str,
                     static_cast<int>(error.getCategory()),
                     error.what(),
                     ctx.operation,
                     ctx.component,
                     ctx.request_id);
}

ErrorHandler::ErrorStats ErrorHandler::getStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void ErrorHandler::resetStats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = ErrorStats{};
}

// ============================================================================
// Scoped Error Context
// ============================================================================

ScopedErrorContext::ScopedErrorContext(const std::string& operation) {
    context_.operation = operation;
}

ScopedErrorContext::~ScopedErrorContext() {
    // Context automatically cleaned up
}

void ScopedErrorContext::setComponent(const std::string& component) {
    context_.component = component;
}

void ScopedErrorContext::setUserId(const std::string& user_id) {
    context_.user_id = user_id;
}

void ScopedErrorContext::setRequestId(const std::string& request_id) {
    context_.request_id = request_id;
}

void ScopedErrorContext::addMetadata(const std::string& key, const std::string& value) {
    context_.metadata[key] = value;
}

} // namespace rawrxd::production
